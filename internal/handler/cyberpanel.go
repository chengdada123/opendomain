package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/pkg/crypto"
)

type CyberPanelHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewCyberPanelHandler(db *gorm.DB, cfg *config.Config) *CyberPanelHandler {
	return &CyberPanelHandler{db: db, cfg: cfg}
}

// ─── 信息流：CyberPanel API ────────────────────────────────────────────────

type cpRequest struct {
	AdminUser     string `json:"adminUser"`
	AdminPass     string `json:"adminPass"`
	DomainName    string `json:"domainName,omitempty"`
	WebsiteName   string `json:"websiteName,omitempty"`
	PackageName   string `json:"packageName,omitempty"`
	OwnerEmail    string `json:"ownerEmail,omitempty"`
	WebsiteOwner  string `json:"websiteOwner,omitempty"`
	OwnerPassword string `json:"ownerPassword,omitempty"`
	State         string `json:"state,omitempty"`
}

// cpHTTPClient returns an HTTP client that skips TLS certificate verification.
// CyberPanel instances commonly use self-signed certificates with no IP SANs.
func cpHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func (h *CyberPanelHandler) callCyberPanel(serverURL, endpoint string, payload cpRequest) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := cpHTTPClient(30*time.Second).Post(
		serverURL+endpoint,
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("CyberPanel returned HTTP %d: %s", resp.StatusCode, string(raw))
	}

	// CyberPanel always returns HTTP 200; check application-level error in body.
	// All endpoints return {"error_message": "None"} on success,
	// or {"error_message": "<reason>"} on failure.
	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		// Non-JSON response (e.g. HTML error page) — treat as failure
		limit := 256
		if len(raw) < limit {
			limit = len(raw)
		}
		return fmt.Errorf("unexpected response: %s", string(raw[:limit]))
	}
	if errMsg, ok := result["error_message"]; ok {
		s := fmt.Sprintf("%v", errMsg)
		if s != "" && s != "None" && s != "none" {
			return fmt.Errorf("%s", s)
		}
	}
	return nil
}

func (h *CyberPanelHandler) decryptPass(enc string) (string, error) {
	return crypto.Decrypt(enc, h.cfg.CyberPanel.EncryptionKey)
}

func (h *CyberPanelHandler) encryptPass(plain string) (string, error) {
	return crypto.Encrypt(plain, h.cfg.CyberPanel.EncryptionKey)
}

// ─── 服务器分配：轮询（选当前账号数最少的活跃服务器）─────────────────────

func (h *CyberPanelHandler) pickServer(preferServerID *uint) (*models.CyberPanelServer, error) {
	if preferServerID != nil {
		var srv models.CyberPanelServer
		if err := h.db.Where("id = ? AND is_active = ?", *preferServerID, true).First(&srv).Error; err != nil {
			return nil, fmt.Errorf("specified server not found or inactive")
		}
		if srv.MaxAccounts > 0 && srv.CurrentAccounts >= srv.MaxAccounts {
			return nil, fmt.Errorf("specified server has reached its account limit")
		}
		return &srv, nil
	}

	var srv models.CyberPanelServer
	query := h.db.Where("is_active = ?", true).Order("current_accounts ASC, id ASC")
	if err := query.First(&srv).Error; err != nil {
		return nil, fmt.Errorf("no active CyberPanel server available")
	}
	if srv.MaxAccounts > 0 && srv.CurrentAccounts >= srv.MaxAccounts {
		return nil, fmt.Errorf("all CyberPanel servers have reached their account limits")
	}
	return &srv, nil
}

// ════════════════════════════════════════════════════════════════════════════
// 管理员接口
// ════════════════════════════════════════════════════════════════════════════

// AdminListServers GET /api/admin/cyberpanel/servers
func (h *CyberPanelHandler) AdminListServers(c *gin.Context) {
	var servers []models.CyberPanelServer
	if err := h.db.Order("id ASC").Find(&servers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch servers"})
		return
	}
	resp := make([]*models.CyberPanelServerResponse, len(servers))
	for i, s := range servers {
		resp[i] = s.ToResponse()
	}
	c.JSON(http.StatusOK, gin.H{"servers": resp})
}

// AdminCreateServer POST /api/admin/cyberpanel/servers
func (h *CyberPanelHandler) AdminCreateServer(c *gin.Context) {
	var req models.CyberPanelServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	encPass, err := h.encryptPass(req.AdminPass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
		return
	}

	// 如果设置为 default，先清除其他 default
	if req.IsDefault != nil && *req.IsDefault {
		h.db.Model(&models.CyberPanelServer{}).Where("is_default = ?", true).Update("is_default", false)
	}

	server := models.CyberPanelServer{
		Name:        req.Name,
		URL:         req.URL,
		AdminUser:   req.AdminUser,
		AdminPass:   encPass,
		PackageName: req.PackageName,
		Description: req.Description,
	}
	if req.IsActive != nil {
		server.IsActive = *req.IsActive
	} else {
		server.IsActive = true
	}
	if req.IsDefault != nil {
		server.IsDefault = *req.IsDefault
	}
	if req.MaxAccounts != nil {
		server.MaxAccounts = *req.MaxAccounts
	}

	if err := h.db.Create(&server).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"server": server.ToResponse()})
}

// AdminUpdateServer PUT /api/admin/cyberpanel/servers/:id
func (h *CyberPanelHandler) AdminUpdateServer(c *gin.Context) {
	serverID := c.Param("id")
	var server models.CyberPanelServer
	if err := h.db.First(&server, serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	var req models.CyberPanelServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{
		"name":         req.Name,
		"url":          req.URL,
		"admin_user":   req.AdminUser,
		"package_name": req.PackageName,
	}
	if req.Description != nil {
		updates["description"] = req.Description
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}
	if req.MaxAccounts != nil {
		updates["max_accounts"] = *req.MaxAccounts
	}
	if req.IsDefault != nil && *req.IsDefault {
		h.db.Model(&models.CyberPanelServer{}).Where("id != ? AND is_default = ?", server.ID, true).Update("is_default", false)
		updates["is_default"] = true
	} else if req.IsDefault != nil {
		updates["is_default"] = false
	}

	// 只有在提供了新密码时才更新
	if req.AdminPass != "" {
		encPass, err := h.encryptPass(req.AdminPass)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
			return
		}
		updates["admin_pass"] = encPass
	}

	if err := h.db.Model(&server).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update server"})
		return
	}

	h.db.First(&server, serverID)
	c.JSON(http.StatusOK, gin.H{"server": server.ToResponse()})
}

// AdminDeleteServer DELETE /api/admin/cyberpanel/servers/:id
func (h *CyberPanelHandler) AdminDeleteServer(c *gin.Context) {
	serverID := c.Param("id")
	var server models.CyberPanelServer
	if err := h.db.First(&server, serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// 检查是否还有关联账号
	var count int64
	h.db.Model(&models.CyberPanelAccount{}).Where("server_id = ? AND status != ?", server.ID, "terminated").Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Server still has %d active accounts, cannot delete", count)})
		return
	}

	if err := h.db.Delete(&server).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete server"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Server deleted"})
}

// AdminTestServer POST /api/admin/cyberpanel/servers/:id/test
func (h *CyberPanelHandler) AdminTestServer(c *gin.Context) {
	serverID := c.Param("id")
	var server models.CyberPanelServer
	if err := h.db.First(&server, serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	adminPass, err := h.decryptPass(server.AdminPass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt password"})
		return
	}

	// 使用官方 verifyConn 接口验证连通性
	payload := map[string]string{
		"adminUser": server.AdminUser,
		"adminPass": adminPass,
	}
	body, _ := json.Marshal(payload)
	client := cpHTTPClient(10 * time.Second)
	resp, err := client.Post(server.URL+"/api/verifyConn", "application/json", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(raw))})
		return
	}

	// API 返回 {"verifyConn": "1", "error_message": "..."}
	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "Invalid response from CyberPanel"})
		return
	}
	if v, ok := result["verifyConn"]; !ok || fmt.Sprintf("%v", v) != "1" {
		errMsg := "Authentication failed"
		if em, ok := result["error_message"]; ok {
			errMsg = fmt.Sprintf("%v", em)
		}
		c.JSON(http.StatusOK, gin.H{"success": false, "error": errMsg})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Connection successful"})
}

// AdminListAccounts GET /api/admin/cyberpanel/accounts
func (h *CyberPanelHandler) AdminListAccounts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := h.db.Model(&models.CyberPanelAccount{}).
		Preload("User").Preload("Domain").Preload("Server")

	if status := c.Query("status"); status != "" {
		query = query.Where("cyberpanel_accounts.status = ?", status)
	}
	if serverID := c.Query("server_id"); serverID != "" {
		query = query.Where("server_id = ?", serverID)
	}

	var total int64
	query.Count(&total)

	var accounts []models.CyberPanelAccount
	if err := query.Order("cyberpanel_accounts.created_at DESC").Offset(offset).Limit(pageSize).Find(&accounts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch accounts"})
		return
	}

	resp := make([]models.CyberPanelAccountResponse, len(accounts))
	for i, acc := range accounts {
		resp[i] = h.toAccountResponse(acc)
	}

	c.JSON(http.StatusOK, gin.H{
		"accounts":  resp,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// AdminSuspendAccount POST /api/admin/cyberpanel/accounts/:id/suspend
func (h *CyberPanelHandler) AdminSuspendAccount(c *gin.Context) {
	h.adminChangeAccountState(c, "suspended", "Suspend")
}

// AdminUnsuspendAccount POST /api/admin/cyberpanel/accounts/:id/unsuspend
func (h *CyberPanelHandler) AdminUnsuspendAccount(c *gin.Context) {
	h.adminChangeAccountState(c, "active", "Active")
}

func (h *CyberPanelHandler) adminChangeAccountState(c *gin.Context, newStatus, cpState string) {
	accountID := c.Param("id")
	var account models.CyberPanelAccount
	if err := h.db.Preload("Server").Preload("Domain").First(&account, accountID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	if account.Server == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server not found"})
		return
	}

	adminPass, err := h.decryptPass(account.Server.AdminPass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt server password"})
		return
	}

	domainName := ""
	if account.Domain != nil {
		domainName = account.Domain.FullDomain
	}

	if err := h.callCyberPanel(account.Server.URL, "/api/submitWebsiteStatus", cpRequest{
		AdminUser:   account.Server.AdminUser,
		AdminPass:   adminPass,
		WebsiteName: domainName,
		State:       cpState,
	}); err != nil {
		errMsg := err.Error()
		h.db.Model(&account).Update("error_msg", errMsg)
		c.JSON(http.StatusBadGateway, gin.H{"error": "CyberPanel API error: " + errMsg})
		return
	}

	h.db.Model(&account).Updates(map[string]interface{}{
		"status":    newStatus,
		"error_msg": nil,
	})

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Account %s", newStatus)})
}

// AdminTerminateAccount DELETE /api/admin/cyberpanel/accounts/:id
func (h *CyberPanelHandler) AdminTerminateAccount(c *gin.Context) {
	accountID := c.Param("id")
	var account models.CyberPanelAccount
	if err := h.db.Preload("Server").Preload("Domain").First(&account, accountID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	h.terminateAccount(&account)

	c.JSON(http.StatusOK, gin.H{"message": "Account terminated"})
}

// ════════════════════════════════════════════════════════════════════════════
// 用户接口
// ════════════════════════════════════════════════════════════════════════════

// ListMyAccounts GET /api/cyberpanel/accounts
func (h *CyberPanelHandler) ListMyAccounts(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var accounts []models.CyberPanelAccount
	if err := h.db.Preload("Domain").Preload("Domain.RootDomain").Preload("Server").
		Where("user_id = ?", userID).
		Order("created_at DESC").Find(&accounts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch accounts"})
		return
	}

	resp := make([]models.CyberPanelAccountResponse, len(accounts))
	for i, acc := range accounts {
		resp[i] = h.toAccountResponse(acc)
	}
	c.JSON(http.StatusOK, gin.H{"accounts": resp})
}

// CreateAccount POST /api/cyberpanel/accounts
func (h *CyberPanelHandler) CreateAccount(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.CyberPanelCreateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查询用户
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	// 验证域名归属及状态
	var domain models.Domain
	if err := h.db.Preload("RootDomain").
		Where("id = ? AND user_id = ?", req.DomainID, userID).
		First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found or not owned by you"})
		return
	}
	if domain.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain must be active to create a hosting account"})
		return
	}

	// 域名是否已绑定账号
	var existingCount int64
	h.db.Model(&models.CyberPanelAccount{}).Where("domain_id = ?", domain.ID).Count(&existingCount)
	if existingCount > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "This domain already has a hosting account"})
		return
	}

	// 配额：当前有几个活跃域名，就允许几个主机
	var activeDomainCount int64
	h.db.Model(&models.Domain{}).Where("user_id = ? AND status = ?", userID, "active").Count(&activeDomainCount)
	var activeAccCount int64
	h.db.Model(&models.CyberPanelAccount{}).Where("user_id = ? AND status != ?", userID, "terminated").Count(&activeAccCount)
	if activeAccCount >= activeDomainCount {
		c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("Hosting quota reached (%d/%d). Register more domains to get more hosting slots.", activeAccCount, activeDomainCount)})
		return
	}

	// 选择服务器
	server, err := h.pickServer(req.ServerID)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	// 加密密码
	encPass, err := h.encryptPass(req.CpPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
		return
	}

	now := time.Now()
	account := models.CyberPanelAccount{
		UserID:     userID,
		DomainID:   domain.ID,
		ServerID:   server.ID,
		CpUsername: req.CpUsername,
		CpPassword: encPass,
		Status:     "pending",
	}
	if err := h.db.Create(&account).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create account record"})
		return
	}

	_ = now

	// 解密管理员密码，调用 CyberPanel 创建主机
	adminPass, err := h.decryptPass(server.AdminPass)
	if err != nil {
		errMsg := "Failed to decrypt server password"
		h.db.Model(&account).Updates(map[string]interface{}{"status": "pending", "error_msg": errMsg})
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMsg})
		return
	}

	cpErr := h.callCyberPanel(server.URL, "/api/createWebsite", cpRequest{
		AdminUser:     server.AdminUser,
		AdminPass:     adminPass,
		DomainName:    domain.FullDomain,
		PackageName:   server.PackageName,
		OwnerEmail:    user.Email,
		WebsiteOwner:  req.CpUsername,
		OwnerPassword: req.CpPassword,
	})

	if cpErr != nil {
		errMsg := cpErr.Error()
		h.db.Model(&account).Updates(map[string]interface{}{"status": "pending", "error_msg": errMsg})
		// 仍然返回 201，让用户知道账号已创建，但有错误
		acc := h.loadAccount(account.ID)
		resp := h.toAccountResponse(*acc)
		c.JSON(http.StatusCreated, gin.H{
			"account": resp,
			"warning": "Account created but CyberPanel provisioning failed: " + errMsg,
		})
		return
	}

	// 成功：更新状态和服务器账号计数
	h.db.Model(&account).Updates(map[string]interface{}{"status": "active", "error_msg": nil})
	h.db.Model(server).UpdateColumn("current_accounts", gorm.Expr("current_accounts + 1"))

	acc := h.loadAccount(account.ID)
	resp := h.toAccountResponse(*acc)
	c.JSON(http.StatusCreated, gin.H{"account": resp})
}

// DeleteMyAccount DELETE /api/cyberpanel/accounts/:id
func (h *CyberPanelHandler) DeleteMyAccount(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	accountID := c.Param("id")
	var account models.CyberPanelAccount
	if err := h.db.Preload("Server").Preload("Domain").
		Where("id = ? AND user_id = ?", accountID, userID).
		First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	h.terminateAccount(&account)
	c.JSON(http.StatusOK, gin.H{"message": "Account terminated"})
}

// ════════════════════════════════════════════════════════════════════════════
// 内部工具
// ════════════════════════════════════════════════════════════════════════════

// terminateAccount 调用 CyberPanel 删除主机并更新状态
func (h *CyberPanelHandler) terminateAccount(account *models.CyberPanelAccount) {
	if account.Server == nil || account.Status == "terminated" {
		h.db.Model(account).Update("status", "terminated")
		return
	}

	adminPass, err := h.decryptPass(account.Server.AdminPass)
	if err == nil {
		domainName := ""
		if account.Domain != nil {
			domainName = account.Domain.FullDomain
		}
		if err := h.callCyberPanel(account.Server.URL, "/api/deleteWebsite", cpRequest{
			AdminUser:  account.Server.AdminUser,
			AdminPass:  adminPass,
			DomainName: domainName,
		}); err != nil {
			fmt.Printf("Warning: CyberPanel terminateAccount failed for account %d: %v\n", account.ID, err)
		}
	}

	h.db.Model(account).Update("status", "terminated")
	h.db.Model(&models.CyberPanelServer{}).Where("id = ? AND current_accounts > 0", account.ServerID).
		UpdateColumn("current_accounts", gorm.Expr("current_accounts - 1"))
}

// SuspendAccountByDomain 由 domain handler 调用：挂起某个域名对应的 CyberPanel 账号
func (h *CyberPanelHandler) SuspendAccountByDomain(domainID uint) {
	var account models.CyberPanelAccount
	if err := h.db.Preload("Server").Preload("Domain").
		Where("domain_id = ? AND status = ?", domainID, "active").
		First(&account).Error; err != nil {
		return // 没有关联账号，忽略
	}
	h.changeAccountStatus(&account, "suspended", "Suspend")
}

// UnsuspendAccountByDomain 由 domain handler 调用：恢复某个域名对应的 CyberPanel 账号
func (h *CyberPanelHandler) UnsuspendAccountByDomain(domainID uint) {
	var account models.CyberPanelAccount
	if err := h.db.Preload("Server").Preload("Domain").
		Where("domain_id = ? AND status = ?", domainID, "suspended").
		First(&account).Error; err != nil {
		return
	}
	h.changeAccountStatus(&account, "active", "Active")
}

func (h *CyberPanelHandler) changeAccountStatus(account *models.CyberPanelAccount, newStatus, cpState string) {
	if account.Server == nil {
		return
	}
	adminPass, err := h.decryptPass(account.Server.AdminPass)
	if err != nil {
		return
	}
	domainName := ""
	if account.Domain != nil {
		domainName = account.Domain.FullDomain
	}
	if err := h.callCyberPanel(account.Server.URL, "/api/submitWebsiteStatus", cpRequest{
		AdminUser:   account.Server.AdminUser,
		AdminPass:   adminPass,
		WebsiteName: domainName,
		State:       cpState,
	}); err != nil {
		fmt.Printf("Warning: CyberPanel %s failed for account %d: %v\n", cpState, account.ID, err)
		return
	}
	h.db.Model(account).Update("status", newStatus)
}

func (h *CyberPanelHandler) loadAccount(id uint) *models.CyberPanelAccount {
	var acc models.CyberPanelAccount
	h.db.Preload("Domain").Preload("Domain.RootDomain").Preload("Server").First(&acc, id)
	return &acc
}

func (h *CyberPanelHandler) toAccountResponse(acc models.CyberPanelAccount) models.CyberPanelAccountResponse {
	plainPass, _ := h.decryptPass(acc.CpPassword)

	resp := models.CyberPanelAccountResponse{
		ID:         acc.ID,
		UserID:     acc.UserID,
		DomainID:   acc.DomainID,
		ServerID:   acc.ServerID,
		CpUsername: acc.CpUsername,
		CpPassword: plainPass,
		Status:     acc.Status,
		ErrorMsg:   acc.ErrorMsg,
		CreatedAt:  acc.CreatedAt,
		UpdatedAt:  acc.UpdatedAt,
		Domain:     acc.Domain,
	}
	if acc.Server != nil {
		resp.Server = acc.Server.ToResponse()
	}
	return resp
}
