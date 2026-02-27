package models

import (
	"time"
)

// CyberPanelServer CyberPanel 服务器配置
type CyberPanelServer struct {
	ID              uint      `gorm:"primarykey" json:"id"`
	Name            string    `gorm:"size:100;not null" json:"name"`
	URL             string    `gorm:"size:255;not null" json:"url"`
	AdminUser       string    `gorm:"size:100;not null" json:"admin_user"`
	AdminPass       string    `gorm:"size:512;not null" json:"-"` // 加密存储，不对外暴露
	PackageName     string    `gorm:"size:100;not null;default:Default" json:"package_name"`
	IsActive        bool      `gorm:"default:true" json:"is_active"`
	IsDefault       bool      `gorm:"default:false" json:"is_default"`
	MaxAccounts     int       `gorm:"default:0" json:"max_accounts"`
	CurrentAccounts int       `gorm:"default:0" json:"current_accounts"`
	Description     *string   `gorm:"type:text" json:"description,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (CyberPanelServer) TableName() string {
	return "cyberpanel_servers"
}

// CyberPanelAccount 用户 CyberPanel 主机账号
type CyberPanelAccount struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	UserID     uint      `gorm:"not null;index" json:"user_id"`
	DomainID   uint      `gorm:"not null;uniqueIndex" json:"domain_id"`
	ServerID   uint      `gorm:"not null;index" json:"server_id"`
	CpUsername string    `gorm:"size:100;not null" json:"cp_username"`
	CpPassword string    `gorm:"size:512;not null" json:"-"`            // 加密存储
	Status     string    `gorm:"size:20;default:pending" json:"status"` // pending/active/suspended/terminated
	ErrorMsg   *string   `gorm:"type:text" json:"error_msg,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	User   *User             `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Domain *Domain           `gorm:"foreignKey:DomainID" json:"domain,omitempty"`
	Server *CyberPanelServer `gorm:"foreignKey:ServerID" json:"server,omitempty"`
}

func (CyberPanelAccount) TableName() string {
	return "cyberpanel_accounts"
}

// CyberPanelServerRequest 创建/更新服务器请求
type CyberPanelServerRequest struct {
	Name        string  `json:"name" binding:"required,max=100"`
	URL         string  `json:"url" binding:"required"`
	AdminUser   string  `json:"admin_user" binding:"required"`
	AdminPass   string  `json:"admin_pass" binding:"required"`
	PackageName string  `json:"package_name" binding:"required"`
	IsActive    *bool   `json:"is_active"`
	IsDefault   *bool   `json:"is_default"`
	MaxAccounts *int    `json:"max_accounts"`
	Description *string `json:"description"`
}

// CyberPanelServerResponse 服务器响应（对管理员可见）
type CyberPanelServerResponse struct {
	ID              uint      `json:"id"`
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	AdminUser       string    `json:"admin_user"`
	PackageName     string    `json:"package_name"`
	IsActive        bool      `json:"is_active"`
	IsDefault       bool      `json:"is_default"`
	MaxAccounts     int       `json:"max_accounts"`
	CurrentAccounts int       `json:"current_accounts"`
	Description     *string   `json:"description,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (s *CyberPanelServer) ToResponse() *CyberPanelServerResponse {
	return &CyberPanelServerResponse{
		ID:              s.ID,
		Name:            s.Name,
		URL:             s.URL,
		AdminUser:       s.AdminUser,
		PackageName:     s.PackageName,
		IsActive:        s.IsActive,
		IsDefault:       s.IsDefault,
		MaxAccounts:     s.MaxAccounts,
		CurrentAccounts: s.CurrentAccounts,
		Description:     s.Description,
		CreatedAt:       s.CreatedAt,
		UpdatedAt:       s.UpdatedAt,
	}
}

// CyberPanelCreateAccountRequest 用户申请主机账号请求（无需手动输入用户名密码）
type CyberPanelCreateAccountRequest struct {
	DomainID uint  `json:"domain_id" binding:"required"`
	ServerID *uint `json:"server_id"` // 可选，不填则自动轮询选择
}

// CyberPanelAccountResponse 账号响应（不含密码，密码通过独立接口获取）
type CyberPanelAccountResponse struct {
	ID         uint                      `json:"id"`
	UserID     uint                      `json:"user_id"`
	DomainID   uint                      `json:"domain_id"`
	ServerID   uint                      `json:"server_id"`
	CpUsername string                    `json:"cp_username"`
	Status     string                    `json:"status"`
	ErrorMsg   *string                   `json:"error_msg,omitempty"`
	CreatedAt  time.Time                 `json:"created_at"`
	UpdatedAt  time.Time                 `json:"updated_at"`
	Domain     *Domain                   `json:"domain,omitempty"`
	Server     *CyberPanelServerResponse `json:"server,omitempty"`
}

// CyberPanelCredentials 面板登录凭据（仅账号本人通过专用接口获取）
type CyberPanelCredentials struct {
	CpUsername string `json:"cp_username"`
	CpPassword string `json:"cp_password"`
	LoginURL   string `json:"login_url"` // CyberPanel 面板地址
}
