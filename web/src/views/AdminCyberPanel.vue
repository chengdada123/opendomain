<template>
  <div class="container mx-auto px-4 sm:px-6 lg:px-8 py-8 max-w-7xl space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <div>
        <h1 class="text-3xl font-bold">{{ $t('admin.cyberPanel') }}</h1>
        <p class="text-lg opacity-70 mt-2">{{ $t('admin.cyberPanelDesc') }}</p>
      </div>
    </div>

    <!-- Tabs -->
    <div role="tablist" class="tabs tabs-lifted tabs-lg">
      <button role="tab" class="tab" :class="{ 'tab-active': activeTab === 'servers' }" @click="activeTab = 'servers'">
        🖥 {{ $t('admin.cpServers') }}
        <span class="inline-flex items-center justify-center px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-200 text-gray-700 ml-2">{{ servers.length }}</span>
      </button>
      <button role="tab" class="tab" :class="{ 'tab-active': activeTab === 'accounts' }" @click="activeTab = 'accounts'; fetchAccounts()">
        👤 {{ $t('admin.cpAccounts') }}
        <span class="inline-flex items-center justify-center px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-200 text-gray-700 ml-2">{{ accountTotal }}</span>
      </button>
    </div>

    <!-- ════ TAB: SERVERS ════ -->
    <div v-if="activeTab === 'servers'">
      <div class="flex justify-end mb-4">
        <button @click="openCreateServer" class="btn btn-primary">
          + {{ $t('admin.cpAddServer') }}
        </button>
      </div>

      <div v-if="serversLoading" class="flex justify-center py-12">
        <span class="loading loading-spinner loading-lg"></span>
      </div>

      <div v-else-if="servers.length === 0" class="card bg-base-200 shadow-xl">
        <div class="card-body items-center text-center py-12">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-20 w-20 opacity-40 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
          </svg>
          <h3 class="card-title text-2xl mb-2">{{ $t('admin.cpNoServers') }}</h3>
          <p class="mb-4">{{ $t('admin.cpNoServersDesc') }}</p>
          <button @click="openCreateServer" class="btn btn-primary">{{ $t('admin.cpAddServer') }}</button>
        </div>
      </div>

      <div v-else class="overflow-x-auto">
        <table class="table table-zebra w-full">
          <thead>
            <tr>
              <th>{{ $t('admin.cpServerName') }}</th>
              <th>{{ $t('admin.cpServerUrl') }}</th>
              <th>{{ $t('admin.cpAdminUser') }}</th>
              <th>{{ $t('admin.cpPackage') }}</th>
              <th>{{ $t('admin.cpAccUsage') }}</th>
              <th>{{ $t('admin.status') }}</th>
              <th>{{ $t('admin.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="server in servers" :key="server.id">
              <td>
                <div class="font-semibold">{{ server.name }}</div>
                <div v-if="server.is_default" class="inline-block px-1.5 py-0.5 rounded text-xs font-semibold bg-blue-100 text-blue-700 mt-1">Default</div>
              </td>
              <td class="font-mono text-sm">{{ server.url }}</td>
              <td>{{ server.admin_user }}</td>
              <td>{{ server.package_name }}</td>
              <td>
                <div class="flex items-center gap-2">
                  <span>{{ server.current_accounts }}</span>
                  <span class="opacity-50">/</span>
                  <span>{{ server.max_accounts === 0 ? '∞' : server.max_accounts }}</span>
                  <progress
                    v-if="server.max_accounts > 0"
                    class="progress progress-primary w-16"
                    :value="server.current_accounts"
                    :max="server.max_accounts"
                  ></progress>
                </div>
              </td>
              <td>
                <span class="inline-block px-2 py-0.5 rounded text-xs font-medium" :class="server.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'">
                  {{ server.is_active ? $t('admin.active') : $t('admin.inactive') }}
                </span>
              </td>
              <td>
                <div class="flex gap-2">
                  <button @click="testServer(server)" class="btn btn-xs btn-info" :disabled="testingId === server.id">
                    <span v-if="testingId === server.id" class="loading loading-spinner loading-xs"></span>
                    <span v-else>{{ $t('admin.cpTest') }}</span>
                  </button>
                  <button @click="openServerPanel(server)" class="btn btn-xs btn-primary" :disabled="openingPanelId === server.id">
                    <span v-if="openingPanelId === server.id" class="loading loading-spinner loading-xs"></span>
                    <span v-else>{{ $t('admin.cpOpenPanel') }}</span>
                  </button>
                  <button @click="openEditServer(server)" class="btn btn-xs btn-ghost">{{ $t('admin.edit') }}</button>
                  <button @click="confirmDeleteServer(server)" class="btn btn-xs btn-error">{{ $t('admin.delete') }}</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ════ TAB: ACCOUNTS ════ -->
    <div v-if="activeTab === 'accounts'">
      <!-- Filters -->
      <div class="flex flex-wrap gap-3 mb-4">
        <select v-model="accountFilter.status" @change="fetchAccounts" class="select select-bordered select-sm">
          <option value="">{{ $t('admin.cpAllStatuses') }}</option>
          <option value="pending">pending</option>
          <option value="active">active</option>
          <option value="suspended">suspended</option>
          <option value="terminated">terminated</option>
        </select>
        <select v-model="accountFilter.server_id" @change="fetchAccounts" class="select select-bordered select-sm">
          <option value="">{{ $t('admin.cpAllServers') }}</option>
          <option v-for="s in servers" :key="s.id" :value="s.id">{{ s.name }}</option>
        </select>
      </div>

      <div v-if="accountsLoading" class="flex justify-center py-12">
        <span class="loading loading-spinner loading-lg"></span>
      </div>

      <div v-else-if="accounts.length === 0" class="card bg-base-200 shadow-xl">
        <div class="card-body items-center text-center py-12">
          <p class="opacity-60">{{ $t('admin.cpNoAccounts') }}</p>
        </div>
      </div>

      <div v-else class="overflow-x-auto">
        <table class="table table-zebra w-full text-sm">
          <thead>
            <tr>
              <th>{{ $t('admin.cpDomain') }}</th>
              <th>{{ $t('admin.cpCpUser') }}</th>
              <th>{{ $t('admin.cpServer') }}</th>
              <th>{{ $t('admin.cpOwner') }}</th>
              <th>{{ $t('admin.status') }}</th>
              <th>{{ $t('admin.cpCreatedAt') }}</th>
              <th>{{ $t('admin.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="acc in accounts" :key="acc.id">
              <td class="font-mono">{{ acc.domain?.full_domain || acc.domain_id }}</td>
              <td>{{ acc.cp_username }}</td>
              <td>{{ acc.server?.name || acc.server_id }}</td>
              <td>{{ acc.user?.username || acc.user_id }}</td>
              <td>
                <span class="inline-block px-2 py-0.5 rounded text-xs font-medium" :class="statusClass(acc.status)">{{ acc.status }}</span>
                <div v-if="acc.error_msg" class="tooltip" :data-tip="acc.error_msg">
                  <span class="text-error text-xs ml-1">⚠</span>
                </div>
              </td>
              <td>{{ formatDate(acc.created_at) }}</td>
              <td>
                <div class="flex gap-1">
                  <button
                    v-if="acc.status === 'active'"
                    @click="adminSuspend(acc)"
                    class="btn btn-xs btn-warning"
                  >{{ $t('admin.suspend') }}</button>
                  <button
                    v-if="acc.status === 'suspended'"
                    @click="adminUnsuspend(acc)"
                    class="btn btn-xs btn-success"
                  >{{ $t('admin.unsuspend') }}</button>
                  <button
                    v-if="acc.status !== 'terminated'"
                    @click="confirmTerminateAccount(acc)"
                    class="btn btn-xs btn-error"
                  >{{ $t('admin.cpTerminate') }}</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <!-- Pagination -->
        <div class="flex justify-center mt-4 gap-2" v-if="accountTotal > accountPageSize">
          <button class="btn btn-sm" :disabled="accountPage === 1" @click="accountPage--; fetchAccounts()">«</button>
          <span class="btn btn-sm btn-disabled">{{ accountPage }} / {{ Math.ceil(accountTotal / accountPageSize) }}</span>
          <button class="btn btn-sm" :disabled="accountPage >= Math.ceil(accountTotal / accountPageSize)" @click="accountPage++; fetchAccounts()">»</button>
        </div>
      </div>
    </div>

    <!-- ════ SERVER MODAL ════ -->
    <dialog v-if="showServerModal" class="modal modal-open">
      <div class="modal-box w-11/12 max-w-2xl">
        <h3 class="font-bold text-xl mb-4">
          {{ editingServer ? $t('admin.cpEditServer') : $t('admin.cpAddServer') }}
        </h3>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="form-control">
            <label class="label"><span class="label-text">{{ $t('admin.cpServerName') }} *</span></label>
            <input v-model="serverForm.name" type="text" class="input input-bordered" :placeholder="$t('admin.cpServerNamePlaceholder')" />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text">{{ $t('admin.cpServerUrl') }} *</span></label>
            <input v-model="serverForm.url" type="text" class="input input-bordered" placeholder="http://1.2.3.4:8090" />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text">{{ $t('admin.cpAdminUser') }} *</span></label>
            <input v-model="serverForm.admin_user" type="text" class="input input-bordered" placeholder="admin" />
          </div>
          <div class="form-control">
            <label class="label">
              <span class="label-text">{{ $t('admin.cpAdminPass') }} *</span>
              <span v-if="editingServer" class="label-text-alt opacity-60">{{ $t('admin.cpPassHint') }}</span>
            </label>
            <input v-model="serverForm.admin_pass" type="password" class="input input-bordered" placeholder="••••••••" />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text">{{ $t('admin.cpPackage') }} *</span></label>
            <input v-model="serverForm.package_name" type="text" class="input input-bordered" placeholder="Default" />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text">{{ $t('admin.cpMaxAccounts') }}</span></label>
            <input v-model.number="serverForm.max_accounts" type="number" min="0" class="input input-bordered" placeholder="0 = unlimited" />
          </div>
          <div class="form-control col-span-full">
            <label class="label"><span class="label-text">{{ $t('admin.description') }}</span></label>
            <input v-model="serverForm.description" type="text" class="input input-bordered" />
          </div>
          <div class="form-control">
            <label class="cursor-pointer label">
              <span class="label-text">{{ $t('admin.active') }}</span>
              <input v-model="serverForm.is_active" type="checkbox" class="toggle toggle-success" />
            </label>
          </div>
          <div class="form-control">
            <label class="cursor-pointer label">
              <span class="label-text">{{ $t('admin.cpDefault') }}</span>
              <input v-model="serverForm.is_default" type="checkbox" class="toggle toggle-primary" />
            </label>
          </div>
        </div>

        <div v-if="serverModalError" class="alert alert-error mt-4">{{ serverModalError }}</div>

        <div class="modal-action">
          <button @click="showServerModal = false" class="btn btn-ghost">{{ $t('common.cancel') }}</button>
          <button @click="saveServer" class="btn btn-primary" :disabled="serverSaving">
            <span v-if="serverSaving" class="loading loading-spinner loading-sm"></span>
            {{ $t('common.save') }}
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showServerModal = false"></form>
    </dialog>

    <!-- ════ CONFIRM DELETE SERVER ════ -->
    <dialog v-if="showDeleteServerConfirm" class="modal modal-open">
      <div class="modal-box">
        <h3 class="font-bold text-lg">{{ $t('admin.cpDeleteServerTitle') }}</h3>
        <p class="py-4">{{ $t('admin.cpDeleteServerConfirm', { name: deletingServer?.name }) }}</p>
        <div class="modal-action">
          <button @click="showDeleteServerConfirm = false" class="btn btn-ghost">{{ $t('common.cancel') }}</button>
          <button @click="deleteServer" class="btn btn-error" :disabled="serverSaving">
            <span v-if="serverSaving" class="loading loading-spinner loading-sm"></span>
            {{ $t('admin.delete') }}
          </button>
        </div>
      </div>
    </dialog>

    <!-- ════ CONFIRM TERMINATE ACCOUNT ════ -->
    <dialog v-if="showTerminateConfirm" class="modal modal-open">
      <div class="modal-box">
        <h3 class="font-bold text-lg">{{ $t('admin.cpTerminateTitle') }}</h3>
        <p class="py-4">{{ $t('admin.cpTerminateConfirm', { domain: terminatingAccount?.domain?.full_domain }) }}</p>
        <div class="modal-action">
          <button @click="showTerminateConfirm = false" class="btn btn-ghost">{{ $t('common.cancel') }}</button>
          <button @click="terminateAccount" class="btn btn-error" :disabled="accountActionLoading">
            <span v-if="accountActionLoading" class="loading loading-spinner loading-sm"></span>
            {{ $t('admin.cpTerminate') }}
          </button>
        </div>
      </div>
    </dialog>

    <!-- Toast -->
    <div v-if="toast.show" class="toast toast-top toast-end z-50">
      <div class="alert" :class="toast.type === 'success' ? 'alert-success' : 'alert-error'">
        <span>{{ toast.message }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import axios from '../utils/axios'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// ── State ────────────────────────────────────────────────────────────
const activeTab = ref('servers')

// Servers
const servers = ref([])
const serversLoading = ref(false)
const showServerModal = ref(false)
const editingServer = ref(null)
const serverSaving = ref(false)
const serverModalError = ref('')
const testingId = ref(null)
const openingPanelId = ref(null)
const showDeleteServerConfirm = ref(false)
const deletingServer = ref(null)

const defaultServerForm = () => ({
  name: '',
  url: '',
  admin_user: '',
  admin_pass: '',
  package_name: 'Default',
  is_active: true,
  is_default: false,
  max_accounts: 0,
  description: '',
})
const serverForm = ref(defaultServerForm())

// Accounts
const accounts = ref([])
const accountsLoading = ref(false)
const accountTotal = ref(0)
const accountPage = ref(1)
const accountPageSize = 20
const accountFilter = ref({ status: '', server_id: '' })
const showTerminateConfirm = ref(false)
const terminatingAccount = ref(null)
const accountActionLoading = ref(false)

// Toast
const toast = ref({ show: false, type: 'success', message: '' })

// ── Toast ────────────────────────────────────────────────────────────
const showToast = (message, type = 'success') => {
  toast.value = { show: true, type, message }
  setTimeout(() => (toast.value.show = false), 3000)
}

// ── Servers ──────────────────────────────────────────────────────────
const fetchServers = async () => {
  serversLoading.value = true
  try {
    const res = await axios.get('/api/admin/cyberpanel/servers')
    servers.value = res.data.servers || []
  } catch (e) {
    showToast(e.response?.data?.error || 'Failed to load servers', 'error')
  } finally {
    serversLoading.value = false
  }
}

const openCreateServer = () => {
  editingServer.value = null
  serverForm.value = defaultServerForm()
  serverModalError.value = ''
  showServerModal.value = true
}

const openEditServer = (server) => {
  editingServer.value = server
  serverForm.value = {
    name: server.name,
    url: server.url,
    admin_user: server.admin_user,
    admin_pass: '',
    package_name: server.package_name,
    is_active: server.is_active,
    is_default: server.is_default,
    max_accounts: server.max_accounts,
    description: server.description || '',
  }
  serverModalError.value = ''
  showServerModal.value = true
}

const saveServer = async () => {
  serverModalError.value = ''
  if (!serverForm.value.name || !serverForm.value.url || !serverForm.value.admin_user || !serverForm.value.package_name) {
    serverModalError.value = t('admin.cpRequiredFields')
    return
  }
  if (!editingServer.value && !serverForm.value.admin_pass) {
    serverModalError.value = t('admin.cpPassRequired')
    return
  }

  serverSaving.value = true
  try {
    const payload = { ...serverForm.value }
    if (!payload.admin_pass) delete payload.admin_pass

    if (editingServer.value) {
      await axios.put(`/api/admin/cyberpanel/servers/${editingServer.value.id}`, payload)
      showToast(t('admin.cpServerUpdated'))
    } else {
      await axios.post('/api/admin/cyberpanel/servers', payload)
      showToast(t('admin.cpServerCreated'))
    }
    showServerModal.value = false
    await fetchServers()
  } catch (e) {
    serverModalError.value = e.response?.data?.error || 'Operation failed'
  } finally {
    serverSaving.value = false
  }
}

const confirmDeleteServer = (server) => {
  deletingServer.value = server
  showDeleteServerConfirm.value = true
}

const deleteServer = async () => {
  if (!deletingServer.value) return
  serverSaving.value = true
  try {
    await axios.delete(`/api/admin/cyberpanel/servers/${deletingServer.value.id}`)
    showToast(t('admin.cpServerDeleted'))
    showDeleteServerConfirm.value = false
    await fetchServers()
  } catch (e) {
    showToast(e.response?.data?.error || 'Delete failed', 'error')
  } finally {
    serverSaving.value = false
  }
}

const testServer = async (server) => {
  testingId.value = server.id
  try {
    const res = await axios.post(`/api/admin/cyberpanel/servers/${server.id}/test`)
    if (res.data.success) {
      showToast(t('admin.cpTestSuccess'))
    } else {
      showToast(res.data.error || 'Connection failed', 'error')
    }
  } catch (e) {
    showToast(e.response?.data?.error || 'Test failed', 'error')
  } finally {
    testingId.value = null
  }
}

const cpFormLogin = (username, password, loginUrl) => {
  // 打开命名窗口，先 POST 到 /api/loginAPI（免 CSRF）建立 session cookie，
  // 再导航到 /dashboard/，浏览器会携带已设置的 cookie
  const winName = 'cpanel_' + Date.now()
  const cpWindow = window.open('about:blank', winName)
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = `${loginUrl}/api/loginAPI`
  form.target = winName
  ;[['username', username], ['password', password]].forEach(([name, value]) => {
    const input = document.createElement('input')
    input.type = 'hidden'
    input.name = name
    input.value = value
    form.appendChild(input)
  })
  document.body.appendChild(form)
  form.submit()
  document.body.removeChild(form)
  // 等待 loginAPI 响应后（cookie 已写入浏览器），跳转到面板
  setTimeout(() => {
    if (cpWindow && !cpWindow.closed) {
      cpWindow.location.href = `${loginUrl}/dashboard/`
    }
  }, 1500)
}

const openServerPanel = async (server) => {
  openingPanelId.value = server.id
  try {
    const res = await axios.get(`/api/admin/cyberpanel/servers/${server.id}/autologin`)
    const { username, password, login_url } = res.data
    cpFormLogin(username, password, login_url)
  } catch (e) {
    showToast(e.response?.data?.error || 'Login failed', 'error')
  } finally {
    openingPanelId.value = null
  }
}

// ── Accounts ─────────────────────────────────────────────────────────
const fetchAccounts = async () => {
  accountsLoading.value = true
  try {
    const params = {
      page: accountPage.value,
      page_size: accountPageSize,
    }
    if (accountFilter.value.status) params.status = accountFilter.value.status
    if (accountFilter.value.server_id) params.server_id = accountFilter.value.server_id

    const res = await axios.get('/api/admin/cyberpanel/accounts', { params })
    accounts.value = res.data.accounts || []
    accountTotal.value = res.data.total || 0
  } catch (e) {
    showToast(e.response?.data?.error || 'Failed to load accounts', 'error')
  } finally {
    accountsLoading.value = false
  }
}

const adminSuspend = async (acc) => {
  accountActionLoading.value = true
  try {
    await axios.post(`/api/admin/cyberpanel/accounts/${acc.id}/suspend`)
    showToast(t('admin.cpSuspended'))
    await fetchAccounts()
  } catch (e) {
    showToast(e.response?.data?.error || 'Failed', 'error')
  } finally {
    accountActionLoading.value = false
  }
}

const adminUnsuspend = async (acc) => {
  accountActionLoading.value = true
  try {
    await axios.post(`/api/admin/cyberpanel/accounts/${acc.id}/unsuspend`)
    showToast(t('admin.cpUnsuspended'))
    await fetchAccounts()
  } catch (e) {
    showToast(e.response?.data?.error || 'Failed', 'error')
  } finally {
    accountActionLoading.value = false
  }
}

const confirmTerminateAccount = (acc) => {
  terminatingAccount.value = acc
  showTerminateConfirm.value = true
}

const terminateAccount = async () => {
  if (!terminatingAccount.value) return
  accountActionLoading.value = true
  try {
    await axios.delete(`/api/admin/cyberpanel/accounts/${terminatingAccount.value.id}`)
    showToast(t('admin.cpTerminated'))
    showTerminateConfirm.value = false
    await fetchAccounts()
  } catch (e) {
    showToast(e.response?.data?.error || 'Failed', 'error')
  } finally {
    accountActionLoading.value = false
  }
}

// ── Helpers ───────────────────────────────────────────────────────────
const statusClass = (status) => ({
  'bg-blue-100 text-blue-800': status === 'pending',
  'bg-green-100 text-green-800': status === 'active',
  'bg-amber-100 text-amber-800': status === 'suspended',
  'bg-red-100 text-red-800': status === 'terminated',
})

const formatDate = (d) => {
  if (!d) return '-'
  return new Date(d).toLocaleDateString()
}

onMounted(async () => {
  await fetchServers()
})
</script>
