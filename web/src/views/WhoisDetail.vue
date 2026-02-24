<template>
  <div class="container mx-auto px-4 py-10 max-w-2xl">
    <!-- Loading -->
    <div v-if="loading" class="flex justify-center items-center min-h-[300px]">
      <span class="loading loading-spinner loading-lg"></span>
    </div>

    <!-- Not Found -->
    <div v-else-if="notFound" class="text-center py-16">
      <div class="text-6xl mb-4">🔍</div>
      <h2 class="text-2xl font-bold mb-2">{{ $t('whois.notFound') }}</h2>
      <i18n-t keypath="whois.notFoundDesc" tag="p" class="opacity-60 mb-6">
        <template #domain>
          <span class="font-mono font-semibold">{{ domain }}</span>
        </template>
      </i18n-t>
      <router-link to="/" class="btn btn-primary">{{ $t('whois.searchAnother') }}</router-link>
    </div>

    <!-- WHOIS Info -->
    <div v-else-if="whois">
      <!-- Header -->
      <div class="mb-6">
        <div class="flex items-center gap-2 text-sm opacity-60 mb-1">
          <router-link to="/" class="hover:underline">{{ $t('nav.home') }}</router-link>
          <span>/</span>
          <span>{{ $t('whois.breadcrumb') }}</span>
        </div>
        <h1 class="text-3xl font-bold font-mono break-all">{{ whois.full_domain }}</h1>
      </div>

      <!-- Deletion Warning Banner -->
      <div v-if="whois.days_until_deletion !== null && whois.days_until_deletion !== undefined"
        class="alert mb-6 border-2"
        :class="whois.days_until_deletion <= 3 ? 'alert-error border-error/30' : 'alert-warning border-warning/30'"
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <p class="font-bold">{{ $t('whois.pendingDeletion') }}</p>
          <i18n-t keypath="whois.pendingDeletionDesc" tag="p" class="text-sm">
            <template #days>
              <strong>{{ whois.days_until_deletion }} {{ whois.days_until_deletion !== 1 ? $t('whois.days') : $t('whois.day') }}</strong>
            </template>
          </i18n-t>
        </div>
      </div>

      <!-- Suspension Warning Banner (not yet suspended) -->
      <div v-else-if="whois.days_until_suspension !== null && whois.days_until_suspension !== undefined"
        class="alert alert-warning border-2 border-warning/30 mb-6"
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <p class="font-bold">{{ $t('whois.healthCheckFailed') }}</p>
          <i18n-t keypath="whois.healthCheckFailedDesc" tag="p" class="text-sm">
            <template #days>
              <strong>{{ whois.days_until_suspension }} {{ whois.days_until_suspension !== 1 ? $t('whois.days') : $t('whois.day') }}</strong>
            </template>
          </i18n-t>
        </div>
      </div>

      <!-- WHOIS Table -->
      <div class="card bg-base-200 shadow mb-6">
        <div class="card-body p-0">
          <div class="px-4 pt-4 pb-2">
            <h2 class="font-bold text-base opacity-70 uppercase tracking-wide text-xs">{{ $t('whois.registrationInfo') }}</h2>
          </div>
          <table class="table">
            <tbody>
              <tr>
                <td class="w-40 opacity-60 font-medium text-sm">{{ $t('whois.domain') }}</td>
                <td class="font-mono font-semibold break-all">{{ whois.full_domain }}</td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.status') }}</td>
                <td>
                  <span class="inline-flex items-center rounded-full px-3 py-1 text-sm font-semibold" :class="{
                    'bg-green-100 text-green-700': whois.status === 'active',
                    'bg-amber-100 text-amber-700': whois.status === 'suspended',
                    'bg-red-100 text-red-700': whois.status === 'expired',
                    'bg-gray-100 text-gray-500': !['active','suspended','expired'].includes(whois.status),
                  }">{{ whois.status }}</span>
                </td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.registered') }}</td>
                <td>{{ formatDate(whois.registered_at) }}</td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.expires') }}</td>
                <td :class="isExpiringSoon ? 'text-amber-600 font-semibold' : ''">
                  {{ formatDate(whois.expires_at) }}
                  <span v-if="isExpiringSoon" class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-amber-100 text-amber-700 ml-2">{{ $t('whois.expiringSoon') }}</span>
                </td>
              </tr>
              <tr v-if="whois.suspended_at">
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.suspended') }}</td>
                <td class="text-amber-600">{{ formatDate(whois.suspended_at) }}</td>
              </tr>
              <tr v-if="whois.suspend_reason">
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.suspendReason') }}</td>
                <td class="text-amber-600 text-sm">{{ whois.suspend_reason }}</td>
              </tr>
              <tr v-if="whois.first_failed_at">
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.firstFailed') }}</td>
                <td class="text-sm">{{ formatDate(whois.first_failed_at) }}</td>
              </tr>
              <tr v-if="whois.nameservers && whois.nameservers.length">
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.nameservers') }}</td>
                <td>
                  <div v-for="ns in whois.nameservers" :key="ns" class="font-mono text-sm">{{ ns }}</div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Scan Info -->
      <div v-if="whois.scan" class="card bg-base-200 shadow mb-6">
        <div class="card-body p-0">
          <div class="px-4 pt-4 pb-2 flex items-center justify-between">
            <h2 class="font-bold text-base opacity-70 uppercase tracking-wide text-xs">{{ $t('whois.healthMonitoring') }}</h2>
            <span class="text-xs opacity-50">
              {{ $t('whois.lastScanned') }}: {{ whois.scan.last_scanned_at ? formatDate(whois.scan.last_scanned_at) : $t('whois.never') }}
            </span>
          </div>

          <!-- Overall Health + Uptime -->
          <div class="px-4 pb-3 flex items-center gap-4">
            <span class="inline-flex items-center rounded-full px-3 py-1 text-sm font-semibold" :class="healthBadgeClass(whois.scan.overall_health)">
              {{ whois.scan.overall_health || 'unknown' }}
            </span>
            <div class="flex-1">
              <div class="flex justify-between text-xs opacity-60 mb-1">
                <span>{{ $t('whois.uptime') }}</span>
                <span>{{ whois.scan.uptime_percentage?.toFixed(1) }}%</span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div
                  class="h-2 rounded-full transition-all"
                  :class="uptimeBarClass(whois.scan.uptime_percentage)"
                  :style="{ width: `${whois.scan.uptime_percentage ?? 0}%` }"
                ></div>
              </div>
            </div>
          </div>

          <table class="table">
            <tbody>
              <tr>
                <td class="w-40 opacity-60 font-medium text-sm">{{ $t('whois.http') }}</td>
                <td><span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold" :class="statusBadgeClass(whois.scan.http_status, ['online'], ['offline'])">{{ whois.scan.http_status || 'unknown' }}</span></td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.dns') }}</td>
                <td><span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold" :class="statusBadgeClass(whois.scan.dns_status, ['resolved', 'success'], ['failed'])">{{ whois.scan.dns_status || 'unknown' }}</span></td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.ssl') }}</td>
                <td><span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold" :class="statusBadgeClass(whois.scan.ssl_status, ['valid'], ['invalid'])">{{ whois.scan.ssl_status || 'unknown' }}</span></td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.safeBrowsing') }}</td>
                <td><span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold" :class="statusBadgeClass(whois.scan.safe_browsing_status, ['safe'], ['unsafe', 'threat_detected'])">{{ whois.scan.safe_browsing_status || 'unknown' }}</span></td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.virusTotal') }}</td>
                <td><span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold" :class="statusBadgeClass(whois.scan.virustotal_status, ['clean'], ['malicious', 'suspicious'])">{{ whois.scan.virustotal_status || 'unknown' }}</span></td>
              </tr>
              <tr>
                <td class="opacity-60 font-medium text-sm">{{ $t('whois.totalScans') }}</td>
                <td class="text-sm">{{ $t('whois.totalScansValue', { total: whois.scan.total_scans, successful: whois.scan.successful_scans }) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Footer -->
      <div class="text-center mt-4">
        <router-link to="/" class="btn btn-outline btn-sm">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          {{ $t('whois.searchAnother') }}
        </router-link>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import axios from '../utils/axios'

const route = useRoute()
const domain = ref(route.params.domain)
const whois = ref(null)
const loading = ref(true)
const notFound = ref(false)

const isExpiringSoon = computed(() => {
  if (!whois.value?.expires_at) return false
  const diff = new Date(whois.value.expires_at) - new Date()
  return diff > 0 && diff < 30 * 24 * 60 * 60 * 1000
})

const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A'
  return new Date(dateStr).toLocaleString()
}

const healthBadgeClass = (health) => {
  if (health === 'healthy') return 'bg-green-100 text-green-700'
  if (health === 'degraded') return 'bg-amber-100 text-amber-700'
  if (health === 'down') return 'bg-red-100 text-red-700'
  return 'bg-gray-100 text-gray-500'
}

const statusBadgeClass = (value, okValues, badValues) => {
  if (okValues.includes(value)) return 'bg-green-100 text-green-700'
  if (badValues.includes(value)) return 'bg-red-100 text-red-700'
  return 'bg-gray-100 text-gray-500'
}

const uptimeBarClass = (pct) => {
  if (pct >= 90) return 'bg-green-500'
  if (pct >= 50) return 'bg-amber-500'
  return 'bg-red-500'
}

const fetchWhois = async () => {
  loading.value = true
  notFound.value = false
  try {
    const response = await axios.get(`/api/public/whois/${domain.value}`)
    whois.value = response.data
  } catch (error) {
    if (error.response?.status === 404) {
      notFound.value = true
    }
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchWhois()
})
</script>
