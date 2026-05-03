<template>
  <div class="min-h-[70vh] flex items-center justify-center px-4">
    <div class="card w-full max-w-lg bg-base-100 shadow-xl border border-base-300">
      <div class="card-body text-center">
        <h1 class="text-2xl font-bold mb-2">邮箱验证</h1>

        <div v-if="loading" class="py-6">
          <span class="loading loading-spinner loading-lg"></span>
          <p class="mt-3 opacity-70">正在验证，请稍候...</p>
        </div>

        <div v-else>
          <p class="mb-4" :class="ok ? 'text-success' : 'text-error'">{{ message }}</p>
          <div class="flex justify-center gap-2">
            <router-link class="btn btn-primary" to="/login">去登录</router-link>
            <router-link class="btn btn-ghost" to="/register">去注册</router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import axios from '../utils/axios'

const route = useRoute()
const loading = ref(true)
const ok = ref(false)
const message = ref('')

onMounted(async () => {
  const token = route.query.token
  if (!token || typeof token !== 'string') {
    loading.value = false
    ok.value = false
    message.value = '验证链接无效或缺少 token。'
    return
  }

  try {
    const response = await axios.post('/api/auth/verify-email', { token })
    ok.value = true
    message.value = response.data?.message || '邮箱验证成功，请登录。'
  } catch (error) {
    ok.value = false
    message.value = error.response?.data?.error || '邮箱验证失败，请重新获取验证邮件。'
  } finally {
    loading.value = false
  }
})
</script>
