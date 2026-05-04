<template>
  <div class="min-h-[70vh] flex items-center justify-center px-4">
    <div class="card w-full max-w-lg bg-base-100 shadow-xl border border-base-300">
      <div class="card-body">
        <h1 class="text-2xl font-bold mb-4 text-center">重置密码</h1>

        <div v-if="message" class="alert" :class="ok ? 'alert-success' : 'alert-error'">
          <span>{{ message }}</span>
        </div>

        <form class="space-y-4" @submit.prevent="handleReset">
          <div class="form-control">
            <label class="label"><span class="label-text">新密码</span></label>
            <input v-model="newPassword" type="password" class="input input-bordered" minlength="6" required />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text">确认新密码</span></label>
            <input v-model="confirmPassword" type="password" class="input input-bordered" minlength="6" required />
          </div>
          <button class="btn btn-primary w-full" :disabled="loading">
            <span v-if="loading" class="loading loading-spinner loading-xs"></span>
            <span v-else>提交重置</span>
          </button>
        </form>

        <div class="text-center mt-4">
          <router-link to="/login" class="link link-primary">返回登录</router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import axios from '../utils/axios'

const route = useRoute()
const token = route.query.token
const newPassword = ref('')
const confirmPassword = ref('')
const loading = ref(false)
const ok = ref(false)
const message = ref('')

const handleReset = async () => {
  if (!token || typeof token !== 'string') {
    ok.value = false
    message.value = '重置链接无效或缺少 token。'
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    ok.value = false
    message.value = '两次输入的密码不一致。'
    return
  }

  loading.value = true
  message.value = ''
  try {
    const response = await axios.post('/api/auth/reset-password', {
      token,
      new_password: newPassword.value,
    })
    ok.value = true
    message.value = response.data?.message || '密码重置成功。'
  } catch (e) {
    ok.value = false
    message.value = e.response?.data?.error || '密码重置失败。'
  } finally {
    loading.value = false
  }
}
</script>
