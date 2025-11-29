import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import api from '../services/api'

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
      
      // Login
      login: async (email, password) => {
        try {
          const response = await api.post('/api/auth/login', { email, password })
          const { access_token, refresh_token } = response.data
          
          // Set tokens
          set({ accessToken: access_token, refreshToken: refresh_token })
          
          // Get user info
          const userResponse = await api.get('/api/auth/me', {
            headers: { Authorization: `Bearer ${access_token}` }
          })
          
          set({
            user: userResponse.data,
            isAuthenticated: true,
            isLoading: false
          })
          
          return { success: true }
        } catch (error) {
          set({ isLoading: false })
          return {
            success: false,
            error: error.response?.data?.detail || 'خطا در ورود'
          }
        }
      },
      
      // Register
      register: async (userData) => {
        try {
          const response = await api.post('/api/auth/register', userData)
          return { success: true, data: response.data }
        } catch (error) {
          return {
            success: false,
            error: error.response?.data?.detail || 'خطا در ثبت‌نام'
          }
        }
      },
      
      // Logout
      logout: async () => {
        try {
          await api.post('/api/auth/logout')
        } catch (error) {
          console.error('Logout error:', error)
        } finally {
          set({
            user: null,
            accessToken: null,
            refreshToken: null,
            isAuthenticated: false
          })
        }
      },
      
      // Refresh token
      refreshAccessToken: async () => {
        const { refreshToken } = get()
        if (!refreshToken) {
          set({ isAuthenticated: false, isLoading: false })
          return false
        }
        
        try {
          const response = await api.post('/api/auth/refresh', {
            refresh_token: refreshToken
          })
          
          const { access_token, refresh_token } = response.data
          set({ accessToken: access_token, refreshToken: refresh_token })
          return true
        } catch (error) {
          set({
            user: null,
            accessToken: null,
            refreshToken: null,
            isAuthenticated: false,
            isLoading: false
          })
          return false
        }
      },
      
      // Check auth status
      checkAuth: async () => {
        const { accessToken, refreshAccessToken } = get()
        
        if (!accessToken) {
          set({ isLoading: false })
          return
        }
        
        try {
          const response = await api.get('/api/auth/me', {
            headers: { Authorization: `Bearer ${accessToken}` }
          })
          
          set({
            user: response.data,
            isAuthenticated: true,
            isLoading: false
          })
        } catch (error) {
          // Try to refresh token
          const refreshed = await refreshAccessToken()
          if (refreshed) {
            await get().checkAuth()
          }
        }
      },
      
      // Update user
      updateUser: (updates) => {
        set((state) => ({
          user: { ...state.user, ...updates }
        }))
      },
      
      // Check if user has role
      hasRole: (roles) => {
        const { user } = get()
        if (!user) return false
        return roles.includes(user.role)
      },
      
      // Initialize auth state
      initialize: async () => {
        set({ isLoading: true })
        await get().checkAuth()
      }
    }),
    {
      name: 'owasp-scanner-auth',
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken
      })
    }
  )
)

// Initialize on load
useAuthStore.getState().initialize()