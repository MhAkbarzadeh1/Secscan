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
          
          set({ accessToken: access_token, refreshToken: refresh_token })
          
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
          const detail = error.response?.data?.detail
          let errorMsg = 'Login failed'
          
          if (typeof detail === 'string') {
            errorMsg = detail
          } else if (Array.isArray(detail)) {
            errorMsg = detail.map(e => e.msg || String(e)).join(', ')
          }
          
          return { success: false, error: errorMsg }
        }
      },
      
      // Register
      register: async (userData) => {
        try {
          const response = await api.post('/api/auth/register', userData)
          return { success: true, data: response.data }
        } catch (error) {
          const detail = error.response?.data?.detail
          let errorMsg = 'Registration failed'
          
          if (typeof detail === 'string') {
            errorMsg = detail
          } else if (Array.isArray(detail)) {
            errorMsg = detail.map(e => e.msg || String(e)).join(', ')
          }
          
          return { success: false, error: errorMsg }
        }
      },
      
      // Logout
      logout: async () => {
        try {
          const { accessToken } = get()
          if (accessToken) {
            await api.post('/api/auth/logout', {}, {
              headers: { Authorization: `Bearer ${accessToken}` }
            })
          }
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

useAuthStore.getState().initialize()