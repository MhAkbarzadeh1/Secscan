import axios from 'axios'

// Create axios instance
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor - add auth token
api.interceptors.request.use(
  (config) => {
    // Get token from localStorage (managed by Zustand persist)
    const authData = localStorage.getItem('owasp-scanner-auth')
    if (authData) {
      try {
        const { state } = JSON.parse(authData)
        if (state?.accessToken) {
          config.headers.Authorization = `Bearer ${state.accessToken}`
        }
      } catch (error) {
        console.error('Error parsing auth data:', error)
      }
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor - handle errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config
    
    // If 401 and not already retrying, try to refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      
      try {
        // Get refresh token
        const authData = localStorage.getItem('owasp-scanner-auth')
        if (authData) {
          const { state } = JSON.parse(authData)
          
          if (state?.refreshToken) {
            const response = await axios.post(
              `${api.defaults.baseURL}/api/auth/refresh`,
              { refresh_token: state.refreshToken }
            )
            
            // Update stored tokens
            const newState = {
              state: {
                accessToken: response.data.access_token,
                refreshToken: response.data.refresh_token
              }
            }
            localStorage.setItem('owasp-scanner-auth', JSON.stringify(newState))
            
            // Retry original request
            originalRequest.headers.Authorization = `Bearer ${response.data.access_token}`
            return api(originalRequest)
          }
        }
      } catch (refreshError) {
        // Refresh failed - clear auth and redirect to login
        localStorage.removeItem('owasp-scanner-auth')
        window.location.href = '/login'
        return Promise.reject(refreshError)
      }
    }
    
    return Promise.reject(error)
  }
)

export default api

// API helper functions
export const apiService = {
  // Projects
  getProjects: (params) => api.get('/api/projects', { params }),
  getProject: (id) => api.get(`/api/projects/${id}`),
  createProject: (data) => api.post('/api/projects', data),
  updateProject: (id, data) => api.put(`/api/projects/${id}`, data),
  deleteProject: (id) => api.delete(`/api/projects/${id}`),
  
  // Verification
  initiateVerification: (projectId, data) => 
    api.post(`/api/verification/${projectId}/initiate`, data),
  verifyDomain: (projectId) => 
    api.post(`/api/verification/${projectId}/verify`),
  getVerificationStatus: (projectId) => 
    api.get(`/api/verification/${projectId}/status`),
  
  // Scans
  getScans: (params) => api.get('/api/scans', { params }),
  getScan: (id) => api.get(`/api/scans/${id}`),
  createScan: (data) => api.post('/api/scans', data),
  cancelScan: (id) => api.post(`/api/scans/${id}/cancel`),
  retryScan: (id) => api.post(`/api/scans/${id}/retry`),
  getScanProgress: (id) => api.get(`/api/scans/${id}/progress`),
  
  // Findings
  getFindings: (params) => api.get('/api/findings', { params }),
  getFinding: (id) => api.get(`/api/findings/${id}`),
  updateFinding: (id, data) => api.patch(`/api/findings/${id}`, data),
  getFindingsStats: (params) => api.get('/api/findings/stats', { params }),
  
  // Reports
  generateReport: (data) => api.post('/api/reports/generate', data),
  getReportStatus: (id) => api.get(`/api/reports/${id}`),
  downloadReport: (id) => api.get(`/api/reports/${id}/download`, { responseType: 'blob' }),
  deleteReport: (id) => api.delete(`/api/reports/${id}`),
  
  // Users (Admin)
  getUsers: (params) => api.get('/api/users', { params }),
  getUser: (id) => api.get(`/api/users/${id}`),
  updateUser: (id, data) => api.put(`/api/users/${id}`, data),
  updateUserRole: (id, role) => api.patch(`/api/users/${id}/role`, null, { params: { role } }),
  toggleUserStatus: (id, isActive) => api.patch(`/api/users/${id}/status`, null, { params: { is_active: isActive } }),
  deleteUser: (id) => api.delete(`/api/users/${id}`),
  
  // Payloads
  getPayloadStats: () => api.get('/api/payloads/stats'),
  getPayloadCategories: () => api.get('/api/payloads/categories'),
  syncPayloads: () => api.post('/api/payloads/sync'),
  getSyncStatus: () => api.get('/api/payloads/sync/status'),
  
  // OWASP reference
  getWSTGCategories: () => api.get('/api/findings/wstg/categories'),
  getOWASPTop10: () => api.get('/api/findings/owasp/top10'),
}