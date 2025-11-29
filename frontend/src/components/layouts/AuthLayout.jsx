import { Outlet } from 'react-router-dom'
import { Shield } from 'lucide-react'

export default function AuthLayout() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-900 via-primary-800 to-primary-900 flex items-center justify-center p-4">
      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white/10 backdrop-blur-sm mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">اسکنر امنیتی OWASP</h1>
          <p className="text-primary-200 mt-2">بررسی امنیت وب‌سایت</p>
        </div>
        
        {/* Auth card */}
        <div className="bg-white rounded-2xl shadow-2xl p-8">
          <Outlet />
        </div>
        
        <p className="text-center text-primary-300 text-sm mt-6">
          © {new Date().getFullYear()} OWASP Security Scanner
        </p>
      </div>
    </div>
  )
}