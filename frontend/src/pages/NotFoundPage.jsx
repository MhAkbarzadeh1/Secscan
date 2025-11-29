import { Link } from 'react-router-dom'
import { Home, ArrowRight, Shield } from 'lucide-react'

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="text-center">
        {/* Logo */}
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary-100 mb-6">
          <Shield className="w-8 h-8 text-primary-600" />
        </div>
        
        {/* 404 */}
        <h1 className="text-8xl font-bold text-gray-200 mb-4">404</h1>
        
        {/* Message */}
        <h2 className="text-2xl font-bold text-gray-900 mb-2">صفحه یافت نشد</h2>
        <p className="text-gray-500 mb-8 max-w-md mx-auto">
          صفحه‌ای که به دنبال آن هستید وجود ندارد یا منتقل شده است.
        </p>
        
        {/* Actions */}
        <div className="flex items-center justify-center gap-4">
          <Link to="/" className="btn-primary">
            <Home className="w-5 h-5" />
            صفحه اصلی
          </Link>
          <button
            onClick={() => window.history.back()}
            className="btn-secondary"
          >
            <ArrowRight className="w-5 h-5" />
            بازگشت
          </button>
        </div>
      </div>
    </div>
  )
}