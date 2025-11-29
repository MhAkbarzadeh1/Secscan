import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../hooks/useAuthStore'

function RegisterPage() {
  const navigate = useNavigate()
  const { register, isLoading } = useAuthStore()

  const [formData, setFormData] = useState({
    username: '',
    full_name: '',
    email: '',
    password: '',
    confirmPassword: ''
  })

  const [error, setError] = useState('')

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value })
    setError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (formData.password !== formData.confirmPassword) {
      setError('رمز عبور و تکرار آن یکسان نیستند')
      return
    }

    if (formData.password.length < 8) {
      setError('رمز عبور باید حداقل ۸ کاراکتر باشد')
      return
    }

    if (!/[A-Z]/.test(formData.password)) {
      setError('رمز عبور باید حداقل یک حرف بزرگ انگلیسی داشته باشد')
      return
    }

    if (!/[a-z]/.test(formData.password)) {
      setError('رمز عبور باید حداقل یک حرف کوچک انگلیسی داشته باشد')
      return
    }

    if (!/\d/.test(formData.password)) {
      setError('رمز عبور باید حداقل یک عدد داشته باشد')
      return
    }

    const result = await register({
      username: formData.username,
      full_name: formData.full_name,
      email: formData.email,
      password: formData.password
    })

    if (result.success) {
      navigate('/login')
    } else {
      setError(result.error || 'ثبت‌نام انجام نشد')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 py-12 px-4">
      <div className="max-w-md w-full space-y-8">

        <div className="text-center">
          <h2 className="text-3xl font-bold text-white">
            اسکنر OWASP
          </h2>
          <p className="mt-2 text-gray-400">
            ایجاد حساب کاربری جدید
          </p>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          {error && (
            <div className="bg-red-500/10 border border-red-500 text-red-500 px-4 py-3 rounded">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="username" className="text-sm font-medium text-gray-300">
                نام کاربری
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                value={formData.username}
                onChange={handleChange}
                className="mt-1 w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white 
                focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="user123"
              />
            </div>

            <div>
              <label htmlFor="full_name" className="text-sm font-medium text-gray-300">
                نام و نام خانوادگی
              </label>
              <input
                id="full_name"
                name="full_name"
                type="text"
                required
                value={formData.full_name}
                onChange={handleChange}
                className="mt-1 w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white 
                focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="مثلاً: علی رضایی"
              />
            </div>

            <div>
              <label htmlFor="email" className="text-sm font-medium text-gray-300">
                ایمیل
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                value={formData.email}
                onChange={handleChange}
                className="mt-1 w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white 
                focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="text-sm font-medium text-gray-300">
                رمز عبور
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                value={formData.password}
                onChange={handleChange}
                className="mt-1 w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white 
                focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="••••••••"
              />
              <p className="mt-1 text-xs text-gray-500">
                حداقل ۸ کاراکتر، دارای حرف بزرگ، حرف کوچک و عدد
              </p>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="text-sm font-medium text-gray-300">
                تکرار رمز عبور
              </label>
              <input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                required
                value={formData.confirmPassword}
                onChange={handleChange}
                className="mt-1 w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white 
                focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 
            text-white font-medium rounded-md transition"
          >
            {isLoading ? 'در حال ایجاد حساب...' : 'ایجاد حساب'}
          </button>

          <p className="text-center text-gray-400">
            قبلاً ثبت‌نام کرده‌اید؟{' '}
            <Link to="/login" className="text-blue-500 hover:text-blue-400">
              ورود
            </Link>
          </p>
        </form>
      </div>
    </div>
  )
}

export default RegisterPage
