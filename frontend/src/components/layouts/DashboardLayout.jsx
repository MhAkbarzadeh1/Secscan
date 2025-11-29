import { useState } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../hooks/useAuthStore'
import {
  LayoutDashboard,
  FolderKanban,
  Scan,
  AlertTriangle,
  FileText,
  Users,
  Settings,
  LogOut,
  Menu,
  X,
  Shield,
  ChevronDown,
  User
} from 'lucide-react'

const navigation = [
  { name: 'داشبورد', href: '/', icon: LayoutDashboard },
  { name: 'پروژه‌ها', href: '/projects', icon: FolderKanban },
  { name: 'اسکن‌ها', href: '/scans', icon: Scan },
  { name: 'یافته‌ها', href: '/findings', icon: AlertTriangle },
  { name: 'گزارش‌ها', href: '/reports', icon: FileText },
]

const adminNavigation = [
  { name: 'کاربران', href: '/users', icon: Users },
  { name: 'تنظیمات', href: '/settings', icon: Settings },
]

export default function DashboardLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const { user, logout, hasRole } = useAuthStore()
  const navigate = useNavigate()
  
  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }
  
  const isAdmin = hasRole(['owner', 'admin'])
  
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      
      {/* Sidebar */}
      <aside
        className={`
          fixed top-0 right-0 z-50 h-full w-64 bg-white border-l border-gray-200
          transform transition-transform duration-300 ease-in-out
          lg:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : 'translate-x-full lg:translate-x-0'}
        `}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-primary-600" />
            <span className="font-bold text-lg text-gray-900">اسکنر OWASP</span>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-2 rounded-lg hover:bg-gray-100"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        
        {/* Navigation */}
        <nav className="p-4 space-y-1">
          {navigation.map((item) => (
            <NavLink
              key={item.href}
              to={item.href}
              end={item.href === '/'}
              className={({ isActive }) =>
                `sidebar-item ${isActive ? 'active' : ''}`
              }
              onClick={() => setSidebarOpen(false)}
            >
              <item.icon className="w-5 h-5" />
              <span>{item.name}</span>
            </NavLink>
          ))}
          
          {isAdmin && (
            <>
              <div className="pt-4 pb-2">
                <span className="px-4 text-xs font-medium text-gray-400 uppercase">
                  مدیریت
                </span>
              </div>
              {adminNavigation.map((item) => (
                <NavLink
                  key={item.href}
                  to={item.href}
                  className={({ isActive }) =>
                    `sidebar-item ${isActive ? 'active' : ''}`
                  }
                  onClick={() => setSidebarOpen(false)}
                >
                  <item.icon className="w-5 h-5" />
                  <span>{item.name}</span>
                </NavLink>
              ))}
            </>
          )}
        </nav>
        
        {/* User section */}
        <div className="absolute bottom-0 right-0 left-0 p-4 border-t border-gray-200">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center">
              <User className="w-5 h-5 text-primary-600" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">
                {user?.full_name || user?.username}
              </p>
              <p className="text-xs text-gray-500 truncate">{user?.email}</p>
            </div>
          </div>
        </div>
      </aside>
      
      {/* Main content */}
      <div className="lg:mr-64">
        {/* Top header */}
        <header className="sticky top-0 z-30 h-16 bg-white border-b border-gray-200">
          <div className="flex items-center justify-between h-full px-4">
            {/* Mobile menu button */}
            <button
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-2 rounded-lg hover:bg-gray-100"
            >
              <Menu className="w-6 h-6" />
            </button>
            
            {/* Spacer */}
            <div className="flex-1" />
            
            {/* User menu */}
            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 p-2 rounded-lg hover:bg-gray-100"
              >
                <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center">
                  <User className="w-4 h-4 text-primary-600" />
                </div>
                <span className="hidden sm:block text-sm font-medium text-gray-700">
                  {user?.username}
                </span>
                <ChevronDown className="w-4 h-4 text-gray-500" />
              </button>
              
              {/* Dropdown */}
              {userMenuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setUserMenuOpen(false)}
                  />
                  <div className="absolute left-0 mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-200 z-20">
                    <div className="p-3 border-b border-gray-100">
                      <p className="text-sm font-medium text-gray-900">
                        {user?.full_name || user?.username}
                      </p>
                      <p className="text-xs text-gray-500">{user?.email}</p>
                      <span className="inline-block mt-1 px-2 py-0.5 text-xs font-medium bg-primary-100 text-primary-700 rounded">
                        {user?.role === 'owner' ? 'مالک' : user?.role === 'admin' ? 'مدیر' : 'کاربر'}
                      </span>
                    </div>
                    <div className="p-2">
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50 rounded-lg"
                      >
                        <LogOut className="w-4 h-4" />
                        خروج از حساب
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>
        
        {/* Page content */}
        <main className="p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}