import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiService } from '../services/api'
import {
  Plus,
  Search,
  MoreVertical,
  Globe,
  CheckCircle,
  XCircle,
  Clock,
  Trash2,
  ExternalLink,
  Shield,
  AlertTriangle
} from 'lucide-react'
import toast from 'react-hot-toast'

export default function ProjectsPage() {
  const [search, setSearch] = useState('')
  const [openMenu, setOpenMenu] = useState(null)
  const queryClient = useQueryClient()
  
  // Fetch projects
  const { data, isLoading, error } = useQuery({
    queryKey: ['projects', search],
    queryFn: () => apiService.getProjects({ search, limit: 50 }),
  })
  
  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id) => apiService.deleteProject(id),
    onSuccess: () => {
      toast.success('پروژه با موفقیت حذف شد')
      queryClient.invalidateQueries(['projects'])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در حذف پروژه')
    }
  })
  
  const handleDelete = (id, name) => {
    if (confirm(`آیا از حذف پروژه "${name}" اطمینان دارید؟`)) {
      deleteMutation.mutate(id)
    }
    setOpenMenu(null)
  }
  
  const projects = data?.data?.items || []
  
  const getVerificationBadge = (status) => {
    switch (status) {
      case 'verified':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700">
            <CheckCircle className="w-3 h-3" />
            تأیید شده
          </span>
        )
      case 'pending':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-700">
            <Clock className="w-3 h-3" />
            در انتظار
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
            <XCircle className="w-3 h-3" />
            تأیید نشده
          </span>
        )
    }
  }
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">پروژه‌ها</h1>
          <p className="text-gray-500 mt-1">مدیریت وب‌سایت‌های تحت اسکن</p>
        </div>
        <Link to="/projects/new" className="btn-primary">
          <Plus className="w-5 h-5" />
          پروژه جدید
        </Link>
      </div>
      
      {/* Search */}
      <div className="relative">
        <Search className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
        <input
          type="text"
          placeholder="جستجوی پروژه..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input pr-10"
        />
      </div>
      
      {/* Projects Grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="card animate-pulse">
              <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
              <div className="h-3 bg-gray-200 rounded w-1/2 mb-2"></div>
              <div className="h-3 bg-gray-200 rounded w-1/4"></div>
            </div>
          ))}
        </div>
      ) : error ? (
        <div className="card text-center py-12">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-600">خطا در دریافت پروژه‌ها</p>
          <p className="text-sm text-gray-500 mt-1">{error.message}</p>
        </div>
      ) : projects.length === 0 ? (
        <div className="card text-center py-12">
          <Globe className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">هنوز پروژه‌ای ندارید</h3>
          <p className="text-gray-500 mb-4">اولین پروژه خود را ایجاد کنید</p>
          <Link to="/projects/new" className="btn-primary inline-flex">
            <Plus className="w-5 h-5" />
            ایجاد پروژه
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {projects.map((project) => (
            <div key={project._id} className="card hover:shadow-lg transition-shadow">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary-100 flex items-center justify-center">
                    <Globe className="w-5 h-5 text-primary-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900">{project.name}</h3>
                    <p className="text-sm text-gray-500">{project.domain}</p>
                  </div>
                </div>
                
                <div className="relative">
                  <button
                    onClick={() => setOpenMenu(openMenu === project._id ? null : project._id)}
                    className="p-1 rounded hover:bg-gray-100"
                  >
                    <MoreVertical className="w-5 h-5 text-gray-400" />
                  </button>
                  
                  {openMenu === project._id && (
                    <>
                      <div
                        className="fixed inset-0 z-10"
                        onClick={() => setOpenMenu(null)}
                      />
                      <div className="absolute left-0 mt-1 w-40 bg-white rounded-lg shadow-lg border border-gray-200 z-20">
                        <Link
                          to={`/projects/${project._id}`}
                          className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50"
                          onClick={() => setOpenMenu(null)}
                        >
                          <ExternalLink className="w-4 h-4" />
                          مشاهده جزئیات
                        </Link>
                        <button
                          onClick={() => handleDelete(project._id, project.name)}
                          className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                        >
                          <Trash2 className="w-4 h-4" />
                          حذف پروژه
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </div>
              
              <div className="flex items-center gap-2 mb-4">
                {getVerificationBadge(project.verification_status)}
              </div>
              
              <div className="flex items-center justify-between text-sm text-gray-500">
                <div className="flex items-center gap-1">
                  <Shield className="w-4 h-4" />
                  <span>{project.scan_count || 0} اسکن</span>
                </div>
                {project.last_scan_at && (
                  <span>
                    آخرین: {new Date(project.last_scan_at).toLocaleDateString('fa-IR')}
                  </span>
                )}
              </div>
              
              <Link
                to={`/projects/${project._id}`}
                className="mt-4 w-full btn-outline text-sm"
              >
                مشاهده پروژه
              </Link>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}