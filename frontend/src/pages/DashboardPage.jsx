import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { apiService } from '../services/api'
import {
  FolderKanban,
  Scan,
  AlertTriangle,
  Shield,
  TrendingUp,
  Clock,
  CheckCircle,
  XCircle,
  Loader2,
  Plus,
  ArrowLeft
} from 'lucide-react'

const severityColors = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
  info: 'bg-blue-500'
}

const severityLabels = {
  critical: 'بحرانی',
  high: 'بالا',
  medium: 'متوسط',
  low: 'پایین',
  info: 'اطلاعاتی'
}

export default function DashboardPage() {
  // Fetch projects
  const { data: projectsData, isLoading: projectsLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => apiService.getProjects(),
  })
  
  // Fetch scans
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => apiService.getScans(),
  })
  
  // Fetch findings stats
  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings-stats'],
    queryFn: () => apiService.getFindingsStats(),
  })
  
  const projects = projectsData?.data?.items || []
  const scans = scansData?.data?.items || []
  const findingsStats = findingsData?.data || {}
  
  const totalProjects = projectsData?.data?.total || 0
  const totalScans = scansData?.data?.total || 0
  const totalFindings = findingsStats.total || 0
  
  // Get severity counts
  const getSeverityCount = (key) => {
    const val = findingsStats.by_severity?.[key]
    if (typeof val === 'number') return val
    if (val && typeof val === 'object') return val.count || 0
    return 0
  }
  
  const criticalCount = getSeverityCount('critical')
  const highCount = getSeverityCount('high')
  
  const recentScans = scans.slice(0, 5)
  const recentProjects = projects.slice(0, 5)
  
  const isLoading = projectsLoading || scansLoading || findingsLoading
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
      </div>
    )
  }
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">داشبورد</h1>
          <p className="text-gray-500 mt-1">خلاصه وضعیت امنیتی پروژه‌های شما</p>
        </div>
        <Link to="/projects/new" className="btn-primary">
          <Plus className="w-5 h-5" />
          پروژه جدید
        </Link>
      </div>
      
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">پروژه‌ها</p>
              <p className="text-3xl font-bold text-gray-900 mt-1">{totalProjects}</p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center">
              <FolderKanban className="w-6 h-6 text-primary-600" />
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">اسکن‌ها</p>
              <p className="text-3xl font-bold text-gray-900 mt-1">{totalScans}</p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-blue-100 flex items-center justify-center">
              <Scan className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">یافته‌ها</p>
              <p className="text-3xl font-bold text-gray-900 mt-1">{totalFindings}</p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-yellow-100 flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-yellow-600" />
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">بحرانی + بالا</p>
              <p className="text-3xl font-bold text-red-600 mt-1">{criticalCount + highCount}</p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-red-100 flex items-center justify-center">
              <Shield className="w-6 h-6 text-red-600" />
            </div>
          </div>
        </div>
      </div>
      
      {/* Severity Breakdown */}
      {totalFindings > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">توزیع شدت یافته‌ها</h2>
          <div className="flex gap-2 h-8 rounded-lg overflow-hidden">
            {Object.entries(severityColors).map(([key, color]) => {
              const count = getSeverityCount(key)
              const percentage = totalFindings > 0 ? (count / totalFindings) * 100 : 0
              if (percentage === 0) return null
              return (
                <div
                  key={key}
                  className={`${color} flex items-center justify-center text-white text-xs font-medium`}
                  style={{ width: `${percentage}%` }}
                  title={`${severityLabels[key]}: ${count}`}
                >
                  {percentage > 10 && count}
                </div>
              )
            })}
          </div>
          <div className="flex flex-wrap gap-4 mt-4">
            {Object.entries(severityLabels).map(([key, label]) => {
              const count = getSeverityCount(key)
              return (
                <div key={key} className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${severityColors[key]}`} />
                  <span className="text-sm text-gray-600">{label}: {count}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}
      
      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">اسکن‌های اخیر</h2>
            <Link to="/scans" className="text-sm text-primary-600 hover:underline flex items-center gap-1">
              مشاهده همه
              <ArrowLeft className="w-4 h-4" />
            </Link>
          </div>
          
          {recentScans.length === 0 ? (
            <div className="text-center py-8">
              <Scan className="w-12 h-12 text-gray-300 mx-auto mb-3" />
              <p className="text-gray-500">هنوز اسکنی انجام نشده</p>
              <Link to="/projects" className="text-primary-600 hover:underline text-sm mt-2 inline-block">
                یک پروژه انتخاب کنید
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {recentScans.map((scan) => (
                <Link
                  key={scan.id || scan._id}
                  to={`/scans/${scan.id || scan._id}`}
                  className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {scan.status === 'completed' ? (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    ) : scan.status === 'failed' ? (
                      <XCircle className="w-5 h-5 text-red-500" />
                    ) : scan.status === 'running' ? (
                      <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />
                    ) : (
                      <Clock className="w-5 h-5 text-gray-400" />
                    )}
                    <div>
                      <p className="font-medium text-gray-900">{scan.project_name || 'پروژه'}</p>
                      <p className="text-sm text-gray-500">
                        {scan.total_findings || 0} یافته
                      </p>
                    </div>
                  </div>
                  <span className="text-xs text-gray-400">
                    {scan.created_at ? new Date(scan.created_at).toLocaleDateString('fa-IR') : '-'}
                  </span>
                </Link>
              ))}
            </div>
          )}
        </div>
        
        {/* Recent Projects */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">پروژه‌های اخیر</h2>
            <Link to="/projects" className="text-sm text-primary-600 hover:underline flex items-center gap-1">
              مشاهده همه
              <ArrowLeft className="w-4 h-4" />
            </Link>
          </div>
          
          {recentProjects.length === 0 ? (
            <div className="text-center py-8">
              <FolderKanban className="w-12 h-12 text-gray-300 mx-auto mb-3" />
              <p className="text-gray-500">هنوز پروژه‌ای ایجاد نشده</p>
              <Link to="/projects/new" className="text-primary-600 hover:underline text-sm mt-2 inline-block">
                اولین پروژه را بسازید
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {recentProjects.map((project) => (
                <Link
                  key={project.id || project._id}
                  to={`/projects/${project.id || project._id}`}
                  className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-primary-100 flex items-center justify-center">
                      <FolderKanban className="w-5 h-5 text-primary-600" />
                    </div>
                    <div>
                      <p className="font-medium text-gray-900">{project.name}</p>
                      <p className="text-sm text-gray-500">{project.domain}</p>
                    </div>
                  </div>
                  <div className="text-left">
                    {project.is_verified ? (
                      <span className="text-xs text-green-600 flex items-center gap-1">
                        <CheckCircle className="w-4 h-4" />
                        تأیید شده
                      </span>
                    ) : (
                      <span className="text-xs text-yellow-600 flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        در انتظار
                      </span>
                    )}
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
      
      {/* Quick Actions */}
      {totalProjects === 0 && (
        <div className="card bg-gradient-to-r from-primary-500 to-primary-600 text-white">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div>
              <h2 className="text-xl font-bold">شروع کنید!</h2>
              <p className="mt-1 opacity-90">اولین پروژه خود را ایجاد کرده و اسکن امنیتی انجام دهید.</p>
            </div>
            <Link
              to="/projects/new"
              className="bg-white text-primary-600 px-6 py-3 rounded-lg font-medium hover:bg-gray-100 transition-colors flex items-center gap-2"
            >
              <Plus className="w-5 h-5" />
              ایجاد پروژه
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}