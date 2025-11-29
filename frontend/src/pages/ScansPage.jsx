import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { apiService } from '../services/api'
import {
  Search,
  Filter,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  AlertTriangle,
  ChevronLeft,
  Calendar
} from 'lucide-react'

const statusConfig = {
  queued: { label: 'در صف', color: 'bg-gray-100 text-gray-700', icon: Clock },
  running: { label: 'در حال اجرا', color: 'bg-blue-100 text-blue-700', icon: Loader2 },
  completed: { label: 'کامل شد', color: 'bg-green-100 text-green-700', icon: CheckCircle },
  failed: { label: 'خطا', color: 'bg-red-100 text-red-700', icon: XCircle },
  cancelled: { label: 'لغو شده', color: 'bg-yellow-100 text-yellow-700', icon: XCircle },
}

export default function ScansPage() {
  const [searchParams] = useSearchParams()
  const projectId = searchParams.get('project')
  
  const [filters, setFilters] = useState({
    status: '',
    search: ''
  })
  
  // Fetch scans
  const { data, isLoading, error } = useQuery({
    queryKey: ['scans', filters, projectId],
    queryFn: () => apiService.getScans({
      ...filters,
      project_id: projectId,
      limit: 50
    }),
    refetchInterval: 5000 // Refresh every 5 seconds for running scans
  })
  
  const scans = data?.data?.items || []
  
  const getStatusBadge = (status) => {
    const config = statusConfig[status] || statusConfig.queued
    const Icon = config.icon
    return (
      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${config.color}`}>
        <Icon className={`w-3.5 h-3.5 ${status === 'running' ? 'animate-spin' : ''}`} />
        {config.label}
      </span>
    )
  }
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">اسکن‌ها</h1>
          <p className="text-gray-500 mt-1">لیست تمام اسکن‌های امنیتی</p>
        </div>
      </div>
      
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="جستجو..."
            value={filters.search}
            onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
            className="input pr-10"
          />
        </div>
        
        <select
          value={filters.status}
          onChange={(e) => setFilters(f => ({ ...f, status: e.target.value }))}
          className="input w-full sm:w-48"
        >
          <option value="">همه وضعیت‌ها</option>
          <option value="queued">در صف</option>
          <option value="running">در حال اجرا</option>
          <option value="completed">کامل شده</option>
          <option value="failed">خطا</option>
          <option value="cancelled">لغو شده</option>
        </select>
      </div>
      
      {/* Scans List */}
      {isLoading ? (
        <div className="space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="card animate-pulse">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 bg-gray-200 rounded-lg"></div>
                <div className="flex-1">
                  <div className="h-4 bg-gray-200 rounded w-1/3 mb-2"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/4"></div>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : error ? (
        <div className="card text-center py-12">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-600">خطا در دریافت اسکن‌ها</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="card text-center py-12">
          <Play className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">اسکنی وجود ندارد</h3>
          <p className="text-gray-500 mb-4">از صفحه پروژه یک اسکن جدید شروع کنید</p>
          <Link to="/projects" className="btn-primary inline-flex">
            مشاهده پروژه‌ها
          </Link>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <Link
              key={scan._id}
              to={`/scans/${scan._id}`}
              className="card hover:shadow-lg transition-shadow block"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                    scan.status === 'completed' ? 'bg-green-100' :
                    scan.status === 'running' ? 'bg-blue-100' :
                    scan.status === 'failed' ? 'bg-red-100' :
                    'bg-gray-100'
                  }`}>
                    <Play className={`w-5 h-5 ${
                      scan.status === 'completed' ? 'text-green-600' :
                      scan.status === 'running' ? 'text-blue-600' :
                      scan.status === 'failed' ? 'text-red-600' :
                      'text-gray-600'
                    }`} />
                  </div>
                  
                  <div>
                    <p className="font-medium text-gray-900">
                      {scan.project_name || 'پروژه'}
                    </p>
                    <div className="flex items-center gap-3 text-sm text-gray-500 mt-1">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-4 h-4" />
                        {new Date(scan.created_at).toLocaleDateString('fa-IR')}
                      </span>
                      <span>
                        حالت: {scan.config?.mode === 'aggressive' ? 'تهاجمی' : 'امن'}
                      </span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center gap-4">
                  {/* Progress for running scans */}
                  {scan.status === 'running' && (
                    <div className="w-32 hidden sm:block">
                      <div className="progress-bar">
                        <div
                          className="progress-bar-fill"
                          style={{ width: `${scan.progress || 0}%` }}
                        />
                      </div>
                      <p className="text-xs text-gray-500 mt-1 text-center">
                        {Math.round(scan.progress || 0)}%
                      </p>
                    </div>
                  )}
                  
                  {/* Findings count for completed */}
                  {scan.status === 'completed' && scan.total_findings > 0 && (
                    <div className="text-center hidden sm:block">
                      <p className="text-lg font-semibold text-gray-900">{scan.total_findings}</p>
                      <p className="text-xs text-gray-500">یافته</p>
                    </div>
                  )}
                  
                  {getStatusBadge(scan.status)}
                  
                  <ChevronLeft className="w-5 h-5 text-gray-400" />
                </div>
              </div>
              
              {/* Severity summary for completed scans */}
              {scan.status === 'completed' && scan.findings_by_severity && (
                <div className="flex items-center gap-2 mt-4 pt-4 border-t border-gray-100">
                  {scan.findings_by_severity.critical > 0 && (
                    <span className="badge-critical">{scan.findings_by_severity.critical} بحرانی</span>
                  )}
                  {scan.findings_by_severity.high > 0 && (
                    <span className="badge-high">{scan.findings_by_severity.high} بالا</span>
                  )}
                  {scan.findings_by_severity.medium > 0 && (
                    <span className="badge-medium">{scan.findings_by_severity.medium} متوسط</span>
                  )}
                  {scan.findings_by_severity.low > 0 && (
                    <span className="badge-low">{scan.findings_by_severity.low} پایین</span>
                  )}
                  {scan.findings_by_severity.info > 0 && (
                    <span className="badge-info">{scan.findings_by_severity.info} اطلاعاتی</span>
                  )}
                </div>
              )}
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}