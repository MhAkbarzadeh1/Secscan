import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiService } from '../services/api'
import {
  Search,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Shield,
  ExternalLink
} from 'lucide-react'
import { Link } from 'react-router-dom'

const severityOptions = [
  { value: '', label: 'همه' },
  { value: 'critical', label: 'بحرانی' },
  { value: 'high', label: 'بالا' },
  { value: 'medium', label: 'متوسط' },
  { value: 'low', label: 'پایین' },
  { value: 'info', label: 'اطلاعاتی' },
]

const severityConfig = {
  critical: { label: 'بحرانی', color: 'bg-red-100 text-red-700' },
  high: { label: 'بالا', color: 'bg-orange-100 text-orange-700' },
  medium: { label: 'متوسط', color: 'bg-yellow-100 text-yellow-700' },
  low: { label: 'پایین', color: 'bg-green-100 text-green-700' },
  info: { label: 'اطلاعاتی', color: 'bg-blue-100 text-blue-700' },
}

export default function FindingsPage() {
  const [filters, setFilters] = useState({
    severity: '',
    wstg_category: '',
    search: ''
  })
  const [expandedFinding, setExpandedFinding] = useState(null)
  
  // Build query params - only include non-empty values
  const queryParams = {
    limit: 100,
    ...(filters.severity && { severity: filters.severity }),
    ...(filters.wstg_category && { wstg_category: filters.wstg_category }),
    ...(filters.search && { search: filters.search }),
  }
  
  // Fetch findings
  const { data, isLoading, error } = useQuery({
    queryKey: ['findings', filters.severity, filters.wstg_category, filters.search],
    queryFn: () => apiService.getFindings(queryParams),
    keepPreviousData: false,
  })
  
  // Fetch stats
  const { data: statsData } = useQuery({
    queryKey: ['findings-stats'],
    queryFn: () => apiService.getFindingsStats(),
  })
  
  // Fetch WSTG categories
  const { data: categoriesData } = useQuery({
    queryKey: ['wstg-categories'],
    queryFn: () => apiService.getWSTGCategories(),
  })
  
  const findings = data?.data?.items || []
  const stats = statsData?.data || {}
  
  // Convert categories object to array
  const wstgCategories = (() => {
    const catData = categoriesData?.data
    if (!catData) return []
    if (Array.isArray(catData)) return catData
    return Object.entries(catData).map(([id, cat]) => ({ 
      id, 
      name: cat.name || id,
      name_fa: cat.name_fa || cat.name || id
    }))
  })()
  
  // Helper to get count from stats
  const getSeverityCount = (key) => {
    const val = stats.by_severity?.[key]
    if (typeof val === 'number') return val
    if (val && typeof val === 'object') return val.count || 0
    return 0
  }
  
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">یافته‌های امنیتی</h1>
        <p className="text-gray-500 mt-1">مشاهده و مدیریت تمام آسیب‌پذیری‌ها</p>
      </div>
      
      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {Object.entries(severityConfig).map(([key, config]) => (
          <div
            key={key}
            onClick={() => setFilters(f => ({ ...f, severity: f.severity === key ? '' : key }))}
            className={`card cursor-pointer transition-all ${
              filters.severity === key ? 'ring-2 ring-primary-500' : 'hover:shadow-md'
            }`}
          >
            <p className="text-3xl font-bold text-gray-900">
              {getSeverityCount(key)}
            </p>
            <p className="text-sm text-gray-500">{config.label}</p>
          </div>
        ))}
      </div>
      
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="جستجو در یافته‌ها..."
            value={filters.search}
            onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
            className="input pr-10"
          />
        </div>
        
        <select
          value={filters.severity}
          onChange={(e) => setFilters(f => ({ ...f, severity: e.target.value }))}
          className="input w-full sm:w-40"
        >
          {severityOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
        
        <select
          value={filters.wstg_category}
          onChange={(e) => setFilters(f => ({ ...f, wstg_category: e.target.value }))}
          className="input w-full sm:w-48"
        >
          <option value="">همه دسته‌ها</option>
          {wstgCategories.map((cat) => (
            <option key={cat.id} value={cat.id}>{cat.name_fa || cat.name}</option>
          ))}
        </select>
      </div>
      
      {/* Findings List */}
      {isLoading ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="card animate-pulse">
              <div className="h-5 bg-gray-200 rounded w-1/3 mb-2"></div>
              <div className="h-4 bg-gray-200 rounded w-1/4"></div>
            </div>
          ))}
        </div>
      ) : error ? (
        <div className="card text-center py-12">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-600">خطا در دریافت یافته‌ها</p>
        </div>
      ) : findings.length === 0 ? (
        <div className="card text-center py-12">
          <Shield className="w-12 h-12 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">یافته‌ای موجود نیست</h3>
          <p className="text-gray-500">
            {filters.severity || filters.wstg_category || filters.search
              ? 'فیلترها را تغییر دهید یا جستجوی دیگری انجام دهید'
              : 'اولین اسکن امنیتی را انجام دهید'
            }
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((finding) => {
            const config = severityConfig[finding.severity] || severityConfig.info
            const findingId = finding.id || finding._id
            const isExpanded = expandedFinding === findingId
            
            return (
              <div
                key={findingId}
                className={`card ${finding.is_false_positive ? 'opacity-50' : ''}`}
              >
                <button
                  onClick={() => setExpandedFinding(isExpanded ? null : findingId)}
                  className="w-full flex items-center justify-between"
                >
                  <div className="flex items-center gap-4">
                    <div className={`w-2 h-12 rounded-full ${
                      finding.severity === 'critical' ? 'bg-red-500' :
                      finding.severity === 'high' ? 'bg-orange-500' :
                      finding.severity === 'medium' ? 'bg-yellow-500' :
                      finding.severity === 'low' ? 'bg-green-500' :
                      'bg-blue-500'
                    }`} />
                    <div className="text-right">
                      <p className="font-medium text-gray-900">
                        {finding.title_fa || finding.title}
                      </p>
                      <div className="flex items-center gap-3 text-sm text-gray-500 mt-1">
                        <span>{finding.wstg_id}</span>
                        <span>•</span>
                        <span>{finding.endpoint}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${config.color}`}>
                      {config.label}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="w-5 h-5 text-gray-400" />
                    ) : (
                      <ChevronDown className="w-5 h-5 text-gray-400" />
                    )}
                  </div>
                </button>
                
                {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-gray-100 space-y-4">
                    <div>
                      <h4 className="font-medium text-gray-700 mb-1">توضیحات</h4>
                      <p className="text-gray-600">
                        {finding.description_fa || finding.description}
                      </p>
                    </div>
                    
                    {finding.evidence && (
                      <div>
                        <h4 className="font-medium text-gray-700 mb-1">شواهد</h4>
                        <pre className="bg-gray-50 p-3 rounded-lg text-sm overflow-x-auto" dir="ltr">
                          {finding.evidence}
                        </pre>
                      </div>
                    )}
                    
                    <div>
                      <h4 className="font-medium text-gray-700 mb-1">توصیه</h4>
                      <p className="text-gray-600">
                        {finding.recommendation_fa || finding.recommendation}
                      </p>
                    </div>
                    
                    <div className="flex items-center justify-between pt-2">
                      <div className="flex items-center gap-4 text-sm text-gray-500">
                        {finding.owasp_top10_id && (
                          <span>OWASP Top 10: {finding.owasp_top10_id}</span>
                        )}
                        {finding.cvss_score && (
                          <span>CVSS: {finding.cvss_score}</span>
                        )}
                      </div>
                      
                      <Link
                        to={`/scans/${finding.scan_id}`}
                        className="text-sm text-primary-600 hover:underline flex items-center gap-1"
                      >
                        مشاهده اسکن
                        <ExternalLink className="w-4 h-4" />
                      </Link>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}