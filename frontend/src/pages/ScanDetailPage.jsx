import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiService } from '../services/api'
import {
  ArrowRight,
  Play,
  Pause,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  FileText,
  Download,
  Loader2,
  Shield,
  ChevronDown,
  ChevronUp,
  ExternalLink
} from 'lucide-react'
import toast from 'react-hot-toast'

const severityConfig = {
  critical: { label: 'بحرانی', color: 'bg-red-500', textColor: 'text-red-700', bgLight: 'bg-red-50' },
  high: { label: 'بالا', color: 'bg-orange-500', textColor: 'text-orange-700', bgLight: 'bg-orange-50' },
  medium: { label: 'متوسط', color: 'bg-yellow-500', textColor: 'text-yellow-700', bgLight: 'bg-yellow-50' },
  low: { label: 'پایین', color: 'bg-green-500', textColor: 'text-green-700', bgLight: 'bg-green-50' },
  info: { label: 'اطلاعاتی', color: 'bg-blue-500', textColor: 'text-blue-700', bgLight: 'bg-blue-50' },
}

export default function ScanDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [expandedFinding, setExpandedFinding] = useState(null)
  const [showReportModal, setShowReportModal] = useState(false)
  const [reportConfig, setReportConfig] = useState({
    format: 'pdf',
    language: 'fa',
    include_evidence: false,
    include_remediation: true
  })
  
  // Fetch scan
  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => apiService.getScan(id),
    select: (res) => res.data,
    refetchInterval: (data) => {
      // Refresh every 2 seconds while running
      return data?.status === 'running' ? 2000 : false
    }
  })
  
  // Fetch findings
  const { data: findingsData } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => apiService.getFindings({ scan_id: id, limit: 100 }),
    enabled: scan?.status === 'completed'
  })
  
  const findings = findingsData?.data?.items || []
  
  // Cancel scan
  const cancelMutation = useMutation({
    mutationFn: () => apiService.cancelScan(id),
    onSuccess: () => {
      toast.success('اسکن لغو شد')
      queryClient.invalidateQueries(['scan', id])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در لغو اسکن')
    }
  })
  
  // Retry scan
  const retryMutation = useMutation({
    mutationFn: () => apiService.retryScan(id),
    onSuccess: (res) => {
      toast.success('اسکن مجدد شروع شد')
      navigate(`/scans/${res.data._id}`)
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در شروع مجدد')
    }
  })
  
  // Generate report
  const reportMutation = useMutation({
    mutationFn: (config) => apiService.generateReport({ scan_id: id, ...config }),
    onSuccess: () => {
      toast.success('گزارش در حال تولید است')
      setShowReportModal(false)
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در تولید گزارش')
    }
  })
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
      </div>
    )
  }
  
  if (!scan) {
    return (
      <div className="card text-center py-12">
        <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
        <p className="text-gray-600">اسکن یافت نشد</p>
        <Link to="/scans" className="btn-primary mt-4 inline-flex">
          بازگشت به اسکن‌ها
        </Link>
      </div>
    )
  }
  
  const isRunning = scan.status === 'running'
  const isCompleted = scan.status === 'completed'
  const isFailed = scan.status === 'failed'
  
  return (
    <div className="space-y-6">
      {/* Back button */}
      <button
        onClick={() => navigate('/scans')}
        className="flex items-center gap-2 text-gray-600 hover:text-gray-900"
      >
        <ArrowRight className="w-5 h-5" />
        بازگشت به اسکن‌ها
      </button>
      
      {/* Header */}
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${
              isCompleted ? 'bg-green-100' :
              isRunning ? 'bg-blue-100' :
              isFailed ? 'bg-red-100' :
              'bg-gray-100'
            }`}>
              {isRunning ? (
                <Loader2 className="w-7 h-7 text-blue-600 animate-spin" />
              ) : isCompleted ? (
                <CheckCircle className="w-7 h-7 text-green-600" />
              ) : isFailed ? (
                <XCircle className="w-7 h-7 text-red-600" />
              ) : (
                <Clock className="w-7 h-7 text-gray-600" />
              )}
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                اسکن {scan.project_name || ''}
              </h1>
              <p className="text-gray-500">
                {new Date(scan.created_at).toLocaleString('fa-IR')}
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {isRunning && (
              <button
                onClick={() => cancelMutation.mutate()}
                disabled={cancelMutation.isPending}
                className="btn-secondary"
              >
                <Pause className="w-5 h-5" />
                لغو اسکن
              </button>
            )}
            
            {isFailed && (
              <button
                onClick={() => retryMutation.mutate()}
                disabled={retryMutation.isPending}
                className="btn-primary"
              >
                <RefreshCw className="w-5 h-5" />
                تلاش مجدد
              </button>
            )}
            
            {isCompleted && findings.length > 0 && (
              <button
                onClick={() => setShowReportModal(true)}
                className="btn-primary"
              >
                <FileText className="w-5 h-5" />
                تولید گزارش
              </button>
            )}
          </div>
        </div>
        
        {/* Progress for running scans */}
        {isRunning && (
          <div className="mt-6">
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-gray-600">{scan.current_test || 'در حال اجرا...'}</span>
              <span className="font-medium text-gray-900">{Math.round(scan.progress || 0)}%</span>
            </div>
            <div className="progress-bar h-3">
              <div
                className="progress-bar-fill"
                style={{ width: `${scan.progress || 0}%` }}
              />
            </div>
            <p className="text-sm text-gray-500 mt-2">
              {scan.tests_completed || 0} از {scan.tests_total || 0} تست
            </p>
          </div>
        )}
        
        {/* Error message */}
        {isFailed && scan.error_message && (
          <div className="mt-4 p-4 bg-red-50 rounded-lg">
            <p className="text-red-700">{scan.error_message}</p>
          </div>
        )}
        
        {/* Summary for completed */}
        {isCompleted && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-6 pt-6 border-t border-gray-100">
            {Object.entries(severityConfig).map(([key, config]) => (
              <div key={key} className={`text-center p-3 rounded-lg ${config.bgLight}`}>
                <p className={`text-2xl font-bold ${config.textColor}`}>
                  {scan.findings_by_severity?.[key] || 0}
                </p>
                <p className="text-sm text-gray-600">{config.label}</p>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Findings */}
      {isCompleted && (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary-600" />
            یافته‌های امنیتی ({findings.length})
          </h2>
          
          {findings.length === 0 ? (
            <div className="text-center py-8">
              <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
              <p className="text-gray-600">هیچ آسیب‌پذیری یافت نشد! 🎉</p>
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((finding) => {
                const config = severityConfig[finding.severity] || severityConfig.info
                const isExpanded = expandedFinding === finding._id
                
                return (
                  <div
                    key={finding._id}
                    className={`border rounded-lg overflow-hidden ${
                      finding.is_false_positive ? 'opacity-50' : ''
                    }`}
                  >
                    <button
                      onClick={() => setExpandedFinding(isExpanded ? null : finding._id)}
                      className="w-full flex items-center justify-between p-4 hover:bg-gray-50"
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-3 h-3 rounded-full ${config.color}`} />
                        <div className="text-right">
                          <p className="font-medium text-gray-900">
                            {finding.title_fa || finding.title}
                          </p>
                          <p className="text-sm text-gray-500">
                            {finding.wstg_id} • {finding.endpoint}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className={`badge ${
                          finding.severity === 'critical' ? 'badge-critical' :
                          finding.severity === 'high' ? 'badge-high' :
                          finding.severity === 'medium' ? 'badge-medium' :
                          finding.severity === 'low' ? 'badge-low' :
                          'badge-info'
                        }`}>
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
                      <div className="p-4 border-t border-gray-100 bg-gray-50">
                        <div className="space-y-4">
                          <div>
                            <h4 className="font-medium text-gray-700 mb-1">توضیحات</h4>
                            <p className="text-gray-600">
                              {finding.description_fa || finding.description}
                            </p>
                          </div>
                          
                          {finding.evidence && (
                            <div>
                              <h4 className="font-medium text-gray-700 mb-1">شواهد</h4>
                              <pre className="bg-white p-3 rounded border border-gray-200 text-sm overflow-x-auto" dir="ltr">
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
                          
                          <div className="flex items-center gap-4 text-sm text-gray-500">
                            {finding.owasp_top10_id && (
                              <span>OWASP: {finding.owasp_top10_id}</span>
                            )}
                            {finding.cvss_score && (
                              <span>CVSS: {finding.cvss_score}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
      
      {/* Report Modal */}
      {showReportModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">تولید گزارش</h3>
            
            {/* Format */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                فرمت گزارش
              </label>
              <div className="grid grid-cols-3 gap-2">
                {['pdf', 'html', 'json'].map((format) => (
                  <button
                    key={format}
                    onClick={() => setReportConfig(c => ({ ...c, format }))}
                    className={`p-2 rounded-lg border-2 text-sm font-medium ${
                      reportConfig.format === format
                        ? 'border-primary-500 bg-primary-50 text-primary-700'
                        : 'border-gray-200 text-gray-600'
                    }`}
                  >
                    {format.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
            
            {/* Language */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                زبان گزارش
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => setReportConfig(c => ({ ...c, language: 'fa' }))}
                  className={`p-2 rounded-lg border-2 text-sm font-medium ${
                    reportConfig.language === 'fa'
                      ? 'border-primary-500 bg-primary-50 text-primary-700'
                      : 'border-gray-200 text-gray-600'
                  }`}
                >
                  فارسی
                </button>
                <button
                  onClick={() => setReportConfig(c => ({ ...c, language: 'en' }))}
                  className={`p-2 rounded-lg border-2 text-sm font-medium ${
                    reportConfig.language === 'en'
                      ? 'border-primary-500 bg-primary-50 text-primary-700'
                      : 'border-gray-200 text-gray-600'
                  }`}
                >
                  English
                </button>
              </div>
            </div>
            
            {/* Options */}
            <div className="space-y-2 mb-6">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={reportConfig.include_remediation}
                  onChange={(e) => setReportConfig(c => ({
                    ...c,
                    include_remediation: e.target.checked
                  }))}
                  className="rounded text-primary-600"
                />
                <span className="text-sm text-gray-700">شامل توصیه‌های رفع</span>
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={reportConfig.include_evidence}
                  onChange={(e) => setReportConfig(c => ({
                    ...c,
                    include_evidence: e.target.checked
                  }))}
                  className="rounded text-primary-600"
                />
                <span className="text-sm text-gray-700">شامل شواهد فنی</span>
              </label>
            </div>
            
            <div className="flex gap-3">
              <button
                onClick={() => reportMutation.mutate(reportConfig)}
                disabled={reportMutation.isPending}
                className="btn-primary flex-1"
              >
                {reportMutation.isPending ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <>
                    <Download className="w-5 h-5" />
                    تولید گزارش
                  </>
                )}
              </button>
              <button
                onClick={() => setShowReportModal(false)}
                className="btn-secondary"
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}