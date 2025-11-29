import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiService } from '../services/api'
import {
  FileText,
  Download,
  Trash2,
  Clock,
  CheckCircle,
  XCircle,
  Loader2,
  AlertTriangle,
  Calendar,
  File
} from 'lucide-react'
import toast from 'react-hot-toast'

const formatLabels = {
  pdf: 'PDF',
  html: 'HTML',
  json: 'JSON'
}

const statusConfig = {
  generating: { label: 'در حال تولید', icon: Loader2, color: 'text-blue-600' },
  ready: { label: 'آماده', icon: CheckCircle, color: 'text-green-600' },
  failed: { label: 'خطا', icon: XCircle, color: 'text-red-600' },
  expired: { label: 'منقضی', icon: Clock, color: 'text-gray-500' },
}

export default function ReportsPage() {
  const queryClient = useQueryClient()
  
  // For now, we'll show reports from completed scans
  // In production, you'd have a dedicated reports endpoint
  const { data: scansData, isLoading } = useQuery({
    queryKey: ['scans-for-reports'],
    queryFn: () => apiService.getScans({ status: 'completed', limit: 50 }),
  })
  
  const scans = scansData?.data?.items || []
  
  // Generate report mutation
  const generateMutation = useMutation({
    mutationFn: ({ scanId, config }) => apiService.generateReport({
      scan_id: scanId,
      ...config
    }),
    onSuccess: () => {
      toast.success('گزارش در حال تولید است')
      queryClient.invalidateQueries(['reports'])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در تولید گزارش')
    }
  })
  
  const [selectedScan, setSelectedScan] = useState(null)
  const [reportConfig, setReportConfig] = useState({
    format: 'pdf',
    language: 'fa',
    include_evidence: false,
    include_remediation: true
  })
  
  const handleGenerate = () => {
    if (selectedScan) {
      generateMutation.mutate({
        scanId: selectedScan,
        config: reportConfig
      })
      setSelectedScan(null)
    }
  }
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">گزارش‌ها</h1>
        <p className="text-gray-500 mt-1">تولید و دانلود گزارش‌های امنیتی</p>
      </div>
      
      {/* Info card */}
      <div className="card bg-blue-50 border border-blue-200">
        <div className="flex items-start gap-3">
          <FileText className="w-6 h-6 text-blue-600 flex-shrink-0" />
          <div>
            <h3 className="font-medium text-blue-900">تولید گزارش</h3>
            <p className="text-sm text-blue-700 mt-1">
              برای تولید گزارش، ابتدا یک اسکن کامل شده را انتخاب کنید، سپس فرمت و زبان مورد نظر را مشخص کنید.
            </p>
          </div>
        </div>
      </div>
      
      {/* Scans list for report generation */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">اسکن‌های کامل شده</h2>
        
        {isLoading ? (
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="animate-pulse p-4 border border-gray-200 rounded-lg">
                <div className="h-4 bg-gray-200 rounded w-1/3 mb-2"></div>
                <div className="h-3 bg-gray-200 rounded w-1/4"></div>
              </div>
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="text-center py-8">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <p className="text-gray-600">هنوز اسکن کامل شده‌ای وجود ندارد</p>
          </div>
        ) : (
          <div className="space-y-3">
            {scans.map((scan) => (
              <div
                key={scan._id}
                onClick={() => setSelectedScan(scan._id === selectedScan ? null : scan._id)}
                className={`p-4 border rounded-lg cursor-pointer transition-all ${
                  selectedScan === scan._id
                    ? 'border-primary-500 bg-primary-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-gray-900">
                      {scan.project_name || 'پروژه'}
                    </p>
                    <div className="flex items-center gap-3 text-sm text-gray-500 mt-1">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-4 h-4" />
                        {new Date(scan.created_at).toLocaleDateString('fa-IR')}
                      </span>
                      <span>{scan.total_findings || 0} یافته</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    {scan.findings_by_severity?.critical > 0 && (
                      <span className="badge-critical">{scan.findings_by_severity.critical}</span>
                    )}
                    {scan.findings_by_severity?.high > 0 && (
                      <span className="badge-high">{scan.findings_by_severity.high}</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Report generation panel */}
      {selectedScan && (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">تنظیمات گزارش</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Format */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                فرمت گزارش
              </label>
              <div className="flex gap-2">
                {['pdf', 'html', 'json'].map((format) => (
                  <button
                    key={format}
                    onClick={() => setReportConfig(c => ({ ...c, format }))}
                    className={`flex-1 p-3 rounded-lg border-2 text-sm font-medium ${
                      reportConfig.format === format
                        ? 'border-primary-500 bg-primary-50 text-primary-700'
                        : 'border-gray-200 text-gray-600 hover:border-gray-300'
                    }`}
                  >
                    <File className="w-5 h-5 mx-auto mb-1" />
                    {formatLabels[format]}
                  </button>
                ))}
              </div>
            </div>
            
            {/* Language */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                زبان گزارش
              </label>
              <div className="flex gap-2">
                <button
                  onClick={() => setReportConfig(c => ({ ...c, language: 'fa' }))}
                  className={`flex-1 p-3 rounded-lg border-2 text-sm font-medium ${
                    reportConfig.language === 'fa'
                      ? 'border-primary-500 bg-primary-50 text-primary-700'
                      : 'border-gray-200 text-gray-600 hover:border-gray-300'
                  }`}
                >
                  فارسی
                </button>
                <button
                  onClick={() => setReportConfig(c => ({ ...c, language: 'en' }))}
                  className={`flex-1 p-3 rounded-lg border-2 text-sm font-medium ${
                    reportConfig.language === 'en'
                      ? 'border-primary-500 bg-primary-50 text-primary-700'
                      : 'border-gray-200 text-gray-600 hover:border-gray-300'
                  }`}
                >
                  English
                </button>
              </div>
            </div>
          </div>
          
          {/* Options */}
          <div className="mt-6 space-y-3">
            <label className="flex items-center gap-3">
              <input
                type="checkbox"
                checked={reportConfig.include_remediation}
                onChange={(e) => setReportConfig(c => ({
                  ...c,
                  include_remediation: e.target.checked
                }))}
                className="w-5 h-5 rounded text-primary-600"
              />
              <div>
                <p className="font-medium text-gray-900">توصیه‌های رفع آسیب‌پذیری</p>
                <p className="text-sm text-gray-500">شامل راهنمای رفع هر آسیب‌پذیری</p>
              </div>
            </label>
            
            <label className="flex items-center gap-3">
              <input
                type="checkbox"
                checked={reportConfig.include_evidence}
                onChange={(e) => setReportConfig(c => ({
                  ...c,
                  include_evidence: e.target.checked
                }))}
                className="w-5 h-5 rounded text-primary-600"
              />
              <div>
                <p className="font-medium text-gray-900">شواهد فنی</p>
                <p className="text-sm text-gray-500">شامل جزئیات فنی و شواهد هر یافته</p>
              </div>
            </label>
          </div>
          
          {/* Generate button */}
          <div className="mt-6 flex gap-3">
            <button
              onClick={handleGenerate}
              disabled={generateMutation.isPending}
              className="btn-primary"
            >
              {generateMutation.isPending ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  در حال تولید...
                </>
              ) : (
                <>
                  <Download className="w-5 h-5" />
                  تولید و دانلود گزارش
                </>
              )}
            </button>
            <button
              onClick={() => setSelectedScan(null)}
              className="btn-secondary"
            >
              انصراف
            </button>
          </div>
        </div>
      )}
    </div>
  )
}