import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiService } from '../services/api'
import {
  ArrowRight,
  Globe,
  CheckCircle,
  Clock,
  Shield,
  Play,
  FileText,
  Copy,
  RefreshCw,
  AlertTriangle,
  Loader2,
  ExternalLink
} from 'lucide-react'
import toast from 'react-hot-toast'

export default function ProjectDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [verificationMethod, setVerificationMethod] = useState('dns_txt')
  const [showScanModal, setShowScanModal] = useState(false)
  const [scanConfig, setScanConfig] = useState({
    mode: 'safe',
    categories: ['INFO', 'CONF', 'INPV']
  })
  
  const { data: project, isLoading, error } = useQuery({
    queryKey: ['project', id],
    queryFn: () => apiService.getProject(id),
    select: (res) => res.data
  })
  
  const { data: verification } = useQuery({
    queryKey: ['verification', id],
    queryFn: () => apiService.getVerificationStatus(id),
    select: (res) => res.data,
    enabled: !!project
  })
  
  const initVerification = useMutation({
    mutationFn: () => apiService.initiateVerification(id, { method: verificationMethod }),
    onSuccess: () => {
      toast.success('فرآیند تأیید شروع شد')
      queryClient.invalidateQueries(['verification', id])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در شروع فرآیند تأیید')
    }
  })
  
  const verifyDomain = useMutation({
    mutationFn: () => apiService.verifyDomain(id),
    onSuccess: (res) => {
      if (res.data.status === 'verified') {
        toast.success('دامنه با موفقیت تأیید شد!')
        queryClient.invalidateQueries(['project', id])
        queryClient.invalidateQueries(['verification', id])
      } else {
        toast.error('تأیید دامنه ناموفق بود')
      }
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در تأیید دامنه')
    }
  })
  
  const createScan = useMutation({
    mutationFn: (config) => apiService.createScan({ project_id: id, config }),
    onSuccess: (res) => {
      toast.success('اسکن شروع شد')
      setShowScanModal(false)
      navigate(`/scans/${res.data.id}`)
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در شروع اسکن')
    }
  })
  
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    toast.success('کپی شد!')
  }
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
      </div>
    )
  }
  
  if (error || !project) {
    return (
      <div className="card text-center py-12">
        <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
        <p className="text-gray-600">پروژه یافت نشد</p>
        <Link to="/projects" className="btn-primary mt-4 inline-flex">بازگشت به پروژه‌ها</Link>
      </div>
    )
  }
  
  const isVerified = project.verification_status === 'verified' || project.is_verified === true
  
  return (
    <div className="space-y-6">
      <button onClick={() => navigate('/projects')} className="flex items-center gap-2 text-gray-600 hover:text-gray-900">
        <ArrowRight className="w-5 h-5" />
        بازگشت به پروژه‌ها
      </button>
      
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-xl bg-primary-100 flex items-center justify-center">
              <Globe className="w-7 h-7 text-primary-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{project.name}</h1>
              <a href={`https://${project.domain}`} target="_blank" rel="noopener noreferrer" className="text-primary-600 hover:underline flex items-center gap-1">
                {project.domain}
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {isVerified ? (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-100 text-green-700 font-medium">
                <CheckCircle className="w-5 h-5" />
                تأیید شده
              </span>
            ) : (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-yellow-100 text-yellow-700 font-medium">
                <Clock className="w-5 h-5" />
                نیاز به تأیید
              </span>
            )}
          </div>
        </div>
        
        {project.description && <p className="mt-4 text-gray-600">{project.description}</p>}
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-gray-100">
          <div className="text-center">
            <p className="text-2xl font-bold text-gray-900">{project.scan_count || 0}</p>
            <p className="text-sm text-gray-500">تعداد اسکن</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-gray-900">{project.endpoints?.length || 0}</p>
            <p className="text-sm text-gray-500">endpoint</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-gray-900">{project.last_scan_at ? new Date(project.last_scan_at).toLocaleDateString('fa-IR') : '-'}</p>
            <p className="text-sm text-gray-500">آخرین اسکن</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-gray-900">{new Date(project.created_at).toLocaleDateString('fa-IR')}</p>
            <p className="text-sm text-gray-500">تاریخ ایجاد</p>
          </div>
        </div>
      </div>
      
      {!isVerified && (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary-600" />
            تأیید مالکیت دامنه
          </h2>
          <p className="text-gray-600 mb-6">برای اسکن این دامنه، ابتدا باید مالکیت آن را تأیید کنید.</p>
          
          <div className="flex gap-4 mb-6">
            <button onClick={() => setVerificationMethod('dns_txt')} className={`flex-1 p-4 rounded-lg border-2 ${verificationMethod === 'dns_txt' ? 'border-primary-500 bg-primary-50' : 'border-gray-200'}`}>
              <p className="font-medium text-gray-900">DNS TXT</p>
            </button>
            <button onClick={() => setVerificationMethod('file')} className={`flex-1 p-4 rounded-lg border-2 ${verificationMethod === 'file' ? 'border-primary-500 bg-primary-50' : 'border-gray-200'}`}>
              <p className="font-medium text-gray-900">فایل</p>
            </button>
          </div>
          
          {verification?.token ? (
            <div className="bg-gray-50 rounded-lg p-4 mb-6">
              <p className="font-medium mb-2">توکن:</p>
              <div className="flex items-center gap-2">
                <code className="bg-white p-2 rounded border text-sm">{verification.token}</code>
                <button onClick={() => copyToClipboard(verification.token)} className="p-2 hover:bg-gray-200 rounded">
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>
          ) : (
            <button onClick={() => initVerification.mutate()} disabled={initVerification.isPending} className="btn-secondary mb-6">
              {initVerification.isPending ? <Loader2 className="w-5 h-5 animate-spin" /> : 'شروع تأیید'}
            </button>
          )}
          
          {verification?.token && (
            <button onClick={() => verifyDomain.mutate()} disabled={verifyDomain.isPending} className="btn-primary">
              {verifyDomain.isPending ? <Loader2 className="w-5 h-5 animate-spin" /> : 'بررسی تأیید'}
            </button>
          )}
        </div>
      )}
      
      {isVerified && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <button onClick={() => setShowScanModal(true)} className="card hover:shadow-lg flex items-center gap-4 p-6 text-left">
            <div className="w-12 h-12 rounded-xl bg-green-100 flex items-center justify-center">
              <Play className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <p className="font-semibold text-gray-900">شروع اسکن جدید</p>
              <p className="text-sm text-gray-500">اسکن امنیتی OWASP</p>
            </div>
          </button>
          
          <Link to={`/scans?project=${id}`} className="card hover:shadow-lg flex items-center gap-4 p-6">
            <div className="w-12 h-12 rounded-xl bg-blue-100 flex items-center justify-center">
              <FileText className="w-6 h-6 text-blue-600" />
            </div>
            <div>
              <p className="font-semibold text-gray-900">مشاهده اسکن‌ها</p>
              <p className="text-sm text-gray-500">{project.scan_count || 0} اسکن</p>
            </div>
          </Link>
        </div>
      )}
      
      {showScanModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl max-w-lg w-full p-6">
            <h3 className="text-lg font-semibold mb-4">تنظیمات اسکن</h3>
            
            <div className="mb-6">
              <label className="block text-sm font-medium mb-2">حالت اسکن</label>
              <div className="grid grid-cols-2 gap-3">
                <button onClick={() => setScanConfig(s => ({ ...s, mode: 'safe' }))} className={`p-3 rounded-lg border-2 ${scanConfig.mode === 'safe' ? 'border-green-500 bg-green-50' : 'border-gray-200'}`}>
                  <p className="font-medium">امن</p>
                </button>
                <button onClick={() => setScanConfig(s => ({ ...s, mode: 'aggressive' }))} className={`p-3 rounded-lg border-2 ${scanConfig.mode === 'aggressive' ? 'border-orange-500 bg-orange-50' : 'border-gray-200'}`}>
                  <p className="font-medium">تهاجمی</p>
                </button>
              </div>
            </div>
            
            <div className="mb-6">
              <label className="block text-sm font-medium mb-2">دسته‌های تست</label>
              <div className="space-y-2">
                {[
                  { id: 'INFO', name: 'جمع‌آوری اطلاعات' },
                  { id: 'CONF', name: 'تنظیمات امنیتی' },
                  { id: 'INPV', name: 'تزریق (SQLi, XSS)' },
                  { id: 'SESS', name: 'مدیریت Session' },
                  { id: 'CRYP', name: 'رمزنگاری' },
                ].map((cat) => (
                  <label key={cat.id} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={scanConfig.categories.includes(cat.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setScanConfig(s => ({ ...s, categories: [...s.categories, cat.id] }))
                        } else {
                          setScanConfig(s => ({ ...s, categories: s.categories.filter(c => c !== cat.id) }))
                        }
                      }}
                      className="rounded"
                    />
                    <span>{cat.name}</span>
                  </label>
                ))}
              </div>
            </div>
            
            <div className="flex gap-3">
              <button onClick={() => createScan.mutate(scanConfig)} disabled={createScan.isPending || scanConfig.categories.length === 0} className="btn-primary flex-1">
                {createScan.isPending ? <Loader2 className="w-5 h-5 animate-spin" /> : 'شروع اسکن'}
              </button>
              <button onClick={() => setShowScanModal(false)} className="btn-secondary">انصراف</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}