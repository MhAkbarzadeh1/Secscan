import { useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiService } from '../services/api'
import { useAuthStore } from '../hooks/useAuthStore'
import {
  Settings,
  Database,
  RefreshCw,
  Shield,
  Clock,
  CheckCircle,
  Loader2,
  HardDrive,
  Zap
} from 'lucide-react'
import toast from 'react-hot-toast'

export default function SettingsPage() {
  const { hasRole } = useAuthStore()
  const queryClient = useQueryClient()
  const isAdmin = hasRole(['owner', 'admin'])
  const wasSyncingRef = useRef(false)
  
  // Fetch payload stats
  const { data: payloadStats, isLoading: loadingStats } = useQuery({
    queryKey: ['payload-stats'],
    queryFn: () => apiService.getPayloadStats(),
    select: (res) => res.data
  })
  
  // Fetch sync status with polling every 2 seconds
  const { data: syncStatus } = useQuery({
    queryKey: ['sync-status'],
    queryFn: () => apiService.getSyncStatus(),
    select: (res) => res.data,
    refetchInterval: 2000
  })
  
  // Detect when sync completes
  useEffect(() => {
    if (syncStatus) {
      // If was syncing and now not syncing
      if (wasSyncingRef.current && !syncStatus.is_syncing) {
        // Refresh stats
        queryClient.invalidateQueries({ queryKey: ['payload-stats'] })
        
        // Show success message
        if (syncStatus.progress === 100 && !syncStatus.last_error) {
          toast.success('همگام‌سازی با موفقیت انجام شد')
        } else if (syncStatus.last_error) {
          toast.error(`خطا: ${syncStatus.last_error}`)
        }
      }
      
      // Update ref
      wasSyncingRef.current = syncStatus.is_syncing
    }
  }, [syncStatus, queryClient])
  
  // Sync payloads mutation
  const syncMutation = useMutation({
    mutationFn: () => apiService.syncPayloads(),
    onSuccess: () => {
      toast.success('همگام‌سازی شروع شد')
      wasSyncingRef.current = true
      queryClient.invalidateQueries({ queryKey: ['sync-status'] })
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در شروع همگام‌سازی')
    }
  })
  
  // Get stats values (handle both naming conventions)
  const totalPayloads = payloadStats?.total_count ?? payloadStats?.total ?? 0
  const safePayloads = payloadStats?.safe_count ?? payloadStats?.safe ?? 0
  const aggressivePayloads = payloadStats?.aggressive_count ?? payloadStats?.aggressive ?? 0
  const categoriesCount = payloadStats?.by_category 
    ? Object.keys(payloadStats.by_category).length 
    : (payloadStats?.categories ?? 0)
  
  // Format date for Tehran timezone (UTC+3:30)
  const formatDate = (dateStr) => {
    if (!dateStr) return ''
    try {
      const date = new Date(dateStr)
      // Add 3 hours and 30 minutes for Tehran timezone
      const tehranDate = new Date(date.getTime() + (3.5 * 60 * 60 * 1000))
      return tehranDate.toLocaleString('fa-IR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      })
    } catch {
      return new Date(dateStr).toLocaleString('fa-IR')
    }
  }
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">تنظیمات</h1>
        <p className="text-gray-500 mt-1">مدیریت تنظیمات سیستم</p>
      </div>
      
      {/* Payload Management */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-primary-100 flex items-center justify-center">
            <Database className="w-5 h-5 text-primary-600" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900">مدیریت پیلودها</h2>
            <p className="text-sm text-gray-500">پیلودها از PayloadsAllTheThings</p>
          </div>
        </div>
        
        {/* Stats */}
        {loadingStats ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="p-4 bg-gray-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-gray-900">
                {totalPayloads.toLocaleString('fa-IR')}
              </p>
              <p className="text-sm text-gray-500">کل پیلودها</p>
            </div>
            <div className="p-4 bg-green-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-green-600">
                {safePayloads.toLocaleString('fa-IR')}
              </p>
              <p className="text-sm text-gray-500">امن</p>
            </div>
            <div className="p-4 bg-orange-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-orange-600">
                {aggressivePayloads.toLocaleString('fa-IR')}
              </p>
              <p className="text-sm text-gray-500">تهاجمی</p>
            </div>
            <div className="p-4 bg-blue-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-blue-600">
                {categoriesCount.toLocaleString('fa-IR')}
              </p>
              <p className="text-sm text-gray-500">دسته‌بندی</p>
            </div>
          </div>
        )}
        
        {/* Sync status - in progress */}
        {syncStatus?.is_syncing && (
          <div className="mb-6 p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center gap-3 mb-2">
              <Loader2 className="w-5 h-5 animate-spin text-blue-600" />
              <span className="font-medium text-blue-900">در حال همگام‌سازی...</span>
              <span className="text-sm text-blue-600">({syncStatus.progress || 0}%)</span>
            </div>
            <div className="progress-bar">
              <div
                className="progress-bar-fill transition-all duration-300"
                style={{ width: `${syncStatus.progress || 0}%` }}
              />
            </div>
            <p className="text-sm text-blue-700 mt-2">{syncStatus.message}</p>
          </div>
        )}
        
        {/* Sync status - completed */}
        {!syncStatus?.is_syncing && syncStatus?.progress === 100 && syncStatus?.message?.includes('completed') && (
          <div className="mb-6 p-4 bg-green-50 rounded-lg">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <span className="font-medium text-green-900">{syncStatus.message}</span>
            </div>
          </div>
        )}
        
        {/* Last sync info */}
        {!syncStatus?.is_syncing && (syncStatus?.last_sync || payloadStats?.last_sync) && (
          <div className="mb-6 flex items-center gap-2 text-sm text-gray-500">
            <Clock className="w-4 h-4" />
            <span>
              آخرین همگام‌سازی: {formatDate(syncStatus?.last_sync || payloadStats?.last_sync)}
            </span>
            {syncStatus?.last_error && (
              <span className="text-red-500">({syncStatus.last_error})</span>
            )}
          </div>
        )}
        
        {isAdmin && (
          <button
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending || syncStatus?.is_syncing}
            className="btn-primary"
          >
            {syncMutation.isPending || syncStatus?.is_syncing ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                در حال همگام‌سازی...
              </>
            ) : (
              <>
                <RefreshCw className="w-5 h-5" />
                همگام‌سازی پیلودها
              </>
            )}
          </button>
        )}
      </div>
      
      {/* Scanner Settings */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-green-100 flex items-center justify-center">
            <Shield className="w-5 h-5 text-green-600" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900">تنظیمات اسکنر</h2>
            <p className="text-sm text-gray-500">پیکربندی موتور اسکن</p>
          </div>
        </div>
        
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center gap-3">
              <Zap className="w-5 h-5 text-gray-600" />
              <div>
                <p className="font-medium text-gray-900">حداکثر اسکن همزمان</p>
                <p className="text-sm text-gray-500">تعداد اسکن‌های موازی</p>
              </div>
            </div>
            <span className="text-lg font-semibold text-gray-900">۵</span>
          </div>
          
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center gap-3">
              <Clock className="w-5 h-5 text-gray-600" />
              <div>
                <p className="font-medium text-gray-900">timeout اسکن</p>
                <p className="text-sm text-gray-500">حداکثر زمان هر اسکن</p>
              </div>
            </div>
            <span className="text-lg font-semibold text-gray-900">۶۰ دقیقه</span>
          </div>
          
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center gap-3">
              <HardDrive className="w-5 h-5 text-gray-600" />
              <div>
                <p className="font-medium text-gray-900">مدت نگهداری گزارش</p>
                <p className="text-sm text-gray-500">گزارش‌ها پس از این مدت حذف می‌شوند</p>
              </div>
            </div>
            <span className="text-lg font-semibold text-gray-900">۳۰ روز</span>
          </div>
        </div>
      </div>
      
      {/* System Info */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-purple-100 flex items-center justify-center">
            <Settings className="w-5 h-5 text-purple-600" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900">اطلاعات سیستم</h2>
            <p className="text-sm text-gray-500">نسخه و وضعیت</p>
          </div>
        </div>
        
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-gray-600">نسخه نرم‌افزار</span>
            <span className="font-mono text-gray-900">1.0.0</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-600">استانداردها</span>
            <span className="text-gray-900">OWASP WSTG 4.2, OWASP Top 10 2021</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-600">وضعیت API</span>
            <span className="flex items-center gap-1 text-green-600">
              <CheckCircle className="w-4 h-4" />
              فعال
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}