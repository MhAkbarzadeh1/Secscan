import { useState } from 'react'
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
  AlertTriangle,
  Loader2,
  HardDrive,
  Zap
} from 'lucide-react'
import toast from 'react-hot-toast'

export default function SettingsPage() {
  const { hasRole } = useAuthStore()
  const queryClient = useQueryClient()
  const isAdmin = hasRole(['owner', 'admin'])
  
  // Fetch payload stats
  const { data: payloadStats, isLoading: loadingStats } = useQuery({
    queryKey: ['payload-stats'],
    queryFn: () => apiService.getPayloadStats(),
    select: (res) => res.data
  })
  
  // Fetch sync status
  const { data: syncStatus } = useQuery({
    queryKey: ['sync-status'],
    queryFn: () => apiService.getSyncStatus(),
    select: (res) => res.data,
    refetchInterval: (data) => data?.is_syncing ? 2000 : false
  })
  
  // Sync payloads mutation
  const syncMutation = useMutation({
    mutationFn: () => apiService.syncPayloads(),
    onSuccess: () => {
      toast.success('همگام‌سازی شروع شد')
      queryClient.invalidateQueries(['sync-status'])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در شروع همگام‌سازی')
    }
  })
  
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
                {payloadStats?.total || 0}
              </p>
              <p className="text-sm text-gray-500">کل پیلودها</p>
            </div>
            <div className="p-4 bg-green-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-green-600">
                {payloadStats?.safe || 0}
              </p>
              <p className="text-sm text-gray-500">امن</p>
            </div>
            <div className="p-4 bg-orange-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-orange-600">
                {payloadStats?.aggressive || 0}
              </p>
              <p className="text-sm text-gray-500">تهاجمی</p>
            </div>
            <div className="p-4 bg-blue-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-blue-600">
                {payloadStats?.categories || 0}
              </p>
              <p className="text-sm text-gray-500">دسته‌بندی</p>
            </div>
          </div>
        )}
        
        {/* Sync status */}
        {syncStatus?.is_syncing && (
          <div className="mb-6 p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center gap-3 mb-2">
              <Loader2 className="w-5 h-5 animate-spin text-blue-600" />
              <span className="font-medium text-blue-900">در حال همگام‌سازی...</span>
            </div>
            <div className="progress-bar">
              <div
                className="progress-bar-fill"
                style={{ width: `${syncStatus.progress || 0}%` }}
              />
            </div>
            <p className="text-sm text-blue-700 mt-2">{syncStatus.message}</p>
          </div>
        )}
        
        {syncStatus?.last_sync && !syncStatus?.is_syncing && (
          <div className="mb-6 flex items-center gap-2 text-sm text-gray-500">
            <Clock className="w-4 h-4" />
            <span>
              آخرین همگام‌سازی: {new Date(syncStatus.last_sync).toLocaleString('fa-IR')}
            </span>
            {syncStatus.last_error && (
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
            <span className="text-lg font-semibold text-gray-900">5</span>
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