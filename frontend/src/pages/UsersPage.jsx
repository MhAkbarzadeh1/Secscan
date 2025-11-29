import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiService } from '../services/api'
import { useAuthStore } from '../hooks/useAuthStore'
import {
  Users,
  Search,
  MoreVertical,
  Shield,
  UserCheck,
  UserX,
  Trash2,
  Crown,
  User,
  AlertTriangle,
  Loader2
} from 'lucide-react'
import toast from 'react-hot-toast'

const roleLabels = {
  owner: { label: 'مالک', icon: Crown, color: 'bg-purple-100 text-purple-700' },
  admin: { label: 'مدیر', icon: Shield, color: 'bg-blue-100 text-blue-700' },
  user: { label: 'کاربر', icon: User, color: 'bg-gray-100 text-gray-700' },
}

export default function UsersPage() {
  const { user: currentUser, hasRole } = useAuthStore()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [openMenu, setOpenMenu] = useState(null)
  
  const isOwner = hasRole(['owner'])
  
  // Fetch users
  const { data, isLoading, error } = useQuery({
    queryKey: ['users', search],
    queryFn: () => apiService.getUsers({ search, limit: 50 }),
  })
  
  // Update role mutation
  const updateRoleMutation = useMutation({
    mutationFn: ({ userId, role }) => apiService.updateUserRole(userId, role),
    onSuccess: () => {
      toast.success('نقش کاربر تغییر کرد')
      queryClient.invalidateQueries(['users'])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در تغییر نقش')
    }
  })
  
  // Toggle status mutation
  const toggleStatusMutation = useMutation({
    mutationFn: ({ userId, isActive }) => apiService.toggleUserStatus(userId, isActive),
    onSuccess: () => {
      toast.success('وضعیت کاربر تغییر کرد')
      queryClient.invalidateQueries(['users'])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در تغییر وضعیت')
    }
  })
  
  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (userId) => apiService.deleteUser(userId),
    onSuccess: () => {
      toast.success('کاربر حذف شد')
      queryClient.invalidateQueries(['users'])
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'خطا در حذف کاربر')
    }
  })
  
  const users = data?.data?.items || []
  
  const handleRoleChange = (userId, newRole) => {
    updateRoleMutation.mutate({ userId, role: newRole })
    setOpenMenu(null)
  }
  
  const handleToggleStatus = (userId, currentStatus) => {
    toggleStatusMutation.mutate({ userId, isActive: !currentStatus })
    setOpenMenu(null)
  }
  
  const handleDelete = (userId, username) => {
    if (confirm(`آیا از حذف کاربر "${username}" اطمینان دارید؟`)) {
      deleteMutation.mutate(userId)
    }
    setOpenMenu(null)
  }
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">مدیریت کاربران</h1>
        <p className="text-gray-500 mt-1">مشاهده و مدیریت کاربران سیستم</p>
      </div>
      
      {/* Search */}
      <div className="relative">
        <Search className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
        <input
          type="text"
          placeholder="جستجوی کاربر..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input pr-10"
        />
      </div>
      
      {/* Users table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
            <p className="text-gray-600">خطا در دریافت کاربران</p>
          </div>
        ) : users.length === 0 ? (
          <div className="text-center py-12">
            <Users className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600">کاربری یافت نشد</p>
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>کاربر</th>
                <th>ایمیل</th>
                <th>نقش</th>
                <th>وضعیت</th>
                <th>تاریخ عضویت</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const roleConfig = roleLabels[user.role] || roleLabels.user
                const RoleIcon = roleConfig.icon
                const isCurrentUser = user._id === currentUser?._id
                const canModify = isOwner && !isCurrentUser && user.role !== 'owner'
                
                return (
                  <tr key={user._id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center">
                          <User className="w-5 h-5 text-primary-600" />
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">
                            {user.full_name || user.username}
                            {isCurrentUser && (
                              <span className="mr-2 text-xs text-gray-500">(شما)</span>
                            )}
                          </p>
                          <p className="text-sm text-gray-500">@{user.username}</p>
                        </div>
                      </div>
                    </td>
                    <td className="text-gray-600">{user.email}</td>
                    <td>
                      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${roleConfig.color}`}>
                        <RoleIcon className="w-3.5 h-3.5" />
                        {roleConfig.label}
                      </span>
                    </td>
                    <td>
                      {user.is_active ? (
                        <span className="inline-flex items-center gap-1 text-green-600">
                          <UserCheck className="w-4 h-4" />
                          فعال
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-red-600">
                          <UserX className="w-4 h-4" />
                          غیرفعال
                        </span>
                      )}
                    </td>
                    <td className="text-gray-500">
                      {new Date(user.created_at).toLocaleDateString('fa-IR')}
                    </td>
                    <td>
                      {canModify && (
                        <div className="relative">
                          <button
                            onClick={() => setOpenMenu(openMenu === user._id ? null : user._id)}
                            className="p-2 rounded hover:bg-gray-100"
                          >
                            <MoreVertical className="w-5 h-5 text-gray-400" />
                          </button>
                          
                          {openMenu === user._id && (
                            <>
                              <div
                                className="fixed inset-0 z-10"
                                onClick={() => setOpenMenu(null)}
                              />
                              <div className="absolute left-0 mt-1 w-48 bg-white rounded-lg shadow-lg border border-gray-200 z-20">
                                {/* Role change */}
                                <div className="p-2 border-b border-gray-100">
                                  <p className="px-2 py-1 text-xs text-gray-500 font-medium">تغییر نقش</p>
                                  {user.role !== 'admin' && (
                                    <button
                                      onClick={() => handleRoleChange(user._id, 'admin')}
                                      className="w-full flex items-center gap-2 px-2 py-1.5 text-sm text-gray-700 hover:bg-gray-50 rounded"
                                    >
                                      <Shield className="w-4 h-4" />
                                      ارتقا به مدیر
                                    </button>
                                  )}
                                  {user.role !== 'user' && (
                                    <button
                                      onClick={() => handleRoleChange(user._id, 'user')}
                                      className="w-full flex items-center gap-2 px-2 py-1.5 text-sm text-gray-700 hover:bg-gray-50 rounded"
                                    >
                                      <User className="w-4 h-4" />
                                      تنزل به کاربر
                                    </button>
                                  )}
                                </div>
                                
                                {/* Status toggle */}
                                <div className="p-2 border-b border-gray-100">
                                  <button
                                    onClick={() => handleToggleStatus(user._id, user.is_active)}
                                    className="w-full flex items-center gap-2 px-2 py-1.5 text-sm text-gray-700 hover:bg-gray-50 rounded"
                                  >
                                    {user.is_active ? (
                                      <>
                                        <UserX className="w-4 h-4" />
                                        غیرفعال کردن
                                      </>
                                    ) : (
                                      <>
                                        <UserCheck className="w-4 h-4" />
                                        فعال کردن
                                      </>
                                    )}
                                  </button>
                                </div>
                                
                                {/* Delete */}
                                <div className="p-2">
                                  <button
                                    onClick={() => handleDelete(user._id, user.username)}
                                    className="w-full flex items-center gap-2 px-2 py-1.5 text-sm text-red-600 hover:bg-red-50 rounded"
                                  >
                                    <Trash2 className="w-4 h-4" />
                                    حذف کاربر
                                  </button>
                                </div>
                              </div>
                            </>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}