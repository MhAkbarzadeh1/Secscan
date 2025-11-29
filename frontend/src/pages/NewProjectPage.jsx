import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { apiService } from '../services/api'
import { ArrowRight, Globe, Info, Loader2 } from 'lucide-react'
import toast from 'react-hot-toast'

const projectSchema = z.object({
  name: z.string().min(3, 'نام باید حداقل ۳ کاراکتر باشد').max(100),
  domain: z.string()
    .min(1, 'دامنه الزامی است')
    .regex(
      /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
      'فرمت دامنه صحیح نیست (مثال: example.com)'
    ),
  description: z.string().max(500).optional(),
})

export default function NewProjectPage() {
  const navigate = useNavigate()
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    watch
  } = useForm({
    resolver: zodResolver(projectSchema),
    defaultValues: {
      name: '',
      domain: '',
      description: ''
    }
  })
  
  const domain = watch('domain')
  
  const createMutation = useMutation({
    mutationFn: (data) => apiService.createProject(data),
    onSuccess: (response) => {
      toast.success('پروژه با موفقیت ایجاد شد')
      navigate(`/projects/${response.data._id}`)
    },
    onError: (error) => {
      toast.error(error.response?.data?.detail || 'خطا در ایجاد پروژه')
    }
  })
  
  const onSubmit = (data) => {
    createMutation.mutate(data)
  }
  
  return (
    <div className="max-w-2xl mx-auto">
      {/* Back button */}
      <button
        onClick={() => navigate('/projects')}
        className="flex items-center gap-2 text-gray-600 hover:text-gray-900 mb-6"
      >
        <ArrowRight className="w-5 h-5" />
        بازگشت به پروژه‌ها
      </button>
      
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center">
            <Globe className="w-6 h-6 text-primary-600" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">پروژه جدید</h1>
            <p className="text-gray-500">اطلاعات وب‌سایت مورد نظر را وارد کنید</p>
          </div>
        </div>
        
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          {/* Name */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              نام پروژه
            </label>
            <input
              type="text"
              {...register('name')}
              placeholder="مثال: وب‌سایت شرکت"
              className={`input ${errors.name ? 'input-error' : ''}`}
            />
            {errors.name && (
              <p className="mt-1 text-sm text-red-500">{errors.name.message}</p>
            )}
          </div>
          
          {/* Domain */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              دامنه
            </label>
            <div className="relative">
              <input
                type="text"
                {...register('domain')}
                placeholder="example.com"
                className={`input pl-24 ${errors.domain ? 'input-error' : ''}`}
                dir="ltr"
              />
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm">
                https://
              </span>
            </div>
            {errors.domain && (
              <p className="mt-1 text-sm text-red-500">{errors.domain.message}</p>
            )}
            {domain && !errors.domain && (
              <p className="mt-1 text-sm text-gray-500">
                آدرس کامل: https://{domain}
              </p>
            )}
          </div>
          
          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              توضیحات (اختیاری)
            </label>
            <textarea
              {...register('description')}
              rows={3}
              placeholder="توضیحات درباره پروژه..."
              className={`input ${errors.description ? 'input-error' : ''}`}
            />
            {errors.description && (
              <p className="mt-1 text-sm text-red-500">{errors.description.message}</p>
            )}
          </div>
          
          {/* Info box */}
          <div className="flex items-start gap-3 p-4 bg-blue-50 rounded-lg">
            <Info className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-blue-800">
              <p className="font-medium mb-1">توجه:</p>
              <ul className="list-disc list-inside space-y-1 text-blue-700">
                <li>پس از ایجاد پروژه، باید مالکیت دامنه را تأیید کنید</li>
                <li>اسکن فقط روی دامنه‌های تأیید شده امکان‌پذیر است</li>
                <li>از قانونی بودن اسکن دامنه مطمئن شوید</li>
              </ul>
            </div>
          </div>
          
          {/* Submit */}
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="btn-primary flex-1"
            >
              {createMutation.isPending ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  در حال ایجاد...
                </>
              ) : (
                'ایجاد پروژه'
              )}
            </button>
            <button
              type="button"
              onClick={() => navigate('/projects')}
              className="btn-secondary"
            >
              انصراف
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}