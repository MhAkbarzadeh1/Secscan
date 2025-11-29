import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Merge Tailwind classes with clsx
 */
export function cn(...inputs) {
  return twMerge(clsx(inputs))
}

/**
 * Format date to Persian locale
 */
export function formatDate(date, options = {}) {
  if (!date) return '-'
  
  const defaultOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    ...options
  }
  
  return new Date(date).toLocaleDateString('fa-IR', defaultOptions)
}

/**
 * Format date and time to Persian locale
 */
export function formatDateTime(date) {
  if (!date) return '-'
  
  return new Date(date).toLocaleString('fa-IR', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

/**
 * Format relative time (e.g., "2 hours ago")
 */
export function formatRelativeTime(date) {
  if (!date) return '-'
  
  const now = new Date()
  const then = new Date(date)
  const diffInSeconds = Math.floor((now - then) / 1000)
  
  if (diffInSeconds < 60) {
    return 'همین الان'
  }
  
  const diffInMinutes = Math.floor(diffInSeconds / 60)
  if (diffInMinutes < 60) {
    return `${diffInMinutes} دقیقه پیش`
  }
  
  const diffInHours = Math.floor(diffInMinutes / 60)
  if (diffInHours < 24) {
    return `${diffInHours} ساعت پیش`
  }
  
  const diffInDays = Math.floor(diffInHours / 24)
  if (diffInDays < 30) {
    return `${diffInDays} روز پیش`
  }
  
  return formatDate(date)
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text, length = 50) {
  if (!text) return ''
  if (text.length <= length) return text
  return text.slice(0, length) + '...'
}

/**
 * Convert English numbers to Persian
 */
export function toPersianNumber(num) {
  if (num === null || num === undefined) return ''
  
  const persianDigits = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹']
  return num.toString().replace(/\d/g, (d) => persianDigits[d])
}

/**
 * Format file size
 */
export function formatFileSize(bytes) {
  if (!bytes) return '0 B'
  
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let size = bytes
  
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024
    i++
  }
  
  return `${size.toFixed(1)} ${units[i]}`
}

/**
 * Debounce function
 */
export function debounce(fn, delay) {
  let timeoutId
  return (...args) => {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => fn(...args), delay)
  }
}

/**
 * Sleep function for delays
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Severity color classes
 */
export const severityColors = {
  critical: {
    bg: 'bg-red-500',
    bgLight: 'bg-red-50',
    text: 'text-red-700',
    border: 'border-red-500'
  },
  high: {
    bg: 'bg-orange-500',
    bgLight: 'bg-orange-50',
    text: 'text-orange-700',
    border: 'border-orange-500'
  },
  medium: {
    bg: 'bg-yellow-500',
    bgLight: 'bg-yellow-50',
    text: 'text-yellow-700',
    border: 'border-yellow-500'
  },
  low: {
    bg: 'bg-green-500',
    bgLight: 'bg-green-50',
    text: 'text-green-700',
    border: 'border-green-500'
  },
  info: {
    bg: 'bg-blue-500',
    bgLight: 'bg-blue-50',
    text: 'text-blue-700',
    border: 'border-blue-500'
  }
}

/**
 * Status color classes
 */
export const statusColors = {
  queued: {
    bg: 'bg-gray-100',
    text: 'text-gray-700'
  },
  running: {
    bg: 'bg-blue-100',
    text: 'text-blue-700'
  },
  completed: {
    bg: 'bg-green-100',
    text: 'text-green-700'
  },
  failed: {
    bg: 'bg-red-100',
    text: 'text-red-700'
  },
  cancelled: {
    bg: 'bg-yellow-100',
    text: 'text-yellow-700'
  }
}

/**
 * Persian labels
 */
export const persianLabels = {
  severity: {
    critical: 'بحرانی',
    high: 'بالا',
    medium: 'متوسط',
    low: 'پایین',
    info: 'اطلاعاتی'
  },
  status: {
    queued: 'در صف',
    running: 'در حال اجرا',
    completed: 'کامل شد',
    failed: 'خطا',
    cancelled: 'لغو شده'
  },
  role: {
    owner: 'مالک',
    admin: 'مدیر',
    user: 'کاربر'
  },
  mode: {
    safe: 'امن',
    aggressive: 'تهاجمی'
  }
}