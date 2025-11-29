# 🛡️ OWASP Security Scanner

اسکنر امنیتی وب‌سایت بر اساس استانداردهای **OWASP WSTG** و **OWASP Top 10**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/react-18+-blue.svg)](https://reactjs.org)

---

## ✨ ویژگی‌ها

- 🔍 **اسکن جامع امنیتی** - بر اساس OWASP WSTG 4.2
- 🎯 **تشخیص آسیب‌پذیری** - SQLi, XSS, CSRF, و بیش از 100 نوع دیگر
- 📊 **گزارش فارسی** - گزارش‌های PDF/HTML با توضیحات فارسی
- 🔐 **تأیید مالکیت دامنه** - DNS TXT یا File verification
- ⚡ **دو حالت اسکن** - Safe (امن) و Aggressive (تهاجمی)
- 🤖 **۱۰۰۰+ پیلود** - از PayloadsAllTheThings
- 👥 **RBAC** - سیستم نقش‌ها (Owner, Admin, User)
- 📱 **رابط کاربری RTL** - طراحی فارسی با Tailwind CSS

---

## 🚀 راه‌اندازی سریع

### پیش‌نیازها

- Docker و Docker Compose
- یا: Python 3.11+, Node.js 20+, MongoDB, Redis

### با Docker (توصیه شده)

```bash
# کلون پروژه
git clone https://github.com/your-repo/owasp-scanner.git
cd owasp-scanner

# کپی فایل تنظیمات
cp backend/.env.example backend/.env
# ویرایش .env و تنظیم SECRET_KEY و JWT_SECRET_KEY

# اجرا
docker-compose up -d

# مشاهده لاگ‌ها
docker-compose logs -f
```

سپس به آدرس‌های زیر بروید:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

### بدون Docker

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend (در ترمینال جدید)
cd frontend
npm install
npm run dev
```

---

## 📖 مستندات

### ساختار پروژه

```
owaspscanner/
├── backend/                 # FastAPI Backend
│   ├── app/
│   │   ├── api/routes/     # API endpoints
│   │   ├── core/           # Config, DB, Security
│   │   ├── models/         # Pydantic schemas
│   │   ├── services/       # Business logic
│   │   └── workers/        # Background jobs
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/               # React + Vite Frontend
│   ├── src/
│   │   ├── components/     # UI components
│   │   ├── pages/          # Route pages
│   │   ├── hooks/          # Custom hooks
│   │   ├── services/       # API calls
│   │   └── utils/          # Helpers
│   ├── Dockerfile
│   └── package.json
│
├── docker/                 # Docker configs
├── docker-compose.yml
└── README.md
```

### API Endpoints

| Method | Endpoint | توضیحات |
|--------|----------|---------|
| POST | `/api/auth/register` | ثبت‌نام |
| POST | `/api/auth/login` | ورود |
| GET | `/api/projects` | لیست پروژه‌ها |
| POST | `/api/projects` | ایجاد پروژه |
| POST | `/api/verification/{id}/initiate` | شروع تأیید دامنه |
| POST | `/api/scans` | شروع اسکن |
| GET | `/api/findings` | لیست یافته‌ها |
| POST | `/api/reports/generate` | تولید گزارش |

مستندات کامل: http://localhost:8000/docs

---

## 🔧 تنظیمات

### متغیرهای محیطی (`.env`)

```env
# Security (حتماً تغییر دهید!)
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Database
MONGODB_URL=mongodb://localhost:27017
MONGODB_DB_NAME=owasp_scanner

# Redis
REDIS_URL=redis://localhost:6379/0

# Scanner
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT_SECONDS=3600
```

---

## 🧪 دسته‌های تست (WSTG)

| کد | دسته | تعداد تست |
|----|------|-----------|
| INFO | جمع‌آوری اطلاعات | 10 |
| CONF | تنظیمات | 11 |
| IDNT | مدیریت هویت | 5 |
| ATHN | احراز هویت | 10 |
| ATHZ | مجوزدهی | 4 |
| SESS | مدیریت Session | 9 |
| INPV | اعتبارسنجی ورودی | 19 |
| ERRH | مدیریت خطا | 2 |
| CRYP | رمزنگاری | 4 |
| BUSL | منطق کسب‌وکار | 9 |
| CLNT | سمت کلاینت | 13 |

---

## ⚠️ هشدار قانونی

> **توجه**: این ابزار فقط برای تست سیستم‌های **تحت مالکیت شما** یا با **مجوز کتبی** طراحی شده است.
> استفاده غیرمجاز از این ابزار ممکن است جرم محسوب شود.

---

## 🤝 مشارکت

1. Fork کنید
2. Branch بسازید (`git checkout -b feature/amazing`)
3. Commit کنید (`git commit -m 'Add amazing feature'`)
4. Push کنید (`git push origin feature/amazing`)
5. Pull Request بزنید

---

## 📄 لایسنس

MIT License - برای جزئیات فایل [LICENSE](LICENSE) را ببینید.

---

## 🙏 تشکر

- [OWASP](https://owasp.org) - برای استانداردها
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - برای پیلودها
- [FastAPI](https://fastapi.tiangolo.com) - فریم‌ورک بک‌اند
- [React](https://reactjs.org) - فریم‌ورک فرانت‌اند