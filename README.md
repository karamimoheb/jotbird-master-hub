# 🐦 JotBird Master Hub

مرکز هماهنگی برای ایندکس‌کردن نوت‌های عمومی کاربران JotBird.

---

## 🗺️ معماری سیستم

```
[Obsidian Plugin]
      │
      │  Bearer API_KEY
      ▼
[User Worker (D1)]  ──── Bearer JWT ────►  [Master Hub (D1)]
      │                                          │
      │  /p/:slug                                │  /api/v1/explore
      ▼                                          ▼
 [HTML Page]                              [Public Index]
```

---

## 🔐 سیستم توکن — توضیح ساده

سه «کلید» در این سیستم وجود دارد:

| کلید | کجا تنظیم می‌شود | برای چیست |
|------|-----------------|-----------|
| `API_KEY` | User Worker → Env Vars | پلاگین ابسیدین با این کلید به **ورکر خودتان** وصل می‌شود |
| `MASTER_API_KEY` | **هر دو** Worker → Env Vars | ورکر کاربر با این کلید از Hub درخواست **JWT می‌گیرد** |
| `JWT_SECRET` | Master Hub → Env Vars | Hub با این کلید JWT امضا می‌کند (**فقط Hub می‌داند**) |

### چرخه حیات JWT (Passport):

```
1. اولین بار:
   User Worker ──[MASTER_API_KEY]──► Hub: "بده JWT بهم"
   Hub ──[JWT_SECRET امضا می‌کند]──► User Worker: "بفرما JWT 7 روزه"
   User Worker JWT را در D1 خودش ذخیره می‌کند

2. هر بار sync:
   User Worker ──[JWT]──► Hub: "این نوت را ایندکس کن"
   Hub JWT را verify می‌کند (بدون query به DB) ✓

3. JWT منقضی شد (7 روز):
   Hub با 401 رد می‌کند
   User Worker دوباره از مرحله ۱ شروع می‌کند (auto-retry)
```

**مزیت:** Hub هیچ اطلاعاتی از کاربران در خودش ذخیره نمی‌کند.
هر بار که JWT دریافت می‌شود، با JWT_SECRET verify می‌شود — بدون query به DB.
این باعث صرفه‌جویی در سقف D1 رایگان (۵ میلیون read در روز) می‌شود.

---

## 🚀 راهنمای استقرار (گام به گام)

### پیش‌نیاز
- حساب Cloudflare (رایگان)
- حساب GitHub
- Node.js 18+

---

### گام ۱ — Fork یا Clone ریپو

```bash
git clone https://github.com/YOUR_USERNAME/jotbird-master-hub.git
cd jotbird-master-hub
npm install
```

---

### گام ۲ — ساخت D1 Database در Cloudflare

```bash
# لاگین به Cloudflare
npx wrangler login

# ساخت دیتابیس
npx wrangler d1 create jotbird_hub_db

# خروجی چیزی شبیه این است:
# ✅ Successfully created DB 'jotbird_hub_db'
# database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**database_id** را کپی کنید و در `wrangler.jsonc` جایگزین `REPLACE_WITH_YOUR_D1_DATABASE_ID` کنید:

```jsonc
"d1_databases": [
  {
    "binding": "DB",
    "database_name": "jotbird_hub_db",
    "database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  // ← اینجا
  }
]
```

---

### گام ۳ — ساخت جدول دیتابیس

```bash
npm run db:init
```

---

### گام ۴ — تنظیم Secret ها

```bash
# کلید اشتراکی با ورکر کاربر (هر رشته تصادفی پیچیده)
npx wrangler secret put MASTER_API_KEY
# ← یک رشته تصادفی مثل: mk_a8f3k2p9x7q1m5n4 وارد کنید

# کلید امضای JWT (طولانی‌تر و پیچیده‌تر)
npx wrangler secret put JWT_SECRET
# ← یک رشته تصادفی طولانی مثل: jwt_9f2k8p3x1m7q5n4r6t0y2w8e4u6i0o3a5s7d9f1g3h5j7k9l وارد کنید
```

> 💡 برای ساخت رشته تصادفی: `openssl rand -hex 32`

---

### گام ۵ — استقرار دستی (اولین بار)

```bash
npx wrangler deploy
```

آدرس Worker شما نمایش داده می‌شود: `https://jotbird-master-hub.YOUR_SUBDOMAIN.workers.dev`

---

### گام ۶ — تنظیم GitHub Actions برای auto-deploy

#### الف) ساخت API Token در Cloudflare:
1. به [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) بروید
2. روی **Create Token** کلیک کنید
3. از template **Edit Cloudflare Workers** استفاده کنید
4. توکن ایجادشده را کپی کنید

#### ب) اضافه کردن به GitHub Secrets:
1. در GitHub ریپو خود → **Settings → Secrets and variables → Actions**
2. روی **New repository secret** کلیک کنید
3. نام: `CLOUDFLARE_API_TOKEN`، مقدار: توکن Cloudflare

#### ج) حالا هر بار push به main، خودکار deploy می‌شود! ✅

---

### گام ۷ — تنظیم User Worker

در تنظیمات Environment Variables ورکر کاربر:

```
MASTER_WORKER_URL  = https://jotbird-master-hub.YOUR_SUBDOMAIN.workers.dev
MASTER_API_KEY     = [همان مقداری که در گام ۴ برای Hub تنظیم کردید]
```

---

## 📡 API Reference

### `POST /api/v1/auth`
دریافت JWT (فقط برای User Worker)

```http
Authorization: Bearer {MASTER_API_KEY}
Content-Type: application/json

{
  "worker_url": "https://my-worker.workers.dev",
  "owner_id": "myusername"
}
```

پاسخ:
```json
{
  "token": "eyJ...",
  "expires_in": 604800,
  "expires_at": "2025-03-03T..."
}
```

---

### `POST /api/v1/index`
ایندکس کردن نوت (فقط با JWT)

```http
Authorization: Bearer {JWT}
Content-Type: application/json

{
  "slug": "my-note",
  "owner_id": "myusername",
  "title": "عنوان نوت",
  "tags": ["tech", "ideas"],
  "folder": "Blog",
  "url": "https://my-worker.workers.dev/p/my-note",
  "updatedAt": 1709123456789
}
```

---

### `DELETE /api/v1/index/:owner_id/:slug`
حذف نوت از ایندکس

```http
Authorization: Bearer {JWT}
```

---

### `GET /api/v1/explore`
جستجو در نوت‌های عمومی (بدون احراز هویت)

```
?q=keyword        — جستجوی متنی
?owner=username   — فیلتر بر اساس کاربر
?page=1           — شماره صفحه
?limit=20         — تعداد نتایج (حداکثر ۵۰)
```

---

### `GET /api/v1/health`
بررسی وضعیت سرویس

---

## 🛠️ دستورات مفید

```bash
# مشاهده لاگ‌های لایو
npm run logs

# اجرای local برای توسعه
npm run dev

# استقرار دستی
npm run deploy

# بررسی type errors
npm run type-check
```
