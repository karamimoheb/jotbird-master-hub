-- JotBird Master Hub — Database Schema
-- اجرای این فایل برای اولین بار:
--   wrangler d1 execute jotbird_hub_db --file=schema.sql --remote

CREATE TABLE IF NOT EXISTS global_notes (
  id         TEXT PRIMARY KEY,          -- ترکیب owner_id:slug
  owner_id   TEXT NOT NULL,             -- شناسه منحصربفرد کاربر
  slug       TEXT NOT NULL,             -- آدرس نوت
  title      TEXT NOT NULL,
  tags       TEXT DEFAULT '[]',         -- JSON array
  folder     TEXT DEFAULT '',
  note_url   TEXT NOT NULL,             -- آدرس کامل نوت در ورکر کاربر
  updated_at INTEGER NOT NULL           -- Unix timestamp (ms)
);

-- ایندکس‌ها برای بهبود سرعت جستجو
CREATE INDEX IF NOT EXISTS idx_owner    ON global_notes (owner_id);
CREATE INDEX IF NOT EXISTS idx_updated  ON global_notes (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_title    ON global_notes (title);
