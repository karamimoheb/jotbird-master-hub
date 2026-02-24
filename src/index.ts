/**
 * JotBird Master Hub Worker
 * ─────────────────────────
 * مرکز هماهنگی برای ایندکس‌کردن نوت‌های عمومی کاربران
 *
 * Endpoints:
 *   POST /api/v1/auth     — دریافت Passport JWT (فقط با MASTER_API_KEY)
 *   POST /api/v1/index    — ذخیره/بروزرسانی نوت در ایندکس (با JWT)
 *   GET  /api/v1/explore  — جستجو و مرور نوت‌های عمومی (بدون احراز هویت)
 *   GET  /api/v1/health   — وضعیت سرویس
 *   DELETE /api/v1/index/:id — حذف نوت از ایندکس (با JWT)
 */

export interface Env {
  DB: D1Database;
  MASTER_API_KEY: string;  // کلید اشتراکی برای handshake اولیه
  JWT_SECRET: string;       // کلید امضای توکن‌ها — هرگز فاش نشود
}

// ─────────────────────────────────────────────
// ROUTER
// ─────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // CORS headers برای دسترسی از پلاگین و مرورگر
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    const reqId = crypto.randomUUID().slice(0, 8);

    const respond = (body: any, status = 200) =>
      Response.json(body, { status, headers: corsHeaders });

    try {
      // ── روت‌ها ──
      if (url.pathname === "/api/v1/health" && request.method === "GET") {
        return respond({ status: "ok", version: "1.1.0", ts: Date.now() });
      }

      if (url.pathname === "/api/v1/auth" && request.method === "POST") {
        return await handleAuthChallenge(request, env, reqId, respond);
      }

      if (url.pathname === "/api/v1/index" && request.method === "POST") {
        return await handleSync(request, env, reqId, respond);
      }

      if (url.pathname === "/api/v1/explore" && request.method === "GET") {
        return await handleExplore(url, env, respond);
      }

      // DELETE /api/v1/index/:owner_id/:slug
      const deleteMatch = url.pathname.match(/^\/api\/v1\/index\/([^/]+)\/([^/]+)$/);
      if (deleteMatch && request.method === "DELETE") {
        return await handleDelete(request, env, deleteMatch[1], deleteMatch[2], respond);
      }

      return respond({ error: "Not Found" }, 404);

    } catch (err: any) {
      console.error(`[${reqId}] Unhandled error:`, err.message);
      return respond({ error: "Internal Server Error" }, 500);
    }
  },
};

// ─────────────────────────────────────────────
// PASSPORT SYSTEM
// ─────────────────────────────────────────────

/**
 * مرحله ۱ — Handshake:
 * User Worker با MASTER_API_KEY درخواست می‌دهد و یک JWT 7-روزه می‌گیرد.
 * این JWT در D1 ورکر کاربر ذخیره می‌شود و برای sync بعدی استفاده می‌شود.
 */
async function handleAuthChallenge(
  request: Request,
  env: Env,
  reqId: string,
  respond: Function
) {
  // بررسی کلید اشتراکی
  const auth = request.headers.get("Authorization") ?? "";
  if (auth !== `Bearer ${env.MASTER_API_KEY}`) {
    console.warn(`[${reqId}] Auth challenge rejected — invalid MASTER_API_KEY`);
    return respond({ error: "Unauthorized Handshake" }, 401);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return respond({ error: "Invalid JSON body" }, 400);
  }

  const { worker_url, owner_id } = body;

  if (!worker_url || !owner_id) {
    return respond({ error: "Missing fields: worker_url, owner_id" }, 400);
  }

  // اعتبارسنجی فرمت URL
  try {
    new URL(worker_url);
  } catch {
    return respond({ error: "Invalid worker_url format" }, 400);
  }

  // اعتبارسنجی owner_id (فقط حروف، اعداد، خط تیره، آندرلاین)
  if (!/^[a-zA-Z0-9_-]{3,50}$/.test(owner_id)) {
    return respond({ error: "owner_id must be 3-50 alphanumeric chars" }, 400);
  }

  // صدور توکن ۷ روزه
  const exp = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
  const payload: JWTPayload = {
    sub: owner_id,
    aud: worker_url,
    iat: Math.floor(Date.now() / 1000),
    exp,
  };

  const token = await signJWT(payload, env.JWT_SECRET);

  console.log(`[${reqId}] Passport issued → owner: ${owner_id}, worker: ${worker_url}`);

  return respond({
    token,
    expires_in: 7 * 24 * 60 * 60,
    expires_at: new Date(exp * 1000).toISOString(),
  });
}

// ─────────────────────────────────────────────
// SYNC HANDLER
// ─────────────────────────────────────────────

async function handleSync(
  request: Request,
  env: Env,
  reqId: string,
  respond: Function
) {
  // تأیید JWT
  const payload = await verifyRequestJWT(request, env.JWT_SECRET);
  if (!payload) {
    return respond({ error: "Invalid or Expired Token" }, 401);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return respond({ error: "Invalid JSON body" }, 400);
  }

  const { slug, owner_id, title, tags, folder, url, updatedAt } = body;

  // فیلدهای اجباری
  if (!slug || !owner_id || !title || !url) {
    return respond({ error: "Missing required fields: slug, owner_id, title, url" }, 400);
  }

  // بررسی امنیتی: URL باید با audience توکن مطابقت داشته باشد
  // این مانع می‌شود کاربری با توکن دیگری نوت ارسال کند
  if (!url.startsWith(payload.aud)) {
    console.warn(`[${reqId}] Token Hijack attempt: url=${url}, aud=${payload.aud}`);
    return respond({ error: "Token Hijack Prevented: URL mismatch" }, 403);
  }

  // بررسی امنیتی: owner_id باید با subject توکن مطابقت داشته باشد
  if (owner_id !== payload.sub) {
    console.warn(`[${reqId}] Token Hijack attempt: owner=${owner_id}, sub=${payload.sub}`);
    return respond({ error: "Token Hijack Prevented: Owner mismatch" }, 403);
  }

  const globalId = `${owner_id}:${slug}`;
  const tagsString = JSON.stringify(Array.isArray(tags) ? tags : []);
  const now = updatedAt || Date.now();

  await env.DB.prepare(`
    INSERT INTO global_notes (id, owner_id, slug, title, tags, folder, note_url, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      title      = excluded.title,
      tags       = excluded.tags,
      folder     = excluded.folder,
      note_url   = excluded.note_url,
      updated_at = excluded.updated_at
  `).bind(globalId, owner_id, slug, title, tagsString, folder ?? "", url, now).run();

  console.log(`[${reqId}] Synced: ${globalId}`);
  return respond({ success: true, globalId });
}

// ─────────────────────────────────────────────
// DELETE HANDLER
// ─────────────────────────────────────────────

async function handleDelete(
  request: Request,
  env: Env,
  owner_id: string,
  slug: string,
  respond: Function
) {
  const payload = await verifyRequestJWT(request, env.JWT_SECRET);
  if (!payload) {
    return respond({ error: "Invalid or Expired Token" }, 401);
  }

  // فقط صاحب نوت می‌تواند حذف کند
  if (owner_id !== payload.sub) {
    return respond({ error: "Forbidden" }, 403);
  }

  const globalId = `${owner_id}:${slug}`;
  await env.DB.prepare("DELETE FROM global_notes WHERE id = ?").bind(globalId).run();

  return respond({ success: true, deleted: globalId });
}

// ─────────────────────────────────────────────
// EXPLORE HANDLER (عمومی — بدون احراز هویت)
// ─────────────────────────────────────────────

async function handleExplore(url: URL, env: Env, respond: Function) {
  const search = url.searchParams.get("q") ?? "";
  const owner = url.searchParams.get("owner") ?? "";
  const page = Math.max(1, parseInt(url.searchParams.get("page") ?? "1"));
  const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20")));
  const offset = (page - 1) * limit;

  let query: string;
  let params: any[];

  if (search && owner) {
    query = `SELECT * FROM global_notes WHERE owner_id = ? AND (title LIKE ? OR tags LIKE ?)
             ORDER BY updated_at DESC LIMIT ? OFFSET ?`;
    params = [owner, `%${search}%`, `%${search}%`, limit, offset];
  } else if (search) {
    query = `SELECT * FROM global_notes WHERE title LIKE ? OR tags LIKE ?
             ORDER BY updated_at DESC LIMIT ? OFFSET ?`;
    params = [`%${search}%`, `%${search}%`, limit, offset];
  } else if (owner) {
    query = `SELECT * FROM global_notes WHERE owner_id = ?
             ORDER BY updated_at DESC LIMIT ? OFFSET ?`;
    params = [owner, limit, offset];
  } else {
    query = `SELECT * FROM global_notes ORDER BY updated_at DESC LIMIT ? OFFSET ?`;
    params = [limit, offset];
  }

  const { results } = await env.DB.prepare(query).bind(...params).all();

  return respond({
    results: results.map((r: any) => ({
      ...r,
      tags: safeJsonParse(r.tags as string, []),
    })),
    page,
    limit,
  });
}

// ─────────────────────────────────────────────
// JWT UTILITIES — Native Web Crypto (بدون کتابخانه)
// ─────────────────────────────────────────────

interface JWTPayload {
  sub: string;   // owner_id
  aud: string;   // worker_url
  iat: number;   // issued at (unix timestamp)
  exp: number;   // expiry (unix timestamp)
}

/**
 * Base64URL encode — سازگار با Unicode
 */
function base64urlEncode(str: string): string {
  // TextEncoder برای سازگاری با Unicode
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlDecode(str: string): string {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4;
  const base64 = pad ? padded + "=".repeat(4 - pad) : padded;
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function getHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

export async function signJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header = base64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64urlEncode(JSON.stringify(payload));
  const data = `${header}.${body}`;

  const key = await getHmacKey(secret);
  const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));

  const sigBytes = new Uint8Array(sigBuffer);
  let sigBinary = "";
  sigBytes.forEach(b => sigBinary += String.fromCharCode(b));
  const signature = btoa(sigBinary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  return `${data}.${signature}`;
}

/**
 * تأیید امضای JWT با مقایسه بیتی امن (timing-safe)
 * برگرداندن payload در صورت معتبر بودن، در غیر این صورت null
 */
export async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const data = `${headerB64}.${payloadB64}`;

    // بازسازی امضای مورد انتظار
    const key = await getHmacKey(secret);
    const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));

    // تبدیل امضای دریافتی به ArrayBuffer
    const receivedSigPadded = signatureB64.replace(/-/g, "+").replace(/_/g, "/");
    const pad = receivedSigPadded.length % 4;
    const receivedSigBase64 = pad ? receivedSigPadded + "=".repeat(4 - pad) : receivedSigPadded;
    const receivedSigBinary = atob(receivedSigBase64);
    const receivedSigBytes = Uint8Array.from(receivedSigBinary, c => c.charCodeAt(0));

    // مقایسه timing-safe با crypto.subtle.verify
    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      receivedSigBytes.buffer,
      new TextEncoder().encode(data)
    );

    if (!isValid) return null;

    const payload = JSON.parse(base64urlDecode(payloadB64)) as JWTPayload;

    // بررسی انقضا
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch (err) {
    console.error("JWT verify error:", err);
    return null;
  }
}

async function verifyRequestJWT(request: Request, secret: string): Promise<JWTPayload | null> {
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return null;
  return verifyJWT(auth.slice(7), secret);
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function safeJsonParse(str: string, fallback: any = null) {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}
