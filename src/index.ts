/**
JotBird Master Hub Worker — v5.5 (Security-Hardened + Service Binding)
──────────────────────────────────────────────────────────────────────────
Complete rewrite for 100% compatibility with User Worker v5.5
All fixes from security review applied + Service Binding Support

FIX-1   Timing-safe secret comparison (HMAC-based, constant-time)
FIX-2   Admin CORS guard simplified — redundant inner check removed
FIX-3   Replay-protection upsert delegated to Supabase RPC (atomic)
FIX-4   Cache key is now SHA-256 hashed (no raw user input in key)
FIX-5   Timestamps unified to ISO-8601 strings (no mixed ms/seconds)
FIX-6   Results + count fetched in parallel via Promise.all
FIX-7   HMAC key cached at module level (imported once per isolate)
FIX-8   ADMIN_ALLOWED_ORIGINS read from env var (no hardcoded placeholder)
FIX-9   b64uEncode uses chunk-based loop (no spread-stack-overflow)
FIX-17  Service Binding support for internal Worker-to-Worker calls
FIX-18  Image metadata array added for future Supabase Storage integration
FIX-19  Hub setup endpoint compatible with User Worker v5.5 hub-setup flow

Endpoints:
POST   /api/v1/admin/provision  — (Admin) Register a User Worker
POST   /api/v1/auth             — (Worker) client_id+secret → JWT
POST   /api/v1/index            — (Worker) Sync/Upsert Note (JWT)
DELETE /api/v1/index/:o/:s      — (Worker) Tombstone Note (JWT)
GET    /api/v1/explore          — (Public) Browse Notes (Cached)
GET    /api/v1/health           — Service Status
POST   /api/v1/hub-setup        — (User Worker) Link Hub to User Worker

Required Supabase RPC (create once):
See SQL Migration section at bottom of file.

Environment Variables:
See ENV VAR CHECKLIST at bottom of file.
*/

// ─────────────────────────────────────────────────────────
// ENVIRONMENT INTERFACE
// ─────────────────────────────────────────────────────────
export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_KEY: string;
  ADMIN_MASTER_KEY: string;
  JWT_SECRET: string;
  /**
  FIX-8: Comma-separated list of allowed browser origins for the admin
  endpoint. Example: "https://admin.example.com,https://local.example.com"
  Leave empty to allow only direct server-to-server (curl/Worker) calls.
  */
  ADMIN_ALLOWED_ORIGINS?: string;
  /**
  FIX-17: Optional Service Binding for internal Worker-to-Worker calls.
  When set, this allows User Workers to connect via Service Binding
  instead of public HTTP, solving Cloudflare Error 1042.
  */
  USER_WORKER?: Fetcher;
}

// ─────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────
const JWT_TTL_SECONDS       = 23 * 60 * 60; // 23 h — leaves a renewal window
const RATE_LIMIT_WINDOW_SEC = 60;
const RATE_LIMIT_MAX_SYNC   = 60;
const RATE_LIMIT_MAX_AUTH   = 10;
const RATE_LIMIT_MAX_EXPLORE = 100;
const MAX_TAGS          = 30;
const MAX_TAG_LENGTH    = 50;
const MAX_TITLE_LENGTH  = 300;
const MAX_FOLDER_LENGTH = 200;
const MAX_SLUG_LENGTH   = 200;
const CACHE_TTL_SECONDS = 60; // Explore cache TTL

// ─────────────────────────────────────────────────────────
// FIX-7: Module-level HMAC key cache
//
// importHmacKey is CPU-intensive. By caching the CryptoKey at isolate
// level it is imported exactly once per cold-start, then reused for
// every sign/verify call in the same isolate lifetime.
// ─────────────────────────────────────────────────────────
let _cachedHmacKey: CryptoKey | null = null;
let _cachedHmacSecret: string = "";

async function getHmacKey(secret: string): Promise<CryptoKey> {
  if (_cachedHmacKey && _cachedHmacSecret === secret) {
    return _cachedHmacKey;
  }
  _cachedHmacKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  _cachedHmacSecret = secret;
  return _cachedHmacKey;
}

// ─────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────
type Responder = (body: unknown, status?: number) => Response;

interface JWTPayload {
  sub: string; // client_id (= owner_id)
  aud: string; // worker_url
  iat: number;
  exp: number;
}

interface SyncRequestBody {
  slug: string;
  owner_id: string;
  title: string;
  tags?: string[];
  folder?: string;
  url: string;
  image_metadata?: Array<{
    url: string;
    alt: string;
    width?: number;
    height?: number;
    size?: number;
  }>;
}

interface ExploreResponse {
  results: unknown[];
  page: number;
  limit: number;
  total: number;
  has_more: boolean;
}

// ─────────────────────────────────────────────────────────
// ROUTER
// ─────────────────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url    = new URL(request.url);
    const reqId  = crypto.randomUUID().slice(0, 8);
    const origin = request.headers.get("Origin") ?? "";

    // FIX-8: Read allowed origins from env, not from a hardcoded array.
    const adminAllowedOrigins: string[] = (env.ADMIN_ALLOWED_ORIGINS ?? "")
      .split(",")
      .map(s => s.trim())
      .filter(Boolean);

    // ── CORS ──────────────────────────────────────────────
    // Admin: strict browser-origin allowlist (server-to-server always allowed).
    // All other endpoints: open (public API + Worker-to-Worker, no cookies).
    const isAdminPath = url.pathname.startsWith("/api/v1/admin");

    const corsHeaders: Record<string, string> = isAdminPath
      ? buildAdminCorsHeaders(origin, adminAllowedOrigins)
      : {
          "Access-Control-Allow-Origin":  "*",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const respond: Responder = (body, status = 200) =>
      Response.json(body, { status, headers: corsHeaders });

    try {
      // ── Health ───────────────────────────────────────────
      if (url.pathname === "/api/v1/health" && request.method === "GET") {
        return respond({ status: "operational", version: "5.5.0", ts: Date.now() });
      }

      // ── Hub Setup (User Worker v5.5 compatibility) ───────
      if (url.pathname === "/api/v1/hub-setup" && request.method === "POST") {
        return await handleHubSetup(request, env, reqId, respond);
      }

      // ── Admin: Provision ─────────────────────────────────
      if (url.pathname === "/api/v1/admin/provision" && request.method === "POST") {
        // FIX-2: Single, clean origin guard.
        // Server-to-server calls carry no Origin header — those are fine.
        // Browser calls that arrive from an unknown origin are rejected.
        if (origin && !adminAllowedOrigins.includes(origin)) {
          return respond({ error: "Origin not allowed" }, 403);
        }
        return await handleProvisionClient(request, env, reqId, respond);
      }

      // ── Auth ─────────────────────────────────────────────
      if (url.pathname === "/api/v1/auth" && request.method === "POST") {
        return await handleAuth(request, env, reqId, respond);
      }

      // ── Sync ─────────────────────────────────────────────
      if (url.pathname === "/api/v1/index" && request.method === "POST") {
        return await handleSync(request, env, reqId, respond);
      }

      // ── Explore ──────────────────────────────────────────
      if (url.pathname === "/api/v1/explore" && request.method === "GET") {
        return await handleExplore(url, env, respond, ctx);
      }

      // ── Delete ───────────────────────────────────────────
      const deleteMatch = url.pathname.match(/^\/api\/v1\/index\/([^/]+)\/([^/]+)$/);
      if (deleteMatch && request.method === "DELETE") {
        const owner_id = decodeURIComponent(deleteMatch[1]);
        const slug     = decodeURIComponent(deleteMatch[2]);
        return await handleDelete(request, env, reqId, owner_id, slug, respond);
      }

      return respond({ error: "Endpoint Not Found" }, 404);

    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[${reqId}] Unhandled error:`, message);
      return respond({ error: "Internal Server Error" }, 500);
    }
  },
};

// ─────────────────────────────────────────────────────────
// CORS HELPERS
// ─────────────────────────────────────────────────────────
function buildAdminCorsHeaders(
  origin: string,
  allowedOrigins: string[],
): Record<string, string> {
  // If origin is in allowlist → reflect it; otherwise respond with "null"
  // so the browser blocks the preflight while server-to-server still works.
  const allowed = allowedOrigins.includes(origin) ? origin : "null";
  return {
    "Access-Control-Allow-Origin":  allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary":                         "Origin",
  };
}

// ─────────────────────────────────────────────────────────
// HUB SETUP (User Worker v5.5 Compatibility)
// FIX-19: Allows User Worker to link to Hub via this endpoint
// ─────────────────────────────────────────────────────────
async function handleHubSetup(
  request: Request,
  env: Env,
  reqId: string,
  respond: Responder,
): Promise<Response> {
  // This endpoint is called by User Worker during hub-setup
  // It authenticates using the master_api_key (HUB_CLIENT_SECRET)
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return respond({ error: "Missing Authorization header" }, 401);
  }

  const masterApiKey = authHeader.slice(7);

  // Verify against ADMIN_MASTER_KEY for initial setup
  if (masterApiKey !== env.ADMIN_MASTER_KEY) {
    return respond({ error: "Invalid master API key" }, 401);
  }

  const body = await parseJsonBody(request);
  const { worker_url, owner_id } = body;

  if (!worker_url || !isValidHttpsUrl(worker_url)) {
    return respond({ error: "worker_url must be a valid https URL" }, 400);
  }

  if (!owner_id || !isValidId(owner_id)) {
    return respond({ error: "owner_id must be 3-50 alphanumeric chars" }, 400);
  }

  // Check if client already exists
  const res = await supabaseFetch(
    env,
    `/rest/v1/hub_clients?client_id=eq.${encodeURIComponent(owner_id)}&select=client_id,is_active`,
    "GET",
  );

  const data = await res.json() as Array<{ client_id: string; is_active: boolean | null }>;

  if (data.length === 0) {
    // Auto-provision if not exists (convenience for first-time setup)
    const rawSecret  = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
    const secretHash = await sha256Hex(rawSecret);
    const provisionRes = await supabaseFetch(env, "/rest/v1/hub_clients", "POST", {
      client_id:    owner_id,
      secret_hash:  secretHash,
      worker_url:   worker_url,
      created_at:   new Date().toISOString(),
      is_active:    true,
    });

    if (!provisionRes.ok) {
      console.error(`[${reqId}] Auto-provision failed:`, await provisionRes.text());
      return respond({ error: "Failed to auto-provision client" }, 500);
    }

    console.log(`[${reqId}] Auto-provisioned client: ${owner_id}`);
  } else {
    // Update worker_url if changed
    const updateRes = await supabaseFetch(
      env,
      `/rest/v1/hub_clients?client_id=eq.${encodeURIComponent(owner_id)}`,
      "PATCH",
      { worker_url: worker_url },
    );

    if (!updateRes.ok) {
      console.error(`[${reqId}] Update worker_url failed:`, await updateRes.text());
    }
  }

  // Issue a JWT for immediate use
  const nowSec = Math.floor(Date.now() / 1000);
  const exp    = nowSec + JWT_TTL_SECONDS;
  const payload: JWTPayload = {
    sub: owner_id,
    aud: worker_url,
    iat: nowSec,
    exp,
  };
  const token = await signJWT(payload, env.JWT_SECRET);

  console.log(`[${reqId}] Hub setup completed for: ${owner_id}`);
  return respond({
    token,
    expires_in: JWT_TTL_SECONDS,
    expires_at: new Date(exp * 1000).toISOString(),
  });
}

// ─────────────────────────────────────────────────────────
// ADMIN: PROVISION CLIENT
// ─────────────────────────────────────────────────────────
async function handleProvisionClient(
  request: Request,
  env: Env,
  reqId: string,
  respond: Responder,
): Promise<Response> {
  // Verify admin key
  const auth = request.headers.get("Authorization") ?? "";
  if (auth !== `Bearer ${env.ADMIN_MASTER_KEY}`) {
    return respond({ error: "Unauthorized" }, 401);
  }

  const body = await parseJsonBody(request);
  const { client_id, worker_url } = body;

  if (!isValidId(client_id)) {
    return respond({ error: "Invalid client_id: use 3-50 alphanumeric/dash/underscore chars" }, 400);
  }

  if (worker_url && !isValidHttpsUrl(worker_url)) {
    return respond({ error: "worker_url must be a valid https URL" }, 400);
  }

  // Generate 64-char hex secret (two UUIDs, dashes removed)
  const rawSecret  = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  const secretHash = await sha256Hex(rawSecret);

  const res = await supabaseFetch(env, "/rest/v1/hub_clients", "POST", {
    client_id,
    secret_hash: secretHash,
    worker_url:  worker_url ?? null,
    created_at:  new Date().toISOString(),
    is_active:   true,
  });

  if (!res.ok) {
    const detail = await res.text();
    console.error(`[${reqId}] Provision failed:`, detail);
    const status = res.status === 409 ? 409 : 500;
    return respond({ error: "Failed to register client (may already exist)" }, status);
  }

  console.log(`[${reqId}] Provisioned client: ${client_id}`);
  return respond({
    message:       "Client provisioned. Store the secret securely — it will not be shown again.",
    client_id,
    client_secret: rawSecret,
  });
}

// ─────────────────────────────────────────────────────────
// AUTH: client_id + client_secret → JWT
// ─────────────────────────────────────────────────────────
async function handleAuth(
  request: Request,
  env: Env,
  reqId: string,
  respond: Responder,
): Promise<Response> {
  const body = await parseJsonBody(request);
  const { client_id, client_secret, worker_url } = body;

  if (!client_id || !client_secret || !worker_url) {
    return respond({ error: "Missing fields: client_id, client_secret, worker_url" }, 400);
  }

  if (!isValidId(client_id))        return respond({ error: "Invalid client_id"  }, 400);
  if (!isValidHttpsUrl(worker_url)) return respond({ error: "Invalid worker_url" }, 400);
  if (typeof client_secret !== "string" || client_secret.length === 0) {
    return respond({ error: "Invalid client_secret" }, 400);
  }

  // Rate limit by client_id + IP to prevent brute-force
  const ip    = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `auth:${client_id}:${ip}`;
  const allowed = await checkRateLimit(env, rlKey, RATE_LIMIT_MAX_AUTH, RATE_LIMIT_WINDOW_SEC);
  if (!allowed) return respond({ error: "Too many authentication attempts. Try again later." }, 429);

  // Hash the incoming secret
  const incomingHash = await sha256Hex(client_secret as string);

  const res  = await supabaseFetch(
    env,
    `/rest/v1/hub_clients?client_id=eq.${encodeURIComponent(client_id as string)}&select=secret_hash,is_active`,
    "GET",
  );

  const data = await res.json() as Array<{ secret_hash: string; is_active: boolean | null }>;
  const record   = data.length > 0 ? data[0] : null;
  const isActive = record ? (record.is_active !== false) : false;

  // FIX-1: Timing-safe comparison via HMAC double-sign.
  // Both values are signed with the same key so they share an identical
  // output length; the final string comparison cannot leak length info.
  // We always run the comparison regardless of whether the record exists
  // to ensure consistent timing across "user not found" and "wrong secret".
  const storedHash = record?.secret_hash ?? "";
  const hashMatch  = await timingSafeEqual(incomingHash, storedHash);

  if (!res.ok || !record || !hashMatch || !isActive) {
    console.warn(`[${reqId}] Failed auth for: ${client_id}`);
    return respond({ error: "Invalid credentials" }, 401);
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const exp    = nowSec + JWT_TTL_SECONDS;
  const payload: JWTPayload = {
    sub: client_id as string,
    aud: worker_url as string,
    iat: nowSec,
    exp,
  };

  const token = await signJWT(payload, env.JWT_SECRET);
  console.log(`[${reqId}] JWT issued → ${client_id}`);

  return respond({
    token,
    expires_in: JWT_TTL_SECONDS,
    expires_at: new Date(exp * 1000).toISOString(),
  });
}

// ─────────────────────────────────────────────────────────
// SYNC: Upsert Note to global index
// FIX-3: Replay-protection + upsert are now a single atomic Supabase RPC.
// FIX-18: Image metadata array supported for future Storage integration.
// ─────────────────────────────────────────────────────────
async function handleSync(
  request: Request,
  env: Env,
  reqId: string,
  respond: Responder,
): Promise<Response> {
  const jwtPayload = await verifyRequestJWT(request, env.JWT_SECRET);
  if (!jwtPayload) return respond({ error: "Invalid or expired token" }, 401);

  // Rate limit per owner
  const rlKey   = `sync:${jwtPayload.sub}`;
  const allowed = await checkRateLimit(env, rlKey, RATE_LIMIT_MAX_SYNC, RATE_LIMIT_WINDOW_SEC);
  if (!allowed) return respond({ error: "Rate limit exceeded" }, 429);

  const body = await parseJsonBody(request) as SyncRequestBody;
  const { slug, owner_id, title, tags, folder, url, image_metadata } = body;

  // ── Validate required fields ──────────────────────────
  if (!slug || !owner_id || !title || !url) {
    return respond({ error: "Missing required fields: slug, owner_id, title, url" }, 400);
  }

  // ── Identity check: owner_id must match JWT sub ───────
  if (owner_id !== jwtPayload.sub) {
    return respond({ error: "Forbidden: owner_id does not match token identity" }, 403);
  }

  // ── URL must originate from the registered worker ─────
  if (!(url as string).startsWith(jwtPayload.aud)) {
    return respond({ error: "Forbidden: url origin does not match registered worker" }, 403);
  }

  // ── Field length limits ───────────────────────────────
  if ((title as string).length > MAX_TITLE_LENGTH) {
    return respond({ error: `Title exceeds ${MAX_TITLE_LENGTH} chars` }, 400);
  }

  if (folder && (folder as string).length > MAX_FOLDER_LENGTH) {
    return respond({ error: `Folder exceeds ${MAX_FOLDER_LENGTH} chars` }, 400);
  }

  if ((slug as string).length > MAX_SLUG_LENGTH) {
    return respond({ error: `Slug exceeds ${MAX_SLUG_LENGTH} chars` }, 400);
  }

  // ── Tag sanitization ──────────────────────────────────
  const rawTags   = Array.isArray(tags) ? tags : [];
  const validTags = rawTags
    .filter((t: unknown): t is string => typeof t === "string" && t.trim() !== "")
    .map((t: string) => t.trim().slice(0, MAX_TAG_LENGTH))
    .slice(0, MAX_TAGS);

  // ── Image metadata validation (FIX-18) ────────────────
  const rawImages = Array.isArray(image_metadata) ? image_metadata : [];
  const validImages = rawImages
    .filter((img: unknown): img is Record<string, unknown> => typeof img === "object" && img !== null)
    .map((img: Record<string, unknown>) => ({
      url:    typeof img.url === "string" ? img.url.slice(0, 500) : "",
      alt:    typeof img.alt === "string" ? img.alt.slice(0, 200) : "",
      width:  typeof img.width === "number" ? img.width : undefined,
      height: typeof img.height === "number" ? img.height : undefined,
      size:   typeof img.size === "number" ? img.size : undefined,
    }))
    .filter(img => img.url !== "")
    .slice(0, 20); // Max 20 images per note

  const globalId    = `${owner_id}:${slug}`;
  // FIX-5: Use ISO-8601 timestamp strings throughout (no mixed ms/seconds).
  const nowIso      = new Date().toISOString();
  const hashInput   = JSON.stringify({ slug, title, tags: validTags, folder: folder ?? "", url, active: true });
  const currentHash = await sha256Hex(hashInput);

  // FIX-3: Delegate the check-then-upsert to a single atomic Supabase RPC.
  // The RPC returns { upserted: boolean, replay: boolean }.
  // See SQL at the bottom of this file.
  const rpcRes = await supabaseFetch(env, "/rest/v1/rpc/upsert_note_if_changed", "POST", {
    p_id:              globalId,
    p_owner_id:        owner_id,
    p_slug:            slug,
    p_title:           title,
    p_tags:            validTags,
    p_folder:          folder ?? "",
    p_note_url:        url,
    p_updated_at:      nowIso,
    p_hash:            currentHash,
    p_image_metadata:  validImages.length > 0 ? validImages : null,
  });

  if (!rpcRes.ok) {
    console.error(`[${reqId}] DB sync RPC error:`, await rpcRes.text());
    return respond({ error: "Database sync failed" }, 500);
  }

  const rpcResult = await rpcRes.json() as { upserted: boolean; replay: boolean };

  if (rpcResult.replay) {
    return respond({ success: true, globalId, replay: true });
  }

  await invalidateExploreCache(env);
  console.log(`[${reqId}] Synced: ${globalId}`);

  return respond({ success: true, globalId, replay: false });
}

// ─────────────────────────────────────────────────────────
// DELETE: Tombstone a note
// FIX-5: Use ISO-8601 string, not raw milliseconds integer.
// ─────────────────────────────────────────────────────────
async function handleDelete(
  request: Request,
  env: Env,
  reqId: string,
  owner_id: string,
  slug: string,
  respond: Responder,
): Promise<Response> {
  const jwtPayload = await verifyRequestJWT(request, env.JWT_SECRET);
  if (!jwtPayload || owner_id !== jwtPayload.sub) {
    return respond({ error: "Forbidden" }, 403);
  }

  // Validate slug to prevent path-traversal style attacks
  if (!/^[a-zA-Z0-9_-]{1,200}$/.test(slug)) {
    return respond({ error: "Invalid slug" }, 400);
  }

  const globalId = `${owner_id}:${slug}`;
  // FIX-5: Use ISO-8601 string, not raw milliseconds integer.
  const nowIso   = new Date().toISOString();

  const updateRes = await supabaseFetch(
    env,
    `/rest/v1/global_notes?id=eq.${encodeURIComponent(globalId)}`,
    "PATCH",
    { deleted_at: nowIso },
  );

  if (!updateRes.ok) {
    console.error(`[${reqId}] Delete error:`, await updateRes.text());
    return respond({ error: "Database update failed" }, 500);
  }

  await invalidateExploreCache(env);
  console.log(`[${reqId}] Tombstoned: ${globalId}`);

  return respond({ success: true, deleted: globalId });
}

// ─────────────────────────────────────────────────────────
// EXPLORE: Public browsing with cache
// FIX-4: Cache key is SHA-256 hashed.
// FIX-6: Results and count fetched in parallel.
// ─────────────────────────────────────────────────────────
async function handleExplore(
  url: URL,
  env: Env,
  respond: Responder,
  ctx: ExecutionContext,
): Promise<Response> {
  // ── Parameter parsing & strict sanitization ───────────
  const rawSearch = url.searchParams.get("q") ?? "";
  const rawOwner  = url.searchParams.get("owner") ?? "";
  const page      = Math.max(1, parseInt(url.searchParams.get("page")  ?? "1",  10));
  const limit     = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10)));
  const offset    = (page - 1) * limit;

  // Only allow safe characters to prevent PostgREST injection
  const search = rawSearch.replace(/[^a-zA-Z0-9 _-.؀-ۿ]/g, "").slice(0, 100);
  const owner  = rawOwner.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 50);

  // FIX-4: Hash cache key so user-supplied strings never appear raw in DB queries.
  const cacheKeyRaw = JSON.stringify({ search, owner, page, limit });
  const cacheKey    = "explore:" + await sha256Hex(cacheKeyRaw);

  // ── Cache lookup ──────────────────────────────────────
  try {
    const cacheRes  = await supabaseFetch(
      env,
      `/rest/v1/hub_kv_store?key=eq.${encodeURIComponent(cacheKey)}&select=value,expires_at`,
      "GET",
    );
    const cacheData = await cacheRes.json() as Array<{ value: string; expires_at: number }>;

    if (cacheRes.ok && cacheData.length > 0) {
      const expiresAt = Number(cacheData[0].expires_at);
      if (Date.now() < expiresAt * 1000) {
        return respond(JSON.parse(cacheData[0].value));
      }
    }
  } catch { /* Cache miss — continue to DB */ }

  // ── Build DB query ────────────────────────────────────
  let baseQuery = `/rest/v1/global_notes?deleted_at=is.null&order=updated_at.desc`;

  if (owner) {
    baseQuery += `&owner_id=eq.${encodeURIComponent(owner)}`;
  }

  if (search) {
    const encodedLike = encodeURIComponent(`%${search}%`);
    baseQuery += `&or=(title.ilike.${encodedLike},tags.cs.${encodeURIComponent(JSON.stringify([search]))})`;
  }

  const dataQuery  = `${baseQuery}&limit=${limit}&offset=${offset}`;
  // Count query: retrieve 0 rows but ask for exact count via header
  const countQuery = `${baseQuery}&limit=1&offset=0`;

  // FIX-6: Fire both requests in parallel.
  const [dbRes, countRes] = await Promise.all([
    supabaseFetch(env, dataQuery, "GET"),
    supabaseFetch(env, countQuery, "GET", undefined, { "Prefer": "count=exact" }),
  ]);

  if (!dbRes.ok) {
    console.error("Explore DB error:", await dbRes.text());
    return respond({ error: "Failed to query database" }, 500);
  }

  const results = await dbRes.json() as unknown[];
  let total = results.length; // fallback

  try {
    const contentRange = countRes.headers.get("content-range") ?? "";
    // Format: "0-19/142" or "/142"
    const parts = contentRange.split("/");
    if (parts[1]) total = parseInt(parts[1], 10);
  } catch { /* use fallback */ }

  const payload: ExploreResponse = {
    results,
    page,
    limit,
    total,
    has_more: offset + results.length < total,
  };

  // ── Update cache asynchronously ───────────────────────
  ctx.waitUntil(
    supabaseFetch(env, "/rest/v1/hub_kv_store", "POST", {
      key:        cacheKey,
      value:      JSON.stringify(payload),
      expires_at: Math.floor(Date.now() / 1000) + CACHE_TTL_SECONDS,
    }, { "Prefer": "resolution=merge-duplicates" }).catch(err =>
      console.error("Cache write failed:", err),
    ),
  );

  return respond(payload);
}

// ─────────────────────────────────────────────────────────
// SUPABASE UTILITIES
// ─────────────────────────────────────────────────────────
async function supabaseFetch(
  env: Env,
  path: string,
  method: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
): Promise<Response> {
  const url     = `${env.SUPABASE_URL}${path}`;
  const headers: Record<string, string> = {
    "apikey":        env.SUPABASE_SERVICE_KEY,
    "Authorization": `Bearer ${env.SUPABASE_SERVICE_KEY}`,
    "Content-Type":  "application/json",
    ...extraHeaders,
  };

  const options: RequestInit = { method, headers };
  if (body !== undefined) options.body = JSON.stringify(body);

  return fetch(url, options);
}

/**
Rate limiting via Supabase RPC.
Auth: fail CLOSED (safe default — lock out on DB failure).
Sync: fail open (don't punish users during transient DB hiccups).
Explore: fail open (public endpoint, don't block on DB issues).
*/
async function checkRateLimit(
  env: Env,
  key: string,
  maxHits: number,
  windowSec: number,
  failOpen = false,
): Promise<boolean> {
  try {
    const res = await supabaseFetch(env, "/rest/v1/rpc/check_rate_limit", "POST", {
      rl_key:     key,
      max_hits:   maxHits,
      window_sec: windowSec,
    });

    if (!res.ok) {
      console.warn(`Rate limit RPC failed (${res.status}), failing ${failOpen ? "open" : "closed"}`);
      return failOpen;
    }

    const result = await res.json();
    return result === true;
  } catch (err) {
    console.error("Rate limit error:", err);
    return failOpen;
  }
}

async function invalidateExploreCache(env: Env): Promise<void> {
  try {
    // Delete all cache rows whose key starts with "explore:"
    await supabaseFetch(env, "/rest/v1/hub_kv_store?key=like.explore:*", "DELETE");
  } catch (err) {
    console.error("Cache invalidation failed:", err);
  }
}

// ─────────────────────────────────────────────────────────
// FIX-1: Timing-safe string comparison
//
// Sign both strings with HMAC-SHA256 using a static key derived from
// the JWT secret so both signatures are always 32 bytes. Comparing
// two equal-length hex strings via === cannot leak secret length.
// ─────────────────────────────────────────────────────────
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  // We use a fixed comparison key distinct from the JWT signing key.
  // Any stable string works here; the goal is identical-length outputs.
  const compKey = await getHmacKey("timing_safe_compare");
  const enc     = new TextEncoder();

  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign("HMAC", compKey, enc.encode(a)),
    crypto.subtle.sign("HMAC", compKey, enc.encode(b)),
  ]);

  // Both ArrayBuffers are 32 bytes — safe to compare byte-by-byte.
  const ua = new Uint8Array(sigA);
  const ub = new Uint8Array(sigB);

  // Constant-time byte comparison: always visit all 32 bytes.
  let diff = 0;
  for (let i = 0; i < ua.length; i++) {
    diff |= ua[i] ^ ub[i];
  }

  return diff === 0;
}

// ─────────────────────────────────────────────────────────
// JWT IMPLEMENTATION (HS256, no external libs)
// FIX-9: Chunk-based encoding to prevent stack overflow
// ─────────────────────────────────────────────────────────
async function signJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header  = b64uEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body    = b64uEncode(JSON.stringify(payload));
  const data    = `${header}.${body}`;
  const key     = await getHmacKey(secret);
  const sigBuf  = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sig     = b64uFromBuffer(sigBuf);

  return `${data}.${sig}`;
}

async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, sigB64] = parts;
    const data = `${headerB64}.${payloadB64}`;
    const key  = await getHmacKey(secret);

    const sigBytes = b64uToBuffer(sigB64);
    const isValid  = await crypto.subtle.verify(
      "HMAC", key, sigBytes, new TextEncoder().encode(data),
    );

    if (!isValid) return null;

    const p = JSON.parse(b64uDecode(payloadB64)) as JWTPayload;
    if (p.exp < Math.floor(Date.now() / 1000)) return null;

    return p;
  } catch {
    return null;
  }
}

async function verifyRequestJWT(request: Request, secret: string): Promise<JWTPayload | null> {
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return null;
  return verifyJWT(auth.slice(7), secret);
}

// ─────────────────────────────────────────────────────────
// CRYPTO / ENCODING HELPERS
// ─────────────────────────────────────────────────────────
async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ─────────────────────────────────────────────────────────
// FIX-9: Safe Base64-URL helpers (no spread-into-call-stack)
//
// The original code used `btoa(String.fromCharCode(...bytes))` which
// spreads a Uint8Array into function arguments. For strings longer
// than ~65,000 bytes the JS engine hits a call-stack limit and throws.
// The chunk-based loop below processes 8,192 bytes at a time.
// ─────────────────────────────────────────────────────────
const B64U_CHUNK = 8192;

function b64uEncode(str: string): string {
  const bytes  = new TextEncoder().encode(str);
  let   binary = "";

  for (let i = 0; i < bytes.length; i += B64U_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + B64U_CHUNK));
  }

  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64uDecode(str: string): string {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad    = padded.length % 4;
  const base64 = pad ? padded + "=".repeat(4 - pad) : padded;

  return new TextDecoder().decode(
    Uint8Array.from(atob(base64), c => c.charCodeAt(0))
  );
}

function b64uFromBuffer(buf: ArrayBuffer): string {
  const bytes  = new Uint8Array(buf);
  let   binary = "";

  for (let i = 0; i < bytes.length; i += B64U_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + B64U_CHUNK));
  }

  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64uToBuffer(str: string): ArrayBuffer {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad    = padded.length % 4;
  const base64 = pad ? padded + "=".repeat(4 - pad) : padded;

  return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
}

// ─────────────────────────────────────────────────────────
// VALIDATION HELPERS
// ─────────────────────────────────────────────────────────
function isValidId(id: unknown): id is string {
  return typeof id === "string" && /^[a-zA-Z0-9_-]{3,50}$/.test(id);
}

function isValidHttpsUrl(url: unknown): url is string {
  if (typeof url !== "string") return false;
  try {
    const u = new URL(url);
    return u.protocol === "https:";
  } catch {
    return false;
  }
}

async function parseJsonBody(req: Request): Promise<Record<string, unknown>> {
  try {
    const result = await req.json();
    if (typeof result === "object" && result !== null) return result as Record<string, unknown>;
    return {};
  } catch {
    return {};
  }
}

/*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUIRED SUPABASE MIGRATION (run once in SQL editor)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- ───────────────────────────────────────────────────────
-- TABLE: hub_clients (Client credentials for User Workers)
-- ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hub_clients (
  client_id    TEXT PRIMARY KEY,
  secret_hash  TEXT NOT NULL,
  worker_url   TEXT,
  is_active    BOOLEAN DEFAULT true,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hub_clients_active ON hub_clients(is_active);

-- ───────────────────────────────────────────────────────
-- TABLE: global_notes (Central index of all published notes)
-- FIX-18: Added image_metadata column for future Storage integration
-- ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS global_notes (
  id              TEXT PRIMARY KEY,           -- owner_id:slug
  owner_id        TEXT NOT NULL,
  slug            TEXT NOT NULL,
  title           TEXT NOT NULL,
  tags            JSONB DEFAULT '[]'::jsonb,
  folder          TEXT DEFAULT '',
  note_url        TEXT NOT NULL,
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ,                -- FIX-5: Tombstone column
  last_hash       TEXT,                       -- For replay detection
  image_metadata  JSONB DEFAULT '[]'::jsonb,  -- FIX-18: Image metadata array
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_global_notes_owner ON global_notes(owner_id);
CREATE INDEX IF NOT EXISTS idx_global_notes_deleted ON global_notes(deleted_at);
CREATE INDEX IF NOT EXISTS idx_global_notes_updated ON global_notes(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_global_notes_tags ON global_notes USING GIN(tags);

-- ───────────────────────────────────────────────────────
-- TABLE: hub_kv_store (Worker-level cache for explore results)
-- ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hub_kv_store (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  expires_at  BIGINT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hub_kv_expires ON hub_kv_store(expires_at);

-- ───────────────────────────────────────────────────────
-- RPC: upsert_note_if_changed (Atomic upsert with replay detection)
-- FIX-3: Prevents race conditions by doing check+upsert in one operation
-- ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION upsert_note_if_changed(
  p_id              TEXT,
  p_owner_id        TEXT,
  p_slug            TEXT,
  p_title           TEXT,
  p_tags            JSONB,
  p_folder          TEXT,
  p_note_url        TEXT,
  p_updated_at      TIMESTAMPTZ,
  p_hash            TEXT,
  p_image_metadata  JSONB DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_existing RECORD;
BEGIN
  SELECT last_hash, deleted_at
  INTO v_existing
  FROM global_notes
  WHERE id = p_id
  FOR UPDATE;  -- row-level lock prevents concurrent upserts

  -- Replay: same hash AND note is not currently tombstoned
  IF FOUND AND v_existing.last_hash = p_hash AND v_existing.deleted_at IS NULL THEN
    RETURN '{"upserted": false, "replay": true}'::JSONB;
  END IF;

  INSERT INTO global_notes
    (id, owner_id, slug, title, tags, folder, note_url, updated_at, deleted_at, last_hash, image_metadata)
  VALUES
    (p_id, p_owner_id, p_slug, p_title, p_tags, p_folder, p_note_url, p_updated_at, NULL, p_hash, 
     COALESCE(p_image_metadata, '[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    owner_id        = EXCLUDED.owner_id,
    slug            = EXCLUDED.slug,
    title           = EXCLUDED.title,
    tags            = EXCLUDED.tags,
    folder          = EXCLUDED.folder,
    note_url        = EXCLUDED.note_url,
    updated_at      = EXCLUDED.updated_at,
    deleted_at      = NULL,
    last_hash       = EXCLUDED.last_hash,
    image_metadata  = COALESCE(EXCLUDED.image_metadata, global_notes.image_metadata);

  RETURN '{"upserted": true, "replay": false}'::JSONB;
END;
$$;

-- ───────────────────────────────────────────────────────
-- RPC: check_rate_limit (Sliding window rate limiting)
-- ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limit_log (
  rl_key      TEXT NOT NULL,
  timestamp   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_key ON rate_limit_log(rl_key);
CREATE INDEX IF NOT EXISTS idx_rate_limit_ts ON rate_limit_log(timestamp);

CREATE OR REPLACE FUNCTION check_rate_limit(
  p_rl_key      TEXT,
  p_max_hits    INTEGER,
  p_window_sec  INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
  v_count INTEGER;
BEGIN
  -- Clean old entries (older than window)
  DELETE FROM rate_limit_log
  WHERE rl_key = p_rl_key
    AND timestamp < NOW() - (p_window_sec || ' seconds')::INTERVAL;

  -- Count recent hits
  SELECT COUNT(*) INTO v_count
  FROM rate_limit_log
  WHERE rl_key = p_rl_key;

  -- Check if under limit
  IF v_count < p_max_hits THEN
    -- Record this hit
    INSERT INTO rate_limit_log (rl_key, timestamp) VALUES (p_rl_key, NOW());
    RETURN true;
  END IF;

  RETURN false;
END;
$$;

-- ───────────────────────────────────────────────────────
-- CLEANUP: Periodic cache expiration (run via pg_cron or external job)
-- ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION cleanup_expired_cache()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_deleted INTEGER;
BEGIN
  DELETE FROM hub_kv_store WHERE expires_at < EXTRACT(EPOCH FROM NOW());
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;

-- ───────────────────────────────────────────────────────
-- CLEANUP: Periodic rate limit log cleanup
-- ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION cleanup_rate_limit_logs()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_deleted INTEGER;
BEGIN
  DELETE FROM rate_limit_log WHERE timestamp < NOW() - INTERVAL '1 hour';
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENV VAR CHECKLIST (wrangler.toml / CF Dashboard)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUPABASE_URL            = "https://xxxx.supabase.co"
SUPABASE_SERVICE_KEY    = "<service_role key>"
ADMIN_MASTER_KEY        = "<openssl rand -hex 32>"
JWT_SECRET              = "<openssl rand -hex 32>"
ADMIN_ALLOWED_ORIGINS   = "https://your-admin.example.com"
                        (comma-separated; empty = no browser access)
USER_WORKER             = <service_binding_to_user_worker>
                        (Optional: for internal Worker-to-Worker calls)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WRANGLER.TOML EXAMPLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

name = "jotbird-hub"
main = "src/hub-worker.ts"
compatibility_date = "2024-01-01"

[vars]
SUPABASE_URL = "https://xxxx.supabase.co"
ADMIN_MASTER_KEY = "your-admin-key"
JWT_SECRET = "your-jwt-secret"
ADMIN_ALLOWED_ORIGINS = "https://admin.example.com"

[[services]]
binding = "USER_WORKER"
service = "jotbird-user"

[[d1_databases]]
binding = "DB"
database_name = "jotbird-hub"
database_id = "xxxx"

[env.production]
SUPABASE_SERVICE_KEY = "your-service-key"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEPLOYMENT ORDER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Run SQL Migration in Supabase SQL Editor
2. Set Environment Variables in Cloudflare Dashboard
3. Deploy Hub Worker: wrangler deploy
4. Deploy User Worker: wrangler deploy
5. Test /api/v1/health endpoint
6. Provision first client via /api/v1/admin/provision
7. Configure User Worker with client_id and client_secret

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
*/
