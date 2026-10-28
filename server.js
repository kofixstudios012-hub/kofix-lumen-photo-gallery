'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const cfg = require('./lib/config');
const { openDb } = require('./lib/db');
const { createStorage } = require('./lib/storage');
const { writeZip } = require('./lib/zip');

const scrypt = promisify(crypto.scrypt);
const PUBLIC_DIR = path.join(__dirname, 'public');
const MODES = ['view', 'download', 'full'];
const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const SESSION_MS = 14 * 24 * 3600 * 1000;
const GALLERY_SESSION_MS = 12 * 3600 * 1000;

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

// ---------- small helpers ----------
const uid = () => crypto.randomBytes(9).toString('base64url');
const newToken = () => crypto.randomBytes(18).toString('base64url'); // 144 bits: not guessable
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hmac = (s) => crypto.createHmac('sha256', cfg.sessionSecret).update(s).digest('base64url');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

function sniff(buf) {
  if (buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  return null;
}
function cleanName(n, fallback) {
  n = String(n || '').replace(/[\\/\u0000-\u001f"<>|?*:]/g, '_').replace(/^\.+/, '').trim().slice(0, 120);
  return n || fallback;
}
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function setCookie(res, name, value, { maxAge, path: p = '/' }) {
  const attrs = [`${name}=${encodeURIComponent(value)}`, `Path=${p}`, 'HttpOnly', 'SameSite=Strict', `Max-Age=${Math.floor(maxAge / 1000)}`];
  if (cfg.secureCookies) attrs.push('Secure');
  const prev = res.getHeader('set-cookie') || [];
  res.setHeader('set-cookie', [].concat(prev, attrs.join('; ')));
}
function clientIp(req) {
  if (cfg.trustProxy) {
    const x = req.headers['x-forwarded-for'];
    if (x) { const parts = String(x).split(',').map((s) => s.trim()); return parts[parts.length - 1]; }
  }
  return req.socket.remoteAddress || 'unknown';
}
function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}
async function readBody(req, limit) {
  const declared = Number(req.headers['content-length']);
  if (declared > limit) { req.resume(); throw new HttpError(413, `File too large (max ${Math.floor(limit / 1048576)} MB)`); }
  const chunks = []; let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > limit) { req.destroy(); throw new HttpError(413, `File too large (max ${Math.floor(limit / 1048576)} MB)`); }
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}
async function readJson(req) {
  const buf = await readBody(req, 64 * 1024);
  if (!buf.length) return {};
  try { return JSON.parse(buf.toString('utf8')); } catch { throw new HttpError(400, 'Invalid JSON'); }
}

// ---------- rate limiting (memory only; no personal data is persisted) ----------
class Limiter {
  constructor(max, windowMs) { this.max = max; this.windowMs = windowMs; this.m = new Map(); }
  _get(k) { const now = Date.now(); let e = this.m.get(k); if (!e || e.reset < now) { e = { n: 0, reset: now + this.windowMs }; this.m.set(k, e); } return e; }
  blocked(k) { return this._get(k).n >= this.max; }
  retryAfter(k) { return Math.max(1, Math.ceil((this._get(k).reset - Date.now()) / 1000)); }
  hit(k) { this._get(k).n++; }
  clear(k) { this.m.delete(k); }
  sweep() { const now = Date.now(); for (const [k, e] of this.m) if (e.reset < now) this.m.delete(k); }
}
const loginLimit = new Limiter(8, 15 * 60 * 1000);
const unlockLimit = new Limiter(6, 15 * 60 * 1000);      // per visitor IP + gallery
const unlockGlobal = new Limiter(40, 15 * 60 * 1000);    // per gallery, all visitors
setInterval(() => { loginLimit.sweep(); unlockLimit.sweep(); unlockGlobal.sweep(); }, 60000).unref();

// ---------- passwords ----------
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = await scrypt(pw, salt, 32);
  return `scrypt$${salt.toString('base64')}$${dk.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  const [alg, s, h] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const dk = await scrypt(pw, Buffer.from(s, 'base64'), 32);
  const want = Buffer.from(h, 'base64');
  return dk.length === want.length && crypto.timingSafeEqual(dk, want);
}

// ---------- owner session ----------
const ownerFp = () => sha('owner|' + cfg.ownerPassword).slice(0, 10);
function issueOwnerSession(res) {
  const exp = Date.now() + SESSION_MS;
  setCookie(res, 'lumen_owner', `${exp}.${hmac(`owner|${exp}|${ownerFp()}`)}`, { maxAge: SESSION_MS });
}
function isOwner(req) {
  const [exp, sig] = String(parseCookies(req).lumen_owner || '').split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEq(sig, hmac(`owner|${exp}|${ownerFp()}`));
}
function requireOwner(req) {
  if (!isOwner(req)) throw new HttpError(401, 'Please sign in');
  // CSRF defence in depth (cookie is also SameSite=Strict): state-changing calls need a custom header.
  if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-lumen'] !== '1') throw new HttpError(403, 'Forbidden');
}

// ---------- gallery visitor access ----------
const galleryFp = (g) => sha(`${g.pw_hash || ''}|${g.token}`).slice(0, 12);
function issueGalleryCookie(res, g) {
  const exp = Date.now() + GALLERY_SESSION_MS;
  setCookie(res, 'lg_' + g.id.slice(0, 8), `${exp}.${hmac(`g|${g.id}|${exp}|${galleryFp(g)}`)}`, { maxAge: GALLERY_SESSION_MS, path: `/api/public/${g.token}` });
}
function hasGalleryCookie(req, g) {
  const [exp, sig] = String(parseCookies(req)['lg_' + g.id.slice(0, 8)] || '').split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEq(sig, hmac(`g|${g.id}|${exp}|${galleryFp(g)}`));
}

// ---------- app ----------
async function main() {
  if (!cfg.ownerPassword || cfg.ownerPassword.length < 8) {
    console.error('\nOWNER_PASSWORD is missing or shorter than 8 characters.\nSet it in your environment (or in a .env file, see .env.example) and start again.\n');
    process.exit(1);
  }
  const db = await openDb(cfg);
  const storage = createStorage(cfg);
  if (cfg.onRender && storage.kind === 'local') {
    console.warn('WARNING: running on Render without S3_* storage settings. Photos on local disk are LOST on every restart. Configure Backblaze B2 (see README).');
  }
  const log = (...a) => console.log(new Date().toISOString(), ...a);

  const q = {
    gallery: async (id) => (await db.all('SELECT * FROM galleries WHERE id = ?', [id]))[0],
    byToken: async (t) => (await db.all('SELECT * FROM galleries WHERE token = ?', [t]))[0],
    photo: async (id) => (await db.all('SELECT * FROM photos WHERE id = ?', [id]))[0],
    photos: (gid) => db.all('SELECT * FROM photos WHERE gallery_id = ? ORDER BY position, created_at', [gid]),
    used: async () => Number((await db.all('SELECT COALESCE(SUM(size + thumb_size), 0) AS n FROM photos'))[0].n),
    event: (gid, type) => db.run('INSERT INTO events (gallery_id, type, at) VALUES (?, ?, ?)', [gid, type, Date.now()]),
  };

  async function stats(gid) {
    const rows = await db.all('SELECT type, COUNT(*) AS n, MAX(at) AS last FROM events WHERE gallery_id = ? GROUP BY type', [gid]);
    const s = { opens: 0, unlocks: 0, failedAttempts: 0, downloads: 0, zips: 0, lastOpened: null };
    for (const r of rows) {
      if (r.type === 'open') { s.opens = r.n; s.lastOpened = r.last; }
      if (r.type === 'unlock_ok') s.unlocks = r.n;
      if (r.type === 'unlock_fail') s.failedAttempts = r.n;
      if (r.type === 'download') s.downloads = r.n;
      if (r.type === 'zip') s.zips = r.n;
    }
    return s;
  }
  const statusOf = (g) => (g.revoked ? 'revoked' : g.expires_at && g.expires_at <= Date.now() ? 'expired' : 'active');
  const ownerGallery = (g, extra = {}) => ({
    id: g.id, title: g.title, mode: g.mode, token: g.token, hasPassword: !!g.pw_hash,
    expiresAt: g.expires_at, status: statusOf(g), watermark: g.watermark, createdAt: g.created_at, ...extra,
  });
  const photoView = (p) => ({ id: p.id, name: p.name, size: p.size, mime: p.mime, hasThumb: !!p.thumb_key, v: sha(p.key).slice(0, 8), createdAt: p.created_at });

  async function checkQuota(add) {
    const used = await q.used();
    if (used + add > cfg.storageLimitBytes) throw new HttpError(507, 'Storage limit reached. Delete some photos or raise STORAGE_LIMIT_GB.');
  }
  async function storeThumb(g, p, body) {
    const mime = sniff(body);
    if (!mime) throw new HttpError(415, 'Thumbnail must be a JPEG, PNG or WebP image');
    if (body.length > 2 * 1048576) throw new HttpError(413, 'Thumbnail too large');
    await checkQuota(body.length);
    const key = `g/${g.id}/${p.id}-${uid().slice(0, 6)}.t.${EXT[mime]}`;
    await storage.put(key, body, mime);
    await db.run('UPDATE photos SET thumb_key = ?, thumb_size = ? WHERE id = ?', [key, body.length, p.id]);
    if (p.thumb_key) storage.del(p.thumb_key).catch(() => {});
  }

  // Resolve a visitor request to a gallery they are allowed to see, or throw.
  async function visitorGallery(req, token, { needAuth = true } = {}) {
    const g = typeof token === 'string' && token.length >= 16 && token.length <= 64 ? await q.byToken(token) : null;
    // Unknown, revoked and expired links all look identical (no information for guessers).
    if (!g || g.revoked || (g.expires_at && g.expires_at <= Date.now())) throw new HttpError(404, 'This link is not available');
    if (needAuth && g.pw_hash && !hasGalleryCookie(req, g)) throw new HttpError(401, 'password_required');
    return g;
  }

  // ---------- route table ----------
  const routes = [];
  const route = (method, re, fn) => routes.push({ method, re, fn });

  // --- owner auth
  route('POST', /^\/api\/login$/, async (req, res) => {
    const ip = clientIp(req);
    if (loginLimit.blocked(ip)) { res.setHeader('retry-after', loginLimit.retryAfter(ip)); throw new HttpError(429, 'Too many attempts. Try again later.'); }
    const { password } = await readJson(req);
    if (typeof password !== 'string' || !safeEq(sha(password), sha(cfg.ownerPassword))) {
      loginLimit.hit(ip);
      throw new HttpError(401, 'Incorrect password');
    }
    loginLimit.clear(ip);
    issueOwnerSession(res);
    json(res, 200, { ok: true });
  });
  route('POST', /^\/api\/logout$/, async (req, res) => {
    setCookie(res, 'lumen_owner', '', { maxAge: 0 });
    json(res, 200, { ok: true });
  });
  route('GET', /^\/api\/me$/, async (req, res) => {
    requireOwner(req);
    json(res, 200, {
      storage: {
        used: await q.used(), limit: cfg.storageLimitBytes, backend: storage.label,
        persistent: storage.persistent, database: db.kind,
      },
      maxUploadBytes: cfg.maxUploadBytes,
      warning: cfg.onRender && storage.kind === 'local' ? 'Photos are on temporary disk and will be lost on restart. Configure Backblaze B2 storage.' : null,
    });
  });

  // --- galleries
  route('GET', /^\/api\/galleries$/, async (req, res) => {
    requireOwner(req);
    const rows = await db.all('SELECT * FROM galleries ORDER BY created_at DESC');
    const agg = await db.all('SELECT gallery_id, COUNT(*) AS n, SUM(size + thumb_size) AS bytes, MIN(id) AS any_id FROM photos GROUP BY gallery_id');
    const firsts = await db.all('SELECT gallery_id, id, thumb_key FROM photos ORDER BY position, created_at');
    const cover = {};
    for (const f of firsts) if (!cover[f.gallery_id]) cover[f.gallery_id] = f.id;
    const byG = Object.fromEntries(agg.map((a) => [a.gallery_id, a]));
    json(res, 200, rows.map((g) => ownerGallery(g, { photoCount: byG[g.id] ? byG[g.id].n : 0, bytes: byG[g.id] ? Number(byG[g.id].bytes) : 0, cover: cover[g.id] || null })));
  });
  route('POST', /^\/api\/galleries$/, async (req, res) => {
    requireOwner(req);
    const { title } = await readJson(req);
    const t = String(title || '').trim().slice(0, 80);
    if (!t) throw new HttpError(400, 'Please enter a gallery name');
    const now = Date.now(); const id = uid();
    await db.run('INSERT INTO galleries (id, token, title, mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)', [id, newToken(), t, 'view', now, now]);
    json(res, 201, ownerGallery(await q.gallery(id)));
  });
  route('GET', /^\/api\/galleries\/([\w-]+)$/, async (req, res, m) => {
    requireOwner(req);
    const g = await q.gallery(m[1]); if (!g) throw new HttpError(404, 'Not found');
    json(res, 200, { ...ownerGallery(g), photos: (await q.photos(g.id)).map(photoView), stats: await stats(g.id) });
  });
  route('PATCH', /^\/api\/galleries\/([\w-]+)$/, async (req, res, m) => {
    requireOwner(req);
    const g = await q.gallery(m[1]); if (!g) throw new HttpError(404, 'Not found');
    const b = await readJson(req);
    const sets = []; const args = [];
    if ('title' in b) { const t = String(b.title || '').trim().slice(0, 80); if (!t) throw new HttpError(400, 'Name cannot be empty'); sets.push('title = ?'); args.push(t); }
    if ('mode' in b) { if (!MODES.includes(b.mode)) throw new HttpError(400, 'Invalid access mode'); sets.push('mode = ?'); args.push(b.mode); }
    if ('password' in b) {
      if (b.password === null || b.password === '') { sets.push('pw_hash = ?'); args.push(null); }
      else {
        if (typeof b.password !== 'string' || b.password.length < 6 || b.password.length > 200) throw new HttpError(400, 'Password must be at least 6 characters');
        sets.push('pw_hash = ?'); args.push(await hashPassword(b.password));
      }
    }
    if ('expiresAt' in b) {
      if (b.expiresAt === null) { sets.push('expires_at = ?'); args.push(null); }
      else if (Number.isFinite(b.expiresAt) && b.expiresAt > Date.now()) { sets.push('expires_at = ?'); args.push(Math.floor(b.expiresAt)); }
      else throw new HttpError(400, 'Expiry must be a date in the future');
    }
    if ('watermark' in b) { const w = b.watermark ? String(b.watermark).trim().slice(0, 40) : null; sets.push('watermark = ?'); args.push(w || null); }
    if (sets.length) { sets.push('updated_at = ?'); args.push(Date.now(), g.id); await db.run(`UPDATE galleries SET ${sets.join(', ')} WHERE id = ?`, args); }
    json(res, 200, ownerGallery(await q.gallery(g.id)));
  });
  route('POST', /^\/api\/galleries\/([\w-]+)\/(revoke|restore|rotate)$/, async (req, res, m) => {
    requireOwner(req);
    const g = await q.gallery(m[1]); if (!g) throw new HttpError(404, 'Not found');
    if (m[2] === 'revoke') await db.run('UPDATE galleries SET revoked = 1, updated_at = ? WHERE id = ?', [Date.now(), g.id]);
    if (m[2] === 'restore') await db.run('UPDATE galleries SET revoked = 0, updated_at = ? WHERE id = ?', [Date.now(), g.id]);
    // rotate = brand-new link; the old link is dead forever and all visitor sessions are invalidated
    if (m[2] === 'rotate') await db.run('UPDATE galleries SET token = ?, revoked = 0, updated_at = ? WHERE id = ?', [newToken(), Date.now(), g.id]);
    json(res, 200, ownerGallery(await q.gallery(g.id)));
  });
  route('DELETE', /^\/api\/galleries\/([\w-]+)$/, async (req, res, m) => {
    requireOwner(req);
    const g = await q.gallery(m[1]); if (!g) throw new HttpError(404, 'Not found');
    for (const p of await q.photos(g.id)) {
      await storage.del(p.key).catch(() => {});
      if (p.thumb_key) await storage.del(p.thumb_key).catch(() => {});
    }
    await db.run('DELETE FROM photos WHERE gallery_id = ?', [g.id]);
    await db.run('DELETE FROM events WHERE gallery_id = ?', [g.id]);
    await db.run('DELETE FROM galleries WHERE id = ?', [g.id]);
    json(res, 200, { ok: true });
  });

  // --- photos (owner)
  route('POST', /^\/api\/galleries\/([\w-]+)\/photos$/, async (req, res, m, url) => {
    requireOwner(req);
    const g = await q.gallery(m[1]); if (!g) { req.resume(); throw new HttpError(404, 'Not found'); }
    const body = await readBody(req, cfg.maxUploadBytes);
    const mime = sniff(body);
    if (!mime) throw new HttpError(415, 'Only JPEG, PNG and WebP images are supported');
    await checkQuota(body.length);
    const id = uid();
    const key = `g/${g.id}/${id}.${EXT[mime]}`;
    await storage.put(key, body, mime);
    try {
      const pos = Number((await db.all('SELECT COALESCE(MAX(position), 0) + 1 AS n FROM photos WHERE gallery_id = ?', [g.id]))[0].n);
      await db.run('INSERT INTO photos (id, gallery_id, name, key, mime, size, position, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [id, g.id, cleanName(url.searchParams.get('name'), `photo-${pos}.${EXT[mime]}`), key, mime, body.length, pos, Date.now()]);
    } catch (e) { storage.del(key).catch(() => {}); throw e; }
    json(res, 201, photoView(await q.photo(id)));
  });
  route('POST', /^\/api\/photos\/([\w-]+)\/thumb$/, async (req, res, m) => {
    requireOwner(req);
    const p = await q.photo(m[1]); if (!p) { req.resume(); throw new HttpError(404, 'Not found'); }
    await storeThumb({ id: p.gallery_id }, p, await readBody(req, 2 * 1048576));
    json(res, 200, photoView(await q.photo(p.id)));
  });
  route('PUT', /^\/api\/photos\/([\w-]+)\/file$/, async (req, res, m, url) => {
    requireOwner(req);
    const p = await q.photo(m[1]); if (!p) { req.resume(); throw new HttpError(404, 'Not found'); }
    const body = await readBody(req, cfg.maxUploadBytes);
    const mime = sniff(body);
    if (!mime) throw new HttpError(415, 'Only JPEG, PNG and WebP images are supported');
    await checkQuota(Math.max(0, body.length - p.size));
    const key = `g/${p.gallery_id}/${p.id}-${uid().slice(0, 6)}.${EXT[mime]}`;
    await storage.put(key, body, mime);
    const name = url.searchParams.get('name') ? cleanName(url.searchParams.get('name'), p.name) : p.name;
    await db.run('UPDATE photos SET key = ?, mime = ?, size = ?, name = ?, thumb_key = NULL, thumb_size = 0 WHERE id = ?', [key, mime, body.length, name, p.id]);
    storage.del(p.key).catch(() => {});
    if (p.thumb_key) storage.del(p.thumb_key).catch(() => {});
    json(res, 200, photoView(await q.photo(p.id)));
  });
  route('PATCH', /^\/api\/photos\/([\w-]+)$/, async (req, res, m) => {
    requireOwner(req);
    const p = await q.photo(m[1]); if (!p) throw new HttpError(404, 'Not found');
    const { name } = await readJson(req);
    const n = cleanName(name, '');
    if (!n) throw new HttpError(400, 'Name cannot be empty');
    await db.run('UPDATE photos SET name = ? WHERE id = ?', [n, p.id]);
    json(res, 200, photoView(await q.photo(p.id)));
  });
  route('DELETE', /^\/api\/photos\/([\w-]+)$/, async (req, res, m) => {
    requireOwner(req);
    const p = await q.photo(m[1]); if (!p) throw new HttpError(404, 'Not found');
    await db.run('DELETE FROM photos WHERE id = ?', [p.id]);
    await storage.del(p.key).catch(() => {});
    if (p.thumb_key) await storage.del(p.thumb_key).catch(() => {});
    json(res, 200, { ok: true });
  });

  // Small in-memory cache for thumbnails (keys are immutable). Saves storage requests, which matter on free tiers.
  const thumbCache = new Map(); let thumbBytes = 0;
  const THUMB_CACHE_MAX = 40 * 1048576;
  async function getThumb(key) {
    const hit = thumbCache.get(key);
    if (hit) { thumbCache.delete(key); thumbCache.set(key, hit); return hit; }
    const buf = await storage.get(key);
    if (buf && buf.length < 2 * 1048576) {
      thumbCache.set(key, buf); thumbBytes += buf.length;
      for (const [k, v] of thumbCache) { if (thumbBytes <= THUMB_CACHE_MAX) break; thumbCache.delete(k); thumbBytes -= v.length; }
    }
    return buf;
  }

  async function sendImage(res, p, size, headers) {
    const useThumb = size === 'thumb' && p.thumb_key;
    const buf = useThumb ? await getThumb(p.thumb_key) : await storage.get(p.key);
    if (!buf) throw new HttpError(404, 'File missing');
    // Low-resolution previews may be cached by the visitor's browser; full-size images in restricted modes never are.
    if (useThumb) headers = { ...headers, 'cache-control': 'private, max-age=3600' };
    const mime = useThumb ? (sniff(buf) || 'image/webp') : p.mime;
    res.writeHead(200, { 'content-type': mime, 'content-length': buf.length, ...headers });
    res.end(buf);
  }
  route('GET', /^\/api\/owner-img\/([\w-]+)$/, async (req, res, m, url) => {
    requireOwner(req);
    const p = await q.photo(m[1]); if (!p) throw new HttpError(404, 'Not found');
    await sendImage(res, p, url.searchParams.get('size'), { 'cache-control': 'private, max-age=3600' });
  });

  // --- public (visitor) API
  route('GET', /^\/api\/public\/([\w-]+)\/info$/, async (req, res, m) => {
    const g = await visitorGallery(req, m[1], { needAuth: false });
    const unlocked = !g.pw_hash || hasGalleryCookie(req, g);
    json(res, 200, { needsPassword: !!g.pw_hash, unlocked, title: unlocked ? g.title : 'Private gallery' });
  });
  route('POST', /^\/api\/public\/([\w-]+)\/unlock$/, async (req, res, m) => {
    const g = await visitorGallery(req, m[1], { needAuth: false });
    if (!g.pw_hash) return json(res, 200, { ok: true });
    const kIp = `${clientIp(req)}|${g.id}`;
    if (unlockLimit.blocked(kIp) || unlockGlobal.blocked(g.id)) {
      res.setHeader('retry-after', unlockLimit.retryAfter(kIp));
      throw new HttpError(429, 'Too many attempts. Please wait a few minutes and try again.');
    }
    const { password } = await readJson(req);
    if (typeof password !== 'string' || !password || password.length > 200 || !(await verifyPassword(password, g.pw_hash))) {
      unlockLimit.hit(kIp); unlockGlobal.hit(g.id);
      await q.event(g.id, 'unlock_fail');
      throw new HttpError(401, 'Incorrect password');
    }
    unlockLimit.clear(kIp);
    issueGalleryCookie(res, g);
    await q.event(g.id, 'unlock_ok');
    json(res, 200, { ok: true });
  });
  route('GET', /^\/api\/public\/([\w-]+)\/photos$/, async (req, res, m) => {
    const g = await visitorGallery(req, m[1]);
    await q.event(g.id, 'open');
    json(res, 200, {
      title: g.title, mode: g.mode, watermark: g.watermark, canDownload: g.mode !== 'view',
      photos: (await q.photos(g.id)).map((p) => ({ id: p.id, name: p.name, hasThumb: !!p.thumb_key, v: sha(p.key).slice(0, 8) })),
    });
  });
  route('GET', /^\/api\/public\/([\w-]+)\/img\/([\w-]+)$/, async (req, res, m, url) => {
    const g = await visitorGallery(req, m[1]);
    const p = await q.photo(m[2]);
    if (!p || p.gallery_id !== g.id) throw new HttpError(404, 'Not found');
    const h = req.headers;
    const headers = { 'cache-control': 'private, no-store' };
    if (g.mode !== 'full') {
      // Restricted modes: images can only be loaded by the gallery page itself (as <img>), never by
      // opening the URL directly, from another site, or as a downloadable document.
      if (h['sec-fetch-dest'] && h['sec-fetch-dest'] !== 'image') throw new HttpError(403, 'Not allowed');
      if (h['sec-fetch-site'] && h['sec-fetch-site'] !== 'same-origin') throw new HttpError(403, 'Not allowed');
      headers['content-disposition'] = 'inline; filename="photo"';
    } else headers['cache-control'] = 'private, max-age=300';
    await sendImage(res, p, url.searchParams.get('size'), headers);
  });
  route('GET', /^\/api\/public\/([\w-]+)\/download\/([\w-]+)$/, async (req, res, m) => {
    const g = await visitorGallery(req, m[1]);
    if (g.mode === 'view') throw new HttpError(403, 'Downloads are disabled for this gallery');
    const p = await q.photo(m[2]);
    if (!p || p.gallery_id !== g.id) throw new HttpError(404, 'Not found');
    await q.event(g.id, 'download');
    const ext = EXT[p.mime];
    const fname = /\.(jpe?g|png|webp)$/i.test(p.name) ? p.name : `${p.name}.${ext}`;
    await sendImage(res, p, 'full', {
      'cache-control': 'private, no-store',
      'content-disposition': `attachment; filename="${fname.replace(/[^\x20-\x7e]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(fname)}`,
    });
  });
  route('GET', /^\/api\/public\/([\w-]+)\/zip$/, async (req, res, m) => {
    const g = await visitorGallery(req, m[1]);
    if (g.mode === 'view') throw new HttpError(403, 'Downloads are disabled for this gallery');
    const photos = await q.photos(g.id);
    if (!photos.length) throw new HttpError(404, 'This gallery is empty');
    if (photos.reduce((s, p) => s + p.size, 0) > 3.9 * 1073741824) throw new HttpError(413, 'Gallery is too large for a single ZIP. Please download photos individually.');
    await q.event(g.id, 'zip');
    const used = new Set();
    const entries = photos.map((p, i) => {
      let base = cleanName(p.name, `photo-${i + 1}`);
      if (!/\.(jpe?g|png|webp)$/i.test(base)) base += '.' + EXT[p.mime];
      let name = base, n = 1;
      while (used.has(name.toLowerCase())) name = base.replace(/(\.[^.]+)$/, `-${++n}$1`);
      used.add(name.toLowerCase());
      return { name, read: async () => { const b = await storage.get(p.key); if (!b) throw new Error('missing file'); return b; } };
    });
    const zipName = cleanName(g.title, 'gallery').replace(/[^\x20-\x7e]/g, '_');
    res.writeHead(200, { 'content-type': 'application/zip', 'cache-control': 'private, no-store', 'content-disposition': `attachment; filename="${zipName}.zip"` });
    try { await writeZip(res, entries); } catch (e) { log('zip failed', e.message); res.destroy(); }
  });

  // ---------- static files ----------
  const PAGES = { '/': 'index.html', '/login': 'login.html', '/dashboard': 'dashboard.html' };
  const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
  async function serveFile(res, rel, { cache = false } = {}) {
    const abs = path.resolve(PUBLIC_DIR, rel);
    if (!abs.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(404, 'Not found');
    let buf;
    try { buf = await fs.promises.readFile(abs); } catch { throw new HttpError(404, 'Not found'); }
    res.writeHead(200, { 'content-type': TYPES[path.extname(abs)] || 'application/octet-stream', 'cache-control': cache ? 'public, max-age=300' : 'no-store' });
    res.end(buf);
  }

  function securityHeaders(res) {
    res.setHeader('x-robots-tag', 'noindex, nofollow, noarchive, nosnippet');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'no-referrer'); // the secret link must never leak through Referer
    res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('content-security-policy', "default-src 'self'; img-src 'self' blob: data:; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
    if (cfg.secureCookies) res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
  }

  const server = http.createServer(async (req, res) => {
    securityHeaders(res);
    try {
      const url = new URL(req.url, 'http://localhost');
      const p = url.pathname;
      if (p.startsWith('/api/')) {
        for (const r of routes) {
          if (r.method !== req.method) continue;
          const m = p.match(r.re);
          if (m) return await r.fn(req, res, m, url);
        }
        throw new HttpError(404, 'Not found');
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed');
      if (p === '/robots.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('User-agent: *\nDisallow: /\n'); }
      if (PAGES[p]) return await serveFile(res, PAGES[p]);
      if (/^\/g\/[\w-]+\/?$/.test(p)) return await serveFile(res, 'gallery.html');
      if (/^\/assets\/[\w.-]+$/.test(p)) return await serveFile(res, p.slice(1), { cache: true });
      throw new HttpError(404, 'Not found');
    } catch (e) {
      if (res.headersSent) return res.destroy();
      if (e instanceof HttpError) {
        if (req.url.startsWith('/api/')) return json(res, e.status, { error: e.message });
        res.writeHead(e.status, { 'content-type': 'text/plain; charset=utf-8' });
        return res.end(e.status === 404 ? 'Not found' : e.message);
      }
      log('ERROR', req.method, req.url.split('?')[0].replace(/\/public\/[^/]+/, '/public/<token>'), e.message);
      json(res, 500, { error: 'Something went wrong. Please try again.' });
    }
  });
  server.requestTimeout = 10 * 60 * 1000;
  server.listen(cfg.port, () => log(`Lumen running on port ${cfg.port} | storage: ${storage.label} | database: ${db.kind}`));
  process.on('SIGTERM', () => server.close(() => process.exit(0)));
}

main().catch((e) => { console.error(e); process.exit(1); });
