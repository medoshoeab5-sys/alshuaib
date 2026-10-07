'use strict';

/*
  منصة الشعيب — الخادم الخلفي (Backend)
  ------------------------------------
  خادم Node.js بلا أي تبعيات خارجية:
  - node:http    لاستقبال الطلبات
  - node:sqlite  قاعدة بيانات SQLite محلية على القرص
  - node:crypto  تجزئة كلمات المرور (scrypt) والجلسات والتحقق بتوقيت آمن

  كلمات المرور لا تُحفظ كنص صريح أبداً:
  - الحسابات الجديدة:                       s2$<saltHex>$<scryptKeyHex>
  - الحسابات المُرحَّلة من النسخة المحلية:  s1$<salt>$<sha256Hex>  (وبعد أول تسجيل دخول ناجح
    تُرقَّى تلقائياً إلى صيغة scrypt الحديثة دون أن يشعر الطالب بأي فرق).

  الجلسات تُدار على الخادم فقط: رمز عشوائي في كوكي HttpOnly، ويُحفظ في قاعدة البيانات
  بصمته (SHA-256) وليس الرمز نفسه — فلا يمكن سرقة الجلسة من قاعدة البيانات.
*/

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const PORT = Number(process.env.PORT) || 3000;
const DB_PATH = path.resolve(ROOT, process.env.DATABASE_PATH || './data/alshuaib.db');
const NODE_ENV = process.env.NODE_ENV || 'development';

const COOKIE_NAME = 'alshuaib_session';
const SESSION_REMEMBER_MS = 30 * 24 * 60 * 60 * 1000; /* تذكرني: 30 يوماً */
const SESSION_SHORT_MS = 12 * 60 * 60 * 1000;         /* بدون تذكرني: 12 ساعة (كوكي جلسة) */
const BODY_LIMIT = 2 * 1024 * 1024;                   /* 2MB كحد أقصى لجسم الطلب */
const AVATAR_LIMIT = 400000;                          /* ~390KB لصورة الحساب (Data URL) */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const AVATAR_RE = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;

/* ===== قاعدة البيانات ===== */
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS students (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT,
    legacy        INTEGER NOT NULL DEFAULT 0,
    avatar        TEXT,
    created_at    INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    remember   INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_student ON sessions(student_id);
`);

/* ===== أدوات التشفير ===== */
const sha256hex = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch { return false; }
}

function scryptHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = crypto.scryptSync(password, Buffer.from(salt, 'hex'), 32).toString('hex');
  return 's2$' + salt + '$' + key;
}

/* يتحقق من كلمة المرور مقابل المخزون (s2 الحديث أو s1 المُرحَّل)، ويطلب الترقية عند الحاجة */
function verifyPassword(stored, password) {
  if (typeof stored !== 'string' || !stored) return { ok: false, needsUpgrade: false };
  const parts = stored.split('$');
  if (parts[0] === 's2' && parts.length === 3) {
    const key = crypto.scryptSync(password, Buffer.from(parts[1], 'hex'), 32).toString('hex');
    return { ok: safeEqualHex(key, parts[2]), needsUpgrade: false };
  }
  if (parts[0] === 's1' && parts.length === 3) {
    const ok = safeEqualHex(sha256hex(parts[1] + ':' + password), parts[2]);
    return { ok, needsUpgrade: ok };
  }
  return { ok: false, needsUpgrade: false };
}

/* ===== الجلسات (على الخادم) ===== */
function createSession(res, studentId, remember, secure) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = sha256hex(token);
  const now = Date.now();
  const expiresAt = now + (remember ? SESSION_REMEMBER_MS : SESSION_SHORT_MS);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  db.prepare('INSERT INTO sessions (token_hash, student_id, created_at, expires_at, remember) VALUES (?, ?, ?, ?, ?)')
    .run(tokenHash, studentId, now, expiresAt, remember ? 1 : 0);
  let cookie = COOKIE_NAME + '=' + token + '; Path=/; HttpOnly; SameSite=Lax';
  if (remember) cookie += '; Max-Age=' + Math.floor(SESSION_REMEMBER_MS / 1000);
  if (secure) cookie += '; Secure';
  res.setHeader('Set-Cookie', cookie);
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  raw.split(';').forEach(pair => {
    const i = pair.indexOf('=');
    if (i > 0) out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  });
  return out;
}

/* يعيد {student, tokenHash} للجلسة الصالحة، أو null */
function getSession(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token || token.length > 200) return null;
  const tokenHash = sha256hex(token);
  const row = db.prepare(`
    SELECT s.id AS sid, s.email, s.name, s.avatar, s.legacy, s.created_at, se.expires_at
    FROM sessions se JOIN students s ON s.id = se.student_id
    WHERE se.token_hash = ?
  `).get(tokenHash);
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
    return null;
  }
  return { student: publicStudent(row), tokenHash };
}

function publicStudent(row) {
  return {
    name: row.name,
    email: row.email,
    createdAt: row.created_at,
    avatar: row.avatar || null,
    legacy: !!row.legacy
  };
}

/* ===== تحديد معدل الطلبات (حماية من التخمين) ===== */
const rateBuckets = new Map();
function rateLimited(ip, key, limit, windowMs) {
  const now = Date.now();
  const id = key + ':' + ip;
  let b = rateBuckets.get(id);
  if (!b || b.resetAt < now) { b = { count: 0, resetAt: now + windowMs }; rateBuckets.set(id, b); }
  b.count++;
  if (rateBuckets.size > 5000) {
    for (const [k, v] of rateBuckets) if (v.resetAt < now) rateBuckets.delete(k);
  }
  return b.count > limit;
}

/* ===== أدوات HTTP ===== */
function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; " +
    "img-src 'self' data:; " +
    "connect-src 'self'; " +
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  securityHeaders(res);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

const sendError = (res, status, code) => sendJson(res, status, { error: code });

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > BODY_LIMIT) { reject(new Error('BODY_TOO_LARGE')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new Error('BAD_JSON')); }
    });
    req.on('error', reject);
  });
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function isSecureRequest(req) {
  if (req.socket.encrypted) return true;
  const proto = req.headers['x-forwarded-proto'];
  return typeof proto === 'string' && proto.split(',')[0].trim() === 'https';
}

/* يمنع الطلبات المتغيّرة من نطاقات أخرى (حماية CSRF إضافية فوق SameSite) */
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin || origin === 'null') return true;
  try { return new URL(origin).host === req.headers.host; }
  catch { return false; }
}

/* ===== التحقق من المدخلات ===== */
const normEmail = e => String(e || '').trim().toLowerCase();

function validName(v) { const s = String(v || '').trim(); return s.length >= 2 && s.length <= 100 ? s : null; }
function validPassword(v) { return typeof v === 'string' && v.length >= 6 && v.length <= 128; }
function validAvatar(v) { return v === null || (typeof v === 'string' && v.length <= AVATAR_LIMIT && AVATAR_RE.test(v)); }

/* ===== مسارات الـ API ===== */
async function handleApi(req, res, url) {
  const route = url.pathname;
  const method = req.method;

  if (!['GET', 'POST', 'PATCH'].includes(method)) return sendError(res, 405, 'METHOD_NOT_ALLOWED');
  if (method !== 'GET' && !sameOrigin(req)) return sendError(res, 403, 'FORBIDDEN');

  /* GET /api/health — فحص الحالة */
  if (route === '/api/health' && method === 'GET') {
    return sendJson(res, 200, { ok: true, time: Date.now() });
  }

  /* GET /api/stats — عداد الطلاب من قاعدة البيانات الحقيقية */
  if (route === '/api/stats' && method === 'GET') {
    const row = db.prepare('SELECT COUNT(*) AS n FROM students').get();
    return sendJson(res, 200, { students: Number(row.n) });
  }

  /* GET /api/students/exists?email= — فحص تعارض بريد الطلاب (لنظام المدرسين) */
  if (route === '/api/students/exists' && method === 'GET') {
    if (rateLimited(clientIp(req), 'exists', 120, 15 * 60 * 1000)) return sendError(res, 429, 'RATE_LIMITED');
    const email = normEmail(url.searchParams.get('email'));
    if (!email || email.length > 254 || !EMAIL_RE.test(email)) return sendJson(res, 200, { exists: false });
    const row = db.prepare('SELECT id FROM students WHERE email = ?').get(email);
    return sendJson(res, 200, { exists: !!row });
  }

  /* POST /api/auth/signup — إنشاء حساب طالب جديد */
  if (route === '/api/auth/signup' && method === 'POST') {
    if (rateLimited(clientIp(req), 'auth', 30, 15 * 60 * 1000)) return sendError(res, 429, 'RATE_LIMITED');
    const body = await readBody(req);
    const name = validName(body.name);
    if (!name) return sendError(res, 400, 'INVALID_NAME');
    const email = normEmail(body.email);
    if (!email || email.length > 254 || !EMAIL_RE.test(email)) return sendError(res, 400, 'INVALID_EMAIL');
    if (!validPassword(body.password)) return sendError(res, 400, 'WEAK_PASSWORD');

    const existing = db.prepare('SELECT id, legacy FROM students WHERE email = ?').get(email);
    const hash = scryptHash(body.password);
    let studentId;
    if (existing && existing.legacy) {
      /* إكمال حساب قديم مُرحَّل — لا يُحتسب الطالب مرتين */
      db.prepare('UPDATE students SET name = ?, password_hash = ?, legacy = 0 WHERE id = ?')
        .run(name, hash, existing.id);
      studentId = existing.id;
    } else if (existing) {
      return sendError(res, 409, 'EMAIL_TAKEN');
    } else {
      const r = db.prepare('INSERT INTO students (email, name, password_hash, legacy, created_at) VALUES (?, ?, ?, 0, ?)')
        .run(email, name, hash, Date.now());
      studentId = Number(r.lastInsertRowid);
    }
    createSession(res, studentId, true, isSecureRequest(req));
    const row = db.prepare('SELECT name, email, created_at, avatar, legacy FROM students WHERE id = ?').get(studentId);
    return sendJson(res, existing ? 200 : 201, { student: publicStudent(row) });
  }

  /* POST /api/auth/login — تسجيل الدخول */
  if (route === '/api/auth/login' && method === 'POST') {
    if (rateLimited(clientIp(req), 'auth', 30, 15 * 60 * 1000)) return sendError(res, 429, 'RATE_LIMITED');
    const body = await readBody(req);
    const email = normEmail(body.email);
    const password = typeof body.password === 'string' ? body.password : '';
    const remember = !!body.remember;
    if (!email || !password) return sendError(res, 400, 'INVALID_INPUT');

    const acc = db.prepare('SELECT id, email, name, password_hash, legacy, avatar, created_at FROM students WHERE email = ?').get(email);
    if (!acc) return sendError(res, 401, 'NO_ACCOUNT');
    if (acc.legacy || !acc.password_hash) return sendError(res, 401, 'LEGACY_ACCOUNT');
    const check = verifyPassword(acc.password_hash, password);
    if (!check.ok) return sendError(res, 401, 'WRONG_PASSWORD');
    if (check.needsUpgrade) {
      /* ترقية شفافة: الصيغة القديمة sha256 تصبح scrypt بعد أول دخول ناجح */
      db.prepare('UPDATE students SET password_hash = ? WHERE id = ?').run(scryptHash(password), acc.id);
    }
    createSession(res, acc.id, remember, isSecureRequest(req));
    return sendJson(res, 200, { student: publicStudent(acc) });
  }

  /* POST /api/auth/logout — تسجيل الخروج */
  if (route === '/api/auth/logout' && method === 'POST') {
    const token = parseCookies(req)[COOKIE_NAME];
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256hex(token));
    res.setHeader('Set-Cookie', COOKIE_NAME + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }

  /* GET /api/auth/me — الطالب صاحب الجلسة الحالية (لا يُكشف أي طالب آخر)
     بلا جلسة: 200 مع student = null (استعلام هادئ عند الإقلاع بلا أخطاء في الـConsole) */
  if (route === '/api/auth/me' && method === 'GET') {
    const session = getSession(req);
    return sendJson(res, 200, { student: session ? session.student : null });
  }

  /* PATCH /api/auth/profile — تعديل الاسم والصورة */
  if (route === '/api/auth/profile' && method === 'PATCH') {
    const session = getSession(req);
    if (!session) return sendError(res, 401, 'NO_SESSION');
    const body = await readBody(req);
    const email = session.student.email;
    if (body.name !== undefined) {
      const name = validName(body.name);
      if (!name) return sendError(res, 400, 'INVALID_NAME');
      db.prepare('UPDATE students SET name = ? WHERE email = ?').run(name, email);
    }
    if (body.avatar !== undefined) {
      if (!validAvatar(body.avatar)) return sendError(res, 400, 'INVALID_AVATAR');
      db.prepare('UPDATE students SET avatar = ? WHERE email = ?').run(body.avatar, email);
    }
    const row = db.prepare('SELECT name, email, created_at, avatar, legacy FROM students WHERE email = ?').get(email);
    return sendJson(res, 200, { student: publicStudent(row) });
  }

  /* POST /api/auth/password — تغيير كلمة المرور */
  if (route === '/api/auth/password' && method === 'POST') {
    if (rateLimited(clientIp(req), 'auth', 30, 15 * 60 * 1000)) return sendError(res, 429, 'RATE_LIMITED');
    const session = getSession(req);
    if (!session) return sendError(res, 401, 'NO_SESSION');
    const body = await readBody(req);
    const current = typeof body.currentPassword === 'string' ? body.currentPassword : '';
    const next = typeof body.newPassword === 'string' ? body.newPassword : '';
    if (!validPassword(next)) return sendError(res, 400, 'WEAK_PASSWORD');
    if (next === current) return sendError(res, 400, 'SAME_PASSWORD');

    const row = db.prepare('SELECT id, password_hash, legacy FROM students WHERE email = ?').get(session.student.email);
    if (!row) return sendError(res, 401, 'NO_SESSION');
    if (row.legacy || !row.password_hash) return sendError(res, 401, 'LEGACY_ACCOUNT');
    const check = verifyPassword(row.password_hash, current);
    if (!check.ok) return sendError(res, 401, 'WRONG_CURRENT');
    db.prepare('UPDATE students SET password_hash = ? WHERE id = ?').run(scryptHash(next), row.id);
    /* أمان: إبطال كل الجلسات الأخرى مع إبقاء الجلسة الحالية */
    db.prepare('DELETE FROM sessions WHERE student_id = ? AND token_hash != ?').run(row.id, session.tokenHash);
    return sendJson(res, 200, { ok: true });
  }

  /* POST /api/migrate — ترحيل لمرة واحدة للحسابات المحفوظة محلياً في المتصفح */
  if (route === '/api/migrate' && method === 'POST') {
    if (rateLimited(clientIp(req), 'migrate', 10, 15 * 60 * 1000)) return sendError(res, 429, 'RATE_LIMITED');
    const body = await readBody(req);
    const list = Array.isArray(body.accounts) ? body.accounts.slice(0, 5000) : [];
    let migrated = 0, skipped = 0;
    for (const item of list) {
      if (!item || typeof item !== 'object') { skipped++; continue; }
      const email = normEmail(item.email);
      if (!email || email.length > 254 || !EMAIL_RE.test(email)) { skipped++; continue; }
      const name = typeof item.name === 'string' ? item.name.trim().slice(0, 100) : '';
      const createdAt = Number.isFinite(+item.createdAt) && +item.createdAt > 0 ? Math.floor(+item.createdAt) : Date.now();
      const isLegacyPlaceholder = !!item.legacy;
      const hasHash = typeof item.salt === 'string' && /^[0-9a-f]{32}$/i.test(item.salt) &&
                      typeof item.hash === 'string' && /^[0-9a-f]{64}$/i.test(item.hash);
      if (!isLegacyPlaceholder && !hasHash) { skipped++; continue; }
      const avatar = validAvatar(item.avatar) ? (item.avatar || null) : null;
      const passwordHash = hasHash ? 's1$' + item.salt.toLowerCase() + '$' + item.hash.toLowerCase() : null;

      const existing = db.prepare('SELECT id, legacy FROM students WHERE email = ?').get(email);
      if (!existing) {
        db.prepare('INSERT INTO students (email, name, password_hash, legacy, avatar, created_at) VALUES (?, ?, ?, ?, ?, ?)')
          .run(email, name, passwordHash, isLegacyPlaceholder && !hasHash ? 1 : 0, avatar, createdAt);
        migrated++;
      } else if (existing.legacy && hasHash) {
        /* موجود كسجل قديم بلا كلمة مرور، والمصدر المحلي يملك كلمة مرور — نكتمله */
        db.prepare('UPDATE students SET name = ?, password_hash = ?, legacy = 0, avatar = COALESCE(?, avatar) WHERE id = ?')
          .run(name, passwordHash, avatar, existing.id);
        migrated++;
      } else {
        skipped++;
      }
    }
    return sendJson(res, 200, { migrated, skipped });
  }

  return sendError(res, 404, 'NOT_FOUND');
}

/* ===== تقديم الملفات الثابتة ===== */
const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2'
};
const DENY_FILES = new Set(['server.js', 'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);

function serveStatic(req, res, url) {
  let pathname;
  try { pathname = decodeURIComponent(url.pathname); }
  catch { return sendPlain(res, 400, 'طلب غير صالح.'); }
  if (pathname.includes('\0')) return sendPlain(res, 400, 'طلب غير صالح.');
  if (pathname === '/' || pathname === '') pathname = '/index.html';

  const resolved = path.resolve(ROOT, '.' + path.posix.normalize(pathname));
  const base = path.basename(resolved);
  if (!resolved.startsWith(ROOT + path.sep) || base.startsWith('.') || DENY_FILES.has(base)) {
    return sendPlain(res, 404, 'الصفحة غير موجودة.');
  }
  const ext = path.extname(resolved).toLowerCase();
  const type = STATIC_TYPES[ext];
  if (!type) return sendPlain(res, 404, 'الصفحة غير موجودة.');

  fs.stat(resolved, (err, stat) => {
    if (err || !stat.isFile()) return sendPlain(res, 404, 'الصفحة غير موجودة.');
    securityHeaders(res);
    res.writeHead(200, {
      'Content-Type': type,
      'Content-Length': stat.size,
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400'
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(resolved).pipe(res);
  });
}

function sendPlain(res, status, msg) {
  securityHeaders(res);
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(msg);
}

/* ===== الخادم ===== */
const server = http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://' + (req.headers.host || 'localhost')); }
  catch { return sendPlain(res, 400, 'طلب غير صالح.'); }

  try {
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, url);
    return sendPlain(res, 405, 'الطريقة غير مدعومة.');
  } catch (err) {
    if (err && err.message === 'BODY_TOO_LARGE') return sendError(res, 413, 'BODY_TOO_LARGE');
    if (err && err.message === 'BAD_JSON') return sendError(res, 400, 'BAD_JSON');
    console.error('[خطأ داخلي]', err && err.message ? err.message : err);
    if (!res.headersSent) return sendError(res, 500, 'INTERNAL_ERROR');
    res.end();
  }
});

server.listen(PORT, () => {
  console.log('==============================================');
  console.log('  منصة الشعيب — الخادم يعمل الآن');
  console.log('  http://localhost:' + PORT);
  console.log('  قاعدة البيانات: ' + DB_PATH);
  console.log('  البيئة: ' + NODE_ENV);
  console.log('==============================================');
});

function shutdown() {
  server.close(() => {
    try { db.close(); } catch {}
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
