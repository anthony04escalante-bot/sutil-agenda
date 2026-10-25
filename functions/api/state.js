// API de la agenda: clave de acceso + datos compartidos entre celulares.
// Requiere un binding D1 llamado DB (Pages → Settings → Bindings).
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const rand = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const SESSION_DAYS = 120, MAX_FAILS = 5, LOCK_MIN = 15, KEEP = 40, SNAP_EVERY_MS = 30 * 60 * 1000;

async function hashPin(pin, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
async function sha(t) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(t))); }
const same = (a, b) => a.length === b.length && a.split('').reduce((r, c, i) => r | (c.charCodeAt(0) ^ b.charCodeAt(i)), 0) === 0;

async function init(DB) {
  await DB.batch([
    DB.prepare('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)'),
    DB.prepare('CREATE TABLE IF NOT EXISTS sessions (h TEXT PRIMARY KEY, created INTEGER)'),
    DB.prepare('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, rev INTEGER, data TEXT, updated INTEGER)'),
    DB.prepare('CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, rev INTEGER, data TEXT, ts INTEGER)'),
  ]);
}
const getMeta = async (DB, k) => (await DB.prepare('SELECT v FROM meta WHERE k=?').bind(k).first())?.v ?? null;
const setMeta = (DB, k, v) => DB.prepare('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind(k, String(v)).run();

async function newSession(DB) {
  const t = rand(24);
  await DB.prepare('INSERT INTO sessions(h,created) VALUES(?,?)').bind(await sha(t), Date.now()).run();
  await DB.prepare('DELETE FROM sessions WHERE created<?').bind(Date.now() - SESSION_DAYS * 864e5).run();
  return t;
}
async function sessionOk(DB, req) {
  const t = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!t) return false;
  const r = await DB.prepare('SELECT created FROM sessions WHERE h=?').bind(await sha(t)).first();
  return !!r && r.created > Date.now() - SESSION_DAYS * 864e5;
}
async function checkPin(DB, pin) {
  const until = +(await getMeta(DB, 'lock_until')) || 0;
  if (until > Date.now()) return { ok: false, locked: Math.ceil((until - Date.now()) / 60000) };
  const salt = await getMeta(DB, 'salt'), h = await getMeta(DB, 'pin');
  if (!salt || !h) return { ok: false, setup: true };
  if (same(await hashPin(String(pin || ''), salt), h)) { await setMeta(DB, 'fails', 0); return { ok: true }; }
  const f = (+(await getMeta(DB, 'fails')) || 0) + 1;
  if (f >= MAX_FAILS) { await setMeta(DB, 'fails', 0); await setMeta(DB, 'lock_until', Date.now() + LOCK_MIN * 60000); return { ok: false, locked: LOCK_MIN }; }
  await setMeta(DB, 'fails', f);
  return { ok: false, left: MAX_FAILS - f };
}
async function putState(DB, rev, data, prev) {
  const now = Date.now();
  if (prev && prev.data) {
    const last = await DB.prepare('SELECT ts FROM history ORDER BY id DESC LIMIT 1').first();
    if (!last || now - last.ts > SNAP_EVERY_MS || data.length < prev.data.length * 0.6) {
      await DB.prepare('INSERT INTO history(rev,data,ts) VALUES(?,?,?)').bind(prev.rev, prev.data, now).run();
      await DB.prepare('DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT ?)').bind(KEEP).run();
    }
  }
  await DB.prepare('INSERT INTO state(id,rev,data,updated) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET rev=excluded.rev,data=excluded.data,updated=excluded.updated').bind(rev, data, now).run();
}
const validPin = (p) => /^\d{4,8}$/.test(String(p || ''));
const validData = (d) => d && typeof d === 'object' && Array.isArray(d.services) && Array.isArray(d.appts) && Array.isArray(d.clients) && d.settings;

export async function onRequest({ request, env }) {
  const DB = env.DB;
  if (!DB) return J({ error: 'no_db' }, 503);
  try {
    await init(DB);
    const url = new URL(request.url), act = url.searchParams.get('a') || '';
    const hasPin = !!(await getMeta(DB, 'pin'));

    if (request.method === 'GET' && act === 'status') return J({ setup: !hasPin });

    if (request.method === 'POST' && act === 'setup') {
      if (hasPin) return J({ error: 'ya_configurada' }, 409);
      const b = await request.json();
      if (!validPin(b.pin)) return J({ error: 'pin_invalido' }, 400);
      const salt = rand(16);
      await setMeta(DB, 'salt', salt); await setMeta(DB, 'pin', await hashPin(b.pin, salt));
      let rev = 0;
      if (validData(b.data)) { rev = 1; await putState(DB, rev, JSON.stringify(b.data), null); }
      return J({ token: await newSession(DB), rev });
    }

    if (request.method === 'POST' && act === 'login') {
      const b = await request.json(), r = await checkPin(DB, b.pin);
      if (!r.ok) return J(r, r.locked ? 429 : 401);
      return J({ token: await newSession(DB) });
    }

    if (request.method === 'POST' && act === 'changepin') {
      const b = await request.json();
      if (!validPin(b.next)) return J({ error: 'pin_invalido' }, 400);
      const r = await checkPin(DB, b.pin);
      if (!r.ok) return J(r, r.locked ? 429 : 401);
      const salt = rand(16);
      await setMeta(DB, 'salt', salt); await setMeta(DB, 'pin', await hashPin(b.next, salt));
      await DB.prepare('DELETE FROM sessions').run();
      return J({ token: await newSession(DB) });
    }

    // Desde aquí hace falta una sesión iniciada con la clave
    if (!(await sessionOk(DB, request))) return J({ error: 'no_auth', setup: !hasPin }, 401);

    if (request.method === 'POST' && act === 'logout') {
      const t = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
      await DB.prepare('DELETE FROM sessions WHERE h=?').bind(await sha(t)).run();
      return J({ ok: true });
    }

    if (request.method === 'GET') {
      const s = await DB.prepare('SELECT rev,data FROM state WHERE id=1').first();
      const have = +url.searchParams.get('rev');
      if (!s) return J({ rev: 0, data: null });
      if (have && have === s.rev) return J({ rev: s.rev, same: true });
      return J({ rev: s.rev, data: JSON.parse(s.data) });
    }

    if (request.method === 'PUT') {
      const b = await request.json();
      if (!validData(b.data)) return J({ error: 'datos_invalidos' }, 400);
      const s = await DB.prepare('SELECT rev,data FROM state WHERE id=1').first();
      const cur = s ? s.rev : 0;
      if ((+b.rev || 0) !== cur) return J({ conflict: true, rev: cur, data: s ? JSON.parse(s.data) : null }, 409);
      const body = JSON.stringify(b.data);
      if (body.length > 1800000) return J({ error: 'muy_grande' }, 413);
      await putState(DB, cur + 1, body, s);
      return J({ rev: cur + 1 });
    }

    return J({ error: 'ruta' }, 404);
  } catch (e) {
    return J({ error: 'servidor', detail: String(e && e.message || e) }, 500);
  }
}
