const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'daviwld';
const ADMIN_PASS = process.env.ADMIN_PASS || 'luan4520r';
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { settings: { siteTitle: 'JSON Host', siteSubtitle: 'Arquivos JSON disponíveis publicamente.' }, items: [] };
try {
  const r = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (Array.isArray(r)) db.items = r;
  else db = { settings: { ...db.settings, ...(r.settings || {}) }, items: r.items || [] };
} catch {}
let items = db.items;
const save = () => { db.items = items; fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); };

// ---------- sessão (cookie assinado) ----------
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const sha = (v) => crypto.createHash('sha256').update(String(v)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function makeToken() {
  const exp = String(Date.now() + 1000 * 60 * 60 * 12); // 12h
  return exp + '.' + sign(exp);
}
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!exp || !sig || !same(sig, sign(exp))) return false;
  return Number(exp) > Date.now();
}
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map((c) => c.trim()).find((c) => c.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
const isAuth = (req) => validToken(getCookie(req, 'sid'));
const requireAuth = (req, res, next) => (isAuth(req) ? next() : res.status(401).json({ error: 'Não autorizado' }));

// ---------- anti força-bruta simples ----------
const attempts = new Map();
function tooMany(ip) {
  const a = attempts.get(ip);
  return a && a.count >= 5 && Date.now() - a.last < 15 * 60 * 1000;
}
function fail(ip) {
  const a = attempts.get(ip) || { count: 0 };
  attempts.set(ip, { count: a.count + 1, last: Date.now() });
}

// ---------- rotas públicas ----------
app.get('/api/public', (req, res) => {
  res.json({
    settings: db.settings,
    items: items.filter((i) => i.public).map(({ slug, title, content, updatedAt }) => ({ slug, title, content, updatedAt })),
  });
});

// JSON puro: /j/meu-arquivo  ou  /j/meu-arquivo.json
app.get('/j/:slug', (req, res) => {
  const slug = req.params.slug.replace(/\.json$/, '');
  const item = items.find((i) => i.slug === slug);
  if (!item) return res.status(404).json({ error: 'Não encontrado' });
  res.set('Access-Control-Allow-Origin', '*');
  res.type('application/json').send(item.content);
});

// ---------- admin (endereço separado: /admin) ----------
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.post('/admin/api/login', (req, res) => {
  if (tooMany(req.ip)) return res.status(429).json({ error: 'Muitas tentativas. Tente em 15 minutos.' });
  const { user, pass } = req.body || {};
  const ok = same(user || '', ADMIN_USER) & same(pass || '', ADMIN_PASS);
  if (!ok) { fail(req.ip); return res.status(401).json({ error: 'Usuário ou senha inválidos' }); }
  attempts.delete(req.ip);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${secure}`);
  res.json({ ok: true });
});

app.post('/admin/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/admin/api/me', (req, res) => res.json({ auth: isAuth(req) }));

app.get('/admin/api/settings', requireAuth, (req, res) => res.json(db.settings));
app.put('/admin/api/settings', requireAuth, (req, res) => {
  const { siteTitle, siteSubtitle } = req.body || {};
  if (!siteTitle || siteTitle.length > 100) return res.status(400).json({ error: 'Título do site obrigatório' });
  db.settings = { siteTitle: String(siteTitle), siteSubtitle: String(siteSubtitle || '').slice(0, 300) };
  save();
  res.json({ ok: true });
});

app.get('/admin/api/items', requireAuth, (req, res) => res.json(items));

function validate(body) {
  const { title, slug, content } = body || {};
  if (!/^[a-z0-9_-]{1,60}$/.test(slug || '')) return 'Slug inválido (use a-z, 0-9, - e _)';
  if (!title || title.length > 120) return 'Título obrigatório';
  try { JSON.parse(content); } catch (e) { return 'JSON inválido: ' + e.message; }
  return null;
}

app.post('/admin/api/items', requireAuth, (req, res) => {
  const err = validate(req.body);
  if (err) return res.status(400).json({ error: err });
  if (items.some((i) => i.slug === req.body.slug)) return res.status(409).json({ error: 'Slug já existe' });
  const { title, slug, content, public: pub } = req.body;
  items.push({ title, slug, content, public: !!pub, updatedAt: new Date().toISOString() });
  save();
  res.json({ ok: true });
});

app.put('/admin/api/items/:slug', requireAuth, (req, res) => {
  const idx = items.findIndex((i) => i.slug === req.params.slug);
  if (idx < 0) return res.status(404).json({ error: 'Não encontrado' });
  const err = validate(req.body);
  if (err) return res.status(400).json({ error: err });
  if (req.body.slug !== req.params.slug && items.some((i) => i.slug === req.body.slug))
    return res.status(409).json({ error: 'Slug já existe' });
  const { title, slug, content, public: pub } = req.body;
  items[idx] = { title, slug, content, public: !!pub, updatedAt: new Date().toISOString() };
  save();
  res.json({ ok: true });
});

app.delete('/admin/api/items/:slug', requireAuth, (req, res) => {
  items = items.filter((i) => i.slug !== req.params.slug);
  save();
  res.json({ ok: true });
});

// ---------- site público ----------
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', extensions: ['html'] }));

app.listen(PORT, () => console.log('Rodando na porta ' + PORT));
