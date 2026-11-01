import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

const E = process.env;
for (const k of ['JWT_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'RAPIDFILE_SECRET_KEY']) {
  if (!E[k]) { console.error('Missing env: ' + k); process.exit(1); }
}

const db = createClient(E.SUPABASE_URL, E.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });
const RF = 'https://api.rapidfile.cc/v1';
const pub = (key) => (key ? `https://cdn.rapidfile.cc/${key}` : null); // key = '<fileId>/<fileName>'

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: (E.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean) }));
app.use(express.json({ limit: '100kb' }));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : NaN);
const phoneOf = (v) => str(v, 20).replace(/[^\d+]/g, '');

const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const apiLimit = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use(apiLimit);

// ---------- auth helpers ----------
const sign = (u) => jwt.sign({ id: u.id, role: u.role }, E.JWT_SECRET, { expiresIn: '7d' });
const clean = ({ password_hash, ...u }) => ({ ...u, avatar_url: pub(u.avatar_key) });

const auth = (...roles) => wrap(async (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    const p = jwt.verify(t, E.JWT_SECRET);
    const { data: u } = await db.from('users').select('id,role,status').eq('id', p.id).single();
    if (!u || u.status === 'blocked') return bad(res, 'Account unavailable', 403);
    if (roles.length && !roles.includes(u.role)) return bad(res, 'Forbidden', 403);
    req.user = u;
    next();
  } catch { return bad(res, 'Login required', 401); }
});

const myShop = async (uid) => (await db.from('shops').select('*').eq('owner_id', uid).maybeSingle()).data;

// ---------- health ----------
app.get('/health', (_q, r) => r.json({ ok: true }));

// ---------- auth ----------
app.post('/auth/register', authLimit, wrap(async (req, res) => {
  const b = req.body || {};
  const role = b.role === 'seller' ? 'seller' : 'customer'; // admin can never self-register
  const name = str(b.name, 80), phone = phoneOf(b.phone), email = str(b.email, 120).toLowerCase() || null;
  const password = typeof b.password === 'string' ? b.password : '';
  if (name.length < 2) return bad(res, 'Name required');
  if (!/^\+?\d{10,14}$/.test(phone)) return bad(res, 'Valid phone required');
  if (email && !/^\S+@\S+\.\S+$/.test(email)) return bad(res, 'Invalid email');
  if (password.length < 8) return bad(res, 'Password must be 8+ characters');
  if (role === 'seller' && str(b.shop_name).length < 2) return bad(res, 'Shop name required');

  const address = role === 'customer' && b.address ? {
    line: str(b.address.line), city: str(b.address.city, 60), state: str(b.address.state, 60),
    country: str(b.address.country, 60) || 'India', pin: str(b.address.pin, 10),
  } : null;

  const { data: u, error } = await db.from('users').insert({
    role, name, phone, email, address,
    password_hash: await bcrypt.hash(password, 10),
    status: role === 'seller' ? 'pending' : 'active',
  }).select().single();
  if (error) { if (error.code !== '23505') console.error('register failed:', error.code, error.message); const dbg = E.DEBUG_ERRORS === 'true' ? ` [${error.code || ''} ${String(error.message).slice(0, 160)}]` : ''; /* temporary: set DEBUG_ERRORS=true to see the real DB error on screen */ return bad(res, error.code === '23505' ? 'Phone or email already registered' : 'Could not register' + dbg, error.code === '23505' ? 409 : 500); }

  if (role === 'seller') {
    await db.from('shops').insert({ owner_id: u.id, name: str(b.shop_name, 80), category: str(b.category, 40), area: str(b.area, 60) });
  }
  res.status(201).json({ token: sign(u), user: clean(u), note: role === 'seller' ? 'Admin approval pending' : undefined });
}));

app.post('/auth/login', authLimit, wrap(async (req, res) => {
  const id = str(req.body?.id, 120).toLowerCase(); // phone or email
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!id || !password) return bad(res, 'Phone/email and password required');
  const { data: u } = await db.from('users').select('*').match(id.includes('@') ? { email: id } : { phone: phoneOf(id) }).maybeSingle();
  // same error for unknown user / wrong password (no user enumeration)
  const ok = u && (await bcrypt.compare(password, u.password_hash));
  if (!ok) return bad(res, 'Invalid credentials', 401);
  if (u.status === 'blocked') return bad(res, 'Account blocked', 403);
  res.json({ token: sign(u), user: clean(u) });
}));

app.get('/me', auth(), wrap(async (req, res) => {
  const { data: u } = await db.from('users').select('*').eq('id', req.user.id).single();
  res.json({ user: clean(u), shop: u.role === 'seller' ? await myShop(u.id) : null });
}));

app.patch('/me', auth(), wrap(async (req, res) => {
  const b = req.body || {}, patch = {};
  if (b.name) patch.name = str(b.name, 80);
  if (b.address) patch.address = { line: str(b.address.line), city: str(b.address.city, 60), state: str(b.address.state, 60), country: str(b.address.country, 60) || 'India', pin: str(b.address.pin, 10) };
  if (b.avatar_key) patch.avatar_key = ownKey(b.avatar_key, `avatar_${req.user.id}_`);
  if (b.password) {
    if (b.password.length < 8) return bad(res, 'Password must be 8+ characters');
    patch.password_hash = await bcrypt.hash(b.password, 10);
  }
  const { data } = await db.from('users').update(patch).eq('id', req.user.id).select().single();
  res.json({ user: clean(data) });
}));

// ---------- Image upload (Rapidfile Upload API -> CDN) ----------
const MIME = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const FOLDERS = { avatar: ['customer', 'seller', 'admin'], product: ['seller'], shop: ['seller'], ad: ['admin'] };
const MAX_BYTES = 5 * 1024 * 1024;

// key = '<fileId>/<fileName>'. The file name starts with a tag that contains the owner id,
// so a user can only attach images they uploaded themselves.
const ownKey = (k, tag) => {
  const ok = typeof k === 'string' && /^[A-Za-z0-9]{6,32}\/[A-Za-z0-9._-]+$/.test(k) && k.split('/')[1].startsWith(tag) && !k.includes('..');
  if (!ok) throw Object.assign(new Error('Invalid image key'), { status: 400 });
  return k;
};
const tagFor = (folder, uid) => (folder === 'ad' ? 'ad' : `${folder}_${uid}`);

// real file type from the first bytes (not trusting the header)
const sniff = (b) => {
  if (b.length < 12) return null;
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png';
  if (b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  return null;
};

// frontend: fetch(API + '/upload?folder=product', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': file.type }, body: file })
app.post('/upload', auth(), express.raw({ type: Object.keys(MIME), limit: MAX_BYTES }), wrap(async (req, res) => {
  const folder = str(req.query.folder, 10);
  if (!FOLDERS[folder]?.includes(req.user.role)) return bad(res, 'Not allowed', 403);
  const body = req.body;
  if (!Buffer.isBuffer(body) || !body.length) return bad(res, 'Send the image as raw body with Content-Type image/jpeg, image/png or image/webp');
  const type = sniff(body);
  if (!type) return bad(res, 'Only JPG, PNG or WebP');
  const name = `${tagFor(folder, req.user.id)}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.${MIME[type]}`;
  const r = await fetch(`${RF}/files?name=${encodeURIComponent(name)}&acl=public`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${E.RAPIDFILE_SECRET_KEY}`, 'Content-Type': type },
    body,
    signal: AbortSignal.timeout(30000),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.file?.id) { console.error('Rapidfile upload failed', r.status, j); return bad(res, 'Upload failed', 502); }
  const key = `${j.file.id}/${j.file.name || name}`;
  res.status(201).json({ key, publicUrl: pub(key) });
}));

const delImage = (key) => key && fetch(`${RF}/files/${String(key).split('/')[0]}`, { method: 'DELETE', headers: { Authorization: `Bearer ${E.RAPIDFILE_SECRET_KEY}` } }).catch(() => {});

// ---------- shops ----------
app.get('/shops', wrap(async (_q, res) => {
  const { data } = await db.from('shops').select('id,name,category,area,logo_key,banner_key').eq('approved', true);
  res.json((data || []).map((s) => ({ ...s, logo_url: pub(s.logo_key), banner_url: pub(s.banner_key) })));
}));

app.patch('/shops/me', auth('seller'), wrap(async (req, res) => {
  const b = req.body || {}, shop = await myShop(req.user.id), patch = {};
  if (b.name) patch.name = str(b.name, 80);
  if (b.category) patch.category = str(b.category, 40);
  if (b.area) patch.area = str(b.area, 60);
  if (b.logo_key) patch.logo_key = ownKey(b.logo_key, `shop_${req.user.id}_`);
  if (b.banner_key) patch.banner_key = ownKey(b.banner_key, `shop_${req.user.id}_`);
  const { data } = await db.from('shops').update(patch).eq('id', shop.id).select().single();
  res.json(data);
}));

// ---------- products ----------
const shape = (p) => ({ ...p, images: (p.image_keys || []).map(pub) });

app.get('/products', wrap(async (req, res) => {
  const { category, shop, q } = req.query;
  let qb = db.from('products').select('*, shops!inner(id,name,approved)').eq('active', true).eq('shops.approved', true).order('created_at', { ascending: false }).limit(100);
  if (category) qb = qb.eq('category', str(category, 40));
  if (shop) qb = qb.eq('shop_id', str(shop, 40));
  if (q) qb = qb.ilike('name', `%${str(q, 60).replace(/[%,]/g, '')}%`);
  const { data, error } = await qb;
  if (error) return bad(res, 'Could not load products', 500);
  res.json(data.map(shape));
}));

const productBody = (b, uid) => {
  const p = {};
  if (b.name !== undefined) p.name = str(b.name, 120);
  if (b.category !== undefined) p.category = str(b.category, 40);
  if (b.brand !== undefined) p.brand = str(b.brand, 60);
  if (b.price !== undefined) p.price = num(b.price);
  if (b.mrp !== undefined) p.mrp = num(b.mrp);
  if (Array.isArray(b.colors)) p.colors = b.colors.slice(0, 12).map((c) => str(c, 20));
  if (b.stock && typeof b.stock === 'object') {
    p.stock = Object.fromEntries(Object.entries(b.stock).slice(0, 12).map(([k, v]) => [str(k, 10), Math.max(0, Math.floor(num(v)) || 0)]));
  }
  if (Array.isArray(b.image_keys)) p.image_keys = b.image_keys.slice(0, 6).map((k) => ownKey(k, `product_${uid}_`));
  if (b.active !== undefined) p.active = !!b.active;
  return p;
};

app.get('/seller/products', auth('seller'), wrap(async (req, res) => {
  const shop = await myShop(req.user.id);
  const { data } = await db.from('products').select('*').eq('shop_id', shop.id).order('created_at', { ascending: false });
  res.json((data || []).map(shape));
}));

app.post('/seller/products', auth('seller'), wrap(async (req, res) => {
  const shop = await myShop(req.user.id);
  if (!shop?.approved) return bad(res, 'Shop not approved yet', 403);
  const p = productBody(req.body || {}, req.user.id);
  if (!p.name || !p.category || !(p.price > 0)) return bad(res, 'name, category and price required');
  const { data, error } = await db.from('products').insert({ ...p, shop_id: shop.id }).select().single();
  if (error) return bad(res, 'Could not save product', 500);
  res.status(201).json(shape(data));
}));

app.patch('/seller/products/:id', auth('seller'), wrap(async (req, res) => {
  const shop = await myShop(req.user.id);
  const { data, error } = await db.from('products').update(productBody(req.body || {}, req.user.id)).eq('id', req.params.id).eq('shop_id', shop.id).select().maybeSingle();
  if (error || !data) return bad(res, 'Product not found', 404);
  res.json(shape(data));
}));

app.delete('/seller/products/:id', auth('seller'), wrap(async (req, res) => {
  const shop = await myShop(req.user.id);
  const { data } = await db.from('products').delete().eq('id', req.params.id).eq('shop_id', shop.id).select().maybeSingle();
  if (!data) return bad(res, 'Product not found', 404);
  await Promise.all((data.image_keys || []).map(delImage)); // free storage space
  res.json({ ok: true });
}));

// ---------- orders ----------
const getSettings = async () => (await db.from('settings').select('value').eq('key', 'platform').single()).data.value;
const step = (st, note) => ({ status: st, at: new Date().toISOString(), note });
const NEXT = { placed: 'confirmed', confirmed: 'packed', packed: 'out_for_delivery', out_for_delivery: 'delivered' };

app.post('/orders', auth('customer'), wrap(async (req, res) => {
  const { items, coupon, address } = req.body || {};
  if (!Array.isArray(items) || !items.length || items.length > 30) return bad(res, 'Cart is empty');

  // prices & stock always come from DB, never from the client
  const ids = [...new Set(items.map((i) => str(i.product_id, 40)))];
  const { data: prods } = await db.from('products').select('*').in('id', ids).eq('active', true);
  const byId = Object.fromEntries((prods || []).map((p) => [p.id, p]));
  const lines = [];
  for (const i of items) {
    const p = byId[i.product_id], qty = Math.floor(num(i.qty)), size = str(i.size, 10) || 'default';
    if (!p) return bad(res, 'A product is unavailable');
    if (!(qty >= 1 && qty <= 10)) return bad(res, 'Invalid quantity');
    if ((p.stock?.[size] ?? 0) < qty) return bad(res, `${p.name} (${size}) is out of stock`, 409);
    lines.push({ p, size, qty });
  }
  if (new Set(lines.map((l) => l.p.shop_id)).size > 1) return bad(res, 'One order per shop. Please order shops separately.');

  const S = await getSettings();
  const subtotal = lines.reduce((a, l) => a + l.p.price * l.qty, 0);
  let discount = 0, code = null;
  if (coupon) {
    const { data: c } = await db.from('coupons').select('*').eq('code', str(coupon, 20).toUpperCase()).eq('active', true).maybeSingle();
    if (!c || subtotal < c.min_order) return bad(res, 'Invalid coupon');
    discount = Math.min(c.max_off ?? Infinity, (subtotal * c.percent) / 100);
    code = c.code;
  }
  const delivery_fee = subtotal - discount >= S.freeOver ? 0 : S.deliveryFee;
  const total = Math.round((subtotal - discount + delivery_fee) * 100) / 100;

  const { data: cust } = await db.from('users').select('address').eq('id', req.user.id).single();
  const addr = address?.line ? { line: str(address.line), city: str(address.city, 60), state: str(address.state, 60), country: str(address.country, 60) || 'India', pin: str(address.pin, 10) } : cust.address;
  if (!addr?.line) return bad(res, 'Delivery address required');

  // reserve stock (conditional update: fails if someone else bought it first)
  const done = [];
  for (const l of lines) {
    const fresh = (await db.from('products').select('stock').eq('id', l.p.id).single()).data.stock;
    const left = (fresh[l.size] ?? 0) - l.qty;
    const { data: ok } = await db.from('products').update({ stock: { ...fresh, [l.size]: left } }).eq('id', l.p.id).eq('stock', fresh).select('id');
    if (left < 0 || !ok?.length) {
      for (const d of done) { const s = (await db.from('products').select('stock').eq('id', d.p.id).single()).data.stock; await db.from('products').update({ stock: { ...s, [d.size]: (s[d.size] ?? 0) + d.qty } }).eq('id', d.p.id); }
      return bad(res, `${l.p.name} just went out of stock`, 409);
    }
    done.push(l);
  }

  const { data: order, error } = await db.from('orders').insert({
    customer_id: req.user.id, shop_id: lines[0].p.shop_id, subtotal, discount, delivery_fee, total,
    commission: Math.round(((subtotal - discount) * S.commission)) / 100, coupon: code, address: addr,
    items: lines.map((l) => ({ product_id: l.p.id, name: l.p.name, size: l.size, qty: l.qty, price: l.p.price })),
    timeline: [step('placed')],
  }).select().single();
  if (error) return bad(res, 'Could not place order', 500);
  res.status(201).json(order);
}));

app.get('/orders', auth(), wrap(async (req, res) => {
  let qb = db.from('orders').select('*').order('created_at', { ascending: false }).limit(100);
  if (req.user.role === 'customer') qb = qb.eq('customer_id', req.user.id);
  if (req.user.role === 'seller') qb = qb.eq('shop_id', (await myShop(req.user.id)).id);
  const { data } = await qb;
  res.json(data || []);
}));

// seller/admin moves order forward
app.post('/orders/:id/advance', auth('seller', 'admin'), wrap(async (req, res) => {
  const { data: o } = await db.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!o) return bad(res, 'Order not found', 404);
  if (req.user.role === 'seller' && o.shop_id !== (await myShop(req.user.id))?.id) return bad(res, 'Not your order', 403);
  const nxt = NEXT[o.status];
  if (!nxt) return bad(res, 'Order cannot move further');
  const { data } = await db.from('orders').update({ status: nxt, timeline: [...o.timeline, step(nxt)] }).eq('id', o.id).select().single();
  res.json(data);
}));

app.post('/orders/:id/cancel', auth('customer'), wrap(async (req, res) => {
  const { data: o } = await db.from('orders').select('*').eq('id', req.params.id).eq('customer_id', req.user.id).maybeSingle();
  if (!o) return bad(res, 'Order not found', 404);
  if (!['placed', 'confirmed'].includes(o.status)) return bad(res, 'Too late to cancel');
  for (const i of o.items) { // put stock back
    const s = (await db.from('products').select('stock').eq('id', i.product_id).single()).data?.stock;
    if (s) await db.from('products').update({ stock: { ...s, [i.size]: (s[i.size] ?? 0) + i.qty } }).eq('id', i.product_id);
  }
  const { data } = await db.from('orders').update({ status: 'cancelled', timeline: [...o.timeline, step('cancelled', str(req.body?.reason, 200))] }).eq('id', o.id).select().single();
  res.json(data);
}));

// ---------- ads (public read, admin write) ----------
app.get('/ads/active', wrap(async (_q, res) => {
  const now = new Date().toISOString();
  const { data } = await db.from('ads').select('*').eq('active', true).or(`starts_at.is.null,starts_at.lte.${now}`).or(`ends_at.is.null,ends_at.gte.${now}`);
  res.json((data || []).map((a) => ({ ...a, image_url: pub(a.image_key) })));
}));

// ---------- contact form ----------
app.post('/contact', rateLimit({ windowMs: 60 * 60 * 1000, max: 10 }), wrap(async (req, res) => {
  const b = req.body || {};
  if (str(b.name).length < 2 || !/^\S+@\S+\.\S+$/.test(str(b.email)) || str(b.message).length < 5) return bad(res, 'Name, valid email and message required');
  await db.from('contact_messages').insert({ name: str(b.name, 80), email: str(b.email, 120), topic: str(b.topic, 40), message: str(b.message, 2000) });
  res.status(201).json({ ok: true });
}));

// ---------- admin ----------
const admin = auth('admin');

app.get('/admin/stats', admin, wrap(async (_q, res) => {
  const c = async (t, f) => { let q = db.from(t).select('*', { count: 'exact', head: true }); if (f) q = f(q); return (await q).count || 0; };
  const { data: paid } = await db.from('orders').select('total,commission').eq('status', 'delivered');
  res.json({
    customers: await c('users', (q) => q.eq('role', 'customer')),
    sellers: await c('users', (q) => q.eq('role', 'seller')),
    pending_sellers: await c('shops', (q) => q.eq('approved', false)),
    orders: await c('orders'),
    gmv: (paid || []).reduce((a, o) => a + Number(o.total), 0),
    commission: (paid || []).reduce((a, o) => a + Number(o.commission), 0),
  });
}));

app.get('/admin/users', admin, wrap(async (req, res) => {
  let qb = db.from('users').select('id,role,name,phone,email,address,status,created_at').order('created_at', { ascending: false }).limit(200);
  if (req.query.role) qb = qb.eq('role', str(req.query.role, 10));
  res.json((await qb).data || []);
}));

app.patch('/admin/users/:id/status', admin, wrap(async (req, res) => {
  if (!['active', 'blocked'].includes(req.body?.status)) return bad(res, 'Invalid status');
  const { data } = await db.from('users').update({ status: req.body.status }).eq('id', req.params.id).neq('role', 'admin').select('id,status').maybeSingle();
  data ? res.json(data) : bad(res, 'User not found', 404);
}));

app.get('/admin/shops', admin, wrap(async (_q, res) => res.json((await db.from('shops').select('*, users(name,phone)').order('created_at', { ascending: false })).data || [])));

app.post('/admin/shops/:id/approve', admin, wrap(async (req, res) => {
  const { data: s } = await db.from('shops').update({ approved: !!(req.body?.approved ?? true) }).eq('id', req.params.id).select().maybeSingle();
  if (!s) return bad(res, 'Shop not found', 404);
  await db.from('users').update({ status: s.approved ? 'active' : 'pending' }).eq('id', s.owner_id);
  res.json(s);
}));

app.get('/admin/messages', admin, wrap(async (_q, res) => res.json((await db.from('contact_messages').select('*').order('created_at', { ascending: false }).limit(200)).data || [])));

app.get('/admin/settings', admin, wrap(async (_q, res) => res.json(await getSettings())));
app.put('/admin/settings', admin, wrap(async (req, res) => {
  const b = req.body || {}, v = { commission: num(b.commission), deliveryFee: num(b.deliveryFee), freeOver: num(b.freeOver) };
  if (Object.values(v).some((x) => !(x >= 0))) return bad(res, 'Invalid settings');
  await db.from('settings').upsert({ key: 'platform', value: v });
  res.json(v);
}));

app.get('/admin/coupons', admin, wrap(async (_q, res) => res.json((await db.from('coupons').select('*')).data || [])));
app.post('/admin/coupons', admin, wrap(async (req, res) => {
  const b = req.body || {}, code = str(b.code, 20).toUpperCase();
  if (!code || !(num(b.percent) > 0 && num(b.percent) <= 90)) return bad(res, 'code and percent (1-90) required');
  const { data } = await db.from('coupons').upsert({ code, percent: num(b.percent), max_off: num(b.max_off) || null, min_order: num(b.min_order) || 0, active: b.active !== false }).select().single();
  res.json(data);
}));

app.post('/admin/ads', admin, wrap(async (req, res) => {
  const b = req.body || {};
  const { data } = await db.from('ads').insert({
    title: str(b.title, 100), link: str(b.link, 300), kind: b.kind === 'bottom_sheet' ? 'bottom_sheet' : 'popup',
    image_key: ownKey(b.image_key, 'ad_'), starts_at: b.starts_at || null, ends_at: b.ends_at || null,
  }).select().single();
  res.status(201).json(data);
}));
app.patch('/admin/ads/:id', admin, wrap(async (req, res) => {
  const { data } = await db.from('ads').update({ active: !!req.body?.active }).eq('id', req.params.id).select().maybeSingle();
  data ? res.json(data) : bad(res, 'Ad not found', 404);
}));
app.delete('/admin/ads/:id', admin, wrap(async (req, res) => {
  const { data } = await db.from('ads').delete().eq('id', req.params.id).select().maybeSingle();
  if (data) await delImage(data.image_key);
  res.json({ ok: true });
}));

// ---------- errors ----------
app.use((_q, res) => bad(res, 'Not found', 404));
app.use((err, _q, res, _n) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Server error' });
});

// ---------- admin from environment (ADMIN_NAME / ADMIN_PHONE / ADMIN_EMAIL / ADMIN_PASSWORD) ----------
if (E.ADMIN_PHONE && E.ADMIN_PASSWORD) {
  if (E.ADMIN_PASSWORD.length < 8) { console.error('ADMIN_PASSWORD must be 8+ characters'); process.exit(1); }
  const phone = phoneOf(E.ADMIN_PHONE);
  const { data: a } = await db.from('users').select('id,password_hash').eq('phone', phone).maybeSingle();
  if (!a) {
    const { error } = await db.from('users').insert({ role: 'admin', name: E.ADMIN_NAME || 'Admin', phone, email: E.ADMIN_EMAIL ? E.ADMIN_EMAIL.toLowerCase() : null, password_hash: await bcrypt.hash(E.ADMIN_PASSWORD, 10) });
    console.log(error ? 'Admin create failed: ' + error.message : 'Admin created');
  } else if (!(await bcrypt.compare(E.ADMIN_PASSWORD, a.password_hash))) {
    await db.from('users').update({ password_hash: await bcrypt.hash(E.ADMIN_PASSWORD, 10), role: 'admin' }).eq('id', a.id);
    console.log('Admin password updated from env');
  }
}

app.listen(E.PORT || 8080, () => console.log('MMart API on :' + (E.PORT || 8080)));
