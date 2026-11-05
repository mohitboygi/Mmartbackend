import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import webpush from 'web-push';
import { createClient } from '@supabase/supabase-js';

const E = process.env;
for (const k of ['JWT_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'RAPIDFILE_SECRET_KEY']) {
  if (!E[k]) { console.error('Missing env: ' + k); process.exit(1); }
}
if (!E.BREVO_API_KEY || !E.BREVO_SENDER_EMAIL) console.warn('BREVO_API_KEY / BREVO_SENDER_EMAIL missing: customer email OTP cannot be sent');

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
const otpLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
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

// ---------- notifications (in-app + phone push) ----------
const FRONT = (E.FRONTEND_URL || 'https://mmart.pntr.dev').replace(/\/$/, '');
let pushReady = false, VAPID_PUBLIC = null;
const initPush = async () => {
  try {
    const { data } = await db.from('settings').select('value').eq('key', 'vapid').maybeSingle();
    let v = data?.value;
    if (!v) { v = webpush.generateVAPIDKeys(); await db.from('settings').upsert({ key: 'vapid', value: v }); }
    webpush.setVapidDetails('mailto:' + (E.ADMIN_EMAIL || 'admin@mmart.pntr.dev'), v.publicKey, v.privateKey);
    VAPID_PUBLIC = v.publicKey; pushReady = true;
  } catch (e) { console.error('Push disabled:', e.message); }
};
const pushTo = async (userId, payload) => {
  if (!pushReady) return;
  const { data: subs } = await db.from('push_subscriptions').select('*').eq('user_id', userId);
  await Promise.allSettled((subs || []).map(async (s) => {
    try { await webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, JSON.stringify(payload), { TTL: 86400 }); }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await db.from('push_subscriptions').delete().eq('endpoint', s.endpoint); }
  }));
};
// fire-and-forget: a failed notification never breaks the main request
const notify = (userId, title, body = '', type = 'info', data = null) => {
  if (!userId) return;
  (async () => {
    const { error } = await db.from('notifications').insert({ user_id: userId, title, body, type, data });
    if (error) return console.error('notify failed:', error.message);
    await pushTo(userId, { title, body, type, url: '/' });
  })().catch((e) => console.error('notify error:', e.message));
};
const short = (id) => String(id).slice(0, 6).toUpperCase();

// ---------- coins + referral ----------
const COINS = async () => (await db.from('settings').select('value').eq('key', 'coins').maybeSingle()).data?.value || { per100: 1, refMin: 100, refMax: 200 };
const REFCH = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const refCode = () => 'MM' + Array.from(crypto.randomBytes(6), (b) => REFCH[b % REFCH.length]).join('');
// the ledger has a unique (user, reason, order) index, so the same reward can never be paid twice
const credit = async (uid, amount, reason, orderId) => {
  if (!(amount > 0)) return 0;
  const { error } = await db.from('coin_ledger').insert({ user_id: uid, amount, reason, order_id: orderId });
  if (error) return 0;
  const { data } = await db.from('coin_ledger').select('amount').eq('user_id', uid);
  await db.from('users').update({ coins: (data || []).reduce((a, r) => a + r.amount, 0) }).eq('id', uid);
  return amount;
};
const onDelivered = async (o) => {
  const C = await COINS();
  const earned = await credit(o.customer_id, Math.floor(((Number(o.subtotal) - Number(o.discount || 0)) / 100) * C.per100), 'order', o.id);
  if (earned) notify(o.customer_id, `You earned ${earned} coins`, `For order #${short(o.id)}`, 'coins');
  const { data: cu } = await db.from('users').select('referred_by').eq('id', o.customer_id).single();
  if (cu?.referred_by) { // referrer is paid once, after the friend's FIRST delivered order (stops fake signups)
    const { count } = await db.from('orders').select('*', { count: 'exact', head: true }).eq('customer_id', o.customer_id).eq('status', 'delivered');
    if (count === 1) {
      const amt = C.refMin + Math.floor(Math.random() * (C.refMax - C.refMin + 1));
      if (await credit(cu.referred_by, amt, 'referral', o.id)) notify(cu.referred_by, `Friend joined: +${amt} coins`, 'Your friend completed their first order', 'coins');
    }
  }
};

// ---------- customer email OTP (Brevo) ----------
// OTP record lives in the existing `settings` table under key 'otp:<userId>':
// { hash, exp (ms), tries, last (ms) }. The 6-digit code itself is never stored, only an HMAC of it.
const OTP_TTL = 5 * 60 * 1000;       // code valid for 5 minutes
const OTP_COOLDOWN = 30 * 1000;      // 30 seconds between codes
const OTP_MAX_TRIES = 5;             // wrong attempts allowed per code
const EMAIL_RE = /^\S+@\S+\.\S+$/;
const otpKey = (uid) => `otp:${uid}`;
const otpHash = (uid, otp) => crypto.createHmac('sha256', E.JWT_SECRET).update(`${uid}:${otp}`).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const getOtp = async (uid) => (await db.from('settings').select('value').eq('key', otpKey(uid)).maybeSingle()).data?.value || null;
const putOtp = (uid, value) => db.from('settings').upsert({ key: otpKey(uid), value });
const dropOtp = (uid) => db.from('settings').delete().eq('key', otpKey(uid));

const sendOtpMail = async (user, otp) => {
  if (!E.BREVO_API_KEY || !E.BREVO_SENDER_EMAIL) { console.error('Brevo env missing'); return false; }
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': E.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        sender: { name: 'MMart', email: E.BREVO_SENDER_EMAIL },
        to: [{ email: user.email, name: user.name || user.email }],
        subject: 'Your MMart verification code',
        htmlContent: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:16px">`
          + `<h2 style="margin:0 0 12px">Verify your email</h2>`
          + `<p>Hi ${esc(user.name || 'there')}, use this code to verify your MMart account:</p>`
          + `<p style="font-size:32px;letter-spacing:8px;font-weight:bold;margin:16px 0">${otp}</p>`
          + `<p>This code is valid for 5 minutes. If you did not sign up for MMart, ignore this email.</p></div>`,
        textContent: `Your MMart verification code is ${otp}. It is valid for 5 minutes.`,
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) { console.error('Brevo send failed', r.status, await r.text().catch(() => '')); return false; }
    return true;
  } catch (e) { console.error('Brevo error:', e.message); return false; }
};

// creates a fresh code and mails it. Returns { sent } or { sent:false, wait } while in cooldown.
const issueOtp = async (user) => {
  const old = await getOtp(user.id);
  if (old && Date.now() - old.last < OTP_COOLDOWN) return { sent: false, wait: Math.ceil((OTP_COOLDOWN - (Date.now() - old.last)) / 1000) };
  const otp = String(crypto.randomInt(100000, 1000000));
  const { error } = await putOtp(user.id, { hash: otpHash(user.id, otp), exp: Date.now() + OTP_TTL, tries: 0, last: Date.now() });
  if (error) { console.error('otp store failed:', error.message); return { sent: false }; }
  if (!(await sendOtpMail(user, otp))) { await dropOtp(user.id); return { sent: false }; }
  return { sent: true };
};
const findCustomer = async (email) => (await db.from('users').select('id,name,email,status,email_verified').eq('role', 'customer').eq('email', email).maybeSingle()).data;

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
  if (role === 'customer' && !email) return bad(res, 'Email required'); // customers must verify their email
  if (email && !EMAIL_RE.test(email)) return bad(res, 'Invalid email');
  if (password.length < 8) return bad(res, 'Password must be 8+ characters');
  if (role === 'seller' && str(b.shop_name).length < 2) return bad(res, 'Shop name required');

  const address = role === 'customer' && b.address ? {
    line: str(b.address.line), city: str(b.address.city, 60), state: str(b.address.state, 60),
    country: str(b.address.country, 60) || 'India', pin: str(b.address.pin, 10),
  } : null;

  const row = { role, name, phone, email, address, password_hash: await bcrypt.hash(password, 10), status: role === 'seller' ? 'pending' : 'active', email_verified: role !== 'customer' };
  if (role === 'customer') {
    const rc = str(b.ref, 20).toUpperCase();
    if (rc) { const { data: r } = await db.from('users').select('id').eq('ref_code', rc).eq('role', 'customer').maybeSingle(); if (r) row.referred_by = r.id; }
  }
  let u, error;
  for (let i = 0; i < 4; i++) { // auto-generate a unique referral code for every customer
    if (role === 'customer') row.ref_code = refCode();
    ({ data: u, error } = await db.from('users').insert(row).select().single());
    if (!(error && error.code === '23505' && /ref_code/.test(error.message))) break;
  }
  if (error) { if (error.code !== '23505') console.error('register failed:', error.code, error.message); const dbg = E.DEBUG_ERRORS === 'true' ? ` [${error.code || ''} ${String(error.message).slice(0, 160)}]` : ''; /* temporary: set DEBUG_ERRORS=true to see the real DB error on screen */ return bad(res, error.code === '23505' ? 'Phone or email already registered' : 'Could not register' + dbg, error.code === '23505' ? 409 : 500); }

  if (role === 'seller') {
    const { data: admins } = await db.from('users').select('id').eq('role', 'admin');
    (admins || []).forEach((a) => notify(a.id, 'New seller waiting for approval', str(b.shop_name, 80), 'seller'));
    await db.from('shops').insert({ owner_id: u.id, name: str(b.shop_name, 80), category: str(b.category, 40), area: str(b.area, 60) });
  }

  if (role === 'customer') { // no login token until the email is verified
    const r = await issueOtp(u);
    return res.status(201).json({
      otp_sent: r.sent,
      email: u.email,
      requires_verification: true,
      message: r.sent
        ? `Verification code sent to ${u.email}. It is valid for 5 minutes.`
        : 'Account created, but we could not send the code. Please tap Resend code.',
    });
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
  if (u.role === 'customer' && !u.email_verified) {
    return res.status(403).json({ error: 'Please verify your email before logging in', code: 'EMAIL_NOT_VERIFIED', email_verified: false, email: u.email });
  }
  res.json({ token: sign(u), user: clean(u) });
}));

app.post('/auth/email/resend', otpLimit, wrap(async (req, res) => {
  const email = str(req.body?.email, 120).toLowerCase();
  if (!EMAIL_RE.test(email)) return bad(res, 'Valid email required');
  const u = await findCustomer(email);
  // unknown / blocked emails get the same answer, so this endpoint cannot be used to probe accounts
  if (!u || u.status === 'blocked') return res.json({ ok: true, otp_sent: true, email, message: `If this email needs verification, a new code has been sent to ${email}.` });
  if (u.email_verified) return res.json({ ok: true, otp_sent: false, already_verified: true, email, message: 'Email already verified. Please log in.' });
  const r = await issueOtp(u);
  if (r.wait) return res.status(429).json({ error: `Please wait ${r.wait} seconds before asking for a new code.`, code: 'OTP_COOLDOWN', retry_after: r.wait });
  if (!r.sent) return bad(res, 'Could not send the email. Please try again.', 502);
  res.json({ ok: true, otp_sent: true, email, message: `New code sent to ${email}. It is valid for 5 minutes.`, expires_in: 300, resend_after: 30 });
}));

app.post('/auth/email/verify', otpLimit, wrap(async (req, res) => {
  const email = str(req.body?.email, 120).toLowerCase();
  const otp = str(req.body?.otp, 10);
  if (!EMAIL_RE.test(email) || !/^\d{6}$/.test(otp)) return bad(res, 'Email and 6-digit code required');
  const u = await findCustomer(email);
  if (!u) return res.status(400).json({ error: 'Invalid or expired code', code: 'OTP_INVALID' });
  if (u.email_verified) return res.json({ ok: true, verified: true, message: 'Email already verified. Please log in.' });

  const rec = await getOtp(u.id);
  if (!rec || Date.now() > rec.exp) return res.status(400).json({ error: 'Code expired. Please request a new one.', code: 'OTP_EXPIRED' });
  if (rec.tries >= OTP_MAX_TRIES) return res.status(429).json({ error: 'Too many wrong attempts. Please request a new code.', code: 'OTP_LOCKED' });

  rec.tries += 1;
  await putOtp(u.id, rec); // count the attempt first, then compare
  if (!safeEq(otpHash(u.id, otp), rec.hash)) {
    const left = OTP_MAX_TRIES - rec.tries;
    return res.status(400).json({
      error: left > 0 ? `Wrong code. ${left} attempt${left === 1 ? '' : 's'} left.` : 'Too many wrong attempts. Please request a new code.',
      code: left > 0 ? 'OTP_WRONG' : 'OTP_LOCKED',
      attempts_left: left,
    });
  }
  const { error } = await db.from('users').update({ email_verified: true }).eq('id', u.id);
  if (error) { console.error('verify update failed:', error.message); return bad(res, 'Could not verify email. Please try again.', 500); }
  await dropOtp(u.id);
  res.json({ ok: true, verified: true, message: 'Email verified. You can now log in.' });
}));

app.get('/me', auth(), wrap(async (req, res) => {
  const { data: u } = await db.from('users').select('*').eq('id', req.user.id).single();
  if (u.role === 'customer' && !u.ref_code) { u.ref_code = refCode(); await db.from('users').update({ ref_code: u.ref_code }).eq('id', u.id); }
  const { count } = u.role === 'customer' ? await db.from('users').select('*', { count: 'exact', head: true }).eq('referred_by', u.id) : { count: 0 };
  res.json({ user: clean(u), shop: u.role === 'seller' ? await myShop(u.id) : null, ref_link: u.ref_code ? `${FRONT}/?ref=${u.ref_code}` : null, referrals: count || 0 });
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
  if (b.description !== undefined) p.description = str(b.description, 500);
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
// Platform commission is fixed at 4% (override with COMMISSION env var); admin settings cannot change it.
const COMMISSION = Number(process.env.COMMISSION ?? 4);
const getSettings = async () => ({ ...(await db.from('settings').select('value').eq('key', 'platform').single()).data.value, commission: COMMISSION });
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
  let discount = 0, code = null, c = null;
  if (coupon) { // customer typed a code
    ({ data: c } = await db.from('coupons').select('*').eq('code', str(coupon, 20).toUpperCase()).eq('active', true).maybeSingle());
    if (!c || subtotal < c.min_order) return bad(res, 'Invalid coupon');
  } else { // otherwise the best live "auto" coupon (set by admin) applies by itself
    const { data: autos } = await db.from('coupons').select('*').eq('active', true).eq('auto', true).lte('min_order', subtotal).order('percent', { ascending: false }).limit(1);
    c = autos?.[0] || null;
  }
  if (c) { discount = Math.min(c.max_off ?? Infinity, (subtotal * c.percent) / 100); code = c.code; }
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
  const { data: sh } = await db.from('shops').select('owner_id').eq('id', order.shop_id).single();
  notify(sh?.owner_id, 'New order received', `Order #${short(order.id)} · ₹${order.total}`, 'order', { order_id: order.id });
  notify(req.user.id, 'Order placed', `Order #${short(order.id)} · ₹${order.total}. We will keep you updated.`, 'order', { order_id: order.id });
  res.status(201).json(order);
}));

app.get('/orders', auth(), wrap(async (req, res) => {
  let qb = db.from('orders').select('*').order('created_at', { ascending: false }).limit(100);
  if (req.user.role === 'customer') qb = qb.eq('customer_id', req.user.id);
  if (req.user.role === 'seller') {
    const shop = await myShop(req.user.id);
    if (!shop) return res.json([]);
    qb = qb.eq('shop_id', shop.id);
  }
  const { data: rows, error } = await qb;
  if (error) { console.error('orders load failed:', error.message); return bad(res, 'Could not load orders', 500); }
  const list = rows || [];
  // customer + shop names are fetched separately (no table-join dependency), then attached to each order
  const cids = [...new Set(list.map((o) => o.customer_id).filter(Boolean))];
  const sids = [...new Set(list.map((o) => o.shop_id).filter(Boolean))];
  const [{ data: cs }, { data: ss }] = await Promise.all([
    cids.length ? db.from('users').select('id,name,phone').in('id', cids) : { data: [] },
    sids.length ? db.from('shops').select('id,name,area,owner_id').in('id', sids) : { data: [] },
  ]);
  // admin also sees which seller (shop owner) each order belongs to
  const oids = req.user.role === 'admin' ? [...new Set((ss || []).map((x) => x.owner_id).filter(Boolean))] : [];
  const { data: os } = oids.length ? await db.from('users').select('id,name,phone').in('id', oids) : { data: [] };
  const om = Object.fromEntries((os || []).map((u) => [u.id, u]));
  const cm = Object.fromEntries((cs || []).map((c) => [c.id, c])), sm = Object.fromEntries((ss || []).map((x) => [x.id, x]));
  res.json(list.map((o) => {
    const c = cm[o.customer_id] ? { name: cm[o.customer_id].name, phone: cm[o.customer_id].phone } : null;
    const sh = sm[o.shop_id], ow = sh && om[sh.owner_id];
    const base = { ...o, customer: c, shop: sh ? (req.user.role === 'admin' ? { name: sh.name, area: sh.area, owner: ow ? { name: ow.name, phone: ow.phone } : null } : { name: sh.name }) : null };
    return req.user.role === 'seller' && c ? { ...base, customer: { ...c, phone: String(c.phone).replace(/\d(?=\d{2})/g, 'x') } } : base;
  }));
}));

// seller/admin moves order forward
app.post('/orders/:id/advance', auth('seller', 'admin'), wrap(async (req, res) => {
  const { data: o } = await db.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!o) return bad(res, 'Order not found', 404);
  if (req.user.role === 'seller' && o.shop_id !== (await myShop(req.user.id))?.id) return bad(res, 'Not your order', 403);
  const nxt = NEXT[o.status];
  if (!nxt) return bad(res, 'Order cannot move further');
  const { data } = await db.from('orders').update({ status: nxt, timeline: [...o.timeline, step(nxt)] }).eq('id', o.id).select().single();
  notify(o.customer_id, { confirmed: 'Order accepted', packed: 'Order packed', out_for_delivery: 'Out for delivery', delivered: 'Order delivered' }[nxt], `Order #${short(o.id)}`, 'order', { order_id: o.id });
  if (nxt === 'delivered') await onDelivered(data);
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
  const { data: shp } = await db.from('shops').select('owner_id').eq('id', o.shop_id).single();
  notify(shp?.owner_id, 'Order cancelled by customer', `Order #${short(o.id)}`, 'order', { order_id: o.id });
  const { data } = await db.from('orders').update({ status: 'cancelled', timeline: [...o.timeline, step('cancelled', str(req.body?.reason, 200))] }).eq('id', o.id).select().single();
  res.json(data);
}));

app.post('/orders/:id/return', auth('customer'), wrap(async (req, res) => {
  const { data: o } = await db.from('orders').select('*').eq('id', req.params.id).eq('customer_id', req.user.id).maybeSingle();
  if (!o) return bad(res, 'Order not found', 404);
  if (o.status !== 'delivered') return bad(res, 'Only delivered orders can be returned');
  const { data: shp } = await db.from('shops').select('owner_id').eq('id', o.shop_id).single();
  notify(shp?.owner_id, 'Return requested', `Order #${short(o.id)}`, 'order', { order_id: o.id });
  const { data } = await db.from('orders').update({ status: 'return_requested', timeline: [...o.timeline, step('return_requested', str(req.body?.reason, 200))] }).eq('id', o.id).select().single();
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
  if (str(b.name).length < 2 || !EMAIL_RE.test(str(b.email)) || str(b.message).length < 5) return bad(res, 'Name, valid email and message required');
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
  notify(s.owner_id, s.approved ? 'Your shop is approved' : 'Your shop is paused', s.approved ? 'You can now add products and receive orders.' : 'Please contact MMart support.', 'seller');
  res.json(s);
}));

app.get('/admin/messages', admin, wrap(async (_q, res) => res.json((await db.from('contact_messages').select('*').order('created_at', { ascending: false }).limit(200)).data || [])));

app.get('/admin/settings', admin, wrap(async (_q, res) => res.json({ ...(await getSettings()), coins: await COINS() })));
app.put('/admin/settings', admin, wrap(async (req, res) => {
  const b = req.body || {}, v = { commission: COMMISSION, deliveryFee: num(b.deliveryFee), freeOver: num(b.freeOver) };
  if (Object.values(v).some((x) => !(x >= 0))) return bad(res, 'Invalid settings');
  await db.from('settings').upsert({ key: 'platform', value: v });
  if (b.coins) {
    const k = { per100: num(b.coins.per100), refMin: num(b.coins.refMin), refMax: num(b.coins.refMax) };
    if (Object.values(k).some((x) => !(x >= 0)) || k.refMax < k.refMin) return bad(res, 'Invalid coin settings');
    await db.from('settings').upsert({ key: 'coins', value: k });
  }
  res.json(v);
}));

app.get('/admin/coupons', admin, wrap(async (_q, res) => res.json((await db.from('coupons').select('*')).data || [])));
app.post('/admin/coupons', admin, wrap(async (req, res) => {
  const b = req.body || {}, code = str(b.code, 20).toUpperCase();
  if (!code || !(num(b.percent) > 0 && num(b.percent) <= 90)) return bad(res, 'code and percent (1-90) required');
  const { data } = await db.from('coupons').upsert({ code, percent: num(b.percent), max_off: num(b.max_off) || null, min_order: num(b.min_order) || 0, active: b.active !== false, auto: !!b.auto }).select().single();
  res.json(data);
}));

app.patch('/admin/coupons/:code', admin, wrap(async (req, res) => {
  const { data } = await db.from('coupons').update({ active: !!req.body?.active }).eq('code', str(req.params.code, 20).toUpperCase()).select().maybeSingle();
  data ? res.json(data) : bad(res, 'Coupon not found', 404);
}));
app.delete('/admin/coupons/:code', admin, wrap(async (req, res) => { await db.from('coupons').delete().eq('code', str(req.params.code, 20).toUpperCase()); res.json({ ok: true }); }));
app.get('/admin/ads', admin, wrap(async (q, res) => res.json(((await db.from('ads').select('*').order('created_at', { ascending: false })).data || []).map((a) => ({ ...a, image_url: pub(a.image_key) })))));
app.post('/admin/ads', admin, wrap(async (req, res) => {
  const b = req.body || {};
  const { data } = await db.from('ads').insert({
    title: str(b.title, 100), link: str(b.link, 300), kind: b.kind === 'bottom_sheet' ? 'bottom_sheet' : 'popup',
    image_key: ownKey(b.image_key, 'ad'), starts_at: b.starts_at || null, ends_at: b.ends_at || null,
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

// ---------- public app config (fees, coins, support number) ----------
app.get('/config', wrap(async (_q, res) => {
  const P = await getSettings(), C = await COINS();
  const { data: au } = await db.from('coupons').select('code,percent,max_off,min_order').eq('active', true).eq('auto', true).order('percent', { ascending: false }).limit(1);
  res.json({ ...P, coinPer100: C.per100, refMin: C.refMin, refMax: C.refMax, whatsapp: E.SUPPORT_WHATSAPP || '', autoCoupon: au?.[0] || null });
}));

// ---------- notification + push routes ----------
app.get('/notifications', auth(), wrap(async (req, res) => {
  const { data } = await db.from('notifications').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
  res.json({ items: data || [], unread: (data || []).filter((n) => !n.read).length });
}));
app.post('/notifications/read', auth(), wrap(async (req, res) => {
  let qb = db.from('notifications').update({ read: true }).eq('user_id', req.user.id).eq('read', false);
  if (Array.isArray(req.body?.ids) && req.body.ids.length) qb = qb.in('id', req.body.ids.slice(0, 100));
  await qb;
  res.json({ ok: true });
}));
app.get('/push/key', wrap(async (_q, res) => res.json({ key: pushReady ? VAPID_PUBLIC : null })));
app.post('/push/subscribe', auth(), wrap(async (req, res) => {
  const sub = req.body || {};
  if (!/^https:\/\//.test(sub.endpoint || '') || !sub.keys?.p256dh || !sub.keys?.auth) return bad(res, 'Invalid subscription');
  await db.from('push_subscriptions').upsert({ endpoint: sub.endpoint, user_id: req.user.id, p256dh: sub.keys.p256dh, auth: sub.keys.auth });
  res.json({ ok: true });
}));
app.post('/push/unsubscribe', auth(), wrap(async (req, res) => {
  await db.from('push_subscriptions').delete().eq('endpoint', str(req.body?.endpoint, 600)).eq('user_id', req.user.id);
  res.json({ ok: true });
}));

// ---------- coins, coupon check ----------
app.get('/coins', auth(), wrap(async (req, res) => {
  const { data: u } = await db.from('users').select('coins').eq('id', req.user.id).single();
  const { data } = await db.from('coin_ledger').select('amount,reason,created_at').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
  res.json({ balance: u?.coins || 0, ledger: data || [] });
}));
app.post('/coupons/check', auth('customer'), wrap(async (req, res) => {
  const sub = num(req.body?.subtotal);
  const { data: c } = await db.from('coupons').select('*').eq('code', str(req.body?.code, 20).toUpperCase()).eq('active', true).maybeSingle();
  if (!c || !(sub >= c.min_order)) return bad(res, 'Code not valid for this cart');
  res.json({ code: c.code, percent: c.percent, max_off: c.max_off, discount: Math.round(Math.min(c.max_off ?? Infinity, (sub * c.percent) / 100)) });
}));

// ---------- admin: announcement to everyone / customers / sellers ----------
app.post('/admin/broadcast', admin, wrap(async (req, res) => {
  const title = str(req.body?.title, 100), body = str(req.body?.body, 400);
  const aud = ['customer', 'seller'].includes(req.body?.audience) ? req.body.audience : 'all';
  if (title.length < 2) return bad(res, 'Title required');
  let qb = db.from('users').select('id').eq('status', 'active').neq('role', 'admin').limit(5000);
  if (aud !== 'all') qb = qb.eq('role', aud);
  const { data: us } = await qb;
  const rows = (us || []).map((u) => ({ user_id: u.id, title, body, type: 'announcement' }));
  for (let i = 0; i < rows.length; i += 500) await db.from('notifications').insert(rows.slice(i, i + 500));
  (us || []).forEach((u) => pushTo(u.id, { title, body, type: 'announcement', url: '/' }).catch(() => {}));
  res.json({ sent: rows.length });
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

await initPush();
app.listen(E.PORT || 8080, () => console.log('MMart API on :' + (E.PORT || 8080)));
