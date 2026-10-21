require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const catalog = require('./catalog.json');
const products = new Map(catalog.map(p => [p.id, p]));
const dbPath = process.env.DATABASE_PATH || './data/39f-orders.sqlite';
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT UNIQUE NOT NULL,
  customer_name TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  customer_email TEXT,
  payment_method TEXT NOT NULL,
  status TEXT NOT NULL,
  total_sar REAL NOT NULL,
  paylink_transaction_no TEXT,
  payment_url TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  product_id TEXT NOT NULL,
  product_name TEXT NOT NULL,
  unit_price_sar REAL NOT NULL,
  quantity INTEGER NOT NULL
);
`);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 80, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

let cachedToken = null;
let tokenExpiresAt = 0;
function paylinkBase() { return process.env.PAYLINK_MODE === 'production' ? 'https://restapi.paylink.sa' : 'https://restpilot.paylink.sa'; }
async function getPaylinkToken() {
  if (cachedToken && Date.now() < tokenExpiresAt) return cachedToken;
  const apiId = process.env.PAYLINK_API_ID;
  const secretKey = process.env.PAYLINK_SECRET_KEY;
  if (!apiId || !secretKey) throw new Error('PAYLINK_NOT_CONFIGURED');
  const response = await fetch(`${paylinkBase()}/api/auth`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ apiId, secretKey, persistToken: true })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.id_token) throw new Error('PAYLINK_AUTH_FAILED');
  cachedToken = data.id_token;
  tokenExpiresAt = Date.now() + 29 * 60 * 60 * 1000;
  return cachedToken;
}
async function paylinkRequest(endpoint, options = {}) {
  const token = await getPaylinkToken();
  const response = await fetch(`${paylinkBase()}${endpoint}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`PAYLINK_HTTP_${response.status}`);
  return data;
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a || '')); const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function adminOnly(req, res, next) {
  const expected = process.env.ADMIN_TOKEN;
  if (!expected || !safeEqual(req.get('x-admin-token'), expected)) return res.status(401).json({ error: 'غير مصرح' });
  next();
}
function normalizeSaudiPhone(input) {
  const digits = String(input || '').replace(/[^0-9]/g, '');
  if (/^05\d{8}$/.test(digits)) return digits;
  if (/^9665\d{8}$/.test(digits)) return `0${digits.slice(3)}`;
  if (/^5\d{8}$/.test(digits)) return `0${digits}`;
  return null;
}
function newOrderNumber() { return `39F-${Date.now().toString().slice(-8)}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`; }

app.get('/api/health', (req, res) => res.json({ ok: true, store: '39F' }));
app.get('/api/products', (req, res) => res.json(catalog));

app.post('/api/orders', async (req, res) => {
  const { customerName, customerPhone, customerEmail, paymentMethod, items } = req.body || {};
  const name = String(customerName || '').trim();
  const phone = normalizeSaudiPhone(customerPhone);
  const email = String(customerEmail || '').trim();
  if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'اكتب الاسم بشكل صحيح.' });
  if (!phone) return res.status(400).json({ error: 'أدخل رقم جوال سعودي صحيحًا مثل 05xxxxxxxx.' });
  if (email && (email.length > 150 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ error: 'البريد الإلكتروني غير صحيح.' });
  if (!['paylink', 'bank_transfer'].includes(paymentMethod)) return res.status(400).json({ error: 'طريقة الدفع غير مدعومة.' });
  if (!Array.isArray(items) || items.length < 1 || items.length > 30) return res.status(400).json({ error: 'السلة فارغة أو تحتوي عددًا غير صالح من المنتجات.' });

  const validated = [];
  let total = 0;
  for (const line of items) {
    const product = products.get(String(line.id || ''));
    const quantity = Number(line.quantity);
    if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > 20) return res.status(400).json({ error: 'أحد المنتجات غير صالح أو الكمية تتجاوز الحد.' });
    validated.push({ product, quantity });
    total += product.price * quantity;
  }
  if (total < 5 && paymentMethod === 'paylink') return res.status(400).json({ error: 'الحد الأدنى للدفع الإلكتروني 5 ر.س.' });
  if (paymentMethod === 'paylink' && (!process.env.PAYLINK_API_ID || !process.env.PAYLINK_SECRET_KEY)) {
    return res.status(503).json({ error: 'بوابة الدفع غير مفعلة بعد. اختر التحويل البنكي أو أكمل إعداد مفاتيح Paylink على الخادم.' });
  }
  const orderNumber = newOrderNumber();
  const now = new Date().toISOString();
  const status = paymentMethod === 'bank_transfer' ? 'awaiting_bank_transfer' : 'payment_pending';
  const tx = db.transaction(() => {
    const info = db.prepare(`INSERT INTO orders (order_number,customer_name,customer_phone,customer_email,payment_method,status,total_sar,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(orderNumber, name, phone, email || null, paymentMethod, status, total, now, now);
    const insertItem = db.prepare(`INSERT INTO order_items (order_id,product_id,product_name,unit_price_sar,quantity) VALUES (?,?,?,?,?)`);
    for (const line of validated) insertItem.run(info.lastInsertRowid, line.product.id, line.product.name, line.product.price, line.quantity);
    return Number(info.lastInsertRowid);
  });
  const orderId = tx();

  if (paymentMethod === 'bank_transfer') {
    return res.status(201).json({
      orderNumber, status, total: Number(total.toFixed(2)),
      bankDetails: { bankName: process.env.BANK_NAME || '', accountName: process.env.BANK_ACCOUNT_NAME || '39F', iban: process.env.BANK_IBAN || '' },
      message: 'تم تسجيل الطلب. سيبقى بانتظار التحويل حتى تتم مراجعة الدفع.'
    });
  }

  try {
    const payload = {
      orderNumber,
      amount: Number(total.toFixed(2)),
      callBackUrl: `${BASE_URL}/api/paylink/callback?orderNumber=${encodeURIComponent(orderNumber)}`,
      cancelUrl: `${BASE_URL}/payment-result.html?status=cancelled&orderNumber=${encodeURIComponent(orderNumber)}`,
      clientName: name,
      clientMobile: phone,
      ...(email ? { clientEmail: email } : {}),
      currency: 'SAR',
      products: validated.map(({ product, quantity }) => ({ title: product.name, price: product.price, qty: quantity, description: product.name, isDigital: true })),
      supportedCardBrands: ['mada', 'visaMastercard', 'amex'],
      displayPending: true,
      note: '39F FC 27 Store order'
    };
    const invoice = await paylinkRequest('/api/addInvoice', { method: 'POST', body: JSON.stringify(payload) });
    if (!invoice.success || !invoice.url || !invoice.transactionNo) throw new Error('PAYLINK_INVOICE_FAILED');
    db.prepare('UPDATE orders SET paylink_transaction_no=?, payment_url=?, updated_at=? WHERE id=?')
      .run(String(invoice.transactionNo), invoice.url, new Date().toISOString(), orderId);
    return res.status(201).json({ orderNumber, status: invoice.orderStatus || status, total: Number(total.toFixed(2)), paymentUrl: invoice.url });
  } catch (err) {
    // Keep the order for staff follow-up; never claim payment was processed.
    const message = err.message === 'PAYLINK_NOT_CONFIGURED'
      ? 'بوابة الدفع غير مفعلة بعد. اختر التحويل البنكي أو أكمل إعداد مفاتيح Paylink على الخادم.'
      : 'تعذر إنشاء رابط الدفع الآن. لم يتم خصم أي مبلغ؛ جرّب التحويل البنكي أو تواصل مع المتجر.';
    return res.status(503).json({ error: message, orderNumber, status: 'payment_setup_or_gateway_error' });
  }
});

app.get('/api/paylink/callback', async (req, res) => {
  const orderNumber = String(req.query.orderNumber || '');
  const order = db.prepare('SELECT * FROM orders WHERE order_number=?').get(orderNumber);
  if (!order) return res.redirect('/payment-result.html?status=unknown');
  if (!order.paylink_transaction_no) return res.redirect(`/payment-result.html?status=pending&orderNumber=${encodeURIComponent(orderNumber)}`);
  try {
    const invoice = await paylinkRequest(`/api/getInvoice/${encodeURIComponent(order.paylink_transaction_no)}`, { method: 'GET' });
    const paid = String(invoice.orderStatus || '').toUpperCase() === 'PAID' && Number(invoice.amount) >= Number(order.total_sar);
    const status = paid ? 'paid' : (String(invoice.orderStatus || '').toUpperCase() === 'CANCELED' ? 'payment_cancelled' : 'payment_pending');
    db.prepare('UPDATE orders SET status=?, updated_at=? WHERE order_number=?').run(status, new Date().toISOString(), orderNumber);
    res.redirect(`/payment-result.html?status=${encodeURIComponent(status)}&orderNumber=${encodeURIComponent(orderNumber)}`);
  } catch (_) {
    res.redirect(`/payment-result.html?status=verification_pending&orderNumber=${encodeURIComponent(orderNumber)}`);
  }
});

app.get('/api/admin/orders', adminOnly, (req, res) => {
  const rows = db.prepare(`SELECT o.*, (SELECT json_group_array(json_object('name',i.product_name,'price',i.unit_price_sar,'quantity',i.quantity)) FROM order_items i WHERE i.order_id=o.id) AS items_json FROM orders o ORDER BY o.id DESC LIMIT 200`).all();
  res.json(rows.map(row => ({ ...row, items: JSON.parse(row.items_json || '[]') , items_json: undefined })));
});
app.patch('/api/admin/orders/:orderNumber/status', adminOnly, (req, res) => {
  const allowed = ['awaiting_bank_transfer','payment_pending','paid','processing','completed','cancelled','refunded'];
  const status = String(req.body?.status || '');
  if (!allowed.includes(status)) return res.status(400).json({ error: 'حالة الطلب غير صالحة.' });
  const result = db.prepare('UPDATE orders SET status=?, updated_at=? WHERE order_number=?').run(status, new Date().toISOString(), req.params.orderNumber);
  if (!result.changes) return res.status(404).json({ error: 'الطلب غير موجود.' });
  res.json({ ok: true, orderNumber: req.params.orderNumber, status });
});

app.get('/payment-result.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'payment-result.html')));
app.use((err, req, res, next) => { console.error('Request error:', err.message); res.status(500).json({ error: 'حدث خطأ غير متوقع. حاول مرة أخرى.' }); });
app.listen(PORT, () => console.log(`39F store running at ${BASE_URL}`));
