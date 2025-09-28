// Reordered imports and initialization to avoid using app before it's defined.
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import fetch from 'node-fetch';
import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';
dotenv.config();

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
// import otpRouter from './otp.js';
import resetRouter from './reset.js';

const app = express();
// Middleware setup
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://ocr-application-shop-keeper.web.app'
  ],
  credentials: true
}));
app.use(express.json());

// Attach routers early
// app.use('/api', otpRouter);
app.use('/api', resetRouter);

// Simple in-memory activity log for demo (kept in memory only)
const activityLog = [];
function logActivity(action, user) {
  activityLog.unshift({ action, user, timestamp: Date.now() });
  if (activityLog.length > 50) activityLog.pop();
}
app.get('/api/activity-log', (req, res) => res.json(activityLog));

// PostgreSQL connection
const pool = new Pool({
  user: process.env.PGUSER || 'billuser',
  host: process.env.PGHOST || 'localhost',
  database: process.env.PGDATABASE || 'billdb',
  password: process.env.PGPASSWORD || 'billpass',
  port: Number(process.env.PGPORT || 5432),
});
app.set('pool', pool);

// User profile endpoints
app.get('/api/profile', authRequired, async (req, res) => {
  const userId = req.user.id;
  const r = await pool.query('SELECT id, username, email, phone, shop_id FROM users WHERE id=$1', [userId]);
  if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
  res.json({ user: r.rows[0] });
});

app.put('/api/profile', authRequired, async (req, res) => {
  const userId = req.user.id;
  const { email, phone, password } = req.body;
  let updates = [];
  let params = [];
  if (email) { updates.push('email=$' + (params.length + 1)); params.push(email); }
  if (phone) { updates.push('phone=$' + (params.length + 1)); params.push(phone); }
  if (password) {
    const hash = await bcrypt.hash(password, 10);
    updates.push('password=$' + (params.length + 1)); params.push(hash);
  }
  if (!updates.length) return res.status(400).json({ error: 'No fields to update' });
  params.push(userId);
  const sql = `UPDATE users SET ${updates.join(', ')} WHERE id=$${params.length} RETURNING id, username, email, phone, shop_id`;
  const r = await pool.query(sql, params);
  res.json({ user: r.rows[0] });
});
// Removed duplicate imports

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

async function extractBillDataWithGemini(ocrText) {
  if (!GEMINI_API_KEY || GEMINI_API_KEY === 'PASTE_YOUR_GOOGLE_AI_API_KEY_HERE') {
    throw new Error('Gemini API key missing. Please set GEMINI_API_KEY in backend.');
  }
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${GEMINI_API_KEY}`;
  const prompt = `
You are an expert invoice extraction engine. Analyze the OCR text and return ONLY a valid JSON object with this exact schema. No prose, no markdown, no code fences.

Rules:
- date must be ISO format YYYY-MM-DD if you can infer it, otherwise null.
- subtotal, total_gst, total must be numbers (no currency symbols). Use null if unknown.
- quantity and rate must be numbers when available; amount must be a number.
- items is an array; omit inferred fields rather than guessing wildly (use null if not present).

Schema:
{
  "supplier": string|null,
  "invoiceNo": string|null,
  "date": string|null,
  "subtotal": number|null,
  "total_gst": number|null,
  "total": number|null,
  "items": [
    {
      "product_name": string|null,
  if (out.total == null) {
    const totalPat = /(grand\s*total|total\s*amount|invoice\s*total)[:\s]*([₹$]?\s*[0-9,.]+)/i;
    const mt = ocrText.match(totalPat);
    if (mt && mt[2]) out.total = toNum(mt[2]);
  }
  return out;
}

OCR Text:
---
${ocrText}
---`;
  const payload = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      temperature: 0.2,
      topP: 0.9,
      maxOutputTokens: 1024,
      responseMimeType: 'application/json'
    }
  };
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  let content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  content = content.replace(/```json/g, '').replace(/```/g, '');
  const jsonStart = content.indexOf('{');
  const jsonEnd = content.lastIndexOf('}');
  if (jsonStart === -1 || jsonEnd === -1) throw new Error("No valid JSON object found in AI response.");
  return JSON.parse(content.substring(jsonStart, jsonEnd + 1));
}

// Normalize and coerce numbers/dates in the extracted bill data
function normalizeBillData(bill, ocrText) {
  const out = { ...bill };
  const toNum = (v) => {
    if (v === null || v === undefined || v === '') return null;
    const n = Number(String(v).replace(/[^0-9.\-]/g, ''));
    return Number.isFinite(n) ? n : null;
  };
  // Normalize main fields
  out.subtotal = toNum(out.subtotal);
  out.total_gst = toNum(out.total_gst);
  out.total = toNum(out.total);
  // Normalize items array
  if (Array.isArray(out.items)) {
    out.items = out.items.map((it) => ({
      ...it,
      quantity: toNum(it?.quantity),
      rate: toNum(it?.rate),
      amount: toNum(it?.amount),
    }));
  }
  // Extract date (DD/MM/YYYY or DD-MM-YYYY)
  const ddmmyyyy = /(\b\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})\b/;
  if (!out.date && ddmmyyyy.test(ocrText)) {
    const m = ocrText.match(ddmmyyyy);
    if (m) {
      const d = m[1].padStart(2, '0');
      const mo = m[2].padStart(2, '0');
      let y = m[3];
      if (y.length === 2) y = '20' + y;
      out.date = [y, mo, d].join('-');
    }
  }
  // Extract supplier (first non-header line)
  if (!out.supplier) {
    const lines = ocrText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const badHeader = /(invoice|bill|tax|gst|receipt|estimate|quotation|date|no\.|number|customer)/i;
    const supplierLine = lines.find((ln) => ln && ln.length <= 80 && !badHeader.test(ln));
    if (supplierLine) out.supplier = supplierLine;
  }
  // Extract invoice number
  if (!out.invoiceNo) {
    const inv = ocrText.match(/(invoice\s*(no\.|number|#)\s*[:\-]?\s*)([A-Za-z0-9\-\/]+)/i);
    if (inv && inv[3]) out.invoiceNo = inv[3];
  }
  // Extract totals
  if (out.total == null) {
    const totalPat = /(grand\s*total|total\s*amount|invoice\s*total|net\s*total|amount\s*payable|total\s*due|total)[:\s]*([₹$]?\s*[0-9,.]+)/i;
    let mt = ocrText.match(totalPat);
    if (!mt) {
      // also scan lines for a standalone "total ... number" pattern
      const lines = ocrText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      for (const ln of lines) {
        const m2 = ln.match(/total[:\s]*([₹$]?\s*[0-9,.]+)/i);
        if (m2) { mt = ['', '', m2[1]]; break; }
      }
    }
    if (mt && mt[2]) out.total = toNum(mt[2]);
  }
  // Extract GST
  if (out.total_gst == null) {
    const gstPat = /(gst|tax)[:\s]*([₹$]?\s*[0-9,.]+)/i;
    const gstMatch = ocrText.match(gstPat);
    if (gstMatch && gstMatch[2]) out.total_gst = toNum(gstMatch[2]);
  }
  // Extract subtotal
  if (out.subtotal == null) {
    const subPat = /(subtotal|sub total|amount before tax)[:\s]*([₹$]?\s*[0-9,.]+)/i;
    const subMatch = ocrText.match(subPat);
    if (subMatch && subMatch[2]) out.subtotal = toNum(subMatch[2]);
  }
  // Attempt to extract items (simple line-based)
  if (!out.items || !out.items.length) {
    const itemLines = ocrText.split(/\r?\n/).filter(ln => /[a-zA-Z]/.test(ln) && /[0-9]/.test(ln));
    out.items = itemLines.map(ln => {
      // Try to extract name, quantity, price
      const parts = ln.split(/\s{2,}|\t|,/).map(s => s.trim()).filter(Boolean);
      let name = parts[0] || null;
      let quantity = null, price = null;
      for (const p of parts) {
        if (/qty|quantity/i.test(p)) quantity = toNum(p);
        if (/price|rate|amount/i.test(p)) price = toNum(p);
      }
      // Fallback: last number as price, second as quantity
      const nums = parts.map(toNum).filter(n => n !== null);
      if (nums.length) price = nums[nums.length-1];
      if (nums.length > 1) quantity = nums[nums.length-2];
      return { product_name: name, quantity, price, amount: price };
    });
  }
  return out;
}

// Lightweight fallback: derive minimal fields from raw OCR if AI/DB unavailable
function deriveSummaryFromOCR(ocrText) {
  const toNum = (v) => {
    if (v === null || v === undefined || v === '') return null;
    const n = Number(String(v).replace(/[^0-9.\-]/g, ''));
    return Number.isFinite(n) ? n : null;
  };
  const summary = {
    supplier: null,
    invoiceNo: null,
    date: null,
    subtotal: null,
    total_gst: null,
    total: null,
    items: []
  };
  if (!ocrText || typeof ocrText !== 'string') return summary;
  const lines = ocrText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  // Try to detect a supplier-like header, skip common generic headers
  const badHeader = /(invoice|bill|tax|gst|receipt|estimate|quotation|date|no\.|number|customer)/i;
  const supplierLine = lines.find((ln) => ln && ln.length <= 80 && !badHeader.test(ln));
  if (supplierLine) summary.supplier = supplierLine;
  const ddmmyyyy = /(\b\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})\b/;
  const m = ocrText.match(ddmmyyyy);
  if (m) {
    const d = m[1].padStart(2, '0');
    const mo = m[2].padStart(2, '0');
    let y = m[3];
    if (y.length === 2) y = '20' + y;
    summary.date = [y, mo, d].join('-');
  }
  // Attempt to pick common total patterns
  const totalPat = /(grand\s*total|total\s*amount|invoice\s*total|net\s*total|amount\s*payable|total\s*due|total)[:\s]*([₹$]?\s*[0-9,.]+)/i;
  let mt = ocrText.match(totalPat);
  if (!mt) {
    // also scan lines for a standalone "total ... number" pattern
    for (const ln of lines) {
      const m2 = ln.match(/total[:\s]*([₹$]?\s*[0-9,.]+)/i);
      if (m2) { mt = ['', '', m2[1]]; break; }
    }
  }
  if (mt && mt[2]) summary.total = toNum(mt[2]);
  // Try to capture invoice number if present
  const inv = ocrText.match(/(invoice\s*(no\.|number|#)\s*[:\-]?\s*)([A-Za-z0-9\-\/]+)/i);
  if (inv && inv[3]) summary.invoiceNo = inv[3];
  return summary;
}

// ...existing code...

// Ensure DB is ready before accepting requests
async function ensureDb() {
  // Create table if not exists (core columns)
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bills (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        filepath TEXT,
        ocr TEXT,
        uploaded_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await pool.query(`ALTER TABLE bills ADD COLUMN IF NOT EXISTS user_id INTEGER;`);
  } catch (e) {
    console.warn('Skipping table creation (permission?)', e.message);
  }
  try {
    await pool.query(`ALTER TABLE bills ADD COLUMN IF NOT EXISTS structured JSONB;`);
  } catch (e) {
    console.warn('Skipping column migration (permission?)', e.message);
  }
}

let HAS_STRUCTURED = false;
async function detectStructuredColumn() {
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.columns WHERE table_name = 'bills' AND column_name = 'structured' LIMIT 1;`
    );
    HAS_STRUCTURED = r.rowCount > 0;
    if (!HAS_STRUCTURED) console.warn("'structured' column not found; will insert without it.");
  } catch (e) {
    console.warn('Could not detect structured column (permission?)', e.message);
    HAS_STRUCTURED = false;
  }
}

// (removed duplicate)
const PORT = Number(process.env.PORT || 5000);

// JWT middleware
function authRequired(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Register/login endpoints
app.post('/api/register', async (req, res) => {
  const { username, password, shop_id, email, phone, shop_name, shop_address } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username/password' });
  const hash = await bcrypt.hash(password, 10);
  let finalShopId = shop_id || null;
  // Optional automatic shop creation when name provided
  if (!finalShopId && shop_name) {
    try {
      const rs = await pool.query('INSERT INTO shops (name, address) VALUES ($1, $2) RETURNING id', [shop_name, shop_address || null]);
      finalShopId = rs.rows[0].id;
    } catch (e) {
      // If shop table missing or DB down, continue with null shop_id
      console.warn('Shop creation during register failed:', e.message);
    }
  }
  try {
    const r = await pool.query(
      'INSERT INTO users (username, password, shop_id, email, phone) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [username, hash, finalShopId, email || null, phone || null]
    );
    const token = jwt.sign({ id: r.rows[0].id, username, shop_id: r.rows[0].shop_id }, process.env.JWT_SECRET || 'devsecret');
    res.json({ token, user: r.rows[0] });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  const user = r.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username, shop_id: user.shop_id }, process.env.JWT_SECRET || 'devsecret');
  logActivity('Login', username);
  res.json({ token, user });
});

// Shops CRUD
app.get('/api/shops', authRequired, async (req, res) => {
  const r = await pool.query('SELECT * FROM shops');
  res.json(r.rows);
});
app.post('/api/shops', authRequired, async (req, res) => {
  const { name, address } = req.body;
  const r = await pool.query('INSERT INTO shops (name, address) VALUES ($1, $2) RETURNING *', [name, address]);
  res.json(r.rows[0]);
});

// Items CRUD
app.get('/api/items', authRequired, async (req, res) => {
  const shop_id = req.user.shop_id;
  const r = await pool.query('SELECT * FROM items WHERE shop_id=$1', [shop_id]);
  res.json(r.rows);
});
app.post('/api/items', authRequired, async (req, res) => {
  const { name, barcode, quantity, price } = req.body;
  const shop_id = req.user.shop_id;
  const r = await pool.query('INSERT INTO items (shop_id, name, barcode, quantity, price) VALUES ($1, $2, $3, $4, $5) RETURNING *', [shop_id, name, barcode, quantity || 0, price || null]);
  res.json(r.rows[0]);
});
app.put('/api/items/:id', authRequired, async (req, res) => {
  const { quantity, price } = req.body;
  const r = await pool.query('UPDATE items SET quantity=$2, price=$3 WHERE id=$1 RETURNING *', [req.params.id, quantity, price]);
  res.json(r.rows[0]);
});

// Generate barcode for item
app.post('/api/items/:id/barcode', authRequired, async (req, res) => {
  const { id } = req.params;
  // For demo: generate a simple barcode string
  const code = 'ITEM-' + id + '-' + Math.floor(100000 + Math.random() * 900000);
  await pool.query('UPDATE items SET barcode=$2 WHERE id=$1', [id, code]);
  res.json({ barcode: code });
});

// Inventory log for OCR upsert
app.post('/api/items/:id/log', authRequired, async (req, res) => {
  const { id } = req.params;
  const { ocr_data } = req.body;
  await pool.query('INSERT INTO inventory_logs (item_id, ocr_data) VALUES ($1, $2)', [id, JSON.stringify(ocr_data)]);
  res.json({ success: true });
});

// OCR upsert endpoint (called after bill upload)
app.post('/api/items/upsert-ocr', authRequired, async (req, res) => {
  const { items } = req.body; // [{ name, quantity, price }]
  const shop_id = req.user.shop_id;
  if (!Array.isArray(items)) return res.status(400).json({ error: 'Missing items' });
  const results = [];
  for (const it of items) {
    let r;
    try {
      r = await pool.query('INSERT INTO items (shop_id, name, quantity, price) VALUES ($1, $2, $3, $4) ON CONFLICT (shop_id, name) DO UPDATE SET quantity=items.quantity + $3, price=$4 RETURNING *', [shop_id, it.name, it.quantity || 0, it.price || null]);
    } catch (e) {
      r = await pool.query('SELECT * FROM items WHERE shop_id=$1 AND name=$2', [shop_id, it.name]);
    }
    results.push(r.rows[0]);
  }
  res.json({ items: results });
});

// Approve item endpoint
app.post('/api/items/:id/approve', authRequired, async (req, res) => {
  // For demo: just log and return success
  logActivity(`Approved item ${req.params.id}`, req.user?.username || 'unknown');
  res.json({ success: true });
});

// Reject item endpoint
app.post('/api/items/:id/reject', authRequired, async (req, res) => {
  // For demo: just log and return success
  logActivity(`Rejected item ${req.params.id}`, req.user?.username || 'unknown');
  res.json({ success: true });
});

// Sale endpoint
app.post('/api/sale', authRequired, async (req, res) => {
  const { item, quantity } = req.body;
  // For demo: just log and return success
  logActivity(`Sale: ${item} x${quantity}`, req.user?.username || 'unknown');
  res.json({ success: true });
});

// Storage for uploaded files
const uploadDir = path.resolve('uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Health check
app.get('/', (req, res) => res.send('Bill backend running'));

// Upload endpoint (image/pdf)

import { exec } from 'child_process';

// Upload endpoint (image/pdf) with OCR integration



import { createWriteStream } from 'fs';
import { basename } from 'path';

app.post('/api/bills', async (req, res) => {
  const { imageUrl } = req.body;
  if (!imageUrl) {
    return res.status(400).json({ success: false, error: 'No imageUrl received by server.' });
  }
  // Download image from Firebase Storage
  const filename = Date.now() + '-' + basename(imageUrl.split('?')[0]);
  const filePath = path.join(uploadDir, filename);
  try {
    const response = await fetch(imageUrl);
    if (!response.ok) throw new Error('Failed to download image from Firebase');
    const fileStream = createWriteStream(filePath);
    await new Promise((resolve, reject) => {
      response.body.pipe(fileStream);
      response.body.on('error', reject);
      fileStream.on('finish', resolve);
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Image download failed: ' + err.message });
  }
  // Call Python OCR script
  const PYTHON = process.env.PYTHON_BIN || 'python';
  let user_id = null;
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');
      user_id = decoded.id;
    }
  } catch {}
  exec(`${PYTHON} ./ocr.py "${filePath}"`, async (error, stdout, stderr) => {
    if (error) {
      const msg = (stderr && stderr.trim()) || (stdout && stdout.trim()) || error.message || 'Unknown OCR error';
      console.error('OCR script failed:', { msg, code: error.code, signal: error.signal });
      return res.status(500).json({ success: false, error: msg });
    }
    try {
      // Extract structured bill data using Gemini AI
      const billRaw = await extractBillDataWithGemini(stdout);
      const billData = normalizeBillData(billRaw, stdout);
      // Persist sidecar JSON so history can display even if DB JSONB isn't available
      try {
        const sidecarPath = path.resolve(uploadDir, filename + '.json');
        await fs.promises.writeFile(sidecarPath, JSON.stringify(billData, null, 2), 'utf-8');
      } catch (sideErr) {
        console.warn('Could not write sidecar JSON for', filename, sideErr.message);
      }
      // Save bill info, OCR, and structured data to DB (serialize JSON explicitly)
      try {
        let result;
        if (HAS_STRUCTURED) {
          result = await pool.query(
            'INSERT INTO bills (user_id, filename, filepath, ocr, structured) VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING *',
            [user_id, filename, filePath, stdout, JSON.stringify(billData)]
          );
        } else {
          result = await pool.query(
            'INSERT INTO bills (user_id, filename, filepath, ocr) VALUES ($1, $2, $3, $4) RETURNING *',
            [user_id, filename, filePath, stdout]
          );
        }
        res.json({ success: true, bill: billData, ocr: stdout, db: result.rows[0] });
      } catch (dbErr) {
        console.warn('DB insert failed, returning data without persistence:', dbErr.message);
        res.json({ success: true, bill: billData, ocr: stdout, warning: 'DB insert failed: ' + dbErr.message });
      }
    } catch (aiErr) {
      console.error('AI/DB processing failed:', aiErr);
      res.status(500).json({ success: false, error: aiErr.message || String(aiErr) });
    }
  });
});

// List bills from database
app.get('/api/bills', async (req, res) => {
  // Get user_id from JWT
  let user_id = null;
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');
      user_id = decoded.id;
    }
  } catch {}
  try {
    let result;
    if (user_id) {
      result = await pool.query('SELECT * FROM bills WHERE user_id=$1 ORDER BY uploaded_at DESC', [user_id]);
    } else {
      result = await pool.query('SELECT * FROM bills ORDER BY uploaded_at DESC');
    }
    // Hydrate structured field using DB JSONB, sidecar file, or OCR-derived fallback
    const rows = await Promise.all((result.rows || []).map(async (r) => {
      let structured = r.structured;
      if (typeof structured === 'string') {
        try { structured = JSON.parse(structured); } catch { /* ignore */ }
      }
      if (!structured) {
        try {
          const sidecarPath = path.resolve(uploadDir, r.filename + '.json');
          if (fs.existsSync(sidecarPath)) {
            const txt = await fs.promises.readFile(sidecarPath, 'utf-8');
            structured = JSON.parse(txt);
          }
        } catch { /* ignore */ }
      }
      if (!structured) {
        structured = deriveSummaryFromOCR(r.ocr);
      }
      return { ...r, structured };
    }));
    res.json({ success: true, rows });
  } catch (err) {
    console.warn('DB read failed for /api/bills:', err.message);
    // Degraded mode: return empty list with a warning instead of failing hard
    res.json({ success: true, rows: [], warning: 'DB read failed: ' + err.message });
  }
});

// Start server only after DB migration completes
(async () => {
  try {
    await ensureDb();
    await detectStructuredColumn();
    app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
  } catch (err) {
    console.error('Initialization encountered issues:', err);
    // Start server anyway; routes may error if DB is unreachable
    app.listen(PORT, () => console.log(`Backend running on port ${PORT} (degraded DB init)`));
  }
})();

// Rebuild structured data for a single bill by id
app.post('/api/bills/:id/rebuild', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ success: false, error: 'Invalid id' });
  try {
    const { rows } = await pool.query('SELECT * FROM bills WHERE id=$1 LIMIT 1', [id]);
    if (!rows || rows.length === 0) return res.status(404).json({ success: false, error: 'Not found' });
    const row = rows[0];
    const ocrText = row.ocr || '';
    const billRaw = await extractBillDataWithGemini(ocrText);
    const billData = normalizeBillData(billRaw, ocrText);
    // Write sidecar
    try {
      const sidecarPath = path.resolve(uploadDir, row.filename + '.json');
      await fs.promises.writeFile(sidecarPath, JSON.stringify(billData, null, 2), 'utf-8');
    } catch (e) {
      console.warn('Sidecar write failed for', row.filename, e.message);
    }
    // Update DB if column exists
    try {
      if (HAS_STRUCTURED) {
        const upd = await pool.query('UPDATE bills SET structured=$2::jsonb WHERE id=$1 RETURNING *', [id, JSON.stringify(billData)]);
        return res.json({ success: true, row: upd.rows[0], bill: billData });
      }
    } catch (e) {
      console.warn('DB update failed for rebuild id', id, e.message);
    }
    res.json({ success: true, row, bill: billData, warning: !HAS_STRUCTURED ? 'structured column not available' : undefined });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || String(e) });
  }
});

// Rebuild structured data for all bills (best-effort)
app.post('/api/bills/rebuild-all', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM bills ORDER BY uploaded_at DESC');
    const results = [];
    for (const row of rows) {
      try {
        const ocrText = row.ocr || '';
        const billRaw = await extractBillDataWithGemini(ocrText);
        const billData = normalizeBillData(billRaw, ocrText);
        // Sidecar
        try {
          const sidecarPath = path.resolve(uploadDir, row.filename + '.json');
          await fs.promises.writeFile(sidecarPath, JSON.stringify(billData, null, 2), 'utf-8');
        } catch (e) {
          /* ignore */
        }
        // DB update
        if (HAS_STRUCTURED) {
          await pool.query('UPDATE bills SET structured=$2::jsonb WHERE id=$1', [row.id, JSON.stringify(billData)]);
        }
        results.push({ id: row.id, ok: true });
      } catch (e) {
        results.push({ id: row.id, ok: false, error: (e && e.message) || String(e) });
      }
    }
    res.json({ success: true, results });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || String(e) });
  }
});
