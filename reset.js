import express from 'express';
import bcrypt from 'bcryptjs';
const router = express.Router();

// In-memory OTP store for demo
const otps = {};

// Send OTP for password reset
router.post('/send-reset-otp', async (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) return res.status(400).json({ error: 'Email or phone required' });
  // Check if user exists
  // You may need to import pool from index.js or refactor
  const pool = req.app.get('pool');
  let user;
  if (email) {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    user = r.rows[0];
  } else if (phone) {
    const r = await pool.query('SELECT * FROM users WHERE phone=$1', [phone]);
    user = r.rows[0];
  }
  if (!user) return res.status(404).json({ error: 'User not found' });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const key = email || phone;
  otps[key] = otp;
  // TODO: Integrate with email/SMS provider
  res.json({ success: true, otp }); // For demo, return OTP
});

// Verify OTP and reset password
router.post('/reset-password', async (req, res) => {
  const { email, phone, otp, newPassword } = req.body;
  const key = email || phone;
  if (otps[key] !== otp) return res.status(400).json({ error: 'Invalid OTP' });
  // Update password
  const pool = req.app.get('pool');
  const hash = await bcrypt.hash(newPassword, 10);
  let r;
  if (email) {
    r = await pool.query('UPDATE users SET password=$1 WHERE email=$2 RETURNING *', [hash, email]);
  } else if (phone) {
    r = await pool.query('UPDATE users SET password=$1 WHERE phone=$2 RETURNING *', [hash, phone]);
  }
  delete otps[key];
  if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
  res.json({ success: true });
});

export default router;
