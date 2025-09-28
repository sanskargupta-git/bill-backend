// OTP routes and logic commented out for future use
/*
import express from 'express';
// import twilio from 'twilio'; // Disabled for now
const router = express.Router();

// In-memory OTP store for demo (use Redis or DB in production)
const otps = {};

// Twilio setup disabled for now
// const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

router.post('/send-otp', async (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) return res.status(400).json({ error: 'Email or phone required' });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const key = email || phone;
  otps[key] = otp;
  // Twilio SMS integration disabled for now
  res.json({ success: true }); // Do not return OTP in production
});

// Verify OTP
router.post('/verify-otp', (req, res) => {
  const { email, phone, otp } = req.body;
  const key = email || phone;
  if (otps[key] === otp) {
    delete otps[key];
    return res.json({ success: true });
  }
  res.status(400).json({ error: 'Invalid OTP' });
});

export default router;
*/

export default {};
