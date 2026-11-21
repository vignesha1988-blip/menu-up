const http = require('http');
const fs = require('fs');
const path = require('path');
const https = require('https');
const nodemailer = require('nodemailer');
const {
  validateIndianMobile,
  generateSecureOtp,
  getClientIp,
  checkIpRateLimit,
  createVerificationToken,
  checkResendCooldown,
  verifyVerificationToken
} = require('./lib/otp-security');

// Load .env.local
const envPath = path.join(__dirname, '.env.local');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  envContent.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
      const idx = trimmed.indexOf('=');
      const key = trimmed.substring(0, idx).trim();
      let val = trimmed.substring(idx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.substring(1, val.length - 1);
      }
      if (!process.env[key]) {
        process.env[key] = val;
      }
    }
  });
}

const PORT = process.env.PORT || 8000;
const AUTH_KEY = process.env.MSG91_AUTH_KEY || '575648A2RMCxpoV6ab8ef67P1';
const TEMPLATE_ID = process.env.MSG91_TEMPLATE_ID || '6b01682b7a0876498406a382';
const SENDER_ID = process.env.MSG91_HEADER_NAME || 'SRDVPL';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf',
  '.ico': 'image/x-icon'
};

const MAX_PAYLOAD_BYTES = 10 * 1024; // 10 KB max payload

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX_PAYLOAD_BYTES) {
        req.destroy();
        reject(new Error('Payload too large'));
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function httpsPost(url, payload, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const postData = JSON.stringify(payload);
    const options = {
      hostname: parsed.hostname,
      port: 443,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'accept': 'application/json',
        ...headers
      }
    };

    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  // Security Headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, authkey');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // --- API ROUTE: SEND OTP ---
  if (pathname === '/api/send-otp') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { success: false, message: 'Method Not Allowed' });
    }

    try {
      const clientIp = getClientIp(req);

      // 1. IP Rate Limiting (Anti-SMS Pumping / Abuse)
      const ipCheck = checkIpRateLimit(clientIp);
      if (!ipCheck.allowed) {
        console.warn(`[Security Alert] IP Rate limit triggered for IP ${clientIp}`);
        return sendJson(res, 429, { success: false, message: ipCheck.message });
      }

      const body = await readBody(req);
      const { mobile } = body;

      // 2. Strict Indian Mobile Number Validation
      const phone10 = validateIndianMobile(mobile);
      if (!phone10) {
        return sendJson(res, 400, {
          success: false,
          message: 'Please enter a valid 10-digit Indian mobile number (starting with 6, 7, 8, or 9).'
        });
      }

      // 3. Cryptographically secure OTP & stateless verification token
      const otp = generateSecureOtp();
      const verificationToken = createVerificationToken(phone10, otp);

      const internationalPhone = '91' + phone10;
      console.log(`[MSG91 Dispatch] Sending OTP to +${internationalPhone} via Template ${TEMPLATE_ID}`);

      // MSG91 Flow API payload (DLT registered variable is ##number##)
      const flowPayload = {
        template_id: TEMPLATE_ID,
        sender: SENDER_ID,
        short_url: '0',
        recipients: [
          {
            mobiles: internationalPhone,
            number: otp
          }
        ]
      };

      const result = await httpsPost('https://control.msg91.com/api/v5/flow', flowPayload, {
        'authkey': AUTH_KEY
      });

      if (result.data && (result.data.type === 'success' || result.data.status === 'success' || result.status === 200)) {
        console.log(`[MSG91 Success] Request ID: ${result.data.message}`);
        return sendJson(res, 200, {
          success: true,
          message: 'OTP sent successfully',
          verificationToken,
          requestId: result.data.message
        });
      } else {
        console.error('[MSG91 Error]', result.data);
        return sendJson(res, 400, {
          success: false,
          message: (result.data && result.data.message) || 'Failed to dispatch SMS'
        });
      }
    } catch (err) {
      console.error('[Send OTP Error]', err);
      return sendJson(res, 500, { success: false, message: 'Server error processing OTP request' });
    }
  }

  // --- API ROUTE: VERIFY OTP ---
  if (pathname === '/api/verify-otp') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { success: false, message: 'Method Not Allowed' });
    }

    try {
      const body = await readBody(req);
      const { mobile, otp, verificationToken } = body;

      const phone10 = validateIndianMobile(mobile);
      if (!phone10) {
        return sendJson(res, 400, { success: false, message: 'Invalid mobile number format' });
      }

      if (!verificationToken) {
        return sendJson(res, 400, {
          success: false,
          message: 'No active OTP found for this number. Please request a new code.'
        });
      }

      if (!otp || String(otp).trim().length !== 4) {
        return sendJson(res, 400, { success: false, message: 'Please enter the 4-digit verification code' });
      }

      // Stateless cryptographic verification
      const verification = verifyVerificationToken(verificationToken, phone10, String(otp));

      if (verification.success) {
        console.log(`[Security] Successful OTP verification for +91${phone10}`);
        return sendJson(res, 200, {
          success: true,
          message: 'OTP verified successfully',
          verifiedToken: verification.verifiedToken
        });
      } else {
        console.warn(`[Security Warning] Verification failed for +91${phone10}: ${verification.message}`);
        return sendJson(res, 400, {
          success: false,
          message: verification.message,
          verificationToken: verification.verificationToken
        });
      }
    } catch (err) {
      console.error('[Verify OTP Error]', err);
      return sendJson(res, 500, { success: false, message: 'Server error verifying OTP' });
    }
  }

  // --- API ROUTE: RESEND OTP ---
  if (pathname === '/api/resend-otp') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { success: false, message: 'Method Not Allowed' });
    }

    try {
      const clientIp = getClientIp(req);
      const ipCheck = checkIpRateLimit(clientIp);
      if (!ipCheck.allowed) {
        return sendJson(res, 429, { success: false, message: ipCheck.message });
      }

      const body = await readBody(req);
      const { mobile, verificationToken } = body;
      const phone10 = validateIndianMobile(mobile);
      if (!phone10) {
        return sendJson(res, 400, { success: false, message: 'Invalid mobile number format' });
      }

      // Check resend cooldown
      if (verificationToken) {
        const cooldownCheck = checkResendCooldown(verificationToken);
        if (!cooldownCheck.allowed) {
          return sendJson(res, 429, { success: false, message: cooldownCheck.message });
        }
      }

      const otp = generateSecureOtp();
      const newVerificationToken = createVerificationToken(phone10, otp);

      const internationalPhone = '91' + phone10;
      console.log(`[MSG91 Resend] Resending OTP to +${internationalPhone}`);

      const flowPayload = {
        template_id: TEMPLATE_ID,
        sender: SENDER_ID,
        short_url: '0',
        recipients: [
          {
            mobiles: internationalPhone,
            number: otp
          }
        ]
      };

      const result = await httpsPost('https://control.msg91.com/api/v5/flow', flowPayload, {
        'authkey': AUTH_KEY
      });

      if (result.data && (result.data.type === 'success' || result.data.status === 'success' || result.status === 200)) {
        return sendJson(res, 200, {
          success: true,
          message: 'OTP resent successfully',
          verificationToken: newVerificationToken
        });
      } else {
        return sendJson(res, 400, { success: false, message: (result.data && result.data.message) || 'Failed to resend OTP' });
      }
    } catch (err) {
      console.error('[Resend OTP Error]', err);
      return sendJson(res, 500, { success: false, message: 'Server error resending OTP' });
    }
  }

  // --- API ROUTE: BOOK TABLE ---
  if (pathname === '/api/book-table') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { success: false, message: 'Method Not Allowed' });
    }

    try {
      const clientIp = getClientIp(req);
      const ipCheck = checkIpRateLimit(clientIp);
      if (!ipCheck.allowed) {
        return sendJson(res, 429, { success: false, message: ipCheck.message });
      }

      const body = await readBody(req);
      const {
        name,
        guests,
        date,
        time,
        mobile,
        otp,
        verificationToken,
        specialRequests
      } = body;

      const cleanName = String(name || '').trim();
      if (!cleanName || cleanName.length < 2) {
        return sendJson(res, 400, { success: false, message: 'Please provide a valid guest name (at least 2 characters).' });
      }

      const guestNum = parseInt(guests, 10);
      if (isNaN(guestNum) || guestNum < 1 || guestNum > 50) {
        return sendJson(res, 400, { success: false, message: 'Please specify the number of guests (1-50).' });
      }

      if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return sendJson(res, 400, { success: false, message: 'Please select a valid reservation date.' });
      }
      const todayStr = new Date().toISOString().split('T')[0];
      if (date < todayStr) {
        return sendJson(res, 400, { success: false, message: 'Reservation date cannot be in the past.' });
      }

      const cleanTime = String(time || '').trim();
      if (!cleanTime) {
        return sendJson(res, 400, { success: false, message: 'Please select a reservation time slot.' });
      }

      const phone10 = validateIndianMobile(mobile);
      if (!phone10) {
        return sendJson(res, 400, { success: false, message: 'Invalid 10-digit Indian mobile number.' });
      }

      if (!verificationToken) {
        return sendJson(res, 400, {
          success: false,
          message: 'No active OTP verification session found. Please request an OTP.'
        });
      }

      if (!otp || String(otp).trim().length !== 4) {
        return sendJson(res, 400, {
          success: false,
          message: 'Please enter the 4-digit OTP sent to your mobile.'
        });
      }

      const verification = verifyVerificationToken(verificationToken, phone10, String(otp));
      if (!verification.success) {
        return sendJson(res, 400, {
          success: false,
          message: verification.message,
          verificationToken: verification.verificationToken
        });
      }

      // Generate booking ID
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      let code = '';
      for (let i = 0; i < 5; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      const bookingId = `ABNL-${code}`;
      const cleanSpecialRequests = String(specialRequests || '').trim().slice(0, 500);
      const bookingTimestamp = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

      const appPassword = process.env.GMAIL_APP_PASSWORD;
      const senderEmail = process.env.GMAIL_USER || 'Vigneshagurudas1988@gmail.com';
      const notifyEmails = [
        'vignesha1988@gmail.com',
        'eshvar1234@gmail.com',
        'Absolutebarnlounge@gmail.com'
      ];

      let emailStatus = 'pending';
      let emailError = null;

      if (appPassword) {
        try {
          const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
              user: senderEmail,
              pass: appPassword.replace(/\s+/g, '')
            }
          });

          const subject = `🍽️ Table Reservation Confirmed: ${cleanName} (${guestNum} Guests) - ${date} at ${cleanTime}`;
          const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #0e0204; color: #fbf7f0; margin: 0; padding: 20px; }
    .container { max-width: 600px; margin: 0 auto; background: #190306; border: 1.5px solid #d4af37; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.8); }
    .header { background: linear-gradient(135deg, #7a0c14 0%, #3a060a 100%); padding: 24px; text-align: center; border-bottom: 2px solid #d4af37; }
    .header h1 { margin: 0; font-size: 22px; color: #f3df95; letter-spacing: 2px; text-transform: uppercase; }
    .header p { margin: 6px 0 0; color: #d9c8af; font-size: 13px; }
    .content { padding: 24px; }
    .badge { display: inline-block; background: rgba(37, 211, 102, 0.15); border: 1px solid #25D366; color: #25D366; font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 20px; text-transform: uppercase; margin-bottom: 16px; }
    .details-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .details-table td { padding: 12px 14px; border-bottom: 1px solid rgba(212, 175, 55, 0.2); font-size: 14px; }
    .details-table td.label { color: #d4af37; font-weight: 700; width: 38%; }
    .details-table td.value { color: #fbf7f0; }
    .actions { margin-top: 24px; text-align: center; }
    .btn { display: inline-block; padding: 10px 20px; margin: 6px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 13px; }
    .btn-call { background: #d4af37; color: #190306; }
    .btn-wa { background: #25D366; color: #ffffff; }
    .footer { padding: 16px; text-align: center; font-size: 11px; color: #a89582; border-top: 1px solid rgba(212, 175, 55, 0.2); }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Absolute Bar & Lounge</h1>
      <p>NEW TABLE RESERVATION CONFIRMED</p>
    </div>
    <div class="content">
      <div style="text-align: center;">
        <span class="badge">✓ Phone Verified via SMS OTP</span>
      </div>
      <table class="details-table">
        <tr>
          <td class="label">Booking ID</td>
          <td class="value"><strong style="color: #ffbe3b; font-size: 16px;">${bookingId}</strong></td>
        </tr>
        <tr>
          <td class="label">Guest Name</td>
          <td class="value"><strong>${cleanName}</strong></td>
        </tr>
        <tr>
          <td class="label">Number of Guests</td>
          <td class="value"><strong>${guestNum} ${guestNum > 1 ? 'Guests' : 'Guest'}</strong></td>
        </tr>
        <tr>
          <td class="label">Reservation Date</td>
          <td class="value"><strong>${date}</strong></td>
        </tr>
        <tr>
          <td class="label">Time Slot</td>
          <td class="value"><strong>${cleanTime}</strong></td>
        </tr>
        <tr>
          <td class="label">Contact Mobile</td>
          <td class="value">
            <a href="tel:+91${phone10}" style="color: #ffbe3b; text-decoration: none; font-weight: 700;">+91 ${phone10}</a>
          </td>
        </tr>
        <tr>
          <td class="label">Special Requests</td>
          <td class="value">${cleanSpecialRequests || '<em>None specified</em>'}</td>
        </tr>
        <tr>
          <td class="label">Booked At</td>
          <td class="value">${bookingTimestamp} (IST)</td>
        </tr>
      </table>

      <div class="actions">
        <a href="tel:+91${phone10}" class="btn btn-call">📞 Call Guest</a>
        <a href="https://wa.me/91${phone10}?text=Hi%20${encodeURIComponent(cleanName)}%2C%20greeting%20from%20Absolute%20Bar%20%26%20Lounge.%20Your%20table%20reservation%20(${bookingId})%20for%20${guestNum}%20guests%20on%20${date}%20at%20${encodeURIComponent(cleanTime)}%20is%20confirmed." class="btn btn-wa" target="_blank">💬 WhatsApp Guest</a>
      </div>
    </div>
    <div class="footer">
      Sent from Absolute Bar & Lounge Digital System &bull; <a href="https://menu-up-abnl.vercel.app/" style="color: #d4af37;">menu-up-abnl.vercel.app</a>
    </div>
  </div>
</body>
</html>
`;

          const info = await transporter.sendMail({
            from: `"Absolute Bar & Lounge" <${senderEmail}>`,
            to: notifyEmails.join(', '),
            subject: subject,
            html: htmlContent
          });

          emailStatus = 'sent';
          console.log('[Reservation Email Sent]', info.messageId);
        } catch (err) {
          emailStatus = 'failed';
          emailError = err.message;
          console.error('[Reservation Email Error]', err);
        }
      } else {
        emailStatus = 'skipped_no_app_password';
        console.warn('[Reservation Email Skipped] GMAIL_APP_PASSWORD is not set.');
      }

      return sendJson(res, 200, {
        success: true,
        message: 'Table reservation confirmed successfully!',
        booking: {
          bookingId,
          name: cleanName,
          guests: guestNum,
          date,
          time: cleanTime,
          mobile: phone10,
          specialRequests: cleanSpecialRequests,
          emailStatus,
          emailError
        }
      });
    } catch (err) {
      console.error('[Book Table Error]', err);
      return sendJson(res, 500, { success: false, message: 'Server error processing reservation' });
    }
  }

  // --- STATIC FILE SERVING ---
  let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath).toLowerCase();

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }

    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`Absolute Bar & Lounge Secure Server running on http://localhost:${PORT}`);
});
