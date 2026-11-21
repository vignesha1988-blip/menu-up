const http = require('http');
const fs = require('fs');
const path = require('path');
const https = require('https');
const {
  validateIndianMobile,
  generateSecureOtp,
  getClientIp,
  checkIpRateLimit,
  checkPhoneRateLimit,
  saveOtp,
  verifyOtp
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

      // 3. Per-Phone Rate Limiting (Cooldown & Quota)
      const phoneCheck = checkPhoneRateLimit(phone10);
      if (!phoneCheck.allowed) {
        console.warn(`[Security Alert] Phone limit triggered for ${phone10}`);
        return sendJson(res, 429, { success: false, message: phoneCheck.message });
      }

      // 4. Generate Cryptographically Secure 4-digit OTP
      const otp = generateSecureOtp();
      saveOtp(phone10, otp);

      const internationalPhone = '91' + phone10;
      console.log(`[MSG91 ${new Date().toLocaleTimeString()}] Securely dispatching OTP to +${internationalPhone} (IP: ${clientIp})`);

      // 5. Dispatch via MSG91 Flow API with exact DLT variable "number"
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
          message: 'OTP sent successfully',
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
      const { mobile, otp } = body;

      const phone10 = validateIndianMobile(mobile);
      if (!phone10) {
        return sendJson(res, 400, { success: false, message: 'Invalid mobile number format' });
      }

      if (!otp || String(otp).trim().length < 4) {
        return sendJson(res, 400, { success: false, message: 'Please enter the 4-digit verification code' });
      }

      // Anti-brute force verify
      const verification = verifyOtp(phone10, String(otp));

      if (verification.success) {
        console.log(`[Security] Successful OTP verification for +91${phone10}`);
        return sendJson(res, 200, {
          success: true,
          message: 'OTP verified successfully',
          token: verification.token
        });
      } else {
        console.warn(`[Security Warning] Verification failed for +91${phone10}: ${verification.message}`);
        return sendJson(res, 400, {
          success: false,
          message: verification.message
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
      const { mobile } = body;
      const phone10 = validateIndianMobile(mobile);
      if (!phone10) {
        return sendJson(res, 400, { success: false, message: 'Invalid mobile number format' });
      }

      const phoneCheck = checkPhoneRateLimit(phone10);
      if (!phoneCheck.allowed) {
        return sendJson(res, 429, { success: false, message: phoneCheck.message });
      }

      const otp = generateSecureOtp();
      saveOtp(phone10, otp);

      const internationalPhone = '91' + phone10;
      console.log(`[MSG91 Resend] Securely resending OTP to +${internationalPhone}`);

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
        return sendJson(res, 200, { success: true, message: 'OTP resent successfully' });
      } else {
        return sendJson(res, 400, { success: false, message: (result.data && result.data.message) || 'Failed to resend OTP' });
      }
    } catch (err) {
      console.error('[Resend OTP Error]', err);
      return sendJson(res, 500, { success: false, message: 'Server error resending OTP' });
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
