const crypto = require('crypto');

// Secret key for HMAC signing
function getSecretKey() {
  return process.env.OTP_VERIFY_SECRET || process.env.MSG91_AUTH_KEY || 'abnl_production_otp_secret_key_2026';
}

// In-memory IP rate limiter for abuse prevention within single instances
const ipRateLimits = new Map();

// Security Configurations
const OTP_EXPIRY_MS = 10 * 60 * 1000;   // 10 minutes expiry (matches DLT template)
const MIN_SEND_COOLDOWN_MS = 45 * 1000; // 45 seconds cooldown between sends
const MAX_FAILED_ATTEMPTS = 3;          // Max 3 incorrect OTP guesses before token is burned
const MAX_IP_REQUESTS_PER_WINDOW = 15;  // Max 15 OTP requests per IP per 15 min
const IP_WINDOW_MS = 15 * 60 * 1000;    // 15-minute IP window

/**
 * Validates and normalizes Indian mobile numbers.
 * Enforces 10 digits starting with 6, 7, 8, or 9.
 * Returns normalized 10-digit string or null if invalid.
 */
function validateIndianMobile(mobile) {
  if (!mobile) return null;
  const digits = String(mobile).replace(/\D/g, '');
  let phone10 = '';
  if (digits.length === 10) {
    phone10 = digits;
  } else if (digits.length === 12 && digits.startsWith('91')) {
    phone10 = digits.slice(2);
  } else if (digits.length === 11 && digits.startsWith('0')) {
    phone10 = digits.slice(1);
  } else {
    return null;
  }

  // Indian mobile numbers must start with 6, 7, 8, or 9
  if (!/^[6-9]\d{9}$/.test(phone10)) {
    return null;
  }
  return phone10;
}

/**
 * Generates cryptographically secure 4-digit OTP using OS entropy.
 */
function generateSecureOtp() {
  return crypto.randomInt(1000, 10000).toString();
}

/**
 * Safely extracts client IP address across standard and proxied connections.
 */
function getClientIp(req) {
  const xForwardedFor = req.headers && req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    return String(xForwardedFor).split(',')[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || '127.0.0.1';
}

/**
 * Enforces IP-level rate limiting to stop distributed abuse / SMS pumping.
 */
function checkIpRateLimit(ip) {
  const now = Date.now();
  let record = ipRateLimits.get(ip);
  if (!record || (now - record.windowStart) > IP_WINDOW_MS) {
    record = { count: 1, windowStart: now };
    ipRateLimits.set(ip, record);
    return { allowed: true };
  }

  if (record.count >= MAX_IP_REQUESTS_PER_WINDOW) {
    const waitMins = Math.ceil((IP_WINDOW_MS - (now - record.windowStart)) / 60000);
    return {
      allowed: false,
      message: `Too many OTP requests from this network. Please try again in ${waitMins} minute(s).`
    };
  }

  record.count += 1;
  return { allowed: true };
}

/**
 * Creates a stateless signed verification token.
 * Contains: phone, HMAC hash of OTP, sentAt timestamp, expiry, and attempts count.
 * Completely stateless - no in-memory storage required.
 */
function createVerificationToken(phone10, otp) {
  const secret = getSecretKey();
  const now = Date.now();

  // HMAC-hash the OTP combined with phone number so OTP cannot be extracted or guessed offline
  const otpHash = crypto.createHmac('sha256', secret)
    .update(`${phone10}:${otp}`)
    .digest('hex');

  const payload = {
    phone: phone10,
    hash: otpHash,
    sentAt: now,
    expiresAt: now + OTP_EXPIRY_MS,
    attemptsLeft: MAX_FAILED_ATTEMPTS
  };

  const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret)
    .update(payloadStr)
    .digest('base64url');

  return `${payloadStr}.${signature}`;
}

/**
 * Checks if resend cooldown has elapsed from a verification token.
 */
function checkResendCooldown(token) {
  if (!token || typeof token !== 'string') {
    return { allowed: true };
  }

  try {
    const parts = token.split('.');
    if (parts.length !== 2) return { allowed: true };
    const [payloadStr, sig] = parts;
    const secret = getSecretKey();
    const expectedSig = crypto.createHmac('sha256', secret).update(payloadStr).digest('base64url');
    if (expectedSig !== sig) return { allowed: true };

    const payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));
    const elapsed = Date.now() - (payload.sentAt || 0);

    if (elapsed < MIN_SEND_COOLDOWN_MS) {
      const waitSecs = Math.ceil((MIN_SEND_COOLDOWN_MS - elapsed) / 1000);
      return {
        allowed: false,
        message: `Please wait ${waitSecs} seconds before requesting another code.`
      };
    }
  } catch (e) {
    // Fall back to allowing if parsing fails
  }

  return { allowed: true };
}

/**
 * Verifies user-entered OTP against the stateless verification token.
 * Enforces signature validity, expiration, phone match, and attempt counting.
 */
function verifyVerificationToken(token, phone10, userOtp) {
  if (!token || typeof token !== 'string') {
    return {
      success: false,
      message: 'No active OTP found. Please request a new code.'
    };
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return {
      success: false,
      message: 'Invalid session token format. Please request a new code.'
    };
  }

  const [payloadStr, clientSig] = parts;
  const secret = getSecretKey();

  // Verify HMAC signature using timingSafeEqual
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadStr).digest('base64url');
  const expectedBuf = Buffer.from(expectedSig);
  const clientBuf = Buffer.from(clientSig);

  if (expectedBuf.length !== clientBuf.length || !crypto.timingSafeEqual(expectedBuf, clientBuf)) {
    return {
      success: false,
      message: 'Security validation failed: invalid or tampered verification token.'
    };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));
  } catch (err) {
    return {
      success: false,
      message: 'Malformed verification token. Please request a new code.'
    };
  }

  const now = Date.now();

  // Validate phone number match
  if (payload.phone !== phone10) {
    return {
      success: false,
      message: 'Mobile number mismatch. Please request a code for your number.'
    };
  }

  // Validate expiry (10 minutes)
  if (now > payload.expiresAt) {
    return {
      success: false,
      message: 'This OTP has expired. Please request a new code.'
    };
  }

  // Validate attempts remaining
  if (payload.attemptsLeft <= 0) {
    return {
      success: false,
      message: 'Too many incorrect attempts. This OTP has been invalidated. Please request a new code.'
    };
  }

  // Validate user OTP
  const cleanOtp = String(userOtp || '').trim();
  const inputHash = crypto.createHmac('sha256', secret)
    .update(`${phone10}:${cleanOtp}`)
    .digest('hex');

  const inputHashBuf = Buffer.from(inputHash);
  const targetHashBuf = Buffer.from(payload.hash || '');

  const isMatch = inputHashBuf.length === targetHashBuf.length &&
                  crypto.timingSafeEqual(inputHashBuf, targetHashBuf);

  if (!isMatch) {
    const remaining = payload.attemptsLeft - 1;

    if (remaining <= 0) {
      return {
        success: false,
        message: 'Too many incorrect attempts. This OTP has been invalidated for security. Please request a new code.'
      };
    }

    // Re-sign token with decremented attempts
    const updatedPayload = {
      ...payload,
      attemptsLeft: remaining
    };
    const updatedPayloadStr = Buffer.from(JSON.stringify(updatedPayload)).toString('base64url');
    const updatedSig = crypto.createHmac('sha256', secret).update(updatedPayloadStr).digest('base64url');
    const updatedToken = `${updatedPayloadStr}.${updatedSig}`;

    return {
      success: false,
      message: `Incorrect code. ${remaining} attempt${remaining > 1 ? 's' : ''} remaining.`,
      verificationToken: updatedToken
    };
  }

  // OTP is correct! Generate permanent verification token for device tagging
  const verifiedToken = crypto.createHmac('sha256', secret)
    .update(`verified:${phone10}:${now}`)
    .digest('hex');

  return {
    success: true,
    message: 'OTP verified successfully',
    verifiedToken,
    verifiedAt: now
  };
}

// ========================================================
// Anti-Abuse & Email Security Protections
// ========================================================

// 1. In-memory storage for consumed tokens to prevent replay attacks
const consumedTokens = new Map();

// 2. In-memory tracking for phone-level booking frequency
const phoneBookingHistory = new Map();

// 3. In-memory global email circuit breaker
const emailDispatchTimestamps = [];

// Clean up expired consumed tokens every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, expiresAt] of consumedTokens.entries()) {
    if (now > expiresAt) {
      consumedTokens.delete(key);
    }
  }
  for (const [phone, timestamps] of phoneBookingHistory.entries()) {
    const valid = timestamps.filter(t => (now - t) < 24 * 60 * 60 * 1000);
    if (valid.length === 0) {
      phoneBookingHistory.delete(phone);
    } else {
      phoneBookingHistory.set(phone, valid);
    }
  }
}, 10 * 60 * 1000).unref();

/**
 * Prevents token replay attacks. Ensures an OTP verification token can only be used ONCE.
 */
function consumeVerificationToken(token) {
  if (!token || typeof token !== 'string') {
    return { allowed: false, message: 'Invalid verification token.' };
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return { allowed: false, message: 'Invalid token structure.' };
  }

  const tokenSig = parts[1];
  const now = Date.now();

  if (consumedTokens.has(tokenSig)) {
    return {
      allowed: false,
      message: 'This verification code has already been used for a reservation. Please request a new code.'
    };
  }

  // Parse expiry from token to auto-expire from consumed cache
  let expiresAt = now + OTP_EXPIRY_MS;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (payload.expiresAt) expiresAt = payload.expiresAt;
  } catch (e) {}

  consumedTokens.set(tokenSig, expiresAt);
  return { allowed: true };
}

/**
 * Enforces per-phone booking limits:
 * - Minimum 3 minutes cooldown between bookings for the same phone.
 * - Maximum 3 bookings per phone number per 24 hours.
 */
function checkPhoneBookingLimit(phone10) {
  const now = Date.now();
  const history = phoneBookingHistory.get(phone10) || [];
  const validHistory = history.filter(t => (now - t) < 24 * 60 * 60 * 1000);

  if (validHistory.length > 0) {
    const lastBooking = validHistory[validHistory.length - 1];
    const elapsedMs = now - lastBooking;
    const COOLDOWN_MS = 3 * 60 * 1000; // 3 minutes

    if (elapsedMs < COOLDOWN_MS) {
      const waitMins = Math.ceil((COOLDOWN_MS - elapsedMs) / 60000);
      return {
        allowed: false,
        message: `A recent booking was just made for this number. Please wait ${waitMins} minute(s) before booking again or call +91 8110003883.`
      };
    }
  }

  if (validHistory.length >= 3) {
    return {
      allowed: false,
      message: 'Daily reservation limit reached for this mobile number (max 3 bookings per day). For party or group bookings, please call +91 8110003883 directly.'
    };
  }

  return { allowed: true };
}

function recordPhoneBooking(phone10) {
  const now = Date.now();
  const history = phoneBookingHistory.get(phone10) || [];
  history.push(now);
  phoneBookingHistory.set(phone10, history);
}

/**
 * Global Email Circuit Breaker:
 * Protects Google SMTP account from quota exhaustion:
 * - Maximum 30 emails per rolling hour
 * - Maximum 250 emails per rolling 24 hours
 */
function checkGlobalEmailQuota() {
  const now = Date.now();
  const oneHourAgo = now - 60 * 60 * 1000;
  const oneDayAgo = now - 24 * 60 * 60 * 1000;

  // Prune old timestamps
  while (emailDispatchTimestamps.length > 0 && emailDispatchTimestamps[0] < oneDayAgo) {
    emailDispatchTimestamps.shift();
  }

  const emailsLastHour = emailDispatchTimestamps.filter(t => t > oneHourAgo).length;
  if (emailsLastHour >= 30) {
    return {
      allowed: false,
      message: 'Email notification traffic limit reached for this hour. Reservation recorded in lounge log.'
    };
  }

  if (emailDispatchTimestamps.length >= 250) {
    return {
      allowed: false,
      message: 'Daily email notification capacity reached. Reservation recorded in lounge log.'
    };
  }

  return { allowed: true };
}

function recordEmailSent() {
  emailDispatchTimestamps.push(Date.now());
}

/**
 * Escapes HTML characters to prevent HTML/XSS/Phishing injection in email clients.
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Strips carriage returns, line feeds, and control characters to prevent SMTP header injection.
 */
function sanitizeHeader(str) {
  if (!str) return '';
  return String(str).replace(/[\r\n\t\x00-\x1F\x7F]/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Whitelist of permitted 30-minute time slots.
 */
const ALLOWED_TIME_SLOTS = new Set([
  '11:00 AM', '11:30 AM', '12:00 PM', '12:30 PM',
  '01:00 PM', '01:30 PM', '02:00 PM', '02:30 PM',
  '03:00 PM', '03:30 PM', '04:00 PM', '04:30 PM',
  '05:00 PM', '05:30 PM', '06:00 PM', '06:30 PM',
  '07:00 PM', '07:30 PM', '08:00 PM', '08:30 PM',
  '09:00 PM', '09:30 PM', '10:00 PM', '10:30 PM',
  '11:00 PM', '11:30 PM'
]);

module.exports = {
  validateIndianMobile,
  generateSecureOtp,
  getClientIp,
  checkIpRateLimit,
  createVerificationToken,
  checkResendCooldown,
  verifyVerificationToken,
  consumeVerificationToken,
  checkPhoneBookingLimit,
  recordPhoneBooking,
  checkGlobalEmailQuota,
  recordEmailSent,
  escapeHtml,
  sanitizeHeader,
  ALLOWED_TIME_SLOTS
};
