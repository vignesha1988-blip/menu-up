const crypto = require('crypto');

// In-memory security tracking
const otpStore = new Map(); // phone10 -> { otp, expiresAt, attempts, lastSentAt, sendCount, windowStart }
const ipRateLimits = new Map(); // ip -> { count, windowStart }

// Security Configurations
const MAX_SENDS_PER_WINDOW = 3;         // Max 3 OTP sends per phone within 15 min
const PHONE_WINDOW_MS = 15 * 60 * 1000; // 15-minute sliding window
const MIN_SEND_COOLDOWN_MS = 45 * 1000; // 45 seconds cooldown between sends
const MAX_FAILED_ATTEMPTS = 3;          // Max 3 incorrect OTP guesses before invalidation
const OTP_EXPIRY_MS = 10 * 60 * 1000;   // 10 minutes expiry (matches DLT template)
const MAX_IP_REQUESTS_PER_WINDOW = 10;  // Max 10 OTP sends per IP per 15 min
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
 * Enforces phone-level rate limits:
 * 1. 45-second cooldown between sends to prevent rapid clicking.
 * 2. Max 3 sends per 15 minutes to prevent toll exhaustion.
 */
function checkPhoneRateLimit(phone10) {
  const now = Date.now();
  let record = otpStore.get(phone10);

  if (record) {
    // 1. Cooldown check
    const elapsedSinceLastSend = now - record.lastSentAt;
    if (elapsedSinceLastSend < MIN_SEND_COOLDOWN_MS) {
      const waitSecs = Math.ceil((MIN_SEND_COOLDOWN_MS - elapsedSinceLastSend) / 1000);
      return {
        allowed: false,
        message: `Please wait ${waitSecs} seconds before requesting another code.`
      };
    }

    // 2. Sliding window check
    if (now - record.windowStart > PHONE_WINDOW_MS) {
      record.sendCount = 0;
      record.windowStart = now;
    }

    if (record.sendCount >= MAX_SENDS_PER_WINDOW) {
      const waitMins = Math.ceil((PHONE_WINDOW_MS - (now - record.windowStart)) / 60000);
      return {
        allowed: false,
        message: `Maximum OTP requests reached for this mobile number. Please try again after ${waitMins} minute(s).`
      };
    }
  }

  return { allowed: true };
}

/**
 * Securely stores OTP in memory with 10-minute expiry and attempt counter.
 */
function saveOtp(phone10, otp) {
  const now = Date.now();
  const existing = otpStore.get(phone10);
  const windowStart = (existing && (now - existing.windowStart <= PHONE_WINDOW_MS)) ? existing.windowStart : now;
  const sendCount = (existing && (now - existing.windowStart <= PHONE_WINDOW_MS)) ? existing.sendCount + 1 : 1;

  otpStore.set(phone10, {
    otp,
    expiresAt: now + OTP_EXPIRY_MS,
    attempts: 0,
    lastSentAt: now,
    sendCount,
    windowStart
  });
}

/**
 * Verifies the OTP with anti-brute-force protection:
 * - Burns the OTP on the 3rd failed attempt.
 * - Single-use consumption on successful match.
 * - Generates signed verification token.
 */
function verifyOtp(phone10, userOtp) {
  const record = otpStore.get(phone10);
  if (!record) {
    return {
      success: false,
      message: 'No active OTP found for this number. Please request a new code.'
    };
  }

  const now = Date.now();
  if (now > record.expiresAt) {
    otpStore.delete(phone10);
    return {
      success: false,
      message: 'This OTP has expired. Please request a new code.'
    };
  }

  const cleanOtp = String(userOtp || '').trim();

  // Failed attempt
  if (record.otp !== cleanOtp) {
    record.attempts += 1;
    const remaining = MAX_FAILED_ATTEMPTS - record.attempts;

    if (remaining <= 0) {
      otpStore.delete(phone10);
      return {
        success: false,
        message: 'Too many incorrect attempts. This OTP has been invalidated for security. Please request a new code.'
      };
    }

    return {
      success: false,
      message: `Incorrect code. ${remaining} attempt${remaining > 1 ? 's' : ''} remaining.`
    };
  }

  // Success: burn OTP immediately (replay protection)
  otpStore.delete(phone10);

  // Generate cryptographically signed verification token
  const secret = process.env.OTP_VERIFY_SECRET || 'abnl_secure_device_secret_2026';
  const token = crypto.createHmac('sha256', secret)
    .update(`${phone10}:${now}`)
    .digest('hex');

  return {
    success: true,
    message: 'OTP verified successfully',
    token,
    verifiedAt: now
  };
}

// Background cleanup every 60s
setInterval(() => {
  const now = Date.now();
  for (const [phone, data] of otpStore.entries()) {
    if (now > data.expiresAt && (now - data.windowStart) > PHONE_WINDOW_MS) {
      otpStore.delete(phone);
    }
  }
  for (const [ip, data] of ipRateLimits.entries()) {
    if ((now - data.windowStart) > IP_WINDOW_MS) {
      ipRateLimits.delete(ip);
    }
  }
}, 60000).unref();

module.exports = {
  validateIndianMobile,
  generateSecureOtp,
  getClientIp,
  checkIpRateLimit,
  checkPhoneRateLimit,
  saveOtp,
  verifyOtp
};
