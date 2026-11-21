const nodemailer = require('nodemailer');
const {
  validateIndianMobile,
  verifyVerificationToken,
  consumeVerificationToken,
  checkPhoneBookingLimit,
  recordPhoneBooking,
  checkGlobalEmailQuota,
  recordEmailSent,
  getClientIp,
  checkIpRateLimit,
  escapeHtml,
  sanitizeHeader,
  ALLOWED_TIME_SLOTS
} = require('../lib/otp-security');

// Strictly hardcoded, immutable recipient list (cannot be overridden by requests)
const NOTIFY_EMAILS = Object.freeze([
  'vignesha1988@gmail.com',
  'eshvar1234@gmail.com',
  'Absolutebarnlounge@gmail.com'
]);

const SENDER_EMAIL = process.env.GMAIL_USER || 'vigneshagurudas1988@gmail.com';

function generateBookingId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `ABNL-${code}`;
}

export default async function handler(req, res) {
  // 1. Enforce POST only
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  try {
    const clientIp = getClientIp(req);

    // 2. IP Rate Limiting (Prevents distributed abuse and volumetric attacks)
    const ipCheck = checkIpRateLimit(clientIp);
    if (!ipCheck.allowed) {
      return res.status(429).json({ success: false, message: ipCheck.message });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
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

    // 3. Strict Phone Number Validation
    const phone10 = validateIndianMobile(mobile);
    if (!phone10) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid 10-digit Indian mobile number.'
      });
    }

    // 4. Per-Phone Rate Limiting (Cooldown & Max Bookings Per Day)
    const phoneLimitCheck = checkPhoneBookingLimit(phone10);
    if (!phoneLimitCheck.allowed) {
      return res.status(429).json({
        success: false,
        message: phoneLimitCheck.message
      });
    }

    // 5. Strict Name Validation & Sanitization (Letters, spaces, hyphens, dots only. Max 50 chars)
    const rawName = String(name || '').trim();
    if (!rawName || rawName.length < 2 || rawName.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid guest name (2 to 50 characters).'
      });
    }
    if (!/^[a-zA-Z\s.'-]{2,50}$/.test(rawName)) {
      return res.status(400).json({
        success: false,
        message: 'Name contains invalid characters. Please use alphabets only.'
      });
    }
    const cleanName = sanitizeHeader(rawName);

    // 6. Strict Number of Guests Validation (1-30)
    const guestNum = parseInt(guests, 10);
    if (isNaN(guestNum) || guestNum < 1 || guestNum > 30) {
      return res.status(400).json({
        success: false,
        message: 'Number of guests must be between 1 and 30. For large parties, please call us directly.'
      });
    }

    // 7. Strict Date Validation (YYYY-MM-DD, within today and next 90 days)
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({
        success: false,
        message: 'Please select a valid date in YYYY-MM-DD format.'
      });
    }

    const now = new Date();
    const todayStr = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().split('T')[0];
    const maxDate = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
    const maxDateStr = new Date(maxDate.getTime() - maxDate.getTimezoneOffset() * 60000).toISOString().split('T')[0];

    if (date < todayStr) {
      return res.status(400).json({
        success: false,
        message: 'Reservation date cannot be in the past.'
      });
    }
    if (date > maxDateStr) {
      return res.status(400).json({
        success: false,
        message: 'Reservations can be made up to 90 days in advance only.'
      });
    }

    // 8. Strict Time Slot Validation (Whitelisted 30-min slots only)
    const cleanTime = String(time || '').trim();
    if (!ALLOWED_TIME_SLOTS.has(cleanTime)) {
      return res.status(400).json({
        success: false,
        message: 'Please select a valid 30-minute time slot from the list.'
      });
    }

    // 9. Strict Special Requests Sanitization (Max 200 chars, no control characters)
    const cleanSpecialRequests = String(specialRequests || '')
      .replace(/[\x00-\x1F\x7F]/g, '')
      .trim()
      .slice(0, 200);

    // 10. OTP Format Validation
    if (!verificationToken) {
      return res.status(400).json({
        success: false,
        message: 'No active OTP verification session found. Please request an OTP.'
      });
    }

    const cleanOtp = String(otp || '').trim();
    if (!/^\d{4}$/.test(cleanOtp)) {
      return res.status(400).json({
        success: false,
        message: 'Please enter the 4-digit verification code.'
      });
    }

    // 11. Cryptographic HMAC Token Verification
    const verification = verifyVerificationToken(verificationToken, phone10, cleanOtp);
    if (!verification.success) {
      return res.status(400).json({
        success: false,
        message: verification.message,
        verificationToken: verification.verificationToken
      });
    }

    // 12. Anti-Replay Attack Protection (Burns token so it can NEVER be reused)
    const tokenConsume = consumeVerificationToken(verificationToken);
    if (!tokenConsume.allowed) {
      return res.status(400).json({
        success: false,
        message: tokenConsume.message
      });
    }

    // 13. Record successful phone reservation to enforce cooldown
    recordPhoneBooking(phone10);

    const bookingId = generateBookingId();
    const bookingTimestamp = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // 14. Email Circuit Breaker (Quota protection)
    const emailQuotaCheck = checkGlobalEmailQuota();
    let emailStatus = 'pending';

    if (!emailQuotaCheck.allowed) {
      emailStatus = 'rate_limited_circuit_breaker';
      console.warn('[Circuit Breaker] Global email rate limit reached:', emailQuotaCheck.message);
    } else {
      const appPassword = process.env.GMAIL_APP_PASSWORD;

      if (appPassword) {
        try {
          const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
              user: SENDER_EMAIL,
              pass: appPassword.replace(/\s+/g, '')
            }
          });

          // Sanitize subject against header injection
          const safeSubject = `🍽️ Table Reservation: ${cleanName} (${guestNum} Guests) - ${date} at ${cleanTime}`;

          // Escape all user inputs before interpolating into HTML
          const safeHtmlName = escapeHtml(cleanName);
          const safeHtmlDate = escapeHtml(date);
          const safeHtmlTime = escapeHtml(cleanTime);
          const safeHtmlRequests = cleanSpecialRequests ? escapeHtml(cleanSpecialRequests) : '<em>None specified</em>';

          const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0e0204; color: #fbf7f0; margin: 0; padding: 20px; }
    .container { max-width: 600px; margin: 0 auto; background: #190306; border: 1.5px solid #d4af37; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.8); }
    .header { background: linear-gradient(135deg, #7a0c14 0%, #3a060a 100%); padding: 24px; text-align: center; border-bottom: 2px solid #d4af37; }
    .header h1 { margin: 0; font-size: 22px; color: #f3df95; letter-spacing: 2px; text-transform: uppercase; }
    .header p { margin: 6px 0 0; color: #d9c8af; font-size: 13px; }
    .content { padding: 24px; }
    .badge { display: inline-block; background: rgba(37, 211, 102, 0.15); border: 1px solid #25D366; color: #25D366; font-size: 12px; font-weight: 700; padding: 4px 12px; border-radius: 20px; text-transform: uppercase; margin-bottom: 16px; }
    .details-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .details-table td { padding: 12px 14px; border-bottom: 1px solid rgba(212, 175, 55, 0.2); font-size: 14px; }
    .details-table td.label { color: #d4af37; font-weight: 700; width: 38%; }
    .details-table td.value { color: #fbf7f0; }
    .actions { margin-top: 24px; text-align: center; }
    .btn { display: inline-block; padding: 11px 22px; margin: 6px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 13px; }
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
        <span class="badge">&#10003; Phone Verified via SMS OTP</span>
      </div>
      <table class="details-table">
        <tr>
          <td class="label">Booking ID</td>
          <td class="value"><strong style="color: #ffbe3b; font-size: 16px;">${bookingId}</strong></td>
        </tr>
        <tr>
          <td class="label">Guest Name</td>
          <td class="value"><strong>${safeHtmlName}</strong></td>
        </tr>
        <tr>
          <td class="label">Number of Guests</td>
          <td class="value"><strong>${guestNum} ${guestNum > 1 ? 'Guests' : 'Guest'}</strong></td>
        </tr>
        <tr>
          <td class="label">Reservation Date</td>
          <td class="value"><strong>${safeHtmlDate}</strong></td>
        </tr>
        <tr>
          <td class="label">Time Slot</td>
          <td class="value"><strong>${safeHtmlTime}</strong></td>
        </tr>
        <tr>
          <td class="label">Contact Mobile</td>
          <td class="value">
            <a href="tel:+91${phone10}" style="color: #ffbe3b; text-decoration: none; font-weight: 700;">+91 ${phone10}</a>
          </td>
        </tr>
        <tr>
          <td class="label">Special Requests</td>
          <td class="value">${safeHtmlRequests}</td>
        </tr>
        <tr>
          <td class="label">Verification</td>
          <td class="value" style="color: #25D366;">Verified via MSG91 SMS OTP</td>
        </tr>
        <tr>
          <td class="label">Booked At</td>
          <td class="value">${bookingTimestamp} (IST)</td>
        </tr>
      </table>

      <div class="actions">
        <a href="tel:+91${phone10}" class="btn btn-call">&#128222; Call Guest</a>
        <a href="https://wa.me/91${phone10}?text=Hi%20${encodeURIComponent(cleanName)}%2C%20greeting%20from%20Absolute%20Bar%20%26%20Lounge.%20Your%20table%20reservation%20(${bookingId})%20for%20${guestNum}%20guests%20on%20${date}%20at%20${encodeURIComponent(cleanTime)}%20is%20confirmed." class="btn btn-wa" target="_blank">&#128172; WhatsApp Guest</a>
      </div>
    </div>
    <div class="footer">
      Sent from Absolute Bar & Lounge Digital System &bull; <a href="https://menu-up-abnl.vercel.app/" style="color: #d4af37;">menu-up-abnl.vercel.app</a>
    </div>
  </div>
</body>
</html>
`;

          await transporter.sendMail({
            from: `"Absolute Bar & Lounge" <${SENDER_EMAIL}>`,
            to: NOTIFY_EMAILS.join(', '),
            subject: safeSubject,
            html: htmlContent
          });

          recordEmailSent();
          emailStatus = 'sent';
          console.log('[Reservation Email Sent] ID:', bookingId);
        } catch (err) {
          emailStatus = 'failed';
          console.error('[Reservation Email Error]', err.message);
        }
      } else {
        emailStatus = 'skipped_no_password';
      }
    }

    return res.status(200).json({
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
        emailStatus
      }
    });

  } catch (error) {
    console.error('[Book Table Error]', error);
    return res.status(500).json({ success: false, message: 'Server error processing reservation.' });
  }
}
