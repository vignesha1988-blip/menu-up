const nodemailer = require('nodemailer');
const {
  validateIndianMobile,
  verifyVerificationToken,
  getClientIp,
  checkIpRateLimit
} = require('../lib/otp-security');

// Recipient emails as requested
const NOTIFY_EMAILS = [
  'vignesha1988@gmail.com',
  'eshvar1234@gmail.com',
  'Absolutebarnlounge@gmail.com'
];

const SENDER_EMAIL = process.env.GMAIL_USER || 'Vigneshagurudas1988@gmail.com';

function generateBookingId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `ABNL-${code}`;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  try {
    const clientIp = getClientIp(req);
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

    // Validate Name
    const cleanName = String(name || '').trim();
    if (!cleanName || cleanName.length < 2) {
      return res.status(400).json({ success: false, message: 'Please provide a valid guest name (at least 2 characters).' });
    }

    // Validate Number of Guests
    const guestNum = parseInt(guests, 10);
    if (isNaN(guestNum) || guestNum < 1 || guestNum > 50) {
      return res.status(400).json({ success: false, message: 'Please specify the number of guests (1-50).' });
    }

    // Validate Date (YYYY-MM-DD, must not be past date)
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: 'Please select a valid reservation date.' });
    }
    const todayStr = new Date().toISOString().split('T')[0];
    if (date < todayStr) {
      return res.status(400).json({ success: false, message: 'Reservation date cannot be in the past.' });
    }

    // Validate Time Slot
    const cleanTime = String(time || '').trim();
    if (!cleanTime) {
      return res.status(400).json({ success: false, message: 'Please select a reservation time slot.' });
    }

    // Validate Mobile
    const phone10 = validateIndianMobile(mobile);
    if (!phone10) {
      return res.status(400).json({ success: false, message: 'Invalid 10-digit Indian mobile number.' });
    }

    // Validate OTP Token & Input
    if (!verificationToken) {
      return res.status(400).json({
        success: false,
        message: 'No active OTP verification session found. Please request an OTP.'
      });
    }

    if (!otp || String(otp).trim().length !== 4) {
      return res.status(400).json({
        success: false,
        message: 'Please enter the 4-digit OTP sent to your mobile.'
      });
    }

    // Verify OTP statelessly
    const verification = verifyVerificationToken(verificationToken, phone10, String(otp));
    if (!verification.success) {
      return res.status(400).json({
        success: false,
        message: verification.message,
        verificationToken: verification.verificationToken
      });
    }

    // Booking is verified!
    const bookingId = generateBookingId();
    const cleanSpecialRequests = String(specialRequests || '').trim().slice(0, 500);
    const bookingTimestamp = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // Prepare Email Notification
    const appPassword = process.env.GMAIL_APP_PASSWORD;
    let emailStatus = 'pending';
    let emailError = null;

    if (appPassword) {
      try {
        const transporter = nodemailer.createTransport({
          host: 'smtp.gmail.com',
          port: 465,
          secure: true,
          auth: {
            user: SENDER_EMAIL,
            pass: appPassword.replace(/\s+/g, '') // remove spaces from app password
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
          from: `"Absolute Bar & Lounge" <${SENDER_EMAIL}>`,
          to: NOTIFY_EMAILS.join(', '),
          subject: subject,
          html: htmlContent
        });

        emailStatus = 'sent';
        console.log('[Reservation Email Sent]', info.messageId);
      } catch (err) {
        emailStatus = 'failed';
        emailError = err.message;
        console.error('[Reservation Email Failed]', err);
      }
    } else {
      emailStatus = 'skipped_no_app_password';
      console.warn('[Reservation Email Skipped] GMAIL_APP_PASSWORD is not set.');
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
        emailStatus,
        emailError
      }
    });

  } catch (error) {
    console.error('[Book Table Server Error]', error);
    return res.status(500).json({ success: false, message: 'Server error while processing reservation.' });
  }
}
