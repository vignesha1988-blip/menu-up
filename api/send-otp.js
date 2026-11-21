const {
  validateIndianMobile,
  generateSecureOtp,
  getClientIp,
  checkIpRateLimit,
  checkPhoneRateLimit,
  saveOtp
} = require('../lib/otp-security');

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  try {
    const clientIp = getClientIp(req);

    // IP Rate Limit check (Anti-SMS pumping)
    const ipCheck = checkIpRateLimit(clientIp);
    if (!ipCheck.allowed) {
      return res.status(429).json({ success: false, message: ipCheck.message });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const { mobile } = body;

    // Strict Indian mobile validation
    const phone10 = validateIndianMobile(mobile);
    if (!phone10) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid 10-digit Indian mobile number (starting with 6, 7, 8, or 9).'
      });
    }

    // Per-Phone Rate Limit check (Cooldown & Quota)
    const phoneCheck = checkPhoneRateLimit(phone10);
    if (!phoneCheck.allowed) {
      return res.status(429).json({ success: false, message: phoneCheck.message });
    }

    const authKey = process.env.MSG91_AUTH_KEY || '575648A2RMCxpoV6ab8ef67P1';
    const templateId = process.env.MSG91_TEMPLATE_ID || '6b01682b7a0876498406a382';
    const senderId = process.env.MSG91_HEADER_NAME || 'SRDVPL';

    // Secure random OTP
    const otp = generateSecureOtp();
    saveOtp(phone10, otp);

    const internationalPhone = '91' + phone10;

    const flowPayload = {
      template_id: templateId,
      sender: senderId,
      short_url: '0',
      recipients: [
        {
          mobiles: internationalPhone,
          number: otp
        }
      ]
    };

    const response = await fetch('https://control.msg91.com/api/v5/flow', {
      method: 'POST',
      headers: {
        'authkey': authKey,
        'Content-Type': 'application/json',
        'accept': 'application/json'
      },
      body: JSON.stringify(flowPayload)
    });

    const data = await response.json();

    if (data.type === 'success' || data.status === 'success' || response.ok) {
      return res.status(200).json({
        success: true,
        message: 'OTP sent successfully',
        requestId: data.message
      });
    } else {
      return res.status(400).json({
        success: false,
        message: data.message || 'Failed to send OTP via SMS'
      });
    }
  } catch (error) {
    console.error('[MSG91 Send OTP Error]', error);
    return res.status(500).json({ success: false, message: 'Server error while sending OTP' });
  }
}
