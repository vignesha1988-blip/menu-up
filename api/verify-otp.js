const {
  validateIndianMobile,
  verifyVerificationToken
} = require('../lib/otp-security');

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const { mobile, otp, verificationToken } = body;

    const phone10 = validateIndianMobile(mobile);
    if (!phone10) {
      return res.status(400).json({ success: false, message: 'Invalid mobile number format' });
    }

    if (!verificationToken) {
      return res.status(400).json({
        success: false,
        message: 'No active OTP found for this number. Please request a new code.'
      });
    }

    if (!otp || String(otp).trim().length !== 4) {
      return res.status(400).json({
        success: false,
        message: 'Please enter the 4-digit verification code.'
      });
    }

    // Verify token statelessly
    const verification = verifyVerificationToken(verificationToken, phone10, String(otp));

    if (verification.success) {
      return res.status(200).json({
        success: true,
        message: 'OTP verified successfully',
        verifiedToken: verification.verifiedToken
      });
    } else {
      return res.status(400).json({
        success: false,
        message: verification.message,
        verificationToken: verification.verificationToken
      });
    }
  } catch (error) {
    console.error('[MSG91 Verify OTP Server Error]', error);
    return res.status(500).json({ success: false, message: 'Server error while verifying OTP' });
  }
}
