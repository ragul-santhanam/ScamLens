const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { UserService } = require('../models/User');
const { ScanService } = require('../models/Scan');
const { EmergencySessionService } = require('../models/EmergencySession');
const { signAccessToken, revokeToken } = require('../middleware/auth');

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const MOBILE_REGEX = /^(\+?91[\s-]?)?[6-9]\d{9}$/;

function validatePasswordStrength(password) {
  if (typeof password !== 'string' || password.length < 8) {
    return 'Password must be at least 8 characters long.';
  }
  if (password.length > 128) {
    return 'Password must not exceed 128 characters.';
  }
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    return 'Password must contain at least one letter and one number.';
  }
  return null;
}

/**
 * POST /api/auth/signup
 */
async function signup(req, res, next) {
  try {
    const {
      fullName,
      email,
      mobile,
      password,
      confirmPassword,
      acceptedTerms
    } = req.body || {};

    if (!fullName || typeof fullName !== 'string' || fullName.trim().length < 2) {
      return res.status(400).json({ error: 'Full name is required (minimum 2 characters).' });
    }

    if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }

    if (mobile && typeof mobile === 'string' && mobile.trim() !== '') {
      if (!MOBILE_REGEX.test(mobile.trim())) {
        return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number or leave it blank.' });
      }
    }

    const pwdError = validatePasswordStrength(password);
    if (pwdError) {
      return res.status(400).json({ error: pwdError });
    }

    if (confirmPassword !== undefined && password !== confirmPassword) {
      return res.status(400).json({ error: 'Password and Confirm Password do not match.' });
    }

    if (acceptedTerms === false || acceptedTerms === 'false') {
      return res.status(400).json({ error: 'You must accept the terms and conditions to create an account.' });
    }

    const existingUser = await UserService.findByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email address is already registered.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const createdUser = await UserService.create({
      fullName: fullName.trim(),
      email: email.trim().toLowerCase(),
      mobile: mobile ? mobile.trim() : '',
      passwordHash,
      acceptedTerms: true
    });

    const sanitized = UserService.sanitizeUser(createdUser);
    const token = signAccessToken(createdUser, false);

    res.status(201).json({
      message: 'Account created successfully.',
      token,
      user: sanitized
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/auth/login
 */
async function login(req, res, next) {
  try {
    const { email, password, rememberMe } = req.body || {};

    if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    if (!password || typeof password !== 'string') {
      return res.status(400).json({ error: 'Password is required.' });
    }

    const user = await UserService.findByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = signAccessToken(user, Boolean(rememberMe));
    const sanitized = UserService.sanitizeUser(user);

    res.json({
      message: 'Login successful.',
      token,
      user: sanitized
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/auth/logout
 */
async function logout(req, res, next) {
  try {
    if (req.authToken) {
      const exp = req.tokenPayload ? req.tokenPayload.exp : null;
      revokeToken(req.authToken, exp);
    }
    res.json({
      success: true,
      message: 'Logged out successfully.'
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/auth/forgot-password
 * Supports two-step verification:
 * - Step 1: { email } -> generates a 6-digit verification code, hashes and stores it with 15-min expiry in MongoDB.
 * - Step 2: { email, verificationCode, newPassword, confirmPassword } -> verifies code against stored bcrypt hash and updates password in MongoDB.
 */
async function forgotPassword(req, res, next) {
  try {
    const { email, verificationCode, newPassword, confirmPassword } = req.body || {};

    if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({ error: 'Please enter a valid registered email address.' });
    }

    const user = await UserService.findByEmail(email);
    if (!user) {
      return res.status(404).json({ error: 'No account found with this email address.' });
    }

    // Step 2: Complete password reset using verification code
    if (verificationCode || newPassword) {
      if (!verificationCode || typeof verificationCode !== 'string') {
        return res.status(400).json({ error: 'Verification code is required.' });
      }

      if (!user.resetCodeHash || !user.resetCodeExpiresAt) {
        return res.status(400).json({ error: 'No active password reset request found. Please request a new code.' });
      }

      if (new Date(user.resetCodeExpiresAt).getTime() < Date.now()) {
        return res.status(400).json({ error: 'Verification code has expired. Please request a new code.' });
      }

      const codeValid = await bcrypt.compare(String(verificationCode).trim(), user.resetCodeHash);
      if (!codeValid) {
        return res.status(400).json({ error: 'Invalid verification code.' });
      }

      const pwdError = validatePasswordStrength(newPassword);
      if (pwdError) {
        return res.status(400).json({ error: pwdError });
      }

      if (confirmPassword !== undefined && newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'New password and confirm password do not match.' });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      await UserService.updatePassword(user._id, newPasswordHash);

      return res.json({
        success: true,
        step: 'completed',
        message: 'Your password has been reset successfully. You can now log in with your new password.'
      });
    }

    // Step 1: Generate 6-digit verification code & save hashed code in MongoDB
    const rawCode = String(crypto.randomInt(100000, 999999));
    const codeHash = await bcrypt.hash(rawCode, 10);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await UserService.updateResetCode(user._id, codeHash, expiresAt);

    res.json({
      success: true,
      step: 'code_sent',
      message: 'Verification code generated (valid for 15 minutes). Enter the 6-digit code and your new password to complete reset.',
      verificationCode: rawCode,
      expiresInMinutes: 15
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/auth/me
 */
async function getMe(req, res, next) {
  try {
    const userId = req.user.id;
    const totalScans = await ScanService.countByUser(userId);
    const recentScans = await ScanService.findByOwner({ userId }, 20);
    const emergencySessions = await EmergencySessionService.findByOwner({ userId }, 10);

    res.json({
      user: req.user,
      stats: {
        totalScans,
        highRiskCount: recentScans.filter(s => s.riskLevel === 'High Risk').length,
        emergencySessionsCount: emergencySessions.length
      },
      recentScans: recentScans.slice(0, 10)
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  signup,
  login,
  logout,
  forgotPassword,
  getMe
};

