const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { UserService } = require('../models/User');

// Use environment JWT_SECRET or deterministic per-process fallback secret if not set in .env
const JWT_SECRET = process.env.JWT_SECRET || 'scamlens_jwt_secret_' + crypto.createHash('sha256').update(__dirname).digest('hex').slice(0, 32);

// In-memory revoked token store (cleared automatically as tokens expire)
const revokedTokens = new Map();

function revokeToken(token, expSeconds) {
  if (!token) return;
  const expiresAt = expSeconds ? expSeconds * 1000 : Date.now() + 7 * 24 * 3600 * 1000;
  revokedTokens.set(token, expiresAt);
}

function isTokenRevoked(token) {
  if (!token || !revokedTokens.has(token)) return false;
  const exp = revokedTokens.get(token);
  if (Date.now() > exp) {
    revokedTokens.delete(token);
    return false;
  }
  return true;
}

function signAccessToken(user, rememberMe = false) {
  const expiresIn = rememberMe ? '30d' : '24h';
  return jwt.sign(
    {
      sub: (user._id || user.id).toString(),
      email: user.email,
      fullName: user.fullName
    },
    JWT_SECRET,
    { expiresIn }
  );
}

function extractBearerToken(req) {
  const authHeader = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (!authHeader || typeof authHeader !== 'string') return null;
  const parts = authHeader.trim().split(/\s+/);
  if (parts.length === 2 && /^Bearer$/i.test(parts[0])) {
    return parts[1];
  }
  return null;
}

/**
 * Strict authentication middleware for protected routes
 */
async function requireAuth(req, res, next) {
  try {
    const token = extractBearerToken(req);
    if (!token) {
      return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    if (isTokenRevoked(token)) {
      return res.status(401).json({ error: 'Session has been logged out. Please log in again.' });
    }

    let decoded = null;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Your session has expired. Please log in again.' });
      }
      return res.status(401).json({ error: 'Invalid authentication token.' });
    }

    const user = await UserService.findById(decoded.sub);
    if (!user) {
      return res.status(401).json({ error: 'User account no longer exists.' });
    }

    req.user = UserService.sanitizeUser(user);
    req.authToken = token;
    req.tokenPayload = decoded;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Optional authentication middleware:
 * Attaches req.user if a valid Bearer token is present, otherwise continues cleanly.
 * If an explicitly malformed/expired Bearer token is sent on a protected flow, can still be inspected.
 */
async function optionalAuth(req, res, next) {
  try {
    const token = extractBearerToken(req);
    if (!token || isTokenRevoked(token)) {
      req.user = null;
      return next();
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await UserService.findById(decoded.sub);
      req.user = user ? UserService.sanitizeUser(user) : null;
      req.authToken = token;
    } catch (e) {
      req.user = null;
    }
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = {
  JWT_SECRET,
  signAccessToken,
  revokeToken,
  isTokenRevoked,
  extractBearerToken,
  requireAuth,
  optionalAuth
};

