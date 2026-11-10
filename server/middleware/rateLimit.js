const rateLimit = require('express-rate-limit');

/**
 * Rate Limiter for Analysis endpoints:
 * 30 requests per minute per IP to prevent automated abuse and DoS.
 */
const analyzeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // Limit each IP to 30 requests per `window`
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: {
    error: 'Too many analysis requests from this IP, please try again in a minute.'
  }
});

module.exports = {
  analyzeLimiter
};

