const rateLimit = require('express-rate-limit');

const generalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { status: 'error', error: { message: 'Too many requests, please try again later.' } },
});

const refreshTokenLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 token refresh requests per hour
  message: { status: 'error', error: { message: 'Too many token refresh requests, please try again later.' } },
});

module.exports = { generalRateLimiter, refreshTokenLimiter };