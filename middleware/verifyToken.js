const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

module.exports = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    logger.warn('Authorization token missing');
    return res.status(401).json({ status: 'error', error: { message: 'No token provided' } });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.expiresAt < Date.now()) {
      logger.warn('Token expired');
      return res.status(401).json({ status: 'error', error: { message: 'Token expired' } });
    }
    req.user = decoded;
    next();
  } catch (err) {
    logger.warn('Invalid token', { error: err.message });
    res.status(401).json({ status: 'error', error: { message: 'Invalid token' } });
  }
};