// middleware/verifyToken.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: { message: 'No token provided' } });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.expiresAt < Date.now()) {
      return res.status(401).json({ error: { message: 'Token expired' } });
    }
    req.user = { id: decoded.id };
    next();
  } catch (err) {
    return res.status(401).json({ error: { message: 'Invalid token' } });
  }
};