const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const User = require('../models/User');
const Message = require('../models/Message');
const verifyToken = require('../middleware/verifyToken');
const { generalRateLimiter, refreshTokenLimiter } = require('../middleware/rateLimiter');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_TIME = parseInt(process.env.TOKEN_TIME) || 3600000;

// Validate environment variables
if (!JWT_SECRET) {
  logger.error('JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

// In-memory cache
const memoryCache = new Map();

// Consistent response format
const sendResponse = (res, status, data, error = null) => {
  const response = { data, error, status: error ? 'error' : 'success' };
  if (process.env.NODE_ENV === 'development' && error) {
    response.errorDetails = error.stack || error.message;
  }
  res.status(status).json(response);
};

// Register new user
router.post(
  '/register',
  [
    check('name', 'Name is required').notEmpty().trim().escape(),
    check('email', 'Valid email is required').isEmail().normalizeEmail(),
    check('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
    generalRateLimiter,
  ],
  async (req, res) => {
    logger.info('Received /api/register request', { email: req.body.email });
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Registration validation failed', { errors: errors.array() });
      return sendResponse(res, 422, null, { message: 'Validation failed', details: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      const existUser = await User.findOne({ email: email.toLowerCase() });
      if (existUser) {
        logger.warn(`Registration failed: Email ${email} already exists`);
        return sendResponse(res, 422, null, { message: 'Email already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ name, email: email.toLowerCase(), password: hashedPassword });
      await newUser.save();

      for (const key of memoryCache.keys()) {
        if (key.startsWith('users:')) {
          memoryCache.delete(key);
        }
      }
      logger.info('Invalidated user list cache entries');

      const io = req.app.get('socketio');
      io.emit('new-user', {
        id: newUser._id,
        name,
        email: email.toLowerCase(),
      });
      logger.info(`Emitted new-user event for: ${email}`);

      const expiresAt = Date.now() + TOKEN_TIME;
      const token = jwt.sign({ id: newUser._id, expiresAt }, JWT_SECRET);

      logger.info(`User registered: ${email}`);
      sendResponse(res, 201, { user: { id: newUser._id, name, email: email.toLowerCase(), token } });
    } catch (err) {
      logger.error('Registration error', { error: err.stack });
      sendResponse(res, 500, null, { message: 'Server error', details: err.message });
    }
  }
);

// Login user
router.post(
  '/login',
  [
    check('email', 'Valid email is required').isEmail().normalizeEmail(),
    check('password', 'Password is required').notEmpty(),
    generalRateLimiter,
  ],
  async (req, res) => {
    logger.info('Received /api/login request', { email: req.body.email });
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Login validation failed', { errors: errors.array() });
      return sendResponse(res, 422, null, { message: 'Validation failed', details: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        logger.warn(`Login failed: Email ${email} not found`);
        return sendResponse(res, 404, null, { message: 'Email not found' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Login failed: Incorrect password for ${email}`);
        return sendResponse(res, 401, null, { message: 'Incorrect password' });
      }

      const expiresAt = Date.now() + TOKEN_TIME;
      const token = jwt.sign({ id: user._id, expiresAt }, JWT_SECRET);

      logger.info(`User logged in: ${email}`);
      sendResponse(res, 200, { user: { id: user._id, name: user.name, email: email.toLowerCase(), token } });
    } catch (err) {
      logger.error('Login error', { error: err.stack });
      sendResponse(res, 500, null, { message: 'Server error', details: err.message });
    }
  }
);

// Get unread message counts
router.get('/messages/unread-counts', verifyToken, async (req, res) => {
  logger.info('Received /api/messages/unread-counts request', { userId: req.user.id });
  try {
    const userId = req.user.id;
    const unreadCounts = await Message.aggregate([
      {
        $match: {
          to: new mongoose.Types.ObjectId(userId),
          read: false,
        },
      },
      {
        $group: {
          _id: '$from',
          count: { $sum: 1 },
        },
      },
      {
        $project: {
          userId: '$_id',
          count: 1,
          _id: 0,
        },
      },
    ]);

    logger.info(`Unread counts fetched for user: ${userId}`);
    sendResponse(res, 200, unreadCounts);
  } catch (err) {
    logger.error('Unread counts fetch error', { error: err.stack });
    sendResponse(res, 500, null, { message: 'Server error', details: err.message });
  }
});

// Get messages between users
router.get('/messages/:id', verifyToken, async (req, res) => {
  const from = req.user.id;
  const to = req.params.id;
  logger.info('Received /api/messages/:id request', { from, to });
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const skip = (page - 1) * limit;

  try {
    if (!mongoose.Types.ObjectId.isValid(to)) {
      logger.warn(`Invalid recipient ID: ${to}`);
      return sendResponse(res, 400, null, { message: 'Invalid recipient ID' });
    }

    const recipient = await User.findById(to);
    if (!recipient) {
      logger.warn(`Recipient not found: ${to}`);
      return sendResponse(res, 404, null, { message: 'Recipient not found' });
    }

    const messages = await Message.find({
      $or: [
        { from: new mongoose.Types.ObjectId(from), to: new mongoose.Types.ObjectId(to) },
        { from: new mongoose.Types.ObjectId(to), to: new mongoose.Types.ObjectId(from) },
      ],
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    console.log('Messages found:', messages.length);
    const total = await Message.countDocuments({
      $or: [
        { from: new mongoose.Types.ObjectId(from), to: new mongoose.Types.ObjectId(to) },
        { from: new mongoose.Types.ObjectId(to), to: new mongoose.Types.ObjectId(from) },
      ],
    });

    const formatted = messages
      .reverse()
      .map((msg) => ({
        fromSelf: msg.from.toString() === from,
        content: msg.message,
        createdAt: msg.createdAt.toISOString(),
        read: msg.read,
        id: msg._id,
      }));

    logger.info(`Messages fetched for user: ${from}, to: ${to}, page: ${page}, count: ${messages.length}`);
    sendResponse(res, 200, {
      messages: formatted,
      page,
      totalPages: Math.ceil(total / limit),
      total,
    });
  } catch (err) {
    logger.error('Messages fetch error', { error: err.stack });
    sendResponse(res, 500, null, { message: 'Server error', details: err.message });
  }
});

// Send message
router.post(
  '/messages',
  [
    verifyToken,
    generalRateLimiter,
    check('to', 'Recipient ID is required').notEmpty().isMongoId(),
    check('message', 'Message is required').notEmpty().trim().escape(),
  ],
  async (req, res) => {
    logger.info('Received /api/messages POST request', {
      from: req.user.id,
      to: req.body.to,
      message: req.body.message,
    });
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Message send validation failed', { errors: errors.array() });
      return sendResponse(res, 422, null, { message: 'Validation failed', details: errors.array() });
    }

    const from = req.user.id;
    const { to, message } = req.body;

    try {
      const recipient = await User.findById(to);
      if (!recipient) {
        logger.warn(`Message send failed: Recipient ${to} not found`);
        return sendResponse(res, 404, null, { message: 'Recipient not found' });
      }
      logger.info(`Recipient found: ${recipient.email}`);

      const newMessage = new Message({ from, to, message, read: false });
      console.log('Saving message:', newMessage);
      await newMessage.save();
      console.log('Message saved:', newMessage._id);

      const formattedMessage = {
        fromSelf: true,
        content: newMessage.message,
        createdAt: newMessage.createdAt.toISOString(),
        read: newMessage.read,
        id: newMessage._id,
      };

      const io = req.app.get('socketio');
      logger.info('Emitting receive-message', { messageId: newMessage._id, to, from });
      io.to(to).emit('receive-message', {
        from,
        to,
        message: newMessage.message,
        createdAt: newMessage.createdAt.toISOString(),
        id: newMessage._id,
        read: newMessage.read,
      });
      io.to(from).emit('receive-message', {
        from,
        to,
        message: newMessage.message,
        createdAt: newMessage.createdAt.toISOString(),
        id: newMessage._id,
        read: newMessage.read,
      });

      sendResponse(res, 201, formattedMessage);
    } catch (err) {
      logger.error('Message send error', { error: err.stack });
      sendResponse(res, 500, null, { message: 'Server error', details: err.message });
    }
  }
);

// Mark messages as read
router.post(
  '/messages/mark-read',
  [
    verifyToken,
    generalRateLimiter,
    check('messageIds', 'Message IDs are required').isArray({ min: 1 }),
    check('messageIds.*', 'Invalid message ID').isMongoId(),
  ],
  async (req, res) => {
    logger.info('Received /api/messages/mark-read request', { userId: req.user.id });
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Mark read validation failed', { errors: errors.array() });
      return sendResponse(res, 422, null, { message: 'Validation failed', details: errors.array() });
    }

    const { messageIds } = req.body;
    const userId = req.user.id;

    try {
      const messages = await Message.find({
        _id: { $in: messageIds },
        to: new mongoose.Types.ObjectId(userId),
        read: false,
      });

      if (messages.length === 0) {
        return sendResponse(res, 200, { updated: 0 });
      }

      await Message.updateMany(
        { _id: { $in: messageIds }, to: new mongoose.Types.ObjectId(userId), read: false },
        { $set: { read: true } }
      );

      const io = req.app.get('socketio');
      messages.forEach((msg) => {
        io.to(msg.from.toString()).emit('message-read', { messageId: msg._id });
      });

      logger.info(`Marked ${messages.length} messages as read for user: ${userId}`);
      sendResponse(res, 200, { updated: messages.length });
    } catch (err) {
      logger.error('Mark read error', { error: err.stack });
      sendResponse(res, 500, null, { message: 'Server error', details: err.message });
    }
  }
);

// Get logged-in user profile
router.get('/profile', verifyToken, async (req, res) => {
  logger.info('Received /api/profile request', { userId: req.user.id });
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      logger.warn(`Profile fetch failed: User ${req.user.id} not found`);
      return sendResponse(res, 404, null, { message: 'User not found' });
    }
    logger.info(`Profile fetched for user: ${req.user.id}`);
    sendResponse(res, 200, { user });
  } catch (err) {
    logger.error('Profile fetch error', { error: err.stack });
    sendResponse(res, 500, null, { message: 'Server error', details: err.message });
  }
});

// Debug endpoint to list all users
router.get('/debug/users', async (req, res) => {
  logger.info('Received /api/debug/users request');
  try {
    const users = await User.find({}).select('email name');
    logger.info('Fetched all users for debugging');
    sendResponse(res, 200, users);
  } catch (err) {
    logger.error('Debug users fetch error', { error: err.stack });
    sendResponse(res, 500, null, { message: 'Server error', details: err.message });
  }
});

// Refresh token
router.post('/refreshtoken', [verifyToken, refreshTokenLimiter], async (req, res) => {
  logger.info('Received /api/refreshtoken request', { userId: req.user.id });
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      logger.warn(`Token refresh failed: User ${req.user.id} not found`);
      return sendResponse(res, 404, null, { message: 'User not found' });
    }

    const expiresAt = Date.now() + TOKEN_TIME;
    const newToken = jwt.sign({ id: user._id, expiresAt }, JWT_SECRET);

    logger.info(`Token refreshed for user: ${req.user.id}`);
    sendResponse(res, 200, { token: newToken });
  } catch (err) {
    logger.error('Token refresh error', { error: err.stack });
    sendResponse(res, 500, null, { message: 'Server error', details: err.message });
  }
});

// Get users (with in-memory caching)
router.get('/users', verifyToken, async (req, res) => {
  logger.info('Received /api/users request', { userId: req.user.id });
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const cacheKey = `users:${req.user.id}:${page}:${limit}`;

    if (memoryCache.has(cacheKey)) {
      logger.info('Memory cache hit for users');
      return sendResponse(res, 200, memoryCache.get(cacheKey));
    }

    const users = await User.find({ _id: { $ne: req.user.id } })
      .select('-password')
      .skip(skip)
      .limit(limit);
    console.log('Users fetched from DB:', users.length);

    const total = await User.countDocuments({ _id: { $ne: req.user.id } });

    const response = {
      users,
      page,
      totalPages: Math.ceil(total / limit),
      total,
    };

    memoryCache.set(cacheKey, response);
    logger.info('Querying DB for users');
    sendResponse(res, 200, response);
  } catch (err) {
    logger.error('Users fetch error', { error: err.stack });
    sendResponse(res, 500, null, { message: 'Server error', details: err.message });
  }
});

module.exports = router;