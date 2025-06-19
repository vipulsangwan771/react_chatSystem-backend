const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');
const winston = require('winston');
const Message = require('./models/Message');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true,
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling'],
});

// Validate environment variables
const requiredEnvVars = ['MONGO_URL', 'JWT_SECRET', 'CLIENT_URL'];
const missingEnvVars = requiredEnvVars.filter((varName) => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error(`Missing environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.errors({ stack: true })
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console(),
  ],
});

// Track online users
const onlineUsers = new Set();

app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.set('socketio', io);

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(async () => {
    logger.info('Connected to MongoDB 🚀');
    try {
      const indexes = await Message.collection.getIndexes();
      if (indexes.id_1) {
        await Message.collection.dropIndex('id_1');
        logger.info('Dropped problematic id_1 index');
      }
      await Message.ensureIndexes();
      logger.info('Ensured correct indexes on messages collection');
    } catch (err) {
      logger.error('Error managing indexes', { error: err.stack });
      process.exit(1);
    }
  })
  .catch((err) => {
    logger.error('MongoDB connection error', { error: err.stack });
    process.exit(1);
  });

// Socket.IO authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    logger.warn('Socket authentication failed: No token provided', { socketId: socket.id });
    return next(new Error('Authentication error: No token provided'));
  }

  try {
    const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET);
    if (decoded.expiresAt < Date.now()) {
      logger.warn('Socket authentication failed: Token expired', { socketId: socket.id, userId: decoded.id });
      return next(new Error('Authentication error: Token expired'));
    }
    logger.info('Socket authenticated', { socketId: socket.id, userId: decoded.id });
    socket.user = decoded;
    next();
  } catch (err) {
    logger.warn('Socket authentication failed: Invalid token', { socketId: socket.id, error: err.message });
    next(new Error('Authentication error: Invalid token'));
  }
});

// Socket.IO events
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}, User ID: ${socket.user.id}`);
  socket.join(socket.user.id);
  logger.info(`User ${socket.user.id} joined room: ${socket.user.id}`);

  // Handle user connection
  socket.on('user-connected', ({ userId }) => {
    if (mongoose.Types.ObjectId.isValid(userId) && userId === socket.user.id) {
      onlineUsers.add(userId);
      io.emit('user-connected', { userId });
      io.emit('online-users', { users: Array.from(onlineUsers) });
      logger.info(`User connected: ${userId}`);
    }
  });

  // Handle user disconnection
  socket.on('user-disconnected', ({ userId }) => {
    if (mongoose.Types.ObjectId.isValid(userId) && userId === socket.user.id) {
      onlineUsers.delete(userId);
      io.emit('user-disconnected', { userId });
      io.emit('online-users', { users: Array.from(onlineUsers) });
      logger.info(`User disconnected: ${userId}`);
    }
  });

  // Handle Socket.IO disconnect
  socket.on('disconnect', (reason) => {
    logger.info(`Client disconnected: ${socket.id}, User ID: ${socket.user.id}, Reason: ${reason}`);
    onlineUsers.delete(socket.user.id);
    io.emit('user-disconnected', { userId: socket.user.id });
    io.emit('online-users', { users: Array.from(onlineUsers) });
  });

  socket.on('typing', (data) => {
    if (data.userId && mongoose.Types.ObjectId.isValid(data.userId)) {
      io.to(data.userId).emit('typing', { userId: socket.user.id });
      logger.info(`Typing event from ${socket.user.id} to ${data.userId}`);
    }
  });

  socket.on('message-read', async (data) => {
    if (!data.messageId || !mongoose.Types.ObjectId.isValid(data.messageId)) return;
    try {
      const message = await Message.findById(data.messageId);
      if (message && message.to.toString() === socket.user.id && !message.read) {
        message.read = true;
        await message.save();
        io.to(message.from.toString()).emit('message-read', { messageId: data.messageId });
        logger.info(`Message ${data.messageId} marked as read by ${socket.user.id}`);
      }
    } catch (err) {
      logger.error('Message read error', { error: err.stack });
    }
  });

  socket.on('error', (err) => {
    logger.error(`Socket error: ${socket.id}, User ID: ${socket.user.id}`, { error: err.stack });
  });
});

// Routes
app.use('/api', require('./routes/auth'));

// Health check
app.get('/', (req, res) => res.json({ status: 'Server is running 🚀' }));

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.stack });
  res.status(500).json({ status: 'error', error: { message: 'Server error', details: err.message } });
});

// Graceful shutdown
const shutdown = () => {
  logger.info('Shutting down server...');
  io.emit('server-shutdown', { message: 'Server is shutting down, please reconnect later.' });
  io.close(() => {
    logger.info('Socket.IO server closed');
    server.close((err) => {
      if (err) {
        logger.error('Error during server close', { error: err.stack });
        process.exit(1);
      }
      mongoose.connection.close(false, () => {
        logger.info('MongoDB connection closed');
        logger.info('Server shut down gracefully');
        process.exit(0);
      });
    });
  });
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 15000);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => logger.info(`Server running on port ${PORT} 🚀`));