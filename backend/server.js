const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const productRoutes = require('./routes/products');
const orderRoutes = require('./routes/orders');
const cartRoutes = require('./routes/cart');

// Import middleware
const errorHandler = require('./middleware/errorHandler');

const app = express();

// Security middleware
app.use(helmet());
app.use(compression());

// ------------ Rate limiting & IP blocking -------------
// In-memory blocklist: ip => unblockTimestamp
const blockedIPs = new Map();

// Middleware to reject requests from blocked IPs
app.use((req, res, next) => {
  const unblockAt = blockedIPs.get(req.ip);
  if (unblockAt && Date.now() < unblockAt) {
    return res.status(429).json({
      success: false,
      message: 'Your IP has been temporarily blocked due to excessive requests. Please try again later.'
    });
  }
  // Clean up expired block entries
  if (unblockAt && Date.now() >= unblockAt) {
    blockedIPs.delete(req.ip);
  }
  next();
});

const limiter = rateLimit({
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false,  // Disable the deprecated `X-RateLimit-*` headers
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  onLimitReached: (req, res, options) => {
    const blockDuration = parseInt(process.env.IP_BLOCK_TIME_MS) || 30 * 60 * 1000; // 30 minutes
    blockedIPs.set(req.ip, Date.now() + blockDuration);
  }
});
app.use('/api/', limiter);

const whitelist = [
  process.env.FRONTEND_URL,
  'http://localhost:3000',
  'https://elite-store-frontend.vercel.app'
];

// CORS configuration - support multiple allowed origins
const corsOptions = {
  origin: (origin, cb) => {
    const clean = origin?.replace(/\/$/, '');          // strip trailing /
    if (!origin || whitelist.includes(clean)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Database connection
const connectDB = async () => {
  try {
    const mongoURI = process.env.NODE_ENV === 'production' 
      ? process.env.MONGODB_URI_PROD 
      : process.env.MONGODB_URI;
    
    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log(`MongoDB Connected: ${mongoose.connection.host}`);
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
};

// Connect to database
connectDB();

// Health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Ecommerce API is running',
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/cart', cartRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error handling middleware
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed.');
    process.exit(0);
  });
});

if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
  });
}

module.exports = app;
