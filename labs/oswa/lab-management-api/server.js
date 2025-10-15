const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const session = require('express-session');
require('dotenv').config();

// Import configurations and utilities
const logger = require('./utils/logger');
const { connectDB } = require('./config/database');
const { connectRedis } = require('./config/redis');
const dockerManager = require('./utils/dockerManager');

// Import routes
const authRoutes = require('./routes/auth');
const labRoutes = require('./routes/labs');
const deploymentRoutes = require('./routes/deployments');
const flagRoutes = require('./routes/flags');
const progressRoutes = require('./routes/progress');
const vpnRoutes = require('./routes/vpn');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 4000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// More restrictive rate limiting for sensitive endpoints
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: 'Too many attempts, please try again later.',
});

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-API-Key']
}));

// Request logging
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'lab_management_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize connections
async function initializeServices() {
  try {
    // Connect to MongoDB
    await connectDB();
    logger.info('✅ MongoDB connected successfully');

    // Connect to Redis
    await connectRedis();
    logger.info('✅ Redis connected successfully');

    // Initialize Docker manager
    await dockerManager.initialize();
    logger.info('✅ Docker manager initialized');

  } catch (error) {
    logger.error('❌ Failed to initialize services:', error);
    process.exit(1);
  }
}

// API Routes
app.use('/api/auth', strictLimiter, authRoutes);
app.use('/api/labs', labRoutes);
app.use('/api/deployments', deploymentRoutes);
app.use('/api/flags', flagRoutes);
app.use('/api/progress', progressRoutes);
app.use('/api/vpn', vpnRoutes);
app.use('/api/admin', strictLimiter, adminRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'OSWA Lab Management API',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    services: {
      mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      redis: global.redisClient ? 'connected' : 'disconnected',
      docker: 'initialized'
    },
    available_labs: ['xss-lab', 'jwt-attacks-lab'],
    features: [
      'lab_deployment',
      'flag_submission',
      'progress_tracking',
      'vpn_integration',
      'user_management'
    ]
  });
});

// API documentation endpoint
app.get('/api/docs', (req, res) => {
  res.json({
    api_version: '1.0.0',
    documentation: {
      base_url: `${req.protocol}://${req.get('host')}/api`,
      endpoints: {
        authentication: {
          'POST /auth/login': 'User login',
          'POST /auth/register': 'User registration',
          'POST /auth/logout': 'User logout',
          'GET /auth/me': 'Get current user info'
        },
        labs: {
          'GET /labs': 'List available labs',
          'GET /labs/:id': 'Get lab details',
          'POST /labs/:id/start': 'Start lab instance',
          'POST /labs/:id/stop': 'Stop lab instance',
          'GET /labs/:id/status': 'Get lab status'
        },
        flags: {
          'POST /flags/submit': 'Submit captured flag',
          'GET /flags/history': 'Get flag submission history',
          'GET /flags/leaderboard': 'Get leaderboard'
        },
        progress: {
          'GET /progress': 'Get user progress',
          'GET /progress/stats': 'Get progress statistics'
        },
        vpn: {
          'GET /vpn/config': 'Get VPN configuration',
          'POST /vpn/certificate': 'Generate VPN certificate',
          'GET /vpn/status': 'Check VPN connection status'
        }
      }
    }
  });
});

// Lab-specific proxy endpoints to communicate with individual lab APIs
app.use('/api/proxy/xss', require('./middleware/labProxy')('http://localhost:5000'));
app.use('/api/proxy/jwt', require('./middleware/labProxy')('http://localhost:5001'));

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    success: false,
    error: {
      message: err.message || 'Internal server error',
      code: err.code || 'INTERNAL_ERROR',
      ...(isDevelopment && { stack: err.stack })
    },
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  logger.warn(`404 - Route not found: ${req.method} ${req.url}`);
  res.status(404).json({
    success: false,
    error: {
      message: 'Route not found',
      code: 'NOT_FOUND',
      available_routes: [
        '/api/auth/*',
        '/api/labs/*',
        '/api/deployments/*',
        '/api/flags/*',
        '/api/progress/*',
        '/api/vpn/*',
        '/health',
        '/api/docs'
      ]
    }
  });
});

// Graceful shutdown handling
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown() {
  logger.info('🛑 Shutting down gracefully...');
  
  try {
    // Close MongoDB connection
    await mongoose.connection.close();
    logger.info('✅ MongoDB connection closed');
    
    // Close Redis connection
    if (global.redisClient) {
      await global.redisClient.quit();
      logger.info('✅ Redis connection closed');
    }
    
    // Stop all lab containers
    await dockerManager.stopAllLabs();
    logger.info('✅ All lab containers stopped');
    
    process.exit(0);
  } catch (error) {
    logger.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
}

// Start server
async function startServer() {
  try {
    await initializeServices();
    
    app.listen(PORT, '0.0.0.0', () => {
      logger.info(`🚀 OSWA Lab Management API running on port ${PORT}`);
      logger.info(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`📚 API Documentation: http://localhost:${PORT}/api/docs`);
      logger.info(`❤️  Health Check: http://localhost:${PORT}/health`);
      logger.info(`🔬 Available Labs: XSS Lab, JWT Attacks Lab`);
      logger.info(`⚡ Features: Lab deployment, Flag submission, Progress tracking, VPN integration`);
    });
  } catch (error) {
    logger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Only start server if this file is run directly
if (require.main === module) {
  startServer();
}

module.exports = app;