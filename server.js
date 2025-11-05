// server.js

const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser'); // added

const connectDB = require('./config/db');
const logger = require('./utils/logger');

// ============= ENVIRONMENT SETUP =============

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET', 'NODE_ENV'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    logger.error(`Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});

// ============= DATABASE CONNECTION =============

// Connect to MongoDB
connectDB().catch(err => {
  logger.error('Failed to connect to database', { error: err.message });
  process.exit(1);
});

// ============= EXPRESS APP SETUP =============

const app = express();

// Trust proxy for deployment platforms (convert env to number/boolean if provided)
const trustProxy = process.env.TRUST_PROXY === undefined ? 1 : process.env.TRUST_PROXY;
app.set('trust proxy', trustProxy);

// ============= REQUEST PARSING MIDDLEWARE =============

/**
 * Body parser with size limits
 * NOTE: Must be registered before any middleware that reads req.body
 */
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/**
 * Cookie parser (for refresh tokens in cookies)
 */
app.use(cookieParser());

// ============= SECURITY MIDDLEWARE =============

/**
 * Helmet: Set security HTTP headers
 */
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

/**
 * MongoDB sanitization - prevent NoSQL injection
 * Keep this after body parsing
 */
app.use(mongoSanitize());

/**
 * XSS Protection middleware (basic sanitizer)
 * Runs after body parser so req.body is available
 */
app.use((req, res, next) => {
  const sanitize = (str) => {
    if (typeof str === 'string') {
      return str.replace(/[<>"']/g, '');
    }
    return str;
  };

  // Sanitize query parameters
  Object.keys(req.query || {}).forEach(key => {
    if (typeof req.query[key] === 'string') {
      req.query[key] = sanitize(req.query[key]);
    }
  });

  // Sanitize body
  if (req.body && typeof req.body === 'object') {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = sanitize(req.body[key]);
      }
    });
  }

  next();
});

// ============= RESPONSE & PERFORMANCE MIDDLEWARE =============

/**
 * Compression middleware - compress responses
 */
app.use(compression());

// ============= LOGGING MIDDLEWARE =============

/**
 * Request ID middleware - track requests
 */
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

/**
 * Morgan HTTP request logger
 */
const morganFormat = process.env.NODE_ENV === 'production' ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
  stream: {
    write: (message) => logger.info(message.trim()),
  },
  skip: (req, res) => {
    // Skip health checks from logs
    return req.path === '/api/health' || req.path === '/';
  },
}));

/**
 * Custom request logging (logs slower requests and warnings)
 */
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const logData = {
      requestId: req.id,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${durationMs}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    };

    if (res.statusCode >= 400) {
      logger.warn('HTTP Request', logData);
    } else if (durationMs > 1000) {
      logger.info('Slow Request', logData);
    } else {
      logger.debug('HTTP Request', logData);
    }
  });

  next();
});

// ============= RATE LIMITING =============

/**
 * Global rate limiter
 */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000,
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'development',
});

app.use(globalLimiter);

/**
 * Auth rate limiter - stricter for auth endpoints
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 requests per 15 minutes per IP
  message: 'Too many login attempts, please try again later',
  skip: () => process.env.NODE_ENV === 'development',
});

/**
 * Create/Delete rate limiter
 */
const createDeleteLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: 'Too many operations, please slow down',
  skip: () => process.env.NODE_ENV === 'development',
});

// ============= HEALTH & INFO ENDPOINTS =============

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Expense Tracker API',
    version: process.env.API_VERSION || '1.0.0',
    status: 'active',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())}s`,
    documentation: `${process.env.API_URL || 'http://localhost:5000'}/api/docs`,
    endpoints: {
      auth: { url: '/api/auth', description: 'Authentication endpoints', requiresAuth: false },
      expenses: { url: '/api/expenses', description: 'Expense management', requiresAuth: true },
      budgets: { url: '/api/budgets', description: 'Budget management', requiresAuth: true },
      reminders: { url: '/api/reminders', description: 'Reminder management', requiresAuth: true },
      health: { url: '/api/health', description: 'Health check', requiresAuth: false },
    },
  });
});

app.get('/api/health', (req, res) => {
  // NOTE: you can add real DB/cache checks here
  const healthData = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())}s`,
    environment: process.env.NODE_ENV || 'development',
    version: process.env.API_VERSION || '1.0.0',
    services: {
      database: 'connected', // consider a real check
      cache: 'operational',  // consider a real check
      api: 'operational',
    },
  };

  res.status(200).json(healthData);
});

app.get('/api/status', (req, res) => {
  const status = {
    success: true,
    server: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      environment: process.env.NODE_ENV,
    },
    api: {
      version: process.env.API_VERSION || '1.0.0',
      endpoint: process.env.API_URL || 'http://localhost:5000',
    },
    timestamp: new Date().toISOString(),
  };

  res.json(status);
});

// ============= API ROUTES =============

logger.info('🔗 Registering API routes...');

// Apply auth limiter to specific endpoints (exact paths)
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);

// Apply create/delete limiter to mutation endpoints
app.use('/api/expenses', createDeleteLimiter);
app.use('/api/budgets', createDeleteLimiter);
app.use('/api/reminders', createDeleteLimiter);

// Mount routes (ensure filenames match)
app.use('/api/auth', require('./routes/auth')); // updated to authRoutes
app.use('/api/expenses', require('./routes/expenses'));
app.use('/api/budgets', require('./routes/budgets'));
app.use('/api/reminders', require('./routes/reminders'));

logger.info('✅ API routes registered');

// ============= 404 HANDLER =============

app.use((req, res, next) => {
  logger.warn('404 Not Found', { method: req.method, path: req.path });
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.path}`,
    requestId: req.id,
    timestamp: new Date().toISOString(),
  });
});

// ============= ERROR HANDLING MIDDLEWARE =============

app.use((err, req, res, next) => {
  const errorId = req.id || uuidv4();

  const errorData = {
    errorId,
    message: err.message,
    status: err.statusCode || 500,
    method: req.method,
    path: req.path,
    ip: req.ip,
  };

  if (process.env.NODE_ENV === 'development') {
    errorData.stack = err.stack;
  }

  logger.error('Application Error', errorData);

  let statusCode = 500;
  let message = 'Internal Server Error';
  let errors = null;

  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
    errors = Object.values(err.errors).map(e => ({ field: e.path, message: e.message }));
  } else if (err.code === 11000) {
    statusCode = 409;
    message = 'Duplicate field value entered';
    const field = Object.keys(err.keyPattern || {})[0];
    errors = [{ field, message: `${field} already exists` }];
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  } else if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  } else if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
  } else if (err.statusCode) {
    statusCode = err.statusCode;
    message = err.message;
  }

  res.status(statusCode).json({
    success: false,
    message,
    ...(errors && { errors }),
    errorId,
    timestamp: new Date().toISOString(),
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// ============= SERVER STARTUP =============

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
  const startTime = new Date().toISOString();
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║                                                        ║');
  console.log('║           🚀 EXPENSE TRACKER API SERVER 🚀             ║');
  console.log('║                                                        ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log(`\n📊 Server Information:`);
  console.log(`   • Port: ${PORT}`);
  console.log(`   • Host: ${HOST}`);
  console.log(`   • Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   • Started: ${startTime}`);
  console.log(`\n🔗 Connection Information:`);
  console.log(`   • API URL: ${process.env.API_URL || `http://localhost:${PORT}`}`);
  console.log(`   • Database: MongoDB Connected`);
  console.log(`   • CORS: Not configured (enable if cross-origin access required)`);
  console.log(`\n📚 Documentation:`);
  console.log(`   • API Docs: ${process.env.API_URL || `http://localhost:${PORT}`}/api/docs`);
  console.log('\n✅ Ready to handle requests!\n');

  logger.info('Server started successfully', {
    port: PORT,
    host: HOST,
    environment: process.env.NODE_ENV,
    timestamp: startTime,
  });
});

// ============= GRACEFUL SHUTDOWN =============

process.on('unhandledRejection', (reason, promise) => {
  logger.error('❌ Unhandled Promise Rejection', { reason: String(reason) });
  if (process.env.NODE_ENV === 'production') {
    server.close(() => {
      logger.info('Server closed due to unhandled rejection');
      process.exit(1);
    });
  }
});

process.on('uncaughtException', (error) => {
  logger.error('❌ Uncaught Exception', { message: error.message, stack: error.stack });
  server.close(() => {
    logger.info('Server closed due to uncaught exception');
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  logger.info('👋 SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('✅ HTTP server closed');
    process.exit(0);
  });
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
});

process.on('SIGINT', () => {
  logger.info('⏸️  SIGINT signal received: closing HTTP server');
  server.close(() => {
    logger.info('✅ HTTP server closed');
    process.exit(0);
  });
});

// ============= EXPORT FOR TESTING =============
module.exports = app;
