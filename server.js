// server.js (improved version)
const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const connectDB = require('./config/db');
const logger = require('./utils/logger');

// ============= ENVIRONMENT SETUP =============
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
connectDB().catch(err => {
  logger.error('Failed to connect to database', { error: err?.message || String(err) });
  process.exit(1);
});

// ============= EXPRESS APP SETUP =============
const app = express();

// ============= TRUST PROXY =============
// Parse TRUST_PROXY env var robustly: allowed values:
// - unset  => 1 (default, common for proxies)
// - 'true' / '1' => true
// - 'false' / '0' => false
// - numeric string => parseInt
let trustProxy;
if (typeof process.env.TRUST_PROXY === 'undefined') {
  trustProxy = 1;
} else {
  const val = process.env.TRUST_PROXY.toLowerCase();
  if (val === 'true' || val === '1') trustProxy = 1;
  else if (val === 'false' || val === '0') trustProxy = 0;
  else if (!isNaN(parseInt(val, 10))) trustProxy = parseInt(val, 10);
  else trustProxy = process.env.TRUST_PROXY;
}
app.set('trust proxy', trustProxy);

// ============= REQUEST PARSING MIDDLEWARE =============
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ============= CORS =============
// Configure CORS via env:
// - CORS_ALLOW_ALL=true => allow all origins (useful for early testing)
// - ALLOWED_ORIGINS=comma,separated,origins (preferred)
const allowAll = (process.env.CORS_ALLOW_ALL || 'false').toLowerCase() === 'true';
const rawOrigins = process.env.ALLOWED_ORIGINS || '';
const allowedOrigins = rawOrigins.split(',').map(s => s.trim()).filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    if (allowAll || !origin) return callback(null, true); // allow non-browser or server-to-server calls
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy: Origin not allowed'), false);
    }
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
};
app.use(cors(corsOptions));

// ============= SECURITY MIDDLEWARE =============
// Enable stricter CSP only in production (avoid interfering with dev tooling)
const isProd = process.env.NODE_ENV === 'production';

app.use(
  helmet({
    contentSecurityPolicy: isProd ? {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", (process.env.API_URL || '')],
      },
    } : false,
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

// MongoDB sanitization - prevent NoSQL injection
app.use(mongoSanitize());

// Basic XSS sanitation for simple string fields
app.use((req, res, next) => {
  const sanitize = (str) => (typeof str === 'string' ? str.replace(/[<>"']/g, '') : str);

  if (req.query) {
    Object.keys(req.query).forEach(k => {
      if (typeof req.query[k] === 'string') req.query[k] = sanitize(req.query[k]);
    });
  }
  if (req.body && typeof req.body === 'object') {
    Object.keys(req.body).forEach(k => {
      if (typeof req.body[k] === 'string') req.body[k] = sanitize(req.body[k]);
    });
  }
  next();
});

// ============= PERFORMANCE MIDDLEWARE =============
app.use(compression());

// ============= LOGGING MIDDLEWARE =============
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

const morganFormat = isProd ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
  stream: { write: message => logger.info(message.trim()) },
  skip: req => req.path === '/api/health' || req.path === '/',
}));

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const meta = {
      requestId: req.id,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${durationMs}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    };
    if (res.statusCode >= 400) logger.warn('HTTP Request', meta);
    else if (durationMs > 1000) logger.info('Slow Request', meta);
    else logger.debug('HTTP Request', meta);
  });
  next();
});

// ============= RATE LIMITING =============
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'development',
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later',
  skip: () => process.env.NODE_ENV === 'development',
});

const createDeleteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: 'Too many operations, please slow down',
  skip: () => process.env.NODE_ENV === 'development',
});

// ============= HEALTH & INFO ENDPOINTS =============
// Try to read mongoose connection state if mongoose is present
let mongoose;
try { mongoose = require('mongoose'); } catch (_) { mongoose = null; }

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Expense Tracker API',
    version: process.env.API_VERSION || '1.0.0',
    status: 'active',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())}s`,
    documentation: `${process.env.API_URL || `http://localhost:${process.env.PORT || 5000}`}/api/docs`,
  });
});

app.get('/api/health', (req, res) => {
  const dbStatus = mongoose ? (['disconnected','connected','connecting','disconnecting'][mongoose.connection.readyState] || 'unknown') : 'unavailable';
  res.status(200).json({
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())}s`,
    environment: process.env.NODE_ENV || 'development',
    version: process.env.API_VERSION || '1.0.0',
    services: { database: dbStatus, cache: 'operational', api: 'operational' },
  });
});

app.get('/api/status', (req, res) => {
  res.json({
    success: true,
    server: { uptime: process.uptime(), memory: process.memoryUsage(), environment: process.env.NODE_ENV },
    api: { version: process.env.API_VERSION || '1.0.0', endpoint: process.env.API_URL || `http://localhost:${process.env.PORT || 5000}` },
    timestamp: new Date().toISOString(),
  });
});

// ============= API ROUTES =============
logger.info('🔗 Registering API routes...');

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api/expenses', createDeleteLimiter);
app.use('/api/budgets', createDeleteLimiter);
app.use('/api/reminders', createDeleteLimiter);

// Make sure these files exist: ./routes/auth.js etc.
app.use('/api/auth', require('./routes/auth'));
app.use('/api/expenses', require('./routes/expenses'));
app.use('/api/budgets', require('./routes/budgets'));
app.use('/api/reminders', require('./routes/reminders'));

logger.info('✅ API routes registered');

// ============= 404 =============
app.use((req, res) => {
  logger.warn('404 Not Found', { method: req.method, path: req.path });
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.path}`,
    requestId: req.id,
    timestamp: new Date().toISOString(),
  });
});

// ============= ERROR HANDLER =============
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  const errorId = req.id || uuidv4();
  const base = {
    errorId,
    message: err?.message || 'Internal Server Error',
    status: err?.statusCode || 500,
    method: req.method,
    path: req.path,
    ip: req.ip,
  };

  if (process.env.NODE_ENV === 'development') base.stack = err?.stack;

  logger.error('Application Error', base);

  let statusCode = 500;
  let message = 'Internal Server Error';
  let errors = null;

  if (err?.name === 'ValidationError') {
    statusCode = 400; message = 'Validation Error';
    errors = Object.values(err.errors || {}).map(e => ({ field: e.path, message: e.message }));
  } else if (err?.code === 11000) {
    statusCode = 409; message = 'Duplicate field value entered';
    const field = Object.keys(err.keyPattern || {})[0];
    errors = [{ field, message: `${field} already exists` }];
  } else if (err?.name === 'CastError') {
    statusCode = 400; message = 'Invalid ID format';
  } else if (err?.name === 'JsonWebTokenError') {
    statusCode = 401; message = 'Invalid token';
  } else if (err?.name === 'TokenExpiredError') {
    statusCode = 401; message = 'Token expired';
  } else if (err?.statusCode) {
    statusCode = err.statusCode; message = err.message;
  }

  res.status(statusCode).json({
    success: false,
    message,
    ...(errors && { errors }),
    errorId,
    timestamp: new Date().toISOString(),
    ...(process.env.NODE_ENV === 'development' && { stack: err?.stack }),
  });
});

// ============= SERVER STARTUP & GRACEFUL SHUTDOWN =============
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
  const startTime = new Date().toISOString();
  console.log(`Server started on ${HOST}:${PORT} env=${process.env.NODE_ENV}`);
  logger.info('Server started successfully', { port: PORT, host: HOST, environment: process.env.NODE_ENV, timestamp: startTime });
});

process.on('unhandledRejection', reason => {
  logger.error('Unhandled Promise Rejection', { reason: String(reason) });
  if (process.env.NODE_ENV === 'production') {
    server.close(() => process.exit(1));
  }
});

process.on('uncaughtException', err => {
  logger.error('Uncaught Exception', { message: err?.message, stack: err?.stack });
  server.close(() => process.exit(1));
});

const shutdown = (signal) => {
  logger.info(`${signal} received: closing HTTP server`);
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Export app for testing
module.exports = app;
