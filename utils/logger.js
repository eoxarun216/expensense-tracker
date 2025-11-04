// File: utils/logger.js

const fs = require('fs');
const path = require('path');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// ============= LOG LEVELS =============

const LOG_LEVELS = {
  ERROR: 'ERROR',
  WARN: 'WARN',
  INFO: 'INFO',
  DEBUG: 'DEBUG',
};

// ============= LOGGER CLASS =============

class Logger {
  constructor() {
    this.level = process.env.LOG_LEVEL || 'INFO';
  }

  /**
   * Format log message
   */
  formatMessage(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const dataStr = Object.keys(data).length > 0 ? JSON.stringify(data) : '';
    return `[${timestamp}] [${level}] ${message} ${dataStr}`;
  }

  /**
   * Write to console
   */
  writeConsole(level, message, data) {
    const formattedMessage = this.formatMessage(level, message, data);

    switch (level) {
      case LOG_LEVELS.ERROR:
        console.error('❌', formattedMessage);
        break;
      case LOG_LEVELS.WARN:
        console.warn('⚠️ ', formattedMessage);
        break;
      case LOG_LEVELS.INFO:
        console.log('ℹ️ ', formattedMessage);
        break;
      case LOG_LEVELS.DEBUG:
        if (process.env.NODE_ENV === 'development') {
          console.log('🐛', formattedMessage);
        }
        break;
      default:
        console.log(formattedMessage);
    }
  }

  /**
   * Write to file
   */
  writeFile(level, message, data) {
    const timestamp = new Date();
    const date = timestamp.toISOString().split('T')[0];
    const logFile = path.join(logsDir, `${date}.log`);

    const formattedMessage = this.formatMessage(level, message, data);
    fs.appendFileSync(logFile, formattedMessage + '\n', 'utf8');
  }

  /**
   * Log error
   */
  error(message, data = {}) {
    this.writeConsole(LOG_LEVELS.ERROR, message, data);
    if (process.env.NODE_ENV === 'production') {
      this.writeFile(LOG_LEVELS.ERROR, message, data);
    }
  }

  /**
   * Log warning
   */
  warn(message, data = {}) {
    this.writeConsole(LOG_LEVELS.WARN, message, data);
    if (process.env.NODE_ENV === 'production') {
      this.writeFile(LOG_LEVELS.WARN, message, data);
    }
  }

  /**
   * Log info
   */
  info(message, data = {}) {
    this.writeConsole(LOG_LEVELS.INFO, message, data);
    if (process.env.NODE_ENV === 'production') {
      this.writeFile(LOG_LEVELS.INFO, message, data);
    }
  }

  /**
   * Log debug
   */
  debug(message, data = {}) {
    if (process.env.NODE_ENV === 'development') {
      this.writeConsole(LOG_LEVELS.DEBUG, message, data);
    }
  }

  /**
   * Log with custom tag
   */
  log(level, message, data = {}) {
    const validLevel = Object.values(LOG_LEVELS).includes(level) ? level : LOG_LEVELS.INFO;
    this.writeConsole(validLevel, message, data);
    if (process.env.NODE_ENV === 'production') {
      this.writeFile(validLevel, message, data);
    }
  }
}

// Export singleton instance
module.exports = new Logger();
