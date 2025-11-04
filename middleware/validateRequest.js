// File: middleware/validateRequest.js

const { validationResult } = require('express-validator');
const logger = require('../utils/logger');

/**
 * Validate request and send errors if validation fails
 */
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    logger.warn('Validation failed', {
      path: req.path,
      method: req.method,
      errors: errors.array(),
    });

    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg,
        value: err.value,
      })),
    });
  }

  next();
};

module.exports = validateRequest;
