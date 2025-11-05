// routes/authRoutes.js - Simplified Version (Updated to include getProfile)

const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const logger = require('../utils/logger');

// Controllers (simplified email + password flows only)
// Destructure getProfile along with other functions
const { signup, login, getProfile /*, other functions if added back later */ } = require('../controllers/authController');

// Middleware (simplified protect middleware)
const { protect } = require('../middleware/auth');

// ============= VALIDATION SCHEMAS =============

const signupValidation = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  body('email')
    .trim()
    .toLowerCase()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 }) // Adjusted minimum length as per simplified controller
    .withMessage('Password must be at least 6 characters') // Adjusted message
    .custom((value, { req }) => {
      if (value !== req.body.confirmPassword) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  body('confirmPassword')
    .notEmpty()
    .withMessage('Please confirm your password'),
];

const loginValidation = [
  body('email')
    .trim()
    .toLowerCase()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Please provide a password'),
];

// Removed other validation schemas as they are not needed

// ============= PUBLIC ROUTES =============

router.post(
  '/signup',
  // Removed rateLimiter and validateRequest middleware for simplicity
  signupValidation,
  // validateRequest, // Removed
  signup
);

router.post(
  '/login',
  // Removed rateLimiter and validateRequest middleware for simplicity
  loginValidation,
  // validateRequest, // Removed
  login
);

// ============= PROTECTED ROUTES =============

// Added the /profile route, protected by the 'protect' middleware
router.get('/profile', protect, getProfile);

// Add other protected routes here if you implement them in the simplified controller

// Removed error handling middleware as it's typically handled globally in server.js
// router.use((err, req, res, next) => { ... });

module.exports = router;
