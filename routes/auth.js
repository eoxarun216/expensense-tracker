const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const { signup, login, getProfile } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

const signupValidation = [
  body('name').trim().notEmpty().withMessage('Name required'),
  body('email').isEmail().withMessage('Valid email needed'),
  body('password').isLength({ min: 6 }).withMessage('Min 6 chars'),
  body('confirmPassword').custom((value, { req }) => value === req.body.password ? true : Promise.reject('Passwords do not match'))
];

const loginValidation = [
  body('email').isEmail().withMessage('Valid email needed'),
  body('password').notEmpty().withMessage('Password required')
];

router.post('/signup', signupValidation, signup);
router.post('/login', loginValidation, login);
router.get('/profile', protect, getProfile);

module.exports = router;
