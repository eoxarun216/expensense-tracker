const express = require('express');
const router = express.Router();
const { signup, login, getProfile, updateProfile } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

// Public routes
router.post('/signup', signup);
router.post('/login', login);

// Protected routes
router.get('/me', protect, async (req, res) => {
  try {
    const User = require('../models/User');
    const user = await User.findById(req.user._id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        _id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
    });
  }
});

router.get('/profile', protect, getProfile);
router.put('/profile', protect, updateProfile);

module.exports = router;
