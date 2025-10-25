const express = require('express');
const router = express.Router();
const Category = require('../models/Category');
const auth = require('../middleware/auth');

router.get('/', auth, async (req, res) => {
  try {
    const categories = await Category.find({ userId: req.userId })
      .sort({ createdAt: 1 });

    const formattedCategories = categories.map(cat => ({
      id: cat._id,
      user_id: cat.userId,
      name: cat.name,
      icon: cat.icon,
      color: cat.color,
      created_at: cat.createdAt
    }));

    res.json({
      success: true,
      data: formattedCategories,
      count: formattedCategories.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch categories',
      error: error.message
    });
  }
});

router.post('/', auth, async (req, res) => {
  try {
    const { name, icon, color } = req.body;

    if (!name || !icon || !color) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields'
      });
    }

    const category = await Category.create({
      userId: req.userId,
      name,
      icon,
      color
    });

    res.json({
      success: true,
      data: {
        id: category._id,
        user_id: category.userId,
        name: category.name,
        icon: category.icon,
        color: category.color,
        created_at: category.createdAt
      },
      message: 'Category added successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to add category',
      error: error.message
    });
  }
});

module.exports = router;
