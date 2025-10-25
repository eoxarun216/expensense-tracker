const express = require('express');
const router = express.Router();
const Expense = require('../models/Expense');
const Category = require('../models/Category');
const auth = require('../middleware/auth');

router.get('/', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    const query = { userId: req.userId };
    
    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    const categoryStats = await Expense.aggregate([
      { $match: query },
      {
        $group: {
          _id: '$categoryId',
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      }
    ]);

    const categories = await Category.find({ userId: req.userId }).lean();
    const categoryMap = {};
    categories.forEach(cat => {
      categoryMap[cat._id.toString()] = cat;
    });

    const grandTotal = categoryStats.reduce((sum, stat) => sum + stat.total, 0);

    const categoryBreakdown = categoryStats
      .map(stat => {
        const category = categoryMap[stat._id.toString()];
        if (!category) return null;
        
        return {
          id: category._id,
          name: category.name,
          icon: category.icon,
          color: category.color,
          total: parseFloat(stat.total.toFixed(2)),
          count: stat.count,
          percentage: ((stat.total / grandTotal) * 100).toFixed(1)
        };
      })
      .filter(item => item !== null)
      .sort((a, b) => b.total - a.total);

    res.json({
      success: true,
      data: {
        total: parseFloat(grandTotal.toFixed(2)),
        count: categoryStats.reduce((sum, stat) => sum + stat.count, 0),
        categoryBreakdown
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics',
      error: error.message
    });
  }
});

module.exports = router;
