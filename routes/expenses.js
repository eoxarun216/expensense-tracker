const express = require('express');
const router = express.Router();
const Expense = require('../models/Expense');
const Category = require('../models/Category');
const auth = require('../middleware/auth');

// Get all expenses
router.get('/', auth, async (req, res) => {
  try {
    const { startDate, endDate, categoryId } = req.query;
    
    // Build query
    const query = { userId: req.userId };
    
    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    if (categoryId) {
      query.categoryId = categoryId;
    }

    // Fetch expenses with category details
    const expenses = await Expense.find(query)
      .sort({ date: -1, createdAt: -1 })
      .lean();

    // Get all categories for this user
    const categories = await Category.find({ userId: req.userId }).lean();
    const categoryMap = {};
    categories.forEach(cat => {
      categoryMap[cat._id.toString()] = cat;
    });

    // Format response with category info
    const formattedExpenses = expenses.map(exp => {
      const category = categoryMap[exp.categoryId.toString()];
      return {
        id: exp._id,
        user_id: exp.userId,
        title: exp.title,
        amount: exp.amount,
        category_id: exp.categoryId,
        category_name: category?.name,
        category_icon: category?.icon,
        category_color: category?.color,
        date: exp.date.toISOString().split('T')[0],
        description: exp.description,
        created_at: exp.createdAt,
        updated_at: exp.updatedAt
      };
    });

    res.json({
      success: true,
      data: formattedExpenses,
      count: formattedExpenses.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch expenses',
      error: error.message
    });
  }
});

// Add expense
router.post('/', auth, async (req, res) => {
  try {
    const { title, amount, category_id, date, description } = req.body;

    if (!title || !amount || !category_id || !date) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields'
      });
    }

    const expense = await Expense.create({
      userId: req.userId,
      title,
      amount: parseFloat(amount),
      categoryId: category_id,
      date: new Date(date),
      description: description || ''
    });

    res.json({
      success: true,
      data: {
        id: expense._id,
        user_id: expense.userId,
        title: expense.title,
        amount: expense.amount,
        category_id: expense.categoryId,
        date: expense.date.toISOString().split('T')[0],
        description: expense.description,
        created_at: expense.createdAt
      },
      message: 'Expense added successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to add expense',
      error: error.message
    });
  }
});

// Update expense
router.put('/:id', auth, async (req, res) => {
  try {
    const { title, amount, category_id, date, description } = req.body;

    const expense = await Expense.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      {
        title,
        amount: parseFloat(amount),
        categoryId: category_id,
        date: new Date(date),
        description: description || ''
      },
      { new: true }
    );

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found'
      });
    }

    res.json({
      success: true,
      data: {
        id: expense._id,
        title: expense.title,
        amount: expense.amount,
        category_id: expense.categoryId,
        date: expense.date.toISOString().split('T')[0],
        description: expense.description,
        updated_at: expense.updatedAt
      },
      message: 'Expense updated successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to update expense',
      error: error.message
    });
  }
});

// Delete expense
router.delete('/:id', auth, async (req, res) => {
  try {
    const expense = await Expense.findOneAndDelete({
      _id: req.params.id,
      userId: req.userId
    });

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found'
      });
    }

    res.json({
      success: true,
      message: 'Expense deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to delete expense',
      error: error.message
    });
  }
});

module.exports = router;
