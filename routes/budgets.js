const express = require('express');
const router = express.Router();
const Budget = require('../models/Budget');
const { protect } = require('../middleware/auth');

// Get all budgets for user
router.get('/', protect, async (req, res) => {
  try {
    const budgets = await Budget.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json({ success: true, budgets });
  } catch (error) {
    console.error('Error fetching budgets:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Create budget
router.post('/', protect, async (req, res) => {
  try {
    const { category, limit, period } = req.body;

    // Check if budget already exists for this category
    const existingBudget = await Budget.findOne({
      userId: req.user.id,
      category,
      period,
    });

    if (existingBudget) {
      return res.status(400).json({
        success: false,
        message: 'Budget already exists for this category and period',
      });
    }

    const budget = new Budget({
      userId: req.user.id,
      category,
      limit,
      period,
    });

    await budget.save();
    res.status(201).json({ success: true, budget });
  } catch (error) {
    console.error('Error creating budget:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Update budget
router.put('/:id', protect, async (req, res) => {
  try {
    const { category, limit, period } = req.body;

    let budget = await Budget.findById(req.params.id);

    if (!budget) {
      return res.status(404).json({ success: false, message: 'Budget not found' });
    }

    // Check if budget belongs to user
    if (budget.userId.toString() !== req.user.id) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    budget.category = category || budget.category;
    budget.limit = limit || budget.limit;
    budget.period = period || budget.period;

    await budget.save();
    res.json({ success: true, budget });
  } catch (error) {
    console.error('Error updating budget:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Delete budget
router.delete('/:id', protect, async (req, res) => {
  try {
    const budget = await Budget.findById(req.params.id);

    if (!budget) {
      return res.status(404).json({ success: false, message: 'Budget not found' });
    }

    // Check if budget belongs to user
    if (budget.userId.toString() !== req.user.id) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    await Budget.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Budget deleted' });
  } catch (error) {
    console.error('Error deleting budget:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
