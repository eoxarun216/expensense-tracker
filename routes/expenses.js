const express = require('express');
const router = express.Router();
const {
  getExpenses,
  getExpense,
  createExpense,
  updateExpense,
  deleteExpense,
  getStatistics,
} = require('../controllers/expenseController');
const { protect } = require('../middleware/auth');

// All routes below require authentication
router.use(protect);

// GET statistics BEFORE :id route (ordering matters for param matching)
router.get('/statistics', getStatistics);

// CRUD core routes
router
  .route('/')
  .get(getExpenses)    // GET /api/expenses - list all for user
  .post(createExpense); // POST /api/expenses - create for user

router
  .route('/:id')
  .get(getExpense)     // GET /api/expenses/:id - single expense
  .put(updateExpense)  // PUT /api/expenses/:id
  .delete(deleteExpense); // DELETE /api/expenses/:id

// (Optional) GET expenses by reminder link
// router.get('/by-reminder/:reminderId', getExpensesByReminder);

module.exports = router;
