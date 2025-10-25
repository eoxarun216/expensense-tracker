const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  port: process.env.MYSQLPORT,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const promisePool = pool.promise();

// Test database connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('✅ Connected to Railway MySQL database');
  connection.release();
});

// ==================== ROUTES ====================

// Health check
app.get('/', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Expense Tracker API is running',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'Server is healthy' });
});

// Get all categories
app.get('/api/categories', async (req, res) => {
  try {
    const [rows] = await promisePool.query('SELECT * FROM categories ORDER BY name');
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ success: false, message: 'Error fetching categories', error: error.message });
  }
});

// Add new category
app.post('/api/categories', async (req, res) => {
  const { name, icon, color } = req.body;
  
  if (!name) {
    return res.status(400).json({ success: false, message: 'Category name is required' });
  }

  try {
    const [result] = await promisePool.query(
      'INSERT INTO categories (name, icon, color) VALUES (?, ?, ?)',
      [name, icon || '📦', color || '#A29BFE']
    );
    res.json({ 
      success: true, 
      data: { id: result.insertId, name, icon: icon || '📦', color: color || '#A29BFE' },
      message: 'Category added successfully'
    });
  } catch (error) {
    console.error('Error adding category:', error);
    res.status(500).json({ success: false, message: 'Error adding category', error: error.message });
  }
});

// Get all expenses (with optional filters)
app.get('/api/expenses', async (req, res) => {
  const { startDate, endDate, categoryId } = req.query;
  
  try {
    let query = `
      SELECT e.*, c.name as category_name, c.icon as category_icon, c.color as category_color
      FROM expenses e
      LEFT JOIN categories c ON e.category_id = c.id
      WHERE 1=1
    `;
    const params = [];

    if (startDate) {
      query += ' AND e.date >= ?';
      params.push(startDate);
    }
    if (endDate) {
      query += ' AND e.date <= ?';
      params.push(endDate);
    }
    if (categoryId) {
      query += ' AND e.category_id = ?';
      params.push(categoryId);
    }

    query += ' ORDER BY e.date DESC, e.created_at DESC';

    const [rows] = await promisePool.query(query, params);
    res.json({ success: true, data: rows, count: rows.length });
  } catch (error) {
    console.error('Error fetching expenses:', error);
    res.status(500).json({ success: false, message: 'Error fetching expenses', error: error.message });
  }
});

// Get single expense
app.get('/api/expenses/:id', async (req, res) => {
  try {
    const [rows] = await promisePool.query(
      `SELECT e.*, c.name as category_name, c.icon as category_icon, c.color as category_color
       FROM expenses e
       LEFT JOIN categories c ON e.category_id = c.id
       WHERE e.id = ?`,
      [req.params.id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Expense not found' });
    }
    
    res.json({ success: true, data: rows[0] });
  } catch (error) {
    console.error('Error fetching expense:', error);
    res.status(500).json({ success: false, message: 'Error fetching expense', error: error.message });
  }
});

// Add new expense
app.post('/api/expenses', async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;
  
  // Validation
  if (!title || !amount || !date) {
    return res.status(400).json({ 
      success: false, 
      message: 'Title, amount, and date are required' 
    });
  }

  try {
    const [result] = await promisePool.query(
      'INSERT INTO expenses (title, amount, category_id, date, description) VALUES (?, ?, ?, ?, ?)',
      [title, amount, category_id, date, description || '']
    );
    
    res.json({ 
      success: true, 
      data: { 
        id: result.insertId, 
        title, 
        amount, 
        category_id, 
        date, 
        description 
      },
      message: 'Expense added successfully'
    });
  } catch (error) {
    console.error('Error adding expense:', error);
    res.status(500).json({ success: false, message: 'Error adding expense', error: error.message });
  }
});

// Update expense
app.put('/api/expenses/:id', async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;
  
  if (!title || !amount || !date) {
    return res.status(400).json({ 
      success: false, 
      message: 'Title, amount, and date are required' 
    });
  }

  try {
    const [result] = await promisePool.query(
      'UPDATE expenses SET title = ?, amount = ?, category_id = ?, date = ?, description = ? WHERE id = ?',
      [title, amount, category_id, date, description || '', req.params.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Expense not found' });
    }
    
    res.json({ success: true, message: 'Expense updated successfully' });
  } catch (error) {
    console.error('Error updating expense:', error);
    res.status(500).json({ success: false, message: 'Error updating expense', error: error.message });
  }
});

// Delete expense
app.delete('/api/expenses/:id', async (req, res) => {
  try {
    const [result] = await promisePool.query('DELETE FROM expenses WHERE id = ?', [req.params.id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Expense not found' });
    }
    
    res.json({ success: true, message: 'Expense deleted successfully' });
  } catch (error) {
    console.error('Error deleting expense:', error);
    res.status(500).json({ success: false, message: 'Error deleting expense', error: error.message });
  }
});

// Get statistics
app.get('/api/statistics', async (req, res) => {
  const { startDate, endDate } = req.query;
  
  try {
    let query = 'SELECT SUM(amount) as total, COUNT(*) as count FROM expenses WHERE 1=1';
    const params = [];

    if (startDate) {
      query += ' AND date >= ?';
      params.push(startDate);
    }
    if (endDate) {
      query += ' AND date <= ?';
      params.push(endDate);
    }

    const [totalResult] = await promisePool.query(query, params);
    
    // Category-wise spending
    let categoryQuery = `
      SELECT c.name, c.icon, c.color, SUM(e.amount) as total, COUNT(e.id) as count
      FROM expenses e
      JOIN categories c ON e.category_id = c.id
      WHERE 1=1
    `;
    
    if (startDate) {
      categoryQuery += ' AND e.date >= ?';
    }
    if (endDate) {
      categoryQuery += ' AND e.date <= ?';
    }
    
    categoryQuery += ' GROUP BY c.id, c.name, c.icon, c.color ORDER BY total DESC';
    
    const [categoryResult] = await promisePool.query(categoryQuery, params);

    res.json({
      success: true,
      data: {
        total: parseFloat(totalResult[0].total || 0),
        count: totalResult[0].count || 0,
        categoryBreakdown: categoryResult.map(cat => ({
          ...cat,
          total: parseFloat(cat.total),
          percentage: totalResult[0].total ? ((cat.total / totalResult[0].total) * 100).toFixed(1) : 0
        }))
      }
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).json({ success: false, message: 'Error fetching statistics', error: error.message });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Something went wrong!', error: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});