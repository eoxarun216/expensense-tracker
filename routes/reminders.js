const express = require('express');
const router = express.Router();
const Reminder = require('../models/Reminder');
const { protect } = require('../middleware/auth');

// ==================== GET ALL REMINDERS ====================

router.get('/', protect, async (req, res) => {
  try {
    const { type, status, frequency, from, to } = req.query;
    const query = { userId: req.user.id };

    if (type) query.type = type;
    if (status) query.status = status;
    if (frequency) query.frequency = frequency;
    if (from || to) {
      query.dueDate = {};
      if (from) query.dueDate.$gte = new Date(from);
      if (to) query.dueDate.$lte = new Date(to);
    }

    const reminders = await Reminder.find(query).sort({ dueDate: 1 });
    res.json({ success: true, count: reminders.length, reminders });
  } catch (err) {
    console.error('Error fetching reminders:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== ANALYTICS: UPCOMING & OVERDUE ====================

router.get('/summary', protect, async (req, res) => {
  try {
    const now = new Date();
    const all = await Reminder.find({ userId: req.user.id });

    const upcoming = all.filter(rm => rm.dueDate > now && rm.status !== "paid");
    const overdue = all.filter(rm => rm.dueDate < now && rm.status !== "paid");
    const paid = all.filter(rm => rm.status === "paid");

    res.json({
      success: true,
      total: all.length,
      upcoming: upcoming.length,
      overdue: overdue.length,
      paid: paid.length,
      next: upcoming.sort((a, b) => a.dueDate - b.dueDate)[0] || null
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== CREATE REMINDER ====================

router.post('/', protect, async (req, res) => {
  try {
    const reminder = new Reminder({ ...req.body, userId: req.user.id });
    await reminder.save();
    res.status(201).json({ success: true, reminder });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// ==================== UPDATE REMINDER ====================

router.put('/:id', protect, async (req, res) => {
  try {
    let reminder = await Reminder.findOne({ _id: req.params.id, userId: req.user.id });
    if (!reminder) return res.status(404).json({ success: false, message: "Not found" });

    Object.assign(reminder, req.body);
    await reminder.save();
    res.json({ success: true, reminder });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// ==================== MARK AS PAID ====================

router.patch('/:id/paid', protect, async (req, res) => {
  try {
    let reminder = await Reminder.findOne({ _id: req.params.id, userId: req.user.id });
    if (!reminder) return res.status(404).json({ success: false, message: "Not found" });

    reminder.status = "paid";
    await reminder.save();
    res.json({ success: true, message: "Reminder marked as paid", reminder });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// ==================== DELETE REMINDER ====================

router.delete('/:id', protect, async (req, res) => {
  try {
    await Reminder.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ success: true, message: "Deleted" });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

module.exports = router;
