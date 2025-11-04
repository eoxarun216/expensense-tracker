const Reminder = require('../models/Reminder');

// GET all reminders for current user
exports.getReminders = async (req, res) => {
  try {
    const reminders = await Reminder.find({ userId: req.user._id }).sort({ dueDate: 1 });
    res.json({
      success: true,
      count: reminders.length,
      reminders,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// CREATE new reminder
exports.createReminder = async (req, res) => {
  try {
    // Input validation (customize as needed)
    if (!req.body.title || !req.body.type || !req.body.amount || !req.body.dueDate) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: title, type, amount, dueDate',
      });
    }

    const reminder = new Reminder({
      ...req.body,
      userId: req.user._id,
    });

    await reminder.save();
    res.status(201).json({
      success: true,
      reminder,
    });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
};

// UPDATE a reminder
exports.updateReminder = async (req, res) => {
  try {
    const reminder = await Reminder.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!reminder) {
      return res.status(404).json({ success: false, message: 'Reminder not found' });
    }
    res.json({ success: true, reminder });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
};

// DELETE a reminder
exports.deleteReminder = async (req, res) => {
  try {
    const result = await Reminder.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    if (!result) {
      return res.status(404).json({ success: false, message: 'Reminder not found' });
    }
    res.json({ success: true, message: 'Reminder deleted' });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
};
