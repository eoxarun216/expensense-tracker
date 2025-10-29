const Reminder = require('../models/Reminder');

// GET ALL reminders for a user
exports.getReminders = async (req, res) => {
  try {
    const reminders = await Reminder.find({ userId: req.user._id }).sort({ dueDate: 1 });
    res.json(reminders);
  } catch (err) { res.status(500).json({ error: err.message }); }
};

// CREATE a reminder
exports.createReminder = async (req, res) => {
  try {
    const reminder = new Reminder({ ...req.body, userId: req.user._id });
    await reminder.save();
    res.status(201).json(reminder);
  } catch (err) { res.status(400).json({ error: err.message }); }
};

// UPDATE a reminder
exports.updateReminder = async (req, res) => {
  try {
    const reminder = await Reminder.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id }, req.body, { new: true }
    );
    if (!reminder) return res.status(404).json({ error: 'Reminder not found' });
    res.json(reminder);
  } catch (err) { res.status(400).json({ error: err.message }); }
};

// DELETE a reminder
exports.deleteReminder = async (req, res) => {
  try {
    const result = await Reminder.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    if (!result) return res.status(404).json({ error: 'Reminder not found' });
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(400).json({ error: err.message }); }
};
