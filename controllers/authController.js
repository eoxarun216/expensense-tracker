const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const JWT_EXPIRY = '24h';
const SALT_ROUNDS = 10;

const buildUserResponse = user => ({
  id: user._id,
  name: user.name,
  email: user.email,
  phone: user.phone || null,
  avatar: user.avatar || null,
  role: user.role || 'user',
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

const generateToken = id => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRY });

exports.signup = async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;
    if (!name || !email || !password || !confirmPassword)
      return res.status(400).json({ success: false, message: 'All fields required' });
    if (password !== confirmPassword)
      return res.status(400).json({ success: false, message: 'Passwords do not match' });

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser)
      return res.status(409).json({ success: false, message: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      preferences: { theme: 'auto', language: 'en', currency: 'INR' },
    });

    const token = generateToken(user._id);
    res.status(201).json({
      success: true,
      message: 'Registered successfully',
      token,
      user: buildUserResponse(user),
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Signup failed' });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: 'Email and password required' });

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ success: false, message: 'Invalid credentials' });

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id);
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: buildUserResponse(user),
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Login failed' });
  }
};

exports.getProfile = async (req, res) => {
  try {
    const user = req.user;
    res.json({ success: true, user: buildUserResponse(user) });
  } catch {
    res.status(500).json({ success: false, message: 'Failed to retrieve profile' });
  }
};
