const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const axios = require('axios');
const app = express();
const wss = new WebSocket.Server({ port: 5001 });

app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://localhost/heartsync', { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  gender: { type: String, required: true },
  profile: {
    name: String,
    income: Number,
    occupation: String,
    interests: String,
    bio: String,
  },
  subscription: { type: String, default: 'basic' },
  peerId: String,
  verified: { type: Boolean, default: false },
  verificationToken: String,
  maleSwipeCount: { type: Number, default: 0 }, // Track right swipes for men
});

const User = mongoose.model('User', userSchema);

// Swipe Schema
const swipeSchema = new mongoose.Schema({
  userId: String,
  profileId: String,
  direction: String,
});

const Swipe = mongoose.model('Swipe', swipeSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: String,
  receiver: String,
  message: String,
  timestamp: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);

// Email setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your-email@gmail.com',
    pass: 'your-app-password',
  },
});

// WebSocket for messaging
wss.on('connection', (ws) => {
  ws.on('message', async (data) => {
    const { sender, receiver, message } = JSON.parse(data);
    const newMessage = new Message({ sender, receiver, message });
    await newMessage.save();
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ sender, receiver, message }));
      }
    });
  });
});

// Middleware for authentication
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, 'secret');
    req.user = await User.findById(decoded.userId);
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Auth routes
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, gender } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = Math.random().toString(36).substring(2);
  const user = new User({ email, password: hashedPassword, gender, verificationToken });
  await user.save();
  const token = jwt.sign({ userId: user._id }, 'secret', { expiresIn: '1h' });
  await transporter.sendMail({
    to: email,
    subject: 'Verify your HeartSync account',
    html: `<a href="http://localhost:5000/api/auth/verify/${verificationToken}">Verify Email</a>`,
  });
  res.json({ token, user });
});

app.get('/api/auth/verify/:token', async (req, res) => {
  const user = await User.findOne({ verificationToken: req.params.token });
  if (user) {
    user.verified = true;
    user.verificationToken = null;
    await user.save();
    res.json({ message: 'Email verified' });
  } else {
    res.status(400).json({ message: 'Invalid token' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }
  if (!user.verified) {
    return res.status(400).json({ message: 'Email not verified' });
  }
  const token = jwt.sign({ userId: user._id }, 'secret', { expiresIn: '1h' });
  res.json({ token, user });
});

app.post('/api/auth/recover', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });
  const resetToken = Math.random().toString(36).substring(2);
  user.verificationToken = resetToken;
  await user.save();
  await transporter.sendMail({
    to: email,
    subject: 'Reset your HeartSync password',
    html: `<a href="http://localhost:3000/reset?token=${resetToken}">Reset Password</a>`,
  });
  res.json({ message: 'Recovery email sent' });
});

// Profile routes
app.post('/api/profile', authMiddleware, async (req, res) => {
  req.user.profile = req.body;
  await req.user.save();
  res.json(req.user);
});

app.get('/api/profiles', authMiddleware, async (req, res) => {
  const incomeThresholds = { basic: 0, standard: 1000, premium: 1500, elite: 2000 };
  const profiles = await User.find({
    gender: req.user.gender === 'male' ? 'female' : 'male',
    'profile.income': { $gte: incomeThresholds[req.user.subscription] || 0 },
  });
  const swipeCount = req.user.gender === 'male' ? req.user.maleSwipeCount : 0;
  res.json({ profiles, swipeCount });
});

// Swipe routes
app.post('/api/swipe', authMiddleware, async (req, res) => {
  const { profileId, direction } = req.body;
  const swipe = new Swipe({ userId: req.user._id, profileId, direction });
  await swipe.save();
  if (req.user.gender === 'male' && direction === 'right') {
    req.user.maleSwipeCount += 1;
    await req.user.save();
    if (req.user.maleSwipeCount >= 25) {
      return res.json({ message: 'Swipe recorded', needsPayment: true, swipeCount: req.user.maleSwipeCount });
    }
  }
  res.json({ message: 'Swipe recorded', swipeCount: req.user.maleSwipeCount });
});

// Subscription routes for women
app.post('/api/subscription', authMiddleware, async (req, res) => {
  const { plan, reference } = req.body;
  if (req.user.gender !== 'female') return res.status(403).json({ message: 'Only females can use this endpoint' });
  const response = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
    headers: { Authorization: `Bearer sk_live_86fcee14d403288d8fd5c991850896d1b68e225a` },
  });
  if (response.data.data.status === 'success') {
    req.user.subscription = plan;
    await req.user.save();
    res.json({ message: 'Subscription updated' });
  } else {
    res.status(400).json({ message: 'Payment verification failed' });
  }
});

// Subscription route for men
app.post('/api/male-subscription', authMiddleware, async (req, res) => {
  const { reference } = req.body;
  if (req.user.gender !== 'male') return res.status(403).json({ message: 'Only males can use this endpoint' });
  const response = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
    headers: { Authorization: `Bearer sk_live_86fcee14d403288d8fd5c991850896d1b68e225a` },
  });
  if (response.data.data.status === 'success') {
    req.user.maleSwipeCount = 0; // Reset swipe count after payment
    await req.user.save();
    res.json({ message: 'Subscription updated', swipeCount: req.user.maleSwipeCount });
  } else {
    res.status(400).json({ message: 'Payment verification failed' });
  }
});

// Peer ID for WebRTC
app.post('/api/peer-id', authMiddleware, async (req, res) => {
  req.user.peerId = req.body.peerId;
  await req.user.save();
  res.json({ message: 'Peer ID updated' });
});

app.listen(5000, () => console.log('Server running on port 5000'));