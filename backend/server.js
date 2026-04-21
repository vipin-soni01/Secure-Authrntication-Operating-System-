// =======================
// Secure Authentication Framework - Servers
// =======================''

require('dotenv').config();

const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const { URLSearchParams } = require('url');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 5501;

// =======================
// Google OAuth Configuration
// =======================
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET';
const REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/oauth2callback`;
const FRONTEND_URL =
  process.env.FRONTEND_URL || `http://localhost:${PORT}`;

// =======================
// File-Based User Storage
// =======================
const DB_FILE = path.join(__dirname, 'users.json');

function loadUsers() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading users:', err);
  }
  return [];
}

function saveUsers(users) {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

let users = loadUsers();
let sessions = {};
let otpSessions = {};
let loginAttempts = {};
let securityLogs = [];

const MAX_ATTEMPTS = 3;
const LOCK_TIME = 2 * 60 * 1000; // 2 minutes (120 seconds)

// =======================
// Helper Functions
// =======================
function createSessionToken(username, email) {
  const token = uuidv4();
  sessions[token] = { username, email, loginTime: Date.now() };
  return token;
}

function verifySession(token) {
  return sessions[token] || null;
}

function logEvent(type, message, user = '') {
  securityLogs.push({
    type,
    message,
    user,
    timestamp: new Date().toISOString(),
  });
}

function isStrongPassword(password) {
  return (
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[!@#$%^&*]/.test(password)
  );
}

// =======================
// Nodemailer Configuration
// =======================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'votp158@gmail.com',
    pass: 'YOUR_APP_PASSWORD', // Replace with Gmail App Password
  },
});

// =======================
// Middleware: Authenticate Session
// =======================
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const session = verifySession(token);
  if (!session) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.session = session;
  next();
}

// =======================
// Health Check
// =======================
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// =======================
// Register Endpoint
// =======================
app.post('/register', (req, res) => {
  const { user, email, pass } = req.body;

  if (!user || !email || !pass)
    return res.status(400).json({ error: 'All fields required' });

  if (user.length > 20 || pass.length > 50) {
    logEvent('BUFFER_OVERFLOW', 'Input length exceeded', user);
    return res.status(400).json({ error: 'Input too long' });
  }

  if (!isStrongPassword(pass)) {
    return res.status(400).json({
      error:
        'Password must be at least 8 Characters and include Uppercase, Number, and Special character in it.',
    });
  }

  if (users.some((u) => u.user.toLowerCase() === user.toLowerCase()))
    return res.status(400).json({ error: 'Username already exists' });

  if (users.some((u) => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email already registered' });

  users.push({ user, email, pass, role: 'user', status: 'active' });
  saveUsers(users);
  logEvent('REGISTER', 'User registered', user);

  res.json({ message: 'Registered successfully' });
});

// =======================
// Login Endpoint with Account Lockout
// =======================
app.post('/login', (req, res) => {
  const { user, pass } = req.body;

  if (!user || !pass)
    return res.status(400).json({ error: 'Username and password required' });

  if (
    loginAttempts[user] &&
    loginAttempts[user].lockedUntil > Date.now()
  ) {
    return res
      .status(403)
      .json({ error: 'Account locked. Try again later.' });
  }

  const userData = users.find((u) => u.user === user && u.pass === pass);

  if (!userData) {
    loginAttempts[user] = loginAttempts[user] || {
      count: 0,
      lockedUntil: 0,
    };
    loginAttempts[user].count++;

    if (loginAttempts[user].count >= MAX_ATTEMPTS) {
      loginAttempts[user].lockedUntil = Date.now() + LOCK_TIME;
      logEvent('ACCOUNT_LOCKED', 'Too many failed attempts', user);
    }

    logEvent('LOGIN_FAILED', 'Invalid credentials', user);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  loginAttempts[user] = { count: 0, lockedUntil: 0 };

  // Trapdoor detection (simulation)
  if (user === 'admin' && pass === 'admin123') {
    logEvent('TRAPDOOR', 'Backdoor login attempt detected', user);
  }

  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpSessions[user] = {
    otp,
    expireTime: Date.now() + 30 * 1000,
    email: userData.email,
  };

  const mailOptions = {
    from: 'votp158@gmail.com',
    to: userData.email,
    subject: 'Your OTP Code',
    text: `Your OTP is: ${otp}. It expires in 30 seconds.`,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Failed to send OTP email' });
    }
    logEvent('OTP_SENT', 'OTP sent to email', user);
    res.json({ message: 'OTP sent to email', username: user });
  });
});

// =======================
// Google OAuth: Redirect to Google
// =======================
app.get('/auth/google', (req, res) => {
  const scope = encodeURIComponent('openid email profile');
  const redirect = encodeURIComponent(REDIRECT_URI);

  const url = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${CLIENT_ID}&scope=${scope}&redirect_uri=${redirect}&access_type=offline&prompt=select_account`;

  res.redirect(url);
});

// =======================
// Google OAuth Callback
// =======================
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;

  if (!code) {
    console.error('❌ No authorization code received.');
    return res.status(400).send('Missing authorization code');
  }

  try {
    // Exchange authorization code for access token
    const tokenResponse = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        code: code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    console.log('✅ Token response:', tokenResponse.data);

    const accessToken = tokenResponse.data.access_token;

    // Fetch user information
    const userInfoResponse = await axios.get(
      'https://www.googleapis.com/oauth2/v3/userinfo',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    console.log('✅ User info:', userInfoResponse.data);

    const { email, name } = userInfoResponse.data;

    // Check if user exists
    let userData = users.find(
      (u) => u.email.toLowerCase() === email.toLowerCase()
    );

    // If not, create a new user
    if (!userData) {
      const username =
        name.replace(/\s+/g, '') + Math.floor(Math.random() * 1000);
      userData = {
        user: username,
        email: email,
        pass: '',
        role: 'user',
        status: 'active',
      };
      users.push(userData);
      saveUsers(users);
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpSessions[userData.user] = {
      otp,
      expireTime: Date.now() + 30 * 1000,
      email: email,
    };

    // Send OTP to your email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is: ${otp}. It expires in 30 seconds.`,
    });

    console.log('✅ OTP sent to:', email);

    // Redirect to OTP page
    res.redirect(
      `${process.env.FRONTEND_URL}/otp.html?user=${encodeURIComponent(
        userData.user
      )}`
    );
  } catch (error) {
    console.error(
      '❌ Google OAuth Error:',
      error.response?.data || error.message
    );
    res.status(500).send(
      'Google authentication failed. Check server logs for details.'
    );
  }
});

// =======================
// Verify OTP
// =======================
app.post('/verify-otp', (req, res) => {
  const { user, otp } = req.body;

  const otpData = otpSessions[user];
  if (!otpData)
    return res.status(401).json({ error: 'OTP not found' });

  if (Date.now() > otpData.expireTime) {
    delete otpSessions[user];
    return res.status(401).json({ error: 'OTP expired' });
  }

  if (otp !== otpData.otp)
    return res.status(401).json({ error: 'Invalid OTP' });

  const sessionToken = createSessionToken(user, otpData.email);
  delete otpSessions[user];

  logEvent('LOGIN_SUCCESS', 'User authenticated successfully', user);
  res.json({ sessionToken, message: 'OTP verified successfully' });
});

// =======================
// Admin Routes       
// =======================
app.get('/get-users', authenticate, (req, res) => {
  res.json(users);
});

app.post('/admin/add-user', authenticate, (req, res) => {
  if (req.session.username !== 'admin') {
    logEvent(
      'PRIVILEGE_ESCALATION',
      'Unauthorized admin access',
      req.session.username
    );
    return res.status(403).json({ error: 'Access denied' });
  }

  const { username, email, password, role } = req.body;

  users.push({
    user: username,
    email,
    pass: password,
    role: role || 'user',
  });

  saveUsers(users);
  res.json({ message: 'User added successfully' });
});

// =======================
// Security Logs Endpoint
// =======================
app.get('/logs', authenticate, (req, res) => {
  res.json(securityLogs);
});

// =======================
// Serve Frontend
// =======================
app.use(express.static(path.join(__dirname)));

app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`)
);