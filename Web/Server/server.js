const express = require('express');
const expressEjsLayouts = require('express-ejs-layouts');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const dbloader = require('better-sqlite3');
const bcrypt = require('bcrypt');
const validator = require('validator');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Store CAPTCHA answers temporarily (in production, use Redis or similar)
const captchaStore = new Map();

// Security configuration - random secrets for development
// Note: In production, use environment variables for persistent secrets
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');
let PORT = 3000;

// First create the app
const app = express();
app.use(express.json());


// Then wrap it with HTTP and attach socket.io
const http = require('http').createServer(app);
const io = require('socket.io')(http);

// Ensure upload folder exists
const uploadFolder = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadFolder, { recursive: true });

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadFolder),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({ storage });

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'Public', 'views'));
app.use(expressEjsLayouts);
app.set('layout', 'layout');

// Static files
app.use(express.static(path.join(__dirname, '..', 'Public')));

// sqlite stuff
app.use(express.json());
// load database
const db = dbloader(path.resolve(__dirname, "database.db"))
// load sql schema
const schema = fs.readFileSync(path.resolve(__dirname, "schema.sql"), "utf8")
// set up database to use the sql schema
db.exec(schema);

// Session configuration
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours in milliseconds
  }
}));

// Rate limiting configuration
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 signup attempts per hour
  message: { error: 'Too many signup attempts. Please try again in 1 hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Authentication middleware to protect routes
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    res.redirect('/login');
  } else {
    // Check if this session has been invalidated (account deleted)
    if (global.invalidatedSessions && global.invalidatedSessions.has(req.session.userId)) {
      // Clear the invalidated session flag
      global.invalidatedSessions.delete(req.session.userId);
      // Destroy the session and redirect to login
      req.session.destroy((err) => {
        if (err) {
          console.error('Error destroying invalidated session:', err);
        }
        res.redirect('/login');
      });
      return;
    }
    
    // Fetch user data from database instead of using session data
    try {
      const user = db.prepare("SELECT id, username, email FROM users WHERE id = ?").get(req.session.userId);
      if (!user) {
        // User not found in database, destroy session
        req.session.destroy((err) => {
          if (err) {
            console.error('Error destroying session for non-existent user:', err);
          }
          res.redirect('/login');
        });
        return;
      }
      
      // Add minimal user data to res.locals for templates
      res.locals.user = {
        username: user.username,
        email: user.email
      };
      next();
    } catch (err) {
      console.error('Error fetching user data:', err);
      res.redirect('/login');
    }
  }
};

// Routes
app.get('/', requireAuth, (req, res) => {
  res.render('index',{
    title: 'GoSpoof Home'
  });
});

// Middleware to redirect logged-in users away from auth pages
const redirectIfLoggedIn = (req, res, next) => {
  if (req.session.userId) {
    res.redirect('/');
  } else {
    next();
  }
};

app.get('/login', redirectIfLoggedIn, (req, res) => {
  res.render('login', {
    title: 'GoSpoof Login',
    hideNav: true
  });
});

app.get('/signup', redirectIfLoggedIn, (req, res) => {
  res.render('signup', {
    title: 'GoSpoof Signup',
    hideNav: true
  });
});

app.get('/forgot-password', redirectIfLoggedIn, (req, res) => {
  res.render('forgot-password', {
    title: 'GoSpoof Forgot Password',
    hideNav: true
  });
});

app.get('/attackers', requireAuth, (req, res) => {
  res.render('attackers', {
    title: 'GoSpoof Attackers',
    includeChartJS: true
  });
});

app.get('/payloads', requireAuth, (req, res) => {
  res.render('payloads', {
    title: 'GoSpoof Payloads'
  });
});

app.get('/live', requireAuth, (req, res) => {
  res.render('live', {
    title: 'GoSpoof Live'
  });
});

app.get('/profile', requireAuth, (req, res) => {
  res.render('profile', {
    title: 'GoSpoof Profile'
  });
});

// api routes

app.get('/api/attackers', requireAuth, apiLimiter, (req, res) => {
  const logPath = getLatestLogFilePath();
  if (!logPath) return res.json([]);

  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Could not read log file.');

    const ipPayloadMap = {};
    data.split('\n').forEach(line => {
      const match = line.match(/\[HONEYPOT\] .*? \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*?)"/);
      if (match) {
        const [_, ip, payload] = match;
        if (!ipPayloadMap[ip]) ipPayloadMap[ip] = new Set();
        ipPayloadMap[ip].add(payload || 'Probing Scan');
      }
    });

    const result = Object.entries(ipPayloadMap).map(([ip, payloadSet]) => ({
      ip,
      payloadCount: payloadSet.size
    }));

    res.json(result);
  });
});

app.get('/api/payloads', requireAuth, apiLimiter, (req, res) => {
  const logPath = getLatestLogFilePath();
  if (!logPath) return res.json([]);

  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Could not read log file.');

    const result = {};
    data.split('\n').forEach(line => {
      const match = line.match(/\[HONEYPOT\] (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*?)"/);
      if (match) {
        let [_, date, time, ip, payload] = match;
        payload = payload.trim() || 'Probing Scan';

        if (!result[ip]) {
          result[ip] = { total: 0, payloads: {} };
        }

        result[ip].total++;
        result[ip].payloads[payload] = (result[ip].payloads[payload] || 0) + 1;
      }
    });

    res.json(result);
  });
});

app.post('/upload-log', requireAuth, upload.single('logFile'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  console.log('Uploaded:', req.file.path);

  fs.readFile(req.file.path, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading uploaded log');

    const lines = data.split('\n');
    lines.forEach(line => {
      const match = line.match(/\[HONEYPOT\].*? \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*?)"/);
      if (match) {
        const [_, ip, payloadRaw] = match;
        const payload = payloadRaw.trim() || 'Probing Scan';

        io.emit('new_attack', { ip, payload });
      }
    });

    // Optional: go to live dashboard after upload
    res.redirect('/live');
  });
});

app.post("/api/create_user", signupLimiter, (req, res) => {
  const { username, email, password } = req.body || {};
  
  // Check for missing fields with specific messages
  if (!username) {
    res.status(400).send({ error: "Username is required" });
    return;
  }
  if (username.length < 3 || username.length > 20) {
    res.status(400).send({ error: "Username must be between 3 and 20 characters" });
    return;
  }
  // Sanitize username - only allow alphanumeric characters
  if (!/^[a-zA-Z0-9]+$/.test(username)) {
    res.status(400).send({ error: "Username can only contain letters and numbers" });
    return;
  }
  if (!email) {
    res.status(400).send({ error: "Email is required" });
    return;
  }
  if (!password) {
    res.status(400).send({ error: "Password is required" });
    return;
  }
  if (password.length < 12) {
    res.status(400).send({ error: "Password must be at least 12 characters long" });
    return;
  }
  
  // Check for uppercase letter
  if (!/[A-Z]/.test(password)) {
    res.status(400).send({ error: "Password must contain at least 1 uppercase letter" });
    return;
  }
  
  // Check for lowercase letter
  if (!/[a-z]/.test(password)) {
    res.status(400).send({ error: "Password must contain at least 1 lowercase letter" });
    return;
  }
  
  // Check for number
  if (!/\d/.test(password)) {
    res.status(400).send({ error: "Password must contain at least 1 number" });
    return;
  }
  
  // Check for special character
  if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) {
    res.status(400).send({ error: "Password must contain at least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)" });
    return;
  }
  
  if (!validateEmail(email)) {
    res.status(400).send({ error: "Invalid email" });
    return;
  }
  if (emailInDatabase(email)) {
    res.status(400).send({ error: "Email already in use" });
    return;
  }
  if (usernameInDatabase(username)) {
    res.status(400).send({ error: "Username already in use" });
    return;
  }

  try {
    // Capitalize username before storing
    const usernameCap = username.charAt(0).toUpperCase() + username.slice(1).toLowerCase();
    
    // Hash the password before storing
    const hashedPassword = bcrypt.hashSync(password, 12);
    db.prepare("INSERT INTO users (username, email, pass) VALUES (?, ?, ?)").run(usernameCap, email, hashedPassword);
    res.status(200).send({ message: "User created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: "Failed to create user" });
    return;
  }
});

app.post("/api/delete_user", requireAuth, (req, res) => {
  const { password } = req.body || {};

  // Check for missing password
  if (!password) {
    res.status(400).send({ error: "Password is required" });
    return;
  }

  try {
    // Get current user from database
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
    if (!user) {
      res.status(400).send({ error: "User not found" });
      return;
    }

    // Verify password using bcrypt
    if (!bcrypt.compareSync(password, user.pass)) {
      res.status(400).send({ error: "Invalid password" });
      return;
    }

    // Store user info before deletion for session invalidation
    const userId = req.session.userId;

    // Invalidate all sessions for this user immediately
    if (!global.invalidatedSessions) {
      global.invalidatedSessions = new Set();
    }
    global.invalidatedSessions.add(userId);
    
    // Delete the user from database
    db.prepare("DELETE FROM users WHERE id = ?").run(req.session.userId);
    
    // Destroy the current session
    req.session.destroy((err) => {
      if (err) {
        console.error('Error destroying session:', err);
      }
    });
    
    res.status(200).send({ message: "Account deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: "Failed to delete account" });
  }
});

app.post("/api/login_user", loginLimiter, (req, res) => {
  const { username, email, password } = req.body || {};

  // Require either username or email, and password
  if (!username && !email) {
    res.status(400).send({ error: "Username or email is required" });
    return;
  }
  if (!password) {
    res.status(400).send({ error: "Password is required" });
    return;
  }

  // Find user by username or email
  let user;
  if (username) {
    user = db.prepare("SELECT * FROM users WHERE LOWER(username) = ?").get(username.toLowerCase());
  } else {
    user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  }

  if (!user) {
    res.status(400).send({ error: "User not found" });
    return;
  }

  // Check password using bcrypt
  if (!bcrypt.compareSync(password, user.pass)) {
    res.status(400).send({ error: "Invalid password" });
    return;
  }

  // Regenerate session to prevent session fixation
  req.session.regenerate((err) => {
    if (err) {
      console.error('Error regenerating session:', err);
      res.status(500).send({ error: "Login failed" });
      return;
    }
    
    // Create session - only store userId for security
    req.session.userId = user.id;
    // Note: username and email are no longer stored in session
    // They will be fetched from database when needed

    res.status(200).send({ message: "Login successful" });
  });
});

app.get("/api/check_session", (req, res) => {
  if (req.session.userId) {
    // Check if this session has been invalidated (account deleted)
    if (global.invalidatedSessions && global.invalidatedSessions.has(req.session.userId)) {
      // Clear the invalidated session flag
      global.invalidatedSessions.delete(req.session.userId);
      // Destroy the session immediately
      req.session.destroy((err) => {
        if (err) {
          console.error('Error destroying invalidated session:', err);
        }
      });
      res.status(200).send({ loggedIn: false });
      return;
    }
    
    // Fetch user data from database instead of using session data
    try {
      const user = db.prepare("SELECT id, username, email FROM users WHERE id = ?").get(req.session.userId);
      if (!user) {
        // User not found in database, destroy session
        req.session.destroy((err) => {
          if (err) {
            console.error('Error destroying session for non-existent user:', err);
          }
        });
        res.status(200).send({ loggedIn: false });
        return;
      }
      
      res.status(200).send({ 
        loggedIn: true, 
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        }
      });
    } catch (err) {
      console.error('Error fetching user data for session check:', err);
      res.status(200).send({ loggedIn: false });
    }
  } else {
    res.status(200).send({ loggedIn: false });
  }
});

app.post("/api/logout_user", (req, res) => {
  // Send immediate response for faster feedback
  res.status(200).send({ message: "Logout successful" });
  
  // Destroy the session in background
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session during logout:', err);
    }
  });
});

app.post("/api/change_password", requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};

  // Check for missing fields
  if (!currentPassword) {
    res.status(400).send({ error: "Current password is required" });
    return;
  }
  if (!newPassword) {
    res.status(400).send({ error: "New password is required" });
    return;
  }

  // Validate new password requirements
  if (newPassword.length < 12) {
    res.status(400).send({ error: "New password must be at least 12 characters long" });
    return;
  }
  
  // Check for uppercase letter
  if (!/[A-Z]/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 uppercase letter" });
    return;
  }
  
  // Check for lowercase letter
  if (!/[a-z]/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 lowercase letter" });
    return;
  }
  
  // Check for number
  if (!/\d/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 number" });
    return;
  }
  
  // Check for special character
  if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)" });
    return;
  }

  try {
    // Get current user from database
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
    if (!user) {
      res.status(400).send({ error: "User not found" });
      return;
    }

    // Verify current password
    if (!bcrypt.compareSync(currentPassword, user.pass)) {
      res.status(400).send({ error: "Current password is incorrect" });
      return;
    }

    // Hash the new password
    const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
    
    // Update password in database
    db.prepare("UPDATE users SET pass = ? WHERE id = ?").run(hashedNewPassword, req.session.userId);
    
    res.status(200).send({ message: "Password changed successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: "Failed to change password" });
  }
});

// Password recovery endpoints
app.post("/api/forgot_password", async (req, res) => {
  const { email, captchaAnswer, captchaId } = req.body || {};

  if (!email) {
    res.status(400).send({ error: "Email is required" });
    return;
  }

  if (!validateEmail(email)) {
    res.status(400).send({ error: "Invalid email format" });
    return;
  }

  // Verify CAPTCHA
  if (!captchaAnswer || !captchaId) {
    res.status(400).send({ error: "Please solve the math problem" });
    return;
  }

  const storedAnswer = captchaStore.get(captchaId);
  if (!storedAnswer || storedAnswer !== parseInt(captchaAnswer)) {
    res.status(400).send({ error: "Incorrect answer. Please try again." });
    return;
  }

  // Clean up used CAPTCHA
  captchaStore.delete(captchaId);

  try {
    // Check if user exists
    const user = db.prepare("SELECT id, username FROM users WHERE email = ?").get(email);
    
    if (!user) {
      // Don't reveal if email exists or not (security best practice)
      res.status(200).send({ message: "If an account with that email exists, a password reset link has been sent." });
      return;
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

    // Store reset token in database
    db.prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?").run(
      resetToken, 
      resetExpires.toISOString(), 
      user.id
    );

    // Generate reset link
    const resetLink = `http://localhost:3000/reset-password/${resetToken}`;
    
    // Log reset link to console
    logResetLink(email, resetLink);
    res.status(200).send({ 
      message: "If an account with that email exists, a password reset link has been sent."
    });
  } catch (err) {
    console.error('Error in forgot password:', err);
    res.status(500).send({ error: "Failed to process password reset request" });
  }
});

// Generate CAPTCHA endpoint
app.get("/api/captcha", (req, res) => {
  const captcha = generateMathCaptcha();
  const captchaId = crypto.randomBytes(16).toString('hex');
  
  // Store answer with expiration (5 minutes)
  captchaStore.set(captchaId, captcha.answer);
  setTimeout(() => captchaStore.delete(captchaId), 5 * 60 * 1000);
  
  res.json({
    id: captchaId,
    question: captcha.question
  });
});

app.post("/api/reset_password", (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token) {
    res.status(400).send({ error: "Reset token is required" });
    return;
  }

  if (!newPassword) {
    res.status(400).send({ error: "New password is required" });
    return;
  }

  // Validate new password requirements
  if (newPassword.length < 12) {
    res.status(400).send({ error: "New password must be at least 12 characters long" });
    return;
  }
  
  if (!/[A-Z]/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 uppercase letter" });
    return;
  }
  
  if (!/[a-z]/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 lowercase letter" });
    return;
  }
  
  if (!/\d/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 number" });
    return;
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(newPassword)) {
    res.status(400).send({ error: "New password must contain at least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)" });
    return;
  }

  try {
    // Find user with valid reset token
    const user = db.prepare("SELECT id FROM users WHERE reset_token = ? AND reset_expires > ?").get(
      token, 
      new Date().toISOString()
    );

    if (!user) {
      res.status(400).send({ error: "Invalid or expired reset token" });
      return;
    }

    // Hash the new password
    const hashedPassword = bcrypt.hashSync(newPassword, 12);
    
    // Update password and clear reset token
    db.prepare("UPDATE users SET pass = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?").run(
      hashedPassword, 
      user.id
    );
    
    res.status(200).send({ message: "Password reset successfully" });
  } catch (err) {
    console.error('Error in reset password:', err);
    res.status(500).send({ error: "Failed to reset password" });
  }
});

app.get("/reset-password/:token", (req, res) => {
  const { token } = req.params;

  try {
    // Check if token is valid and not expired
    const user = db.prepare("SELECT id FROM users WHERE reset_token = ? AND reset_expires > ?").get(
      token, 
      new Date().toISOString()
    );

    if (!user) {
      res.render('reset-password', {
        title: 'GoSpoof Reset Password',
        hideNav: true,
        validToken: false,
        error: 'Invalid or expired reset link'
      });
      return;
    }

    res.render('reset-password', {
      title: 'GoSpoof Reset Password',
      hideNav: true,
      validToken: true,
      token: token
    });
  } catch (err) {
    console.error('Error checking reset token:', err);
    res.render('reset-password', {
      title: 'GoSpoof Reset Password',
      hideNav: true,
      validToken: false,
      error: 'Error processing reset link'
    });
  }
});

// Socket.IO
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.emit('welcome', 'You are now connected to GoSpoof Live Feed');
});

app.post('/live-capture', (req, res) => {
  const { ip, payload } = req.body;

  if (ip && payload) {
    io.emit('new_attack', { ip, payload: payload.trim() || 'Probing Scan' });
    res.status(200).send('ok');
  } else {
    res.status(400).send('missing ip or payload');
  }
});

function getLatestLogFilePath() {
  const files = fs.readdirSync(uploadFolder).filter(f => f.endsWith('.log'));
  if (!files.length) return null;

  return path.join(uploadFolder, files.sort((a, b) => {
    return fs.statSync(path.join(uploadFolder, b)).mtime - fs.statSync(path.join(uploadFolder, a)).mtime;
  })[0]);
}

// functions
const validateEmail = (email) => {
  return validator.isEmail(email);
}

function emailInDatabase(email) {
  const data = db.prepare("SELECT email FROM users WHERE email = ?").get(email);
  return data !== undefined;
}


function usernameInDatabase(username) {
  const data = db.prepare("SELECT username FROM users WHERE LOWER(username) = ?").get(username.toLowerCase());
  return data !== undefined;
}

// Simple math CAPTCHA for password reset
function generateMathCaptcha() {
  const num1 = Math.floor(Math.random() * 10) + 1; // 1-10
  const num2 = Math.floor(Math.random() * 10) + 1; // 1-10
  const answer = num1 + num2;
  return { question: `${num1} + ${num2}`, answer: answer };
}

// Log reset link to console (development mode)
function logResetLink(email, resetLink) {
  console.log(`[PASSWORD RESET] Reset link for ${email}: ${resetLink}`);
  console.log('[PASSWORD RESET] In production, this would send an actual email');
}

// Custom error handler for JSON parse errors
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    // Malformed JSON
    return res.status(400).send({ error: "Malformed JSON in request body" });
  }
  // Log all other errors for debugging
  console.error('Unhandled error:', err);
  res.status(500).send({ error: "Internal server error" });
});

// start server
http.listen(PORT)
  .on('listening', () => {
    console.log(`Web UI launched on http://localhost:${PORT}`);
  })
  .on('error', err => {
    if (err.code === 'EADDRINUSE') {
      PORT = PORT + 1;
      console.warn('Port in use. Retrying on http://localhost:${PORT}...');
      http.listen(PORT);
    } else {
      throw err;
    }
  });
