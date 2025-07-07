const express = require('express');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3000;

let server;
if (process.env.RENDER || process.env.NODE_ENV === 'production') {
  // On Render or in production, use HTTP (Render provides HTTPS automatically)
  server = app.listen(PORT, () => {
    console.log(`Secure Chat Server running on http://localhost:${PORT} (Render will provide HTTPS)`);
  });
} else {
  // For local development, use HTTPS with self-signed certs
  const https = require('https');
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
  };
  server = https.createServer(options, app).listen(PORT, () => {
    console.log(`Secure Chat Server running on https://localhost:${PORT}`);
  });
}

const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// File path for user storage
const USERS_FILE = path.join(__dirname, 'users.json');

// Load users from file or create empty Map
function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = fs.readFileSync(USERS_FILE, 'utf8');
      const usersData = JSON.parse(data);
      const users = new Map();
      
      // Convert back to Map and restore Date objects
      for (const [username, userData] of Object.entries(usersData)) {
        users.set(username, {
          ...userData,
          createdAt: new Date(userData.createdAt)
        });
      }
      
      console.log(`Loaded ${users.size} users from file`);
      return users;
    }
  } catch (error) {
    console.error('Error loading users:', error);
  }
  
  console.log('No users file found, starting with empty user list');
  return new Map();
}

// Save users to file
function saveUsers(users) {
  try {
    const usersData = {};
    for (const [username, userData] of users.entries()) {
      usersData[username] = {
        ...userData,
        createdAt: userData.createdAt.toISOString()
      };
    }
    
    fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2));
    console.log(`Saved ${users.size} users to file`);
  } catch (error) {
    console.error('Error saving users:', error);
  }
}

// In-memory storage (in production, use a proper database)
const users = loadUsers();
const activeUsers = new Map();

// JWT secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// User registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (users.has(username)) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Store user
    users.set(username, {
      username,
      password: hashedPassword,
      createdAt: new Date()
    });

    console.log(`User registered: ${username}`);
    console.log(`Total users in memory: ${users.size}`);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    console.log(`Login attempt for user: ${username}`);
    console.log(`Total users in memory: ${users.size}`);
    console.log(`Available users:`, Array.from(users.keys()));

    const user = users.get(username);
    if (!user) {
      console.log(`User not found: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      console.log(`Invalid password for user: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log(`Login successful for user: ${username}`);

    // Generate JWT token
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ token, username: user.username });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get online users endpoint
app.get('/api/users', authenticateToken, (req, res) => {
  const onlineUsers = Array.from(activeUsers.keys());
  res.json({ users: onlineUsers });
});

// Debug endpoint to check users (remove in production)
app.get('/api/debug/users', (req, res) => {
  res.json({ 
    totalUsers: users.size, 
    users: Array.from(users.keys()) 
  });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Handle user authentication
  socket.on('authenticate', (data) => {
    try {
      const decoded = jwt.verify(data.token, JWT_SECRET);
      socket.username = decoded.username;
      activeUsers.set(decoded.username, socket.id);
      
      // Notify all users about new user
      io.emit('userJoined', { username: decoded.username });
      io.emit('userList', Array.from(activeUsers.keys()));
      
      console.log(`User ${decoded.username} authenticated`);
      socket.emit('authenticated');
    } catch (error) {
      socket.emit('authError', { error: 'Invalid token' });
    }
  });

  // Handle encrypted message
  socket.on('sendMessage', (data) => {
    if (!socket.username) {
      socket.emit('error', { error: 'Not authenticated' });
      return;
    }
    // Deliver encrypted message only to the specified recipient
    const targetSocketId = activeUsers.get(data.to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('newMessage', {
        from: socket.username,
        message: data.encryptedMessage,
        timestamp: new Date().toISOString(),
        isPrivate: false
      });
    }
  });

  // Handle private message
  socket.on('sendPrivateMessage', (data) => {
    if (!socket.username) {
      socket.emit('error', { error: 'Not authenticated' });
      return;
    }

    const targetSocketId = activeUsers.get(data.to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('privateMessage', {
        from: socket.username,
        message: data.encryptedMessage,
        timestamp: new Date().toISOString()
      });
      socket.emit('privateMessage', {
        from: socket.username,
        to: data.to,
        message: data.encryptedMessage,
        timestamp: new Date().toISOString()
      });
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    if (socket.username) {
      activeUsers.delete(socket.username);
      io.emit('userLeft', { username: socket.username });
      io.emit('userList', Array.from(activeUsers.keys()));
      console.log(`User ${socket.username} disconnected`);
    }
  });

  // Relay DH public key to a specific user
  socket.on('sendDHPublicKey', (data) => {
    // data: { to: username, publicKey: string }
    console.log(`[DEBUG] Server received DH public key from ${socket.username} for ${data.to}`);
    const targetSocketId = activeUsers.get(data.to);
    if (targetSocketId) {
      console.log(`[DEBUG] Server relaying DH public key from ${socket.username} to ${data.to}`);
      io.to(targetSocketId).emit('receiveDHPublicKey', {
        from: socket.username,
        publicKey: data.publicKey
      });
    } else {
      console.log(`[DEBUG] Server could not find socket for ${data.to}`);
    }
  });
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
}); 