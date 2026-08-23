// server.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();

// ---- Security-critical config (set these as real environment variables in production) ----
if (!process.env.JWT_SECRET || !process.env.ADMIN_PASSWORD) {
  console.warn(
    '[WARNING] JWT_SECRET and/or ADMIN_PASSWORD are not set as environment variables.\n' +
    '          Falling back to insecure development defaults. Set real values before deploying.'
  );
}
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret-change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe-Admin-2026';

// Restrict which origins can call this API. Set ALLOWED_ORIGIN to your deployed
// Netlify URL (e.g. https://your-site.netlify.app) once deployed. Defaults to
// allowing any origin, which is fine for local development only.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

app.use(helmet());
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN }));

// Slow down brute-force attempts against login/admin-login/register
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' }
});

// In-memory storage — resets on every restart/deploy.
// Fine for a demo; use a real database (Postgres, Mongo, etc.) before relying on this.
let users = [];
let shipments = [];

// Adds a checkpoint to a shipment's tracking history
const addTrackingEvent = (shipment, { location, status, note }) => {
  if (location) shipment.currentLocation = location;
  if (status) shipment.status = status;
  shipment.trackingEvents.push({
    location: location || shipment.currentLocation,
    status: status || shipment.status,
    note: note || '',
    timestamp: new Date()
  });
};

// Middleware for authentication
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

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Generate a unique, random (non-guessable) tracking ID, e.g. SHP-7K2QXH9B
const generateTrackingId = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous 0/O/1/I
  let id;
  do {
    let code = '';
    for (let i = 0; i < 8; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    id = `SHP-${code}`;
  } while (shipments.some(s => s.trackingId === id));
  return id;
};

// User Registration
// Note: public registration can only ever create customer accounts.
// Admin access is separate (see POST /admin/login) and gated by ADMIN_PASSWORD.
app.post('/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword,
      role: 'user',
      createdAt: new Date()
    };

    users.push(newUser);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin Login — separate from customer login, gated by a standalone password
// (not a user account, not created through /register).
app.post('/admin/login', authLimiter, (req, res) => {
  try {
    const { password } = req.body;

    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }

    const token = jwt.sign(
      { id: 0, email: 'admin@system', role: 'admin' },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      message: 'Admin login successful',
      token,
      user: { id: 0, username: 'Admin', email: 'admin@system', role: 'admin' }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// User Login
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all shipments (for admin)
app.get('/admin/shipments', authenticateToken, requireAdmin, (req, res) => {
  try {
    res.json(shipments);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create shipment — goes straight to "pending", waiting on admin approval (no OTP step)
app.post('/shipments', authenticateToken, async (req, res) => {
  try {
    const { recipientName, origin, destination, items, value } = req.body;

    const trackingId = generateTrackingId();

    const newShipment = {
      id: shipments.length + 1,
      trackingId,
      userId: req.user.id,
      recipientName,
      origin,
      destination,
      items,
      value,
      status: 'pending',
      currentLocation: origin,
      trackingEvents: [
        { location: origin, status: 'pending', note: 'Shipment created, awaiting admin approval', timestamp: new Date() }
      ],
      createdAt: new Date()
    };

    shipments.push(newShipment);

    res.status(201).json({
      message: 'Shipment created successfully. Awaiting admin approval.',
      shipmentId: newShipment.id,
      trackingId
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Block a shipment
app.put('/admin/shipments/:id/block', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const shipment = shipments.find(s => s.id === parseInt(id));

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    addTrackingEvent(shipment, { status: 'blocked', note: 'Shipment blocked' });
    res.json({ message: 'Shipment blocked successfully', shipment });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Approve a shipment — this is now the only way a shipment moves forward
app.put('/admin/shipments/:id/approve', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const shipment = shipments.find(s => s.id === parseInt(id));

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    addTrackingEvent(shipment, { status: 'approved', note: 'Shipment approved for onward delivery' });
    res.json({ message: 'Shipment approved successfully', shipment });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Add a live tracking checkpoint (location the shipment has reached en route)
app.post('/admin/shipments/:id/track', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { location, status, note } = req.body;
    const shipment = shipments.find(s => s.id === parseInt(id));

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }
    if (!location && !status) {
      return res.status(400).json({ error: 'Provide a location and/or status for the checkpoint' });
    }

    addTrackingEvent(shipment, { location, status, note });
    res.json({ message: 'Tracking checkpoint added', shipment });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's shipments
app.get('/shipments', authenticateToken, (req, res) => {
  try {
    const userShipments = shipments.filter(s => s.userId === req.user.id);
    res.json(userShipments);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get shipment status by tracking ID (e.g. SHP-XXXXXXXX)
app.get('/shipments/tracking/:trackingId', authenticateToken, (req, res) => {
  try {
    const { trackingId } = req.params;
    const shipment = shipments.find(s => s.trackingId === trackingId);

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    if (shipment.userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(shipment);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get shipment status
app.get('/shipments/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const shipment = shipments.find(s => s.id === parseInt(id));

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    if (shipment.userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(shipment);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Simple health check — useful for uptime checks on your hosting platform
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
