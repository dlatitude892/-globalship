// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
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

// ---- Database ----
// Data is persisted in MongoDB Atlas (or any Mongo instance) instead of
// living only in memory, so it survives restarts, redeploys, and Render's
// free-tier spin-downs.
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error(
    '[FATAL] MONGODB_URI is not set. Create a free MongoDB Atlas cluster and set\n' +
    '        MONGODB_URI to its connection string before starting this server.'
  );
  process.exit(1);
}

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('[FATAL] Could not connect to MongoDB:', err.message);
    process.exit(1);
  });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const trackingEventSchema = new mongoose.Schema({
  location: String,
  status: String,
  note: String,
  timestamp: { type: Date, default: Date.now }
}, { _id: false });

const shipmentSchema = new mongoose.Schema({
  trackingId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipientName: String,
  origin: String,
  destination: String,
  items: String,
  value: Number,
  status: { type: String, default: 'pending' },
  currentLocation: String,
  trackingEvents: [trackingEventSchema],
  createdAt: { type: Date, default: Date.now }
});
const Shipment = mongoose.model('Shipment', shipmentSchema);

// Shapes a Mongo document into the plain JSON shape the frontend already expects
const shipmentToJSON = (s) => ({
  id: s._id.toString(),
  trackingId: s.trackingId,
  userId: s.userId.toString(),
  recipientName: s.recipientName,
  origin: s.origin,
  destination: s.destination,
  items: s.items,
  value: s.value,
  status: s.status,
  currentLocation: s.currentLocation,
  trackingEvents: s.trackingEvents,
  createdAt: s.createdAt
});

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

// Adds a checkpoint to a shipment's tracking history and saves it
const addTrackingEvent = async (shipment, { location, status, note }) => {
  if (location) shipment.currentLocation = location;
  if (status) shipment.status = status;
  shipment.trackingEvents.push({
    location: location || shipment.currentLocation,
    status: status || shipment.status,
    note: note || '',
    timestamp: new Date()
  });
  await shipment.save();
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
const generateTrackingId = async () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous 0/O/1/I
  let id, exists;
  do {
    let code = '';
    for (let i = 0; i < 8; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    id = `SHP-${code}`;
    exists = await Shipment.exists({ trackingId: id });
  } while (exists);
  return id;
};

// User Registration
// Note: public registration can only ever create customer accounts.
// Admin access is separate (see POST /admin/login) and gated by ADMIN_PASSWORD.
app.post('/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({ username, email, password: hashedPassword, role: 'user' });
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
      { id: 'admin', email: 'admin@system', role: 'admin' },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      message: 'Admin login successful',
      token,
      user: { id: 'admin', username: 'Admin', email: 'admin@system', role: 'admin' }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// User Login
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id.toString(),
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
app.get('/admin/shipments', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const shipments = await Shipment.find().sort({ createdAt: -1 });
    res.json(shipments.map(shipmentToJSON));
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create shipment — goes straight to "pending", waiting on admin approval (no OTP step)
app.post('/shipments', authenticateToken, async (req, res) => {
  try {
    const { recipientName, origin, destination, items, value } = req.body;

    const trackingId = await generateTrackingId();

    const newShipment = await Shipment.create({
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
      ]
    });

    res.status(201).json({
      message: 'Shipment created successfully. Awaiting admin approval.',
      shipmentId: newShipment._id.toString(),
      trackingId
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Block a shipment
app.put('/admin/shipments/:id/block', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const shipment = await Shipment.findById(req.params.id);

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    await addTrackingEvent(shipment, { status: 'blocked', note: 'Shipment blocked' });
    res.json({ message: 'Shipment blocked successfully', shipment: shipmentToJSON(shipment) });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Approve a shipment — this is now the only way a shipment moves forward
app.put('/admin/shipments/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const shipment = await Shipment.findById(req.params.id);

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    await addTrackingEvent(shipment, { status: 'approved', note: 'Shipment approved for onward delivery' });
    res.json({ message: 'Shipment approved successfully', shipment: shipmentToJSON(shipment) });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Add a live tracking checkpoint (location the shipment has reached en route)
app.post('/admin/shipments/:id/track', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { location, status, note } = req.body;
    const shipment = await Shipment.findById(req.params.id);

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }
    if (!location && !status) {
      return res.status(400).json({ error: 'Provide a location and/or status for the checkpoint' });
    }

    await addTrackingEvent(shipment, { location, status, note });
    res.json({ message: 'Tracking checkpoint added', shipment: shipmentToJSON(shipment) });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's shipments
app.get('/shipments', authenticateToken, async (req, res) => {
  try {
    const userShipments = await Shipment.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(userShipments.map(shipmentToJSON));
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get shipment status by tracking ID (e.g. SHP-XXXXXXXX)
app.get('/shipments/tracking/:trackingId', authenticateToken, async (req, res) => {
  try {
    const shipment = await Shipment.findOne({ trackingId: req.params.trackingId });

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    if (shipment.userId.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(shipmentToJSON(shipment));
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get shipment status
app.get('/shipments/:id', authenticateToken, async (req, res) => {
  try {
    const shipment = await Shipment.findById(req.params.id);

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    if (shipment.userId.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(shipmentToJSON(shipment));
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
