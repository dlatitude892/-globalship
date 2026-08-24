// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
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

// Used to build links inside emails (e.g. back to the tracking page)
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:8080';

// ---- Database ----
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

// ---- Email (SMTP — works with any custom-domain webmail: cPanel, Zoho, etc.) ----
// All of SMTP_HOST/PORT/USER/PASS must be set for email to actually send.
// If they're missing, the app still runs fine — emails are just skipped with a
// warning logged, so this never blocks registration or shipment creation.
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true'; // true for port 465, false for 587/STARTTLS
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER; // e.g. "GlobalShip <info@yourdomain.com>"
const ADMIN_EMAIL = process.env.ADMIN_EMAIL; // where new-signup notification emails go

let transporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
} else {
  console.warn('[WARNING] SMTP_HOST/SMTP_USER/SMTP_PASS not fully set — emails will be skipped.');
}

// Best-effort email send — never throws, never blocks the calling request.
const sendMail = async ({ to, subject, html }) => {
  if (!transporter) return;
  try {
    await transporter.sendMail({ from: SMTP_FROM, to, subject, html });
  } catch (err) {
    console.error(`[EMAIL] Failed to send "${subject}" to ${to}:`, err.message);
  }
};

const emailWrapper = (title, bodyHtml) => `
  <div style="font-family:Arial,sans-serif;background:#0a0c10;padding:32px;color:#f2f0ea;">
    <div style="max-width:520px;margin:0 auto;background:#14171d;border:1px solid #262b34;border-radius:12px;padding:28px;">
      <h2 style="color:#d4a017;margin-top:0;">${title}</h2>
      ${bodyHtml}
      <p style="color:#8791a0;font-size:12px;margin-top:28px;">GlobalShip &middot; APM Terminals Port Elizabeth, NJ</p>
    </div>
  </div>
`;

// ---- Geocoding (free, no API key — OpenStreetMap's Nominatim) ----
// Converts a location string like "New York, US" into {lat, lng} so the
// frontend can plot it on a live map. Nominatim's usage policy asks for a
// descriptive User-Agent and no more than ~1 request/sec — fine for this
// app's scale (geocoding only happens when a shipment is created or a
// checkpoint is added, not on every page view). For heavier traffic, swap
// this for a paid geocoding provider.
const NOMINATIM_UA = `GlobalShipTracker/1.0 (${ADMIN_EMAIL || 'no-contact-set@example.com'})`;
const geocode = async (query) => {
  if (!query) return null;
  try {
    const res = await fetch(
      `https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${encodeURIComponent(query)}`,
      { headers: { 'User-Agent': NOMINATIM_UA } }
    );
    const data = await res.json();
    if (data && data[0]) {
      return { lat: parseFloat(data[0].lat), lng: parseFloat(data[0].lon) };
    }
  } catch (err) {
    console.error('[GEOCODE] Failed for', query, '-', err.message);
  }
  return null;
};

// ---- Models ----
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
  lat: Number,
  lng: Number,
  timestamp: { type: Date, default: Date.now }
}, { _id: false });

const coordsSchema = new mongoose.Schema({ lat: Number, lng: Number }, { _id: false });

const shipmentSchema = new mongoose.Schema({
  trackingId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipientName: String,
  senderName: String,
  senderEmail: String,
  origin: String,
  destination: String,
  items: String,
  value: Number,
  weight: Number, // kg
  estimatedTransitDays: Number,
  estimatedDeliveryDate: Date,
  status: { type: String, default: 'pending' },
  currentLocation: String,
  originCoords: coordsSchema,
  destinationCoords: coordsSchema,
  currentCoords: coordsSchema,
  trackingEvents: [trackingEventSchema],
  createdAt: { type: Date, default: Date.now }
});
const Shipment = mongoose.model('Shipment', shipmentSchema);

// Notifications shown on the admin dashboard (e.g. "new customer registered")
const notificationSchema = new mongoose.Schema({
  type: { type: String, required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', notificationSchema);

// Shapes a Mongo document into the plain JSON shape the frontend already expects
const shipmentToJSON = (s) => ({
  id: s._id.toString(),
  trackingId: s.trackingId,
  userId: s.userId.toString(),
  recipientName: s.recipientName,
  senderName: s.senderName,
  senderEmail: s.senderEmail,
  origin: s.origin,
  destination: s.destination,
  items: s.items,
  value: s.value,
  weight: s.weight,
  estimatedTransitDays: s.estimatedTransitDays,
  estimatedDeliveryDate: s.estimatedDeliveryDate,
  status: s.status,
  currentLocation: s.currentLocation,
  originCoords: s.originCoords,
  destinationCoords: s.destinationCoords,
  currentCoords: s.currentCoords,
  trackingEvents: s.trackingEvents,
  createdAt: s.createdAt
});

const notificationToJSON = (n) => ({
  id: n._id.toString(),
  type: n.type,
  message: n.message,
  read: n.read,
  createdAt: n.createdAt
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
  let coords = null;
  if (location) {
    shipment.currentLocation = location;
    coords = await geocode(location);
    if (coords) shipment.currentCoords = coords;
  }
  if (status) shipment.status = status;
  shipment.trackingEvents.push({
    location: location || shipment.currentLocation,
    status: status || shipment.status,
    note: note || '',
    lat: coords ? coords.lat : (shipment.currentCoords ? shipment.currentCoords.lat : undefined),
    lng: coords ? coords.lng : (shipment.currentCoords ? shipment.currentCoords.lng : undefined),
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

    // Notify admin (dashboard notification + email) and welcome the new user.
    // Both are best-effort — neither blocks or fails the registration itself.
    await Notification.create({
      type: 'new_user',
      message: `New customer registered: ${username} (${email})`
    });

    if (ADMIN_EMAIL) {
      sendMail({
        to: ADMIN_EMAIL,
        subject: 'New customer registered on GlobalShip',
        html: emailWrapper('New Customer', `
          <p><strong>${username}</strong> just created an account.</p>
          <p style="color:#8791a0;">${email}</p>
        `)
      });
    }

    sendMail({
      to: email,
      subject: 'Welcome to GlobalShip',
      html: emailWrapper('Welcome, ' + username, `
        <p>Your account has been created. You can now sign in and create shipments.</p>
      `)
    });

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

// Admin: notifications (new signups, etc.)
app.get('/admin/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const notifications = await Notification.find().sort({ createdAt: -1 }).limit(50);
    res.json(notifications.map(notificationToJSON));
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/admin/notifications/mark-read', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Notification.updateMany({ read: false }, { $set: { read: true } });
    res.json({ message: 'Notifications marked as read' });
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

// Create shipment — goes straight to "pending", waiting on admin approval
app.post('/shipments', authenticateToken, async (req, res) => {
  try {
    const {
      recipientName, senderName, senderEmail, origin, destination,
      items, value, weight, estimatedTransitDays
    } = req.body;

    const trackingId = await generateTrackingId();

    // Best-effort geocoding — a shipment can still be created even if lookup fails
    const [originCoords, destinationCoords] = await Promise.all([
      geocode(origin),
      geocode(destination)
    ]);

    const days = estimatedTransitDays ? parseInt(estimatedTransitDays, 10) : null;
    const estimatedDeliveryDate = days
      ? new Date(Date.now() + days * 24 * 60 * 60 * 1000)
      : null;

    const newShipment = await Shipment.create({
      trackingId,
      userId: req.user.id,
      recipientName,
      senderName,
      senderEmail,
      origin,
      destination,
      items,
      value,
      weight,
      estimatedTransitDays: days,
      estimatedDeliveryDate,
      status: 'pending',
      currentLocation: origin,
      originCoords,
      destinationCoords,
      currentCoords: originCoords,
      trackingEvents: [
        {
          location: origin, status: 'pending',
          note: 'Shipment created, awaiting admin approval',
          lat: originCoords ? originCoords.lat : undefined,
          lng: originCoords ? originCoords.lng : undefined,
          timestamp: new Date()
        }
      ]
    });

    sendMail({
      to: req.user.email,
      subject: `Shipment created — ${trackingId}`,
      html: emailWrapper('Shipment Created', `
        <p>Your shipment from <strong>${origin}</strong> to <strong>${destination}</strong> has been created and is awaiting approval.</p>
        <p style="font-family:monospace;background:#1b1f27;padding:10px 14px;border-radius:6px;display:inline-block;">${trackingId}</p>
        ${estimatedDeliveryDate ? `<p>Estimated delivery: ${estimatedDeliveryDate.toDateString()} (${days} day${days === 1 ? '' : 's'})</p>` : ''}
        <p>Track it anytime: <a href="${FRONTEND_URL}/?track=${trackingId}" style="color:#4f8cff;">${FRONTEND_URL}/?track=${trackingId}</a></p>
      `)
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

// Sends a status-update email to the shipment's owner — best-effort, never throws
const notifyShipmentOwner = async (shipment, subjectStatus) => {
  try {
    const owner = await User.findById(shipment.userId);
    if (!owner) return;
    sendMail({
      to: owner.email,
      subject: `Shipment update — ${shipment.trackingId} is now ${subjectStatus}`,
      html: emailWrapper('Shipment Update', `
        <p>Your shipment <strong>${shipment.trackingId}</strong> is now <strong>${subjectStatus.replace(/_/g, ' ')}</strong>.</p>
        <p>Current location: ${shipment.currentLocation}</p>
        <p>Track it anytime: <a href="${FRONTEND_URL}/?track=${shipment.trackingId}" style="color:#4f8cff;">${FRONTEND_URL}/?track=${shipment.trackingId}</a></p>
      `)
    });
  } catch (err) {
    console.error('[EMAIL] Could not notify shipment owner:', err.message);
  }
};

// Admin: Block a shipment
app.put('/admin/shipments/:id/block', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const shipment = await Shipment.findById(req.params.id);

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    await addTrackingEvent(shipment, { status: 'blocked', note: 'Shipment blocked' });
    notifyShipmentOwner(shipment, 'blocked');
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
    notifyShipmentOwner(shipment, 'approved');
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
    if (status) notifyShipmentOwner(shipment, status);
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

// Public tracking lookup by tracking ID (e.g. SHP-XXXXXXXX) — no login required,
// same as any real carrier's tracking page. Only exposes shipment/route info,
// never account credentials.
app.get('/shipments/tracking/:trackingId', async (req, res) => {
  try {
    const shipment = await Shipment.findOne({ trackingId: req.params.trackingId });

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }

    res.json(shipmentToJSON(shipment));
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Public tracking lookup by raw shipment ID — no login required
app.get('/shipments/:id', async (req, res) => {
  try {
    const shipment = await Shipment.findById(req.params.id);

    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
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
