// server/index.js
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer config
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// MongoDB setup
const uri = `mongodb+srv://${process.env.USER_NAME}:${process.env.USER_PASS}@cluster0.pavg3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

let db, users, officialNotices, studentNotices;

async function connectDB() {
  await client.connect();
  db = client.db('digital_notice_board');
  users = db.collection('users');
  officialNotices = db.collection('official_notices');
  studentNotices = db.collection('student_notices');
  console.log('✅ MongoDB connected');
}
connectDB();

// JWT Middleware
function verifyJWT(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: Access denied' });
    }
    next();
  };
}

// Unified Registration
async function registerUser(req, res, role) {
  const { name, email, password, department, studentId } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const existing = await users.findOne({ email });
  if (existing) return res.status(409).json({ error: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  const userData = { name, email, password: hashed, role, createdAt: new Date() };

  if (role === 'student') {
    if (!studentId || !department) return res.status(400).json({ error: 'Student ID and Department required' });
    userData.studentId = studentId;
    userData.department = department;
  }
  if (role === 'teacher') {
    if (!department) return res.status(400).json({ error: 'Department required' });
    userData.department = department;
  }

  const result = await users.insertOne(userData);
  res.status(201).json({ message: `${role} registered`, id: result.insertedId });
}

// Unified Login
async function loginUser(req, res, role) {
  const { email, password } = req.body;
  const user = await users.findOne({ email, role });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(403).json({ error: 'Wrong password' });

  const token = jwt.sign({ email, role, id: user._id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, role: user.role, name: user.name });
}

// Register Routes
app.post('/api/register/student', (req, res) => registerUser(req, res, 'student'));
app.post('/api/register/teacher', (req, res) => registerUser(req, res, 'teacher'));
app.post('/api/register/admin', (req, res) => registerUser(req, res, 'admin'));

// Login Routes
app.post('/api/login/student', (req, res) => loginUser(req, res, 'student'));
app.post('/api/login/teacher', (req, res) => loginUser(req, res, 'teacher'));
app.post('/api/login/admin', (req, res) => loginUser(req, res, 'admin'));

// ===== Official Notices (Admin Only) =====
app.post('/api/official-notices', verifyJWT, authorizeRoles('admin'), upload.single('file'), async (req, res) => {
  const { notice } = req.body;
  const file = req.file;
  if (!notice) return res.status(400).json({ error: 'Notice is required' });

  const data = {
    content: notice,
    date: new Date(),
    ...(file && {
      file: {
        url: `/uploads/${file.filename}`,
        name: file.originalname,
        type: file.mimetype
      }
    })
  };

  const result = await officialNotices.insertOne(data);
  res.status(201).json({ message: 'Notice saved', id: result.insertedId });
});

app.get('/api/official-notices', async (req, res) => {
  const data = await officialNotices.find().sort({ date: -1 }).toArray();
  res.json(data);
});

// ===== UPDATE Official Notice =====
app.put('/api/official-notices/:id', verifyJWT, authorizeRoles('admin'), upload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { notice } = req.body;
  const file = req.file;

  if (!notice) return res.status(400).json({ error: 'Notice is required' });

  const updateData = {
    content: notice,
    date: new Date(),
  };

  if (file) {
    updateData.file = {
      url: `/uploads/${file.filename}`,
      name: file.originalname,
      type: file.mimetype,
    };
  }

  try {
    const result = await officialNotices.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Notice not found' });
    }

    res.json({ message: 'Notice updated successfully' });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Failed to update notice' });
  }
});

// ===== DELETE Official Notice =====
app.delete('/api/official-notices/:id', verifyJWT, authorizeRoles('admin'), async (req, res) => {
  const { id } = req.params;

  try {
    const result = await officialNotices.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Notice not found' });
    }

    res.json({ message: 'Notice deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete notice' });
  }
});


// ===== Student Notices (Admin/Teacher Only) =====
app.post('/api/student-notices', verifyJWT, authorizeRoles('admin'), upload.single('file'), async (req, res) => {
  const { notice } = req.body;
  const file = req.file;
  if (!notice) return res.status(400).json({ error: 'Notice is required' });

  const data = {
    content: notice,
    date: new Date(),
    ...(file && {
      file: {
        url: `/uploads/${file.filename}`,
        name: file.originalname,
        type: file.mimetype
      }
    })
  };

  const result = await studentNotices.insertOne(data);
  res.status(201).json({ message: 'Notice saved', id: result.insertedId });
});

app.get('/api/student-notices', async (req, res) => {
  const data = await studentNotices.find().sort({ date: -1 }).toArray();
  res.json(data);
});

// Update a student notice
app.put('/api/student-notices/:id', verifyJWT, authorizeRoles('admin'), async (req, res) => {
  const { id } = req.params;
  const { notice } = req.body;
  if (!notice) return res.status(400).json({ error: 'Notice content required' });

  const result = await studentNotices.updateOne({ _id: new ObjectId(id) }, { $set: { content: notice } });
  res.json({ message: 'Notice updated' });
});

// Delete a student notice
app.delete('/api/student-notices/:id', verifyJWT, authorizeRoles('admin'), async (req, res) => {
  const { id } = req.params;
  await studentNotices.deleteOne({ _id: new ObjectId(id) });
  res.json({ message: 'Notice deleted' });
});



// ===== Dashboard Counts (Admin Panel) =====
app.get('/api/admin/stats', verifyJWT, authorizeRoles('admin'), async (req, res) => {
  try {
    const totalStudents = await users.countDocuments({ role: 'student' });
    const totalNotices = await officialNotices.countDocuments();

    // If you later add approval system with status: 'pending', update this query
    const pendingApprovals = 7;

    res.json({
      totalStudents,
      totalNotices,
      pendingApprovals,
    });
  } catch (err) {
    console.error('Failed to fetch admin stats:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// ===== Root =====
app.get('/', (req, res) => {
  res.send('🎉 All-in-One API is Running!');
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`🚀 Server listening at http://localhost:${PORT}`);
});
