import express from 'express';
import multer from 'multer';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import admin from 'firebase-admin';
import crypto from 'crypto';

// ============================================
// ENV SETUP
// ============================================
dotenv.config();

const PORT = process.env.PORT || 4000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const {
  FIREBASE_PROJECT_ID,
  FIREBASE_PRIVATE_KEY,
  FIREBASE_CLIENT_EMAIL,
  R2_ACCOUNT_ID,
  R2_ACCESS_KEY_ID,
  R2_SECRET_ACCESS_KEY,
  R2_BUCKET_NAME = 'localme',
  R2_PUBLIC_BASE_URL,
  CORS_ORIGIN = '*',
} = process.env;

// Hard fail on critical misconfig
if (!R2_PUBLIC_BASE_URL || !R2_PUBLIC_BASE_URL.includes('workers.dev')) {
  console.error('❌ R2_PUBLIC_BASE_URL must be a Cloudflare Worker URL (*.workers.dev)');
  process.exit(1);
}

// ============================================
// APP INIT
// ============================================
const app = express();

// ============================================
// SECURITY & CORE MIDDLEWARE
// ============================================
app.use(helmet());

app.use(
  morgan(NODE_ENV === 'production' ? 'combined' : 'dev')
);

app.use(
  cors({
    origin: CORS_ORIGIN === '*' ? '*' : CORS_ORIGIN.split(','),
    credentials: true,
  })
);

app.use(express.json());

// ============================================
// RATE LIMITING (UPLOADS ONLY)
// ============================================
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/upload', uploadLimiter);

// ============================================
// MULTER (IN-MEMORY, 10MB LIMIT)
// ============================================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// ============================================
// FIREBASE ADMIN INIT
// ============================================
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: FIREBASE_PROJECT_ID,
    privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    clientEmail: FIREBASE_CLIENT_EMAIL,
  }),
});

console.log('✅ Firebase Admin initialized');

// ============================================
// R2 CLIENT
// ============================================
const r2Client = new S3Client({
  region: 'auto',
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
});

// ============================================
// AUTH MIDDLEWARE
// ============================================
async function verifyFirebaseToken(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = auth.split('Bearer ')[1];
    const decoded = await admin.auth().verifyIdToken(token);

    req.user = { uid: decoded.uid, email: decoded.email };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ============================================
// HELPERS
// ============================================
function getExtension(mime) {
  const map = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'image/gif': 'gif',
    'video/mp4': 'mp4',
    'video/webm': 'webm',
    'video/quicktime': 'mov',
  };
  return map[mime] || null;
}

function validateType(mime, type) {
  return type === 'image'
    ? mime.startsWith('image/')
    : mime.startsWith('video/');
}

async function uploadToR2(file, key) {
  const command = new PutObjectCommand({
    Bucket: R2_BUCKET_NAME,
    Key: key,
    Body: file.buffer,
    ContentType: file.mimetype,
    ContentLength: file.size,
    CacheControl: 'public, max-age=31536000, immutable',
  });

  await r2Client.send(command);
  return key;
}

// ============================================
// ROUTES
// ============================================

// Health
app.get('/health', (_, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Upload profile image
app.post(
  '/api/upload/profile',
  verifyFirebaseToken,
  upload.single('file'),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    if (!validateType(req.file.mimetype, 'image')) {
      return res.status(400).json({ error: 'Only images allowed' });
    }

    const ext = getExtension(req.file.mimetype);
    if (!ext) {
      return res.status(400).json({ error: 'Unsupported image format' });
    }

    const key = `profile-images/${req.user.uid}/${crypto.randomUUID()}.${ext}`;
    await uploadToR2(req.file, key);

    res.json({
      key,
      url: `${R2_PUBLIC_BASE_URL}/${key}`,
    });
  }
);

// Upload post media
app.post(
  '/api/upload/post',
  verifyFirebaseToken,
  upload.single('file'),
  async (req, res) => {
    const { mediaType, postId = 'uncategorized' } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    if (!['image', 'video'].includes(mediaType)) {
      return res.status(400).json({ error: 'Invalid mediaType' });
    }

    if (!validateType(req.file.mimetype, mediaType)) {
      return res.status(400).json({ error: 'File type mismatch' });
    }

    const ext = getExtension(req.file.mimetype);
    if (!ext) {
      return res.status(400).json({ error: 'Unsupported media format' });
    }

    const folder = mediaType === 'video' ? 'videos' : 'images';
    const key = `posts/${req.user.uid}/${postId}/${folder}/${crypto.randomUUID()}.${ext}`;

    await uploadToR2(req.file, key);

    res.json({
      key,
      url: `${R2_PUBLIC_BASE_URL}/${key}`,
    });
  }
);

// 404
app.use((_, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error
app.use((err, req, res, next) => {
  console.error('🔥 Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    requestId: crypto.randomUUID(),
  });
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Media base: ${R2_PUBLIC_BASE_URL}`);
});
