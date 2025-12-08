// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// ------------------------------------------------------------
// Global security hardening
// ------------------------------------------------------------

// Hide framework info
app.disable('x-powered-by');

// Basic security headers (X-Frame-Options, X-Content-Type-Options, etc.)
app.use(helmet());

// Very strict CSP + permissions policy + no caching
app.use((req, res, next) => {
  // Only allow this origin to load resources
  res.setHeader('Content-Security-Policy', "default-src 'self'");

  // Disable powerful browser features
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=()');

  // Prevent caching of responses
  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  next();
});

// Rate limiting: max 100 req / minute / IP
const limiter = rateLimit({
  windowMs: 60 * 1000,    // 1 minute
  max: 100,               // 100 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// ------------------------------------------------------------
// Normal app setup
// ------------------------------------------------------------
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

// Helper to canonicalize and resolve a path safely
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // ignore bad encodings, we’ll still validate below
  }
  return path.resolve(baseDir, userInput);
}

// Common validator for filenames
const filenameValidator = body('filename')
  .exists().withMessage('filename required')
  .bail()
  .isString()
  .trim()
  .notEmpty().withMessage('filename must not be empty')
  .custom((value) => {
    if (value.includes('\0')) {
      throw new Error('null byte not allowed');
    }
    return true;
  });

// Helper to handle a safe read once validation has passed
function handleSafeRead(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const filename = req.body.filename;
  const normalized = resolveSafe(BASE_DIR, filename);

  // Ensure the resolved path stays within BASE_DIR (no ../ traversal)
  if (!normalized.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Path traversal detected' });
  }

  if (!fs.existsSync(normalized)) {
    return res.status(404).json({ error: 'File not found' });
  }

  const content = fs.readFileSync(normalized, 'utf8');
  return res.json({ path: normalized, content });
}

// Secure route
app.post('/read', filenameValidator, (req, res) => {
  return handleSafeRead(req, res);
});

// Previously vulnerable route (now secured via same logic)
app.post('/read-no-validate', filenameValidator, (req, res) => {
  return handleSafeRead(req, res);
});

// Helper route to create some test files
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };

  Object.keys(samples).forEach((k) => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });

  res.json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly (not when imported by tests)
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
