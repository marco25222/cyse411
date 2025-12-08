// server.js 
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// ---------------------------------------------------------------------
// Global security hardening
// ---------------------------------------------------------------------

// Hide X-Powered-By header
app.disable('x-powered-by');

// Helmet sets a bunch of standard security headers
app.use(
  helmet({
    // We keep COEP disabled so we don’t break local dev
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'"],
        "connect-src": ["'self'"],
        "object-src": ["'none'"]
      }
    }
  })
);


app.use((req, res, next) => {
  // Clickjacking protection
  res.setHeader('X-Frame-Options', 'DENY');
  // MIME-sniffing protection
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Example minimal Permissions-Policy
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');

  // Tight caching to avoid “storable/cacheable content” infos
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  next();
});

// Basic rate limiting – apply to all routes
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,            // per IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Base directory for files
const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });



function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
  }
  return path.resolve(baseDir, userInput);
}

// Validator for filenames – very strict on characters to keep ZAP happy
const filenameValidator = body('filename')
  .exists().withMessage('filename required')
  .bail()
  .isString()
  .trim()
  .notEmpty().withMessage('filename must not be empty')
  .custom(value => {
    // Disallow null bytes and characters often used in injection/payloads
    if (value.includes('\0')) throw new Error('null byte not allowed');
    if (/['";=]/.test(value)) throw new Error('invalid characters in filename');
    if (value.includes('..')) throw new Error('path traversal not allowed');
    return true;
  });

function handleSafeRead(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const filename = req.body.filename;
  const normalized = resolveSafe(BASE_DIR, filename);

  // Ensure the path stays inside BASE_DIR
  if (!normalized.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Path traversal detected' });
  }

  if (!fs.existsSync(normalized)) {
    return res.status(404).json({ error: 'File not found' });
  }

  const content = fs.readFileSync(normalized, 'utf8');
  return res.json({ path: normalized, content });
}

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

// Secure route
app.post('/read', filenameValidator, (req, res) => {
  return handleSafeRead(req, res);
});

// Legacy route – kept but now uses same safe logic
app.post('/read-no-validate', filenameValidator, (req, res) => {
  return handleSafeRead(req, res);
});

// Helper route to create sample files
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };

  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });

  res.json({ ok: true, base: BASE_DIR });
});

// ---------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Canonicalization example listening on http://localhost:${port}`);
  });
}

module.exports = app;

