// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');   // <-- NEW

const app = express();

// --- RATE LIMITING: max 100 requests per minute per IP ---
const limiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 100,              // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);        // <-- apply to all routes

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// helper to canonicalize and check
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// common validator for filenames
const filenameValidator = body('filename')
  .exists().withMessage('filename required')
  .bail()
  .isString()
  .trim()
  .notEmpty().withMessage('filename must not be empty')
  .custom(value => {
    if (value.includes('\0')) throw new Error('null byte not allowed');
    return true;
  });

// helper to handle validated file read
function handleSafeRead(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const filename = req.body.filename;
  const normalized = resolveSafe(BASE_DIR, filename);

  // make sure the resolved path stays under BASE_DIR
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

// Previously vulnerable route (now secured)
// Kept for backwards compatibility, but it now uses the same safe logic.
app.post('/read-no-validate', filenameValidator, (req, res) => {
  return handleSafeRead(req, res);
});

// Helper route for samples
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

// Only listen when run directly (not when imported by tests)
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
