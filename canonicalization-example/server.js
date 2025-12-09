// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

/* -----------------------------------------------------------
 *  GLOBAL SECURITY HARDENING
 * --------------------------------------------------------- */

// Hide "X-Powered-By: Express"
app.disable("x-powered-by");

// Use Helmet with DEFAULT secure settings (so CodeQL is happy)
app.use(helmet());

// Add our own very strict CSP and cache / permissions headers
// (this runs AFTER helmet, so it overrides its CSP)
app.use((req, res, next) => {
  // Strict CSP with explicit frame-ancestors + form-action
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self'",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'"
    ].join("; ")
  );

  // Lock down powerful browser APIs
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");

  // No caching – helps clear a bunch of ZAP cache-related info alerts
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// Global rate limiting (fixes all “Missing rate limiting” findings)
app.use(
  rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 50,             // 50 requests per minute per IP
    standardHeaders: true,
    legacyHeaders: false
  })
);

/* -----------------------------------------------------------
 *  NORMAL APP SETUP
 * --------------------------------------------------------- */

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

/* -----------------------------------------------------------
 *  PATH TRAVERSAL PROTECTION
 * --------------------------------------------------------- */

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // ignore bad encodings, we still validate below
  }
  return path.resolve(baseDir, userInput);
}

const filenameValidator = body("filename")
  .exists()
  .withMessage("filename is required")
  .bail()
  .isString()
  .trim()
  .notEmpty()
  .withMessage("filename must not be empty")
  .custom((value) => {
    if (value.includes("\0")) {
      throw new Error("null byte not allowed");
    }
    return true;
  });

function handleSafeRead(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const filename = req.body.filename;
  const resolved = resolveSafe(BASE_DIR, filename);

  // Make sure the resolved path stays inside BASE_DIR
  if (!resolved.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: "Path traversal detected" });
  }

  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ error: "File not found" });
  }

  const content = fs.readFileSync(resolved, "utf8");
  return res.json({ path: resolved, content });
}

/* -----------------------------------------------------------
 *  ROUTES
 * --------------------------------------------------------- */

// Secure route
app.post("/read", filenameValidator, handleSafeRead);

// Old “no-validate” route, now using the same safe logic
app.post("/read-no-validate", filenameValidator, handleSafeRead);

// Sample files for testing
app.post("/setup-sample", (req, res) => {
  const samples = {
    "hello.txt": "Hello secure world!\n",
    "notes/readme.md": "# Safe Readme\nSample file content."
  };

  for (const fileName of Object.keys(samples)) {
    const abs = path.resolve(BASE_DIR, fileName);
    const dir = path.dirname(abs);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(abs, samples[fileName], "utf8");
  }

  res.json({ ok: true, base: BASE_DIR });
});

/* -----------------------------------------------------------
 *  SERVER
 * --------------------------------------------------------- */

if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Secure server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
