// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

// ------------------------------------------------------------
// GLOBAL SECURITY HARDENING
// ------------------------------------------------------------

// Hide "X-Powered-By: Express"
app.disable("x-powered-by");

// Use Helmet, but DISABLE its CSP so we can define our OWN strict policy
app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

// SUPER STRONG custom CSP required for ZAP "zero alerts"
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self'",
      "connect-src 'self'",
      "font-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'"
    ].join("; ")
  );

  // Disable dangerous APIs
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");

  // Zero caching to satisfy ZAP
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  // Spectre isolation
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  next();
});

// GLOBAL RATE LIMIT (prevents all “Missing rate limiting” findings)
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// ------------------------------------------------------------
// APP SETUP
// ------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

// ------------------------------------------------------------
// PATH TRAVERSAL PROTECTION
// ------------------------------------------------------------
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// Validate filename safely
const filenameValidator = body("filename")
  .exists()
  .withMessage("filename is required")
  .bail()
  .isString()
  .trim()
  .notEmpty()
  .withMessage("filename must not be empty")
  .custom((value) => {
    if (value.includes("\0")) throw new Error("null byte not allowed");
    return true;
  });

// Shared secure file reading
function handleSafeRead(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const filename = req.body.filename;
  const resolved = resolveSafe(BASE_DIR, filename);

  // Ensure path stays inside BASE_DIR
  if (!resolved.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: "Path traversal detected" });
  }

  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ error: "File not found" });
  }

  const content = fs.readFileSync(resolved, "utf8");
  return res.json({ path: resolved, content });
}

// Secure read endpoint
app.post("/read", filenameValidator, handleSafeRead);

// Previously vulnerable endpoint (now secured)
app.post("/read-no-validate", filenameValidator, handleSafeRead);

// Create sample files
app.post("/setup-sample", (req, res) => {
  const samples = {
    "hello.txt": "Hello secure world!\n",
    "notes/readme.md": "# Safe Readme\nSample file content."
  };

  for (const file in samples) {
    const abs = path.resolve(BASE_DIR, file);
    const d = path.dirname(abs);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(abs, samples[file], "utf8");
  }

  res.json({ ok: true, base: BASE_DIR });
});

// ------------------------------------------------------------
// SERVER
// ------------------------------------------------------------
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Secure server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
