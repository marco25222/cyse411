// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

// ------------------------------------------------------------
// GLOBAL SECURITY HEADERS (APPLY TO ALL ROUTES + STATIC FILES)
// ------------------------------------------------------------
app.disable("x-powered-by");

// Single secure Helmet config
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        "default-src": ["'none'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'"],
        "connect-src": ["'self'"],
        "font-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"]
      }
    },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginEmbedderPolicy: { policy: "require-corp" }
  })
);

// Additional headers ZAP requires
app.use((req, res, next) => {
  // ZAP Spectre fix
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");

  // Disable browser-powerful APIs
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");

  // No caching allowed
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// Apply Helmet + headers BEFORE static
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Serve static files AFTER CSP fix so robots.txt and sitemap.xml also get CSP
app.use(express.static(path.join(__dirname, "public")));

// ------------------------------------------------------------
// RATE LIMITING
// ------------------------------------------------------------
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// ------------------------------------------------------------
// FILE SYSTEM SAFE READ
// ------------------------------------------------------------
const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
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
    if (value.includes("\0")) throw new Error("null byte not allowed");
    return true;
  });

function handleSafeRead(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const filename = req.body.filename;
  const resolved = resolveSafe(BASE_DIR, filename);

  if (!resolved.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: "Path traversal detected" });
  }

  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ error: "File not found" });
  }

  const content = fs.readFileSync(resolved, "utf8");
  return res.json({ path: resolved, content });
}

// Endpoints
app.post("/read", filenameValidator, handleSafeRead);
app.post("/read-no-validate", filenameValidator, handleSafeRead);

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
// START SERVER
// ------------------------------------------------------------
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Secure server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
