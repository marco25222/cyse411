// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

// ---------------------------------------------------------------------------
// GLOBAL SECURITY (Helmet + headers)  — keep this BEFORE express.static()
// ---------------------------------------------------------------------------

// Hide "X-Powered-By: Express"
app.disable("x-powered-by");

// Baseline Helmet with default secure config (CodeQL likes this)
app.use(helmet());

// Strong CSP as a separate middleware (official Helmet pattern)
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "object-src": ["'none'"],

      // Directives that have no fallback — define explicitly for ZAP
      "frame-ancestors": ["'none'"],
      "form-action": ["'self'"],

      // Reasonable defaults
      "script-src": ["'self'"],
      "style-src": ["'self'"],
      "img-src": ["'self'"],
      "connect-src": ["'self'"],
      "font-src": ["'self'"],
      "base-uri": ["'self'"]
    }
  })
);

// Spectre-related isolation headers
app.use(helmet.crossOriginResourcePolicy({ policy: "same-origin" }));
app.use(helmet.crossOriginOpenerPolicy({ policy: "same-origin" }));
app.use(helmet.crossOriginEmbedderPolicy({ policy: "require-corp" }));

// Extra headers ZAP likes (Permissions-Policy + no cache)
app.use((req, res, next) => {
  // Lock down powerful browser features
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");

  // No caching
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// Global rate limiting (fixes “Missing rate limiting” alerts)
app.use(
  rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 50,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// ---------------------------------------------------------------------------
// NORMAL EXPRESS SETUP
// ---------------------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// IMPORTANT: static AFTER Helmet so robots.txt/sitemap.xml also get CSP
app.use(express.static(path.join(__dirname, "public")));

const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// PATH TRAVERSAL PROTECTION
// ---------------------------------------------------------------------------
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
  .withMessage("filename required")
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
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

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

// Secure endpoints
app.post("/read", filenameValidator, handleSafeRead);
app.post("/read-no-validate", filenameValidator, handleSafeRead);

// Seed some sample files
app.post("/setup-sample", (req, res) => {
  const samples = {
    "hello.txt": "Hello secure world!\n",
    "notes/readme.md": "# Safe Readme\nSecure file."
  };

  for (const file in samples) {
    const abs = path.resolve(BASE_DIR, file);
    const dir = path.dirname(abs);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(abs, samples[file], "utf8");
  }

  res.json({ ok: true, base: BASE_DIR });
});

// ---------------------------------------------------------------------------
// START SERVER
// ---------------------------------------------------------------------------
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Secure server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
