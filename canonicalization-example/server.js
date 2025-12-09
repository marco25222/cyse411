// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

app.disable("x-powered-by");

// ------------------------------------------------------------
// GLOBAL SECURITY HEADERS (APPLIED BEFORE STATIC FILES)
// ------------------------------------------------------------

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
        "frame-ancestors": ["'none'"],
        "media-src": ["'self'"],
        "manifest-src": ["'self'"]
      }
    },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginEmbedderPolicy: { policy: "require-corp" },
    crossOriginResourcePolicy: { policy: "same-origin" }
  })
);

// Additional manual headers to satisfy ZAP fully
app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

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
// JSON + FORM PARSING
// ------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ------------------------------------------------------------
// STATIC FILES — NOW GET CSP HEADERS TOO
// ------------------------------------------------------------
app.use(express.static(path.join(__dirname, "public"), {
  setHeaders: (res) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    );
  }
}));

// ------------------------------------------------------------
// SAFE FILE OPERATIONS
// ------------------------------------------------------------
const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

function resolveSafe(baseDir, userInput) {
  try { userInput = decodeURIComponent(userInput); } catch {}
  return path.resolve(baseDir, userInput);
}

const filenameValidator = body("filename")
  .exists().withMessage("filename required")
  .isString()
  .trim()
  .notEmpty().withMessage("filename cannot be empty")
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

app.post("/read", filenameValidator, handleSafeRead);
app.post("/read-no-validate", filenameValidator, handleSafeRead);

// Sample files
app.post("/setup-sample", (req, res) => {
  const files = {
    "hello.txt": "Hello secure world!\n",
    "notes/readme.md": "# Readme\nSecure sample file"
  };

  for (const f in files) {
    const full = path.resolve(BASE_DIR, f);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, files[f], "utf8");
  }

  res.json({ ok: true });
});

// ------------------------------------------------------------
// START SERVER
// ------------------------------------------------------------
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () =>
    console.log(`Secure server running on http://localhost:${PORT}`)
  );
}

module.exports = app;
