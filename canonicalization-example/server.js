const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use((req, res, next) => {
  // explicit CSP including directives ZAP complains about
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
  );

  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");

  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  // Spectre / site isolation header
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  next();
});

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use((req, res, next) => {
  if (typeof req.query.filename === "string") {
    return res
      .status(400)
      .json({
        error:
          'The "filename" query parameter is not supported. Use POST /read instead.',
      });
  }
  next();
});


app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
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
  // allow only safe filename characters
  .matches(/^[A-Za-z0-9_.\-\/]+$/)
  .withMessage("filename contains invalid characters")
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
  const normalized = resolveSafe(BASE_DIR, filename);

  if (!normalized.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: "Path traversal detected" });
  }

  if (!fs.existsSync(normalized)) {
    return res.status(404).json({ error: "File not found" });
  }

  const content = fs.readFileSync(normalized, "utf8");
  return res.json({ path: normalized, content });
}

app.post("/read", filenameValidator, (req, res) => {
  return handleSafeRead(req, res);
});

app.post("/read-no-validate", filenameValidator, (req, res) => {
  return handleSafeRead(req, res);
});

app.post("/setup-sample", (req, res) => {
  const samples = {
    "hello.txt": "Hello from safe file!\n",
    "notes/readme.md": "# Readme\nSample readme file",
  };
  Object.keys(samples).forEach((k) => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], "utf8");
  });
  res.json({ ok: true, base: BASE_DIR });
});

if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
