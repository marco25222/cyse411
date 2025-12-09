// backend/server.js
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

// ------------------------------------------------------------
// Global security hardening
// ------------------------------------------------------------

// Hide framework banner
app.disable("x-powered-by");

// Basic security headers (X-Frame-Options, X-Content-Type-Options, etc.)
app.use(helmet());

// Very strict CSP + permissions policy + no caching
app.use((req, res, next) => {
  // Only allow this origin to load resources
  res.setHeader("Content-Security-Policy", "default-src 'self'");

  // Disable powerful browser features
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");

  // Prevent caching of responses
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// Rate limiting: max 100 req / minute / IP
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,            // limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);


app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const passwordHash = crypto
    .createHash("sha256")
    .update("password123")
    .digest("hex");

  db.run(
    `INSERT INTO users (username, password_hash, email)
     VALUES (?, ?, ?)`,
    ["alice", passwordHash, "alice@example.com"]
  );

  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (?, ?, ?)`,
    [1, 25.5, "Coffee shop"]
  );
  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (?, ?, ?)`,
    [1, 100, "Groceries"]
  );
});

const sessions = {};

function fastHash(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  req.user = { id: sessions[sid].userId };
  next();
}


app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const sql =
    "SELECT id, username, password_hash FROM users WHERE username = ?";

  db.get(sql, [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }

    if (!user) {
      return res.status(404).json({ error: "Unknown username" });
    }

    const candidate = fastHash(password);
    if (candidate !== user.password_hash) {
      return res.status(401).json({ error: "Wrong password" });
    }

    // Predictable session id (kept intentionally for lab)
    const sid = `${username}-${Date.now()}`;
    sessions[sid] = { userId: user.id };

    // Cookie intentionally not HttpOnly / secure (lab)
    res.cookie("sid", sid, {});

    res.json({ success: true });
  });
});


app.get("/me", auth, (req, res) => {
  const sql = "SELECT username, email FROM users WHERE id = ?";
  db.get(sql, [req.user.id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    res.json(row);
  });
});


app.get("/transactions", auth, (req, res) => {
  const q = req.query.q || "";
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
  `;
  const params = [req.user.id, `%${q}%`];

  db.all(sql, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    res.json(rows);
  });
});

app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  const selectUserSql = "SELECT username FROM users WHERE id = ?";
  db.get(selectUserSql, [userId], (err, row) => {
    if (err || !row) {
      return res.status(500).json({ error: "Database error" });
    }
    const username = row.username;

    const insertSql = "INSERT INTO feedback (user, comment) VALUES (?, ?)";
    db.run(insertSql, [username, comment], (err2) => {
      if (err2) {
        return res.status(500).json({ error: "Database error" });
      }
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    res.json(rows);
  });
});

app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail || !newEmail.includes("@")) {
    return res.status(400).json({ error: "Invalid email" });
  }

  const sql = "UPDATE users SET email = ? WHERE id = ?";
  db.run(sql, [newEmail, req.user.id], (err) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ success: true, email: newEmail });
  });
});

app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
