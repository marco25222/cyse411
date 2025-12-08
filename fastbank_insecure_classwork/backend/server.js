const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const bcrypt = require("bcrypt");          // NEW
const csrf = require("csurf");             // NEW
const rateLimit = require("express-rate-limit"); // NEW

const app = express();

// --- BASIC CORS (clean, not vulnerable) ---
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

// ---- CSRF protection ----
const csrfProtection = csrf({ cookie: true });

// ---- Rate limiting (fixes "Missing rate limiting") ----
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,            // 100 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// --- IN-MEMORY SQLITE DB (clean) ---
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

  // SECURE: bcrypt hash instead of fast SHA256
  const passwordHash = bcrypt.hashSync("password123", 10);

  // seed user using a parameterized query
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

// --- SESSION STORE (simple, predictable token exactly like assignment) ---
const sessions = {};

// no more fastHash() with SHA256 – we use bcrypt above

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid])
    return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

// ------------------------------------------------------------
// LOGIN (SQLi fixed + bcrypt used instead of SHA256)
// ------------------------------------------------------------
app.post("/login", csrfProtection, (req, res) => {
  const { username, password } = req.body;

  // SAFE: parameterized query instead of string concatenation
  const sql =
    "SELECT id, username, password_hash FROM users WHERE username = ?";

  db.get(sql, [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }

    if (!user) return res.status(404).json({ error: "Unknown username" });

    // SECURE: compare with bcrypt
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Wrong password" });
    }

    const sid = `${username}-${Date.now()}`; // predictable (kept as-is for lab)
    sessions[sid] = { userId: user.id };

    // Cookie is intentionally “normal” (not HttpOnly / secure)
    res.cookie("sid", sid, {});

    res.json({ success: true });
  });
});

// Optional helper to fetch a CSRF token if your frontend needs it
app.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ------------------------------------------------------------
// /me — cleaned: parameterized query
// ------------------------------------------------------------
app.get("/me", auth, (req, res) => {
  const sql = "SELECT username, email FROM users WHERE id = ?";
  db.get(sql, [req.user.id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    res.json(row);
  });
});

// ------------------------------------------------------------
// Q1 — SQLi in transaction search (fixed already)
// ------------------------------------------------------------
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

// ------------------------------------------------------------
// Q2 — Stored XSS + SQLi in feedback insert (SQLi fixed)
// ------------------------------------------------------------
app.post("/feedback", auth, csrfProtection, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  const selectUserSql = "SELECT username FROM users WHERE id = ?";
  db.get(selectUserSql, [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    const username = row.username;

    const insertSql =
      "INSERT INTO feedback (user, comment) VALUES (?, ?)";
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

// ------------------------------------------------------------
// Q3 — CSRF + SQLi in email update (SQLi fixed + CSRF added)
// ------------------------------------------------------------
app.post("/change-email", auth, csrfProtection, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@"))
    return res.status(400).json({ error: "Invalid email" });

  const sql = "UPDATE users SET email = ? WHERE id = ?";
  db.run(sql, [newEmail, req.user.id], (err) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ success: true, email: newEmail });
  });
});

// ------------------------------------------------------------
app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
