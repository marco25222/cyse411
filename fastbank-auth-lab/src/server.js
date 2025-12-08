const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const csrf = require("csurf");

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// --- CSRF PROTECTION MIDDLEWARE ---
// Store CSRF token in a cookie so the client can send it back in a header or form field.
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// Optional helper: add token to all responses (for templates/front-end to read)
app.use((req, res, next) => {
  // if this throws in non-mutating requests, you can wrap in try/catch
  res.locals.csrfToken = req.csrfToken();
  next();
});

app.use(express.static("public"));

/**
 * SECURE USER DB
 * Replace fastHash with bcrypt hashing + salt.
 */
const users = [
  {
    id: 1,
    username: "student",
    // Secure: bcrypt salted hash of "password123"
    passwordHash: bcrypt.hashSync("password123", 10)
  }
];

// In-memory session store with expiration
const sessions = {}; // token -> { userId, expiresAt }

/**
 * Secure random token generator
 */
function generateSecureToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// Who am I?
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;

  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  // Check expiration
  if (Date.now() > sessions[token].expiresAt) {
    delete sessions[token];
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

/**
 * SECURE LOGIN ENDPOINT
 */
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  // Secure generic error message to prevent username enumeration
  const BAD_LOGIN = { success: false, message: "Invalid username or password" };

  if (!user) return res.status(401).json(BAD_LOGIN);

  const passwordMatch = await bcrypt.compare(password, user.passwordHash);
  if (!passwordMatch) return res.status(401).json(BAD_LOGIN);

  // Secure random session token
  const token = generateSecureToken();

  // Session expires in 15 minutes
  sessions[token] = {
    userId: user.id,
    expiresAt: Date.now() + 15 * 60 * 1000
  };

  // Secure cookie flags added
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 15 * 60 * 1000
  });

  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
