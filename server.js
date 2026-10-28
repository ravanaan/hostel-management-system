require("dotenv").config();

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const express = require("express");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const helmet = require("helmet");

const app = express();
const port = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET;
const dataDirectory = path.join(__dirname, "data");

if (!sessionSecret || sessionSecret.length < 32) {
  throw new Error("Set SESSION_SECRET to a random value of at least 32 characters.");
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

fs.mkdirSync(dataDirectory, { recursive: true });
const database = new Database(process.env.DB_PATH || path.join(dataDirectory, "hostel.sqlite"));
database.pragma("journal_mode = WAL");
database.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS hostel_data (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    payload TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires);
`);

const adminCount = database.prepare("SELECT COUNT(*) AS count FROM admins").get().count;
if (adminCount === 0) {
  const username = process.env.ADMIN_USERNAME?.trim();
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password || password.length < 12) {
    throw new Error("First run requires ADMIN_USERNAME and ADMIN_PASSWORD (at least 12 characters).");
  }
  const passwordHash = bcrypt.hashSync(password, 12);
  database.prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)").run(username, passwordHash);
}

const seed = {
  residents: [
    { id: 101, name: "Aarav Sharma", email: "aarav.sharma@example.com", room: "A-104", block: "A", joined: "2026-08-12", fee: "Paid" },
    { id: 102, name: "Meera Iyer", email: "meera.iyer@example.com", room: "A-104", block: "A", joined: "2026-08-15", fee: "Due" },
    { id: 103, name: "Daniel Okafor", email: "daniel.okafor@example.com", room: "A-106", block: "A", joined: "2026-09-03", fee: "Overdue" },
    { id: 104, name: "Priya Nair", email: "priya.nair@example.com", room: "B-212", block: "B", joined: "2026-07-28", fee: "Paid" },
    { id: 105, name: "Rohan Das", email: "rohan.das@example.com", room: "B-214", block: "B", joined: "2026-09-09", fee: "Due" },
    { id: 106, name: "Sofia Martins", email: "sofia.martins@example.com", room: "C-307", block: "C", joined: "2026-08-21", fee: "Paid" },
    { id: 107, name: "Noah Lee", email: "noah.lee@example.com", room: "C-307", block: "C", joined: "2026-08-21", fee: "Overdue" },
    { id: 108, name: "Aisha Khan", email: "aisha.khan@example.com", room: "C-311", block: "C", joined: "2026-09-11", fee: "Due" }
  ],
  rooms: [
    { number: "A-104", block: "A", type: "Twin share", capacity: 2 },
    { number: "A-105", block: "A", type: "Twin share", capacity: 2 },
    { number: "A-106", block: "A", type: "Single", capacity: 1 },
    { number: "A-107", block: "A", type: "Twin share", capacity: 2 },
    { number: "A-108", block: "A", type: "Twin share", capacity: 2 },
    { number: "B-212", block: "B", type: "Twin share", capacity: 2 },
    { number: "B-213", block: "B", type: "Twin share", capacity: 2 },
    { number: "B-214", block: "B", type: "Single", capacity: 1 },
    { number: "B-215", block: "B", type: "Twin share", capacity: 2 },
    { number: "B-216", block: "B", type: "Twin share", capacity: 2 },
    { number: "C-307", block: "C", type: "Twin share", capacity: 2 },
    { number: "C-308", block: "C", type: "Twin share", capacity: 2 },
    { number: "C-309", block: "C", type: "Single", capacity: 1 },
    { number: "C-310", block: "C", type: "Twin share", capacity: 2 },
    { number: "C-311", block: "C", type: "Single", capacity: 1 }
  ],
  tickets: [],
  notices: []
};

if (!database.prepare("SELECT id FROM hostel_data WHERE id = 1").get()) {
  database.prepare("INSERT INTO hostel_data (id, payload) VALUES (1, ?)").run(JSON.stringify(seed));
}

const loadData = database.prepare("SELECT payload FROM hostel_data WHERE id = 1");
const saveData = database.prepare("UPDATE hostel_data SET payload = ? WHERE id = 1");
const storedData = JSON.parse(loadData.get().payload);
if (JSON.stringify(storedData.rooms) !== JSON.stringify(seed.rooms)) {
  saveData.run(JSON.stringify({ ...storedData, rooms: seed.rooms }));
}
const findAdmin = database.prepare("SELECT id, username, password_hash FROM admins WHERE username = ?");
const validDate = (value) => {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T12:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
};
const text = (value, maxLength) => typeof value === "string" && value.trim().length > 0 && value.length <= maxLength;

class SQLiteSessionStore extends session.Store {
  get(sid, callback) {
    try {
      const row = database.prepare("SELECT sess, expires FROM sessions WHERE sid = ?").get(sid);
      if (!row) return callback(null, null);
      if (row.expires <= Date.now()) {
        database.prepare("DELETE FROM sessions WHERE sid = ?").run(sid);
        return callback(null, null);
      }
      callback(null, JSON.parse(row.sess));
    } catch (error) {
      callback(error);
    }
  }

  set(sid, sessionData, callback = () => {}) {
    try {
      const expiration = sessionData.cookie.expires
        ? Date.parse(sessionData.cookie.expires)
        : Date.now() + (sessionData.cookie.maxAge || 8 * 60 * 60 * 1000);
      database.prepare(`
        INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires = excluded.expires
      `).run(sid, JSON.stringify(sessionData), expiration);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  touch(sid, sessionData, callback) {
    this.set(sid, sessionData, callback);
  }

  destroy(sid, callback = () => {}) {
    try {
      database.prepare("DELETE FROM sessions WHERE sid = ?").run(sid);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }
}

database.prepare("DELETE FROM sessions WHERE expires <= ?").run(Date.now());
const sessionCleanup = setInterval(() => {
  database.prepare("DELETE FROM sessions WHERE expires <= ?").run(Date.now());
}, 15 * 60 * 1000);
sessionCleanup.unref();

function validateData(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.residents) ||
      !Array.isArray(value.rooms) || !Array.isArray(value.tickets) || !Array.isArray(value.notices)) {
    return "Invalid hostel data.";
  }
  const roomNumbers = new Set(seed.rooms.map((room) => room.number));
  const occupancy = new Map();
  const residentIds = new Set();
  const emails = new Set();
  for (const resident of value.residents) {
    if (!resident || !Number.isSafeInteger(resident.id) || !text(resident.name, 80) ||
        typeof resident.email !== "string" || resident.email.length > 120 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(resident.email) ||
        !roomNumbers.has(resident.room) || !validDate(resident.joined) ||
        !["Paid", "Due", "Overdue"].includes(resident.fee) ||
        residentIds.has(resident.id) || emails.has(resident.email.toLowerCase())) {
      return "One or more student records are invalid or duplicated.";
    }
    residentIds.add(resident.id);
    emails.add(resident.email.toLowerCase());
    occupancy.set(resident.room, (occupancy.get(resident.room) || 0) + 1);
    const room = seed.rooms.find((entry) => entry.number === resident.room);
    if (occupancy.get(resident.room) > room.capacity) return `${room.number} has no available beds.`;
  }
  if (value.residents.length > 10000 || value.tickets.length > 10000 || value.notices.length > 10000) {
    return "The submitted data exceeds the allowed size.";
  }
  for (const ticket of value.tickets) {
    if (!ticket || !text(ticket.id, 40) || !text(ticket.category, 40) ||
        !["Low", "Medium", "High", "Critical"].includes(ticket.severity) ||
        !text(ticket.description, 240) || !text(ticket.location, 80) ||
        !["Open", "In progress", "Resolved"].includes(ticket.status) || !validDate(ticket.date)) {
      return "One or more maintenance tickets are invalid.";
    }
  }
  for (const notice of value.notices) {
    if (!notice || !text(notice.title, 90) || !text(notice.audience, 80) ||
        !text(notice.body, 500) || !validDate(notice.date)) {
      return "One or more notices are invalid.";
    }
  }
  return null;
}

app.disable("x-powered-by");
app.set("trust proxy", production ? 1 : false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "64kb" }));
app.use(session({
  store: new SQLiteSessionStore(),
  name: "hosteldesk.sid",
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    maxAge: 30 * 60 * 1000
  }
}));

function requireAdmin(request, response, next) {
  if (!request.session.adminId) return response.status(401).json({ error: "Please sign in as an administrator." });
  next();
}

function requireCsrf(request, response, next) {
  const token = request.get("x-csrf-token");
  if (!token || !request.session.csrfToken || token !== request.session.csrfToken) {
    return response.status(403).json({ error: "Request verification failed. Refresh the page and try again." });
  }
  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many sign-in attempts. Try again in 15 minutes." }
});

app.get("/api/csrf", (request, response, next) => {
  request.session.csrfToken ||= crypto.randomBytes(32).toString("hex");
  request.session.save((error) => {
    if (error) return next(error);
    response.set("Cache-Control", "no-store").json({ token: request.session.csrfToken });
  });
});

app.get("/api/session", (request, response) => {
  response.set("Cache-Control", "no-store").json({
    authenticated: Boolean(request.session.adminId),
    username: request.session.adminUsername || null
  });
});

app.post("/api/login", loginLimiter, requireCsrf, (request, response, next) => {
  const username = typeof request.body?.username === "string" ? request.body.username.trim() : "";
  const password = typeof request.body?.password === "string" ? request.body.password : "";
  if (!username || !password || username.length > 120 || password.length > 200) {
    return response.status(400).json({ error: "Enter a valid username and password." });
  }
  const admin = findAdmin.get(username);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return response.status(401).json({ error: "The username or password is incorrect." });
  }
  request.session.regenerate((error) => {
    if (error) return next(error);
    request.session.adminId = admin.id;
    request.session.adminUsername = admin.username;
    request.session.csrfToken = crypto.randomBytes(32).toString("hex");
    request.session.save((saveError) => {
      if (saveError) return next(saveError);
      response.set("Cache-Control", "no-store").json({ authenticated: true, username: admin.username, csrfToken: request.session.csrfToken });
    });
  });
});

app.post("/api/logout", requireAdmin, requireCsrf, (request, response, next) => {
  request.session.destroy((error) => {
    if (error) return next(error);
    response.clearCookie("hosteldesk.sid", { httpOnly: true, secure: production, sameSite: "lax" });
    response.status(204).end();
  });
});

app.get("/api/data", requireAdmin, (request, response) => {
  response.set("Cache-Control", "no-store").json(JSON.parse(loadData.get().payload));
});

app.put("/api/data", requireAdmin, requireCsrf, (request, response) => {
  const error = validateData(request.body);
  if (error) return response.status(400).json({ error });
  const data = {
    residents: request.body.residents.map((resident) => ({
      id: resident.id,
      name: resident.name.trim(),
      email: resident.email.trim(),
      room: resident.room,
      block: seed.rooms.find((room) => room.number === resident.room).block,
      joined: resident.joined,
      fee: resident.fee
    })),
    rooms: seed.rooms,
    tickets: request.body.tickets,
    notices: request.body.notices
  };
  saveData.run(JSON.stringify(data));
  response.status(204).end();
});

app.get("/", (_request, response) => response.redirect("/hostel-management.html"));
app.get("/hostel-management.html", (_request, response) => {
  response.set("Cache-Control", "no-store").sendFile(path.join(__dirname, "hostel-management.html"));
});
app.use((error, _request, response, _next) => {
  console.error("Request failed:", error.message);
  if (response.headersSent) return;
  response.status(error.type === "entity.too.large" ? 413 : 500).json({
    error: error.type === "entity.too.large" ? "Request payload is too large." : "An unexpected server error occurred."
  });
});

app.listen(port, () => {
  console.log(`HostelDesk running at http://localhost:${port}`);
});
