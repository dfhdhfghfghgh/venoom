const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "change-this-password";
const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-to-a-long-random-secret";
const DB_PATH = process.env.DB_PATH || "./data/panel.db";

const dbDir = path.dirname(DB_PATH);

if (dbDir && dbDir !== ".") {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS inbounds (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    remark TEXT DEFAULT '',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    inbound_id TEXT NOT NULL,
    email TEXT NOT NULL,
    uuid TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "../public")));

function createToken() {
  return jwt.sign(
    {
      username: ADMIN_USER
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  const token = header.slice(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid token"
    });
  }
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "xray-panel"
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username !== ADMIN_USER ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Invalid username or password"
    });
  }

  res.json({
    token: createToken(),
    username: ADMIN_USER
  });
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    username: req.user.username
  });
});

app.get("/api/inbounds", auth, (req, res) => {
  const rows = db
    .prepare(
      "SELECT * FROM inbounds ORDER BY created_at DESC"
    )
    .all();

  res.json(rows);
});

app.post("/api/inbounds", auth, (req, res) => {
  const {
    name,
    protocol,
    port,
    remark
  } = req.body;

  if (!name || !protocol || !port) {
    return res.status(400).json({
      error: "Name, protocol and port are required"
    });
  }

  const portNumber = Number(port);

  if (
    !Number.isInteger(portNumber) ||
    portNumber < 1 ||
    portNumber > 65535
  ) {
    return res.status(400).json({
      error: "Invalid port"
    });
  }

  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO inbounds
    (id, name, protocol, port, remark, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    name,
    protocol,
    portNumber,
    remark || "",
    createdAt
  );

  res.status(201).json({
    id,
    name,
    protocol,
    port: portNumber,
    remark: remark || "",
    created_at: createdAt
  });
});

app.delete("/api/inbounds/:id", auth, (req, res) => {
  const id = req.params.id;

  db.prepare(
    "DELETE FROM clients WHERE inbound_id = ?"
  ).run(id);

  const result = db
    .prepare(
      "DELETE FROM inbounds WHERE id = ?"
    )
    .run(id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Inbound not found"
    });
  }

  res.json({
    ok: true
  });
});

app.get("/api/clients", auth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT
        clients.*,
        inbounds.name AS inbound_name
      FROM clients
      LEFT JOIN inbounds
        ON clients.inbound_id = inbounds.id
      ORDER BY clients.created_at DESC
    `)
    .all();

  res.json(rows);
});

app.post("/api/clients", auth, (req, res) => {
  const {
    inbound_id,
    email
  } = req.body;

  if (!inbound_id || !email) {
    return res.status(400).json({
      error: "Inbound and email are required"
    });
  }

  const inbound = db
    .prepare(
      "SELECT * FROM inbounds WHERE id = ?"
    )
    .get(inbound_id);

  if (!inbound) {
    return res.status(404).json({
      error: "Inbound not found"
    });
  }

  const id = crypto.randomUUID();
  const uuid = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO clients
    (id, inbound_id, email, uuid, enabled, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    inbound_id,
    email,
    uuid,
    1,
    createdAt
  );

  res.status(201).json({
    id,
    inbound_id,
    email,
    uuid,
    enabled: 1,
    created_at: createdAt
  });
});

app.delete("/api/clients/:id", auth, (req, res) => {
  const result = db
    .prepare(
      "DELETE FROM clients WHERE id = ?"
    )
    .run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Client not found"
    });
  }

  res.json({
    ok: true
  });
});

app.get("/api/config", auth, (req, res) => {
  const inbounds = db
    .prepare(
      "SELECT * FROM inbounds ORDER BY created_at"
    )
    .all();

  const clients = db
    .prepare(
      "SELECT * FROM clients WHERE enabled = 1"
    )
    .all();

  res.json({
    type: "xray-config-skeleton",
    note: "This MVP does not install or run Xray Core.",
    inbounds,
    clients
  });
});

/*
  Express 5 compatible fallback route.
  Do not change this to app.get("*", ...).
*/
app.use((req, res) => {
  res.sendFile(
    path.join(__dirname, "../public/index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Xray Panel running on port ${PORT}`
  );
});  const {
    name,
    protocol,
    port,
    remark
  } = req.body;

  if (!name || !protocol || !port) {
    return res.status(400).json({
      error: "name, protocol and port are required"
    });
  }

  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO inbounds
    (id, name, protocol, port, remark, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    name,
    protocol,
    Number(port),
    remark || "",
    createdAt
  );

  res.json({
    id,
    name,
    protocol,
    port: Number(port),
    remark: remark || "",
    created_at: createdAt
  });
});

app.delete("/api/inbounds/:id", auth, (req, res) => {
  const id = req.params.id;

  db.prepare(
    "DELETE FROM clients WHERE inbound_id = ?"
  ).run(id);

  const result = db
    .prepare("DELETE FROM inbounds WHERE id = ?")
    .run(id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Inbound not found"
    });
  }

  res.json({
    ok: true
  });
});

app.get("/api/clients", auth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT
        clients.*,
        inbounds.name AS inbound_name
      FROM clients
      LEFT JOIN inbounds
      ON clients.inbound_id = inbounds.id
      ORDER BY clients.created_at DESC
    `)
    .all();

  res.json(rows);
});

app.post("/api/clients", auth, (req, res) => {
  const {
    inbound_id,
    email
  } = req.body;

  if (!inbound_id || !email) {
    return res.status(400).json({
      error: "inbound_id and email are required"
    });
  }

  const inbound = db
    .prepare("SELECT * FROM inbounds WHERE id = ?")
    .get(inbound_id);

  if (!inbound) {
    return res.status(404).json({
      error: "Inbound not found"
    });
  }

  const id = crypto.randomUUID();
  const uuid = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO clients
    (id, inbound_id, email, uuid, enabled, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    inbound_id,
    email,
    uuid,
    1,
    createdAt
  );

  res.json({
    id,
    inbound_id,
    email,
    uuid,
    enabled: 1,
    created_at: createdAt
  });
});

app.delete("/api/clients/:id", auth, (req, res) => {
  const result = db
    .prepare("DELETE FROM clients WHERE id = ?")
    .run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Client not found"
    });
  }

  res.json({
    ok: true
  });
});

app.get("/api/config", auth, (req, res) => {
  const inbounds = db
    .prepare("SELECT * FROM inbounds ORDER BY created_at")
    .all();

  const clients = db
    .prepare("SELECT * FROM clients WHERE enabled = 1")
    .all();

  res.json({
    type: "xray-config-skeleton",
    note: "This MVP does not install or run Xray Core.",
    inbounds,
    clients
  });
});

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../public/index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Xray Panel running on port ${PORT}`);
});
