const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-this-password";
const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-to-a-long-random-secret";
const DB_PATH = process.env.DB_PATH || "./data/panel.db";

const dir = path.dirname(DB_PATH);
if (dir && dir !== ".") fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "../public")));

function now() {
  return new Date().toISOString();
}

function id() {
  return crypto.randomUUID();
}

function str(v) {
  return v == null ? "" : String(v).trim();
}

function bool(v, fallback = true) {
  if (v === undefined || v === null || v === "") return fallback;
  return v === true || v === 1 || v === "1" || v === "true" ? 1 : 0;
}

function port(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

function json(v, fallback = {}) {
  if (typeof v === "object" && v !== null) return v;
  try {
    return JSON.parse(v || JSON.stringify(fallback));
  } catch {
    return fallback;
  }
}

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some((x) => x.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

/* -------------------------------------------------------
   DATABASE
------------------------------------------------------- */

db.exec(`
CREATE TABLE IF NOT EXISTS inbounds (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  listen TEXT DEFAULT '',
  network TEXT DEFAULT 'tcp',
  security TEXT DEFAULT 'none',
  remark TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  settings_json TEXT DEFAULT '{}',
  stream_settings_json TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  inbound_id TEXT NOT NULL,
  email TEXT NOT NULL,
  uuid TEXT NOT NULL,
  flow TEXT DEFAULT '',
  total_gb REAL DEFAULT 0,
  expiry_at TEXT DEFAULT '',
  reset_days INTEGER DEFAULT 0,
  limit_ip INTEGER DEFAULT 0,
  telegram_id TEXT DEFAULT '',
  subscription_id TEXT DEFAULT '',
  group_id TEXT DEFAULT '',
  comment TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  credential_json TEXT DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY(inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER DEFAULT 443,
  api_port INTEGER DEFAULT 0,
  protocol TEXT DEFAULT 'http',
  username TEXT DEFAULT '',
  password TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  remark TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER DEFAULT 443,
  sni TEXT DEFAULT '',
  path TEXT DEFAULT '/',
  host_header TEXT DEFAULT '',
  type TEXT DEFAULT 'WebSocket',
  enabled INTEGER DEFAULT 1,
  remark TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbounds (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  server TEXT DEFAULT '',
  port INTEGER DEFAULT 443,
  settings_json TEXT DEFAULT '{}',
  enabled INTEGER DEFAULT 1,
  remark TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routings (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domains_json TEXT DEFAULT '[]',
  ips_json TEXT DEFAULT '[]',
  sources_json TEXT DEFAULT '[]',
  outbound_tag TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  remark TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT DEFAULT ''
);
`);

/* Migration for old database */
const migrations = [
  ["inbounds", "listen", "TEXT DEFAULT ''"],
  ["inbounds", "network", "TEXT DEFAULT 'tcp'"],
  ["inbounds", "security", "TEXT DEFAULT 'none'"],
  ["inbounds", "enabled", "INTEGER DEFAULT 1"],
  ["inbounds", "settings_json", "TEXT DEFAULT '{}'"],
  ["inbounds", "stream_settings_json", "TEXT DEFAULT '{}'"],

  ["clients", "flow", "TEXT DEFAULT ''"],
  ["clients", "total_gb", "REAL DEFAULT 0"],
  ["clients", "expiry_at", "TEXT DEFAULT ''"],
  ["clients", "reset_days", "INTEGER DEFAULT 0"],
  ["clients", "limit_ip", "INTEGER DEFAULT 0"],
  ["clients", "telegram_id", "TEXT DEFAULT ''"],
  ["clients", "subscription_id", "TEXT DEFAULT ''"],
  ["clients", "group_id", "TEXT DEFAULT ''"],
  ["clients", "comment", "TEXT DEFAULT ''"],
  ["clients", "enabled", "INTEGER DEFAULT 1"],
  ["clients", "credential_json", "TEXT DEFAULT '{}'"
  ]
];

for (const [table, column, definition] of migrations) {
  ensureColumn(table, column, definition);
}

/* -------------------------------------------------------
   AUTH
------------------------------------------------------- */

function token() {
  return jwt.sign({ username: ADMIN_USER }, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";

  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

/* -------------------------------------------------------
   BASIC
------------------------------------------------------- */

app.get("/api/health", (_, res) => {
  res.json({ ok: true, service: "xray-panel" });
});

app.post("/api/login", (req, res) => {
  if (
    str(req.body.username) !== ADMIN_USER ||
    str(req.body.password) !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  res.json({
    token: token(),
    username: ADMIN_USER
  });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ username: req.user.username });
});

/* -------------------------------------------------------
   DASHBOARD
------------------------------------------------------- */

app.get("/api/stats", auth, (req, res) => {
  const inbounds = db.prepare("SELECT COUNT(*) c FROM inbounds").get().c;
  const clients = db.prepare("SELECT COUNT(*) c FROM clients").get().c;
  const groups = db.prepare("SELECT COUNT(*) c FROM groups").get().c;
  const nodes = db.prepare("SELECT COUNT(*) c FROM nodes").get().c;
  const hosts = db.prepare("SELECT COUNT(*) c FROM hosts").get().c;

  res.json({
    inbounds,
    clients,
    groups,
    nodes,
    hosts,
    cpu: 0,
    ram: 0,
    xray: false
  });
});

/* -------------------------------------------------------
   INBOUNDS
------------------------------------------------------- */

app.get("/api/inbounds", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT
      i.*,
      (
        SELECT COUNT(*)
        FROM clients c
        WHERE c.inbound_id = i.id
      ) AS client_count
    FROM inbounds i
    ORDER BY i.created_at DESC
  `).all();

  res.json(rows.map((r) => ({
    ...r,
    settings: json(r.settings_json),
    stream_settings: json(r.stream_settings_json)
  })));
});

app.post("/api/inbounds", auth, (req, res) => {
  const body = req.body;
  const p = port(body.port);

  if (!str(body.name)) {
    return res.status(400).json({ error: "Inbound name is required" });
  }

  if (!str(body.protocol)) {
    return res.status(400).json({ error: "Protocol is required" });
  }

  if (!p) {
    return res.status(400).json({ error: "Invalid port" });
  }

  const inboundId = id();
  const created = now();

  const settings = {
    sniffing: bool(body.sniffing, false),
    destOverride: str(body.destOverride),
    tls: {
      serverName: str(body.tlsServerName),
      certPath: str(body.tlsCert),
      keyPath: str(body.tlsKey)
    },
    reality: {
      dest: str(body.realityDest),
      serverNames: str(body.realityServerNames),
      privateKey: str(body.realityPrivateKey),
      shortIds: str(body.realityShortIds),
      fingerprint: str(body.realityFingerprint)
    }
  };

  const stream = {
    network: str(body.network) || "tcp",
    ws: {
      path: str(body.wsPath) || "/",
      host: str(body.wsHost)
    },
    grpc: {
      serviceName: str(body.grpcServiceName)
    },
    xhttp: {
      path: str(body.xhttpPath) || "/",
      host: str(body.xhttpHost)
    }
  };

  db.prepare(`
    INSERT INTO inbounds
    (id,name,protocol,port,listen,network,security,remark,enabled,
     settings_json,stream_settings_json,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    inboundId,
    str(body.name),
    str(body.protocol),
    p,
    str(body.listen),
    str(body.network) || "tcp",
    str(body.security) || "none",
    str(body.remark),
    bool(body.enabled),
    JSON.stringify(settings),
    JSON.stringify(stream),
    created
  );

  if (body.clientEmail) {
    const clientId = id();

    db.prepare(`
      INSERT INTO clients
      (id,inbound_id,email,uuid,flow,total_gb,expiry_at,reset_days,
       limit_ip,telegram_id,subscription_id,group_id,comment,enabled,
       credential_json,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      clientId,
      inboundId,
      str(body.clientEmail),
      str(body.clientUuid) || crypto.randomUUID(),
      str(body.clientFlow),
      Number(body.clientTotalGb) || 0,
      str(body.clientExpiry),
      Number(body.clientResetDays) || 0,
      Number(body.clientLimitIp) || 0,
      str(body.clientTelegramId),
      str(body.clientSubscriptionId),
      str(body.clientGroupId),
      str(body.clientComment),
      bool(body.clientEnabled),
      "{}",
      created
    );
  }

  res.status(201).json({ ok: true, id: inboundId });
});

app.put("/api/inbounds/:id", auth, (req, res) => {
  const old = db.prepare("SELECT * FROM inbounds WHERE id=?").get(req.params.id);

  if (!old) return res.status(404).json({ error: "Inbound not found" });

  const b = req.body;
  const p = port(b.port);

  if (!str(b.name) || !p) {
    return res.status(400).json({ error: "Invalid inbound data" });
  }

  db.prepare(`
    UPDATE inbounds SET
      name=?,
      protocol=?,
      port=?,
      listen=?,
      network=?,
      security=?,
      remark=?,
      enabled=?,
      settings_json=?,
      stream_settings_json=?
    WHERE id=?
  `).run(
    str(b.name),
    str(b.protocol),
    p,
    str(b.listen),
    str(b.network) || "tcp",
    str(b.security) || "none",
    str(b.remark),
    bool(b.enabled),
    JSON.stringify(json(b.settings)),
    JSON.stringify(json(b.stream_settings)),
    req.params.id
  );

  res.json({ ok: true });
});

app.patch("/api/inbounds/:id/toggle", auth, (req, res) => {
  const row = db.prepare("SELECT enabled FROM inbounds WHERE id=?").get(req.params.id);

  if (!row) return res.status(404).json({ error: "Inbound not found" });

  db.prepare("UPDATE inbounds SET enabled=? WHERE id=?")
    .run(row.enabled ? 0 : 1, req.params.id);

  res.json({ ok: true });
});

app.delete("/api/inbounds/:id", auth, (req, res) => {
  const result = db.prepare("DELETE FROM inbounds WHERE id=?").run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({ error: "Inbound not found" });
  }

  res.json({ ok: true });
});

/* -------------------------------------------------------
   CLIENTS
------------------------------------------------------- */

app.get("/api/clients", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT
      c.*,
      i.name AS inbound_name,
      g.name AS group_name
    FROM clients c
    LEFT JOIN inbounds i ON i.id=c.inbound_id
    LEFT JOIN groups g ON g.id=c.group_id
    ORDER BY c.created_at DESC
  `).all();

  res.json(rows);
});

app.post("/api/clients", auth, (req, res) => {
  const b = req.body;

  if (!str(b.inbound_id) || !str(b.email)) {
    return res.status(400).json({
      error: "Inbound and email are required"
    });
  }

  const inbound = db.prepare("SELECT id FROM inbounds WHERE id=?")
    .get(str(b.inbound_id));

  if (!inbound) {
    return res.status(404).json({ error: "Inbound not found" });
  }

  const clientId = id();

  db.prepare(`
    INSERT INTO clients
    (id,inbound_id,email,uuid,flow,total_gb,expiry_at,reset_days,
     limit_ip,telegram_id,subscription_id,group_id,comment,enabled,
     credential_json,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    clientId,
    str(b.inbound_id),
    str(b.email),
    str(b.uuid) || crypto.randomUUID(),
    str(b.flow),
    Number(b.total_gb) || 0,
    str(b.expiry_at),
    Number(b.reset_days) || 0,
    Number(b.limit_ip) || 0,
    str(b.telegram_id),
    str(b.subscription_id),
    str(b.group_id),
    str(b.comment),
    bool(b.enabled),
    "{}",
    now()
  );

  res.status(201).json({ ok: true, id: clientId });
});

app.put("/api/clients/:id", auth, (req, res) => {
  const b = req.body;

  const result = db.prepare(`
    UPDATE clients SET
      inbound_id=?,
      email=?,
      uuid=?,
      flow=?,
      total_gb=?,
      expiry_at=?,
      reset_days=?,
      limit_ip=?,
      telegram_id=?,
      subscription_id=?,
      group_id=?,
      comment=?,
      enabled=?
    WHERE id=?
  `).run(
    str(b.inbound_id),
    str(b.email),
    str(b.uuid),
    str(b.flow),
    Number(b.total_gb) || 0,
    str(b.expiry_at),
    Number(b.reset_days) || 0,
    Number(b.limit_ip) || 0,
    str(b.telegram_id),
    str(b.subscription_id),
    str(b.group_id),
    str(b.comment),
    bool(b.enabled),
    req.params.id
  );

  if (!result.changes) {
    return res.status(404).json({ error: "Client not found" });
  }

  res.json({ ok: true });
});

app.patch("/api/clients/:id/toggle", auth, (req, res) => {
  const row = db.prepare("SELECT enabled FROM clients WHERE id=?").get(req.params.id);

  if (!row) return res.status(404).json({ error: "Client not found" });

  db.prepare("UPDATE clients SET enabled=? WHERE id=?")
    .run(row.enabled ? 0 : 1, req.params.id);

  res.json({ ok: true });
});

app.delete("/api/clients/:id", auth, (req, res) => {
  const result = db.prepare("DELETE FROM clients WHERE id=?").run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({ error: "Client not found" });
  }

  res.json({ ok: true });
});

/* -------------------------------------------------------
   GROUPS
------------------------------------------------------- */

app.get("/api/groups", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM groups ORDER BY created_at DESC").all());
});

app.post("/api/groups", auth, (req, res) => {
  if (!str(req.body.name)) {
    return res.status(400).json({ error: "Group name is required" });
  }

  const groupId = id();

  db.prepare(`
    INSERT INTO groups(id,name,description,enabled,created_at)
    VALUES(?,?,?,?,?)
  `).run(
    groupId,
    str(req.body.name),
    str(req.body.description),
    bool(req.body.enabled),
    now()
  );

  res.status(201).json({ ok: true, id: groupId });
});

app.put("/api/groups/:id", auth, (req, res) => {
  const result = db.prepare(`
    UPDATE groups
    SET name=?,description=?,enabled=?
    WHERE id=?
  `).run(
    str(req.body.name),
    str(req.body.description),
    bool(req.body.enabled),
    req.params.id
  );

  if (!result.changes) return res.status(404).json({ error: "Group not found" });

  res.json({ ok: true });
});

app.delete("/api/groups/:id", auth, (req, res) => {
  db.prepare("UPDATE clients SET group_id='' WHERE group_id=?").run(req.params.id);

  const result = db.prepare("DELETE FROM groups WHERE id=?").run(req.params.id);

  if (!result.changes) return res.status(404).json({ error: "Group not found" });

  res.json({ ok: true });
});

/* -------------------------------------------------------
   NODES
------------------------------------------------------- */

app.get("/api/nodes", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM nodes ORDER BY created_at DESC").all());
});

app.post("/api/nodes", auth, (req, res) => {
  const b = req.body;
  const p = port(b.port) || 443;

  if (!str(b.name) || !str(b.address)) {
    return res.status(400).json({ error: "Name and address are required" });
  }

  const nodeId = id();

  db.prepare(`
    INSERT INTO nodes
    (id,name,address,port,api_port,protocol,username,password,enabled,remark,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    nodeId,
    str(b.name),
    str(b.address),
    p,
    Number(b.api_port) || 0,
    str(b.protocol) || "http",
    str(b.username),
    str(b.password),
    bool(b.enabled),
    str(b.remark),
    now()
  );

  res.status(201).json({ ok: true, id: nodeId });
});

app.put("/api/nodes/:id", auth, (req, res) => {
  const b = req.body;

  const result = db.prepare(`
    UPDATE nodes SET
      name=?,address=?,port=?,api_port=?,protocol=?,
      username=?,password=?,enabled=?,remark=?
    WHERE id=?
  `).run(
    str(b.name),
    str(b.address),
    port(b.port) || 443,
    Number(b.api_port) || 0,
    str(b.protocol),
    str(b.username),
    str(b.password),
    bool(b.enabled),
    str(b.remark),
    req.params.id
  );

  if (!result.changes) return res.status(404).json({ error: "Node not found" });

  res.json({ ok: true });
});

app.delete("/api/nodes/:id", auth, (req, res) => {
  const result = db.prepare("DELETE FROM nodes WHERE id=?").run(req.params.id);

  if (!result.changes) return res.status(404).json({ error: "Node not found" });

  res.json({ ok: true });
});

/* -------------------------------------------------------
   HOSTS
------------------------------------------------------- */

app.get("/api/hosts", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM hosts ORDER BY created_at DESC").all());
});

app.post("/api/hosts", auth, (req, res) => {
  const b = req.body;

  if (!str(b.name) || !str(b.address)) {
    return res.status(400).json({ error: "Name and address are required" });
  }

  const hostId = id();

  db.prepare(`
    INSERT INTO hosts
    (id,name,address,port,sni,path,host_header,type,enabled,remark,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    hostId,
    str(b.name),
    str(b.address),
    port(b.port) || 443,
    str(b.sni),
    str(b.path) || "/",
    str(b.host_header),
    str(b.type) || "WebSocket",
    bool(b.enabled),
    str(b.remark),
    now()
  );

  res.status(201).json({ ok: true, id: hostId });
});

app.put("/api/hosts/:id", auth, (req, res) => {
  const b = req.body;

  const result = db.prepare(`
    UPDATE hosts SET
      name=?,address=?,port=?,sni=?,path=?,
      host_header=?,type=?,enabled=?,remark=?
    WHERE id=?
  `).run(
    str(b.name),
    str(b.address),
    port(b.port) || 443,
    str(b.sni),
    str(b.path) || "/",
    str(b.host_header),
    str(b.type),
    bool(b.enabled),
    str(b.remark),
    req.params.id
  );

  if (!result.changes) return res.status(404).json({ error: "Host not found" });

  res.json({ ok: true });
});

app.delete("/api/hosts/:id", auth, (req, res) => {
  const result = db.prepare("DELETE FROM hosts WHERE id=?").run(req.params.id);

  if (!result.changes) return res.status(404).json({ error: "Host not found" });

  res.json({ ok: true });
});

/* -------------------------------------------------------
   OUTBOUND
------------------------------------------------------- */

app.get("/api/outbounds", auth, (req, res) => {
  const rows = db.prepare("SELECT * FROM outbounds ORDER BY created_at DESC").all();

  res.json(rows.map((r) => ({
    ...r,
    settings: json(r.settings_json)
  })));
});

app.post("/api/outbounds", auth, (req, res) => {
  const b = req.body;

  if (!str(b.name) || !str(b.protocol)) {
    return res.status(400).json({ error: "Name and protocol are required" });
  }

  const outboundId = id();

  db.prepare(`
    INSERT INTO outbounds
    (id,name,protocol,server,port,settings_json,enabled,remark,created_at)
    VALUES(?,?,?,?,?,?,?,?,?)
  `).run(
    outboundId,
    str(b.name),
    str(b.protocol),
    str(b.server),
    port(b.port) || 443,
    JSON.stringify(json(b.settings)),
    bool(b.enabled),
    str(b.remark),
    now()
  );

  res.status(201).json({ ok: true, id: outboundId });
});

app.put("/api/outbounds/:id", auth, (req, res) => {
  const b = req.body;

  const result = db.prepare(`
    UPDATE outbounds SET
      name=?,protocol=?,server=?,port=?,
      settings_json=?,enabled=?,remark=?
    WHERE id=?
  `).run(
    str(b.name),
    str(b.protocol),
    str(b.server),
    port(b.port) || 443,
    JSON.stringify(json(b.settings)),
    bool(b.enabled),
    str(b.remark),
    req.params.id
  );

  if (!result.changes) return res.status(404).json({ error: "Outbound not found" });

  res.json({ ok: true });
});

app.delete("/api/outbounds/:id", auth, (req, res) => {
  const result = db.prepare("DELETE FROM outbounds WHERE id=?").run(req.params.id);

  if (!result.changes) return res.status(404).json({ error: "Outbound not found" });

  res.json({ ok: true });
});

/* -------------------------------------------------------
   ROUTING
------------------------------------------------------- */

app.get("/api/routing", auth, (req, res) => {
  const rows = db.prepare("SELECT * FROM routings ORDER BY created_at DESC").all();

  res.json(rows.map((r) => ({
    ...r,
    domains: json(r.domains_json, []),
    ips: json(r.ips_json, []),
    sources: json(r.sources_json, [])
  })));
});

app.post("/api/routing", auth, (req, res) => {
  if (!str(req.body.name)) {
    return res.status(400).json({ error: "Rule name is required" });
  }

  const ruleId = id();

  const array = (v) =>
    Array.isArray(v)
      ? v
      : str(v)
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean);

  db.prepare(`
    INSERT INTO routings
    (id,name,domains_json,ips_json,sources_json,outbound_tag,enabled,remark,created_at)
    VALUES(?,?,?,?,?,?,?,?,?)
  `).run(
    ruleId,
    str(req.body.name),
    JSON.stringify(array(req.body.domains)),
    JSON.stringify(array(req.body.ips)),
    JSON.stringify(array(req.body.sources)),
    str(req.body.outbound_tag),
    bool(req.body.enabled),
    str(req.body.remark),
    now()
  );

  res.status(201).json({ ok: true, id: ruleId });
});

app.delete("/api/routing/:id", auth, (req, res) => {
  const result = db.prepare("DELETE FROM routings WHERE id=?").run(req.params.id);

  if (!result.changes) return res.status(404).json({ error: "Rule not found" });

  res.json({ ok: true });
});

/* -------------------------------------------------------
   SETTINGS
------------------------------------------------------- */

app.get("/api/settings", auth, (req, res) => {
  const rows = db.prepare("SELECT * FROM settings ORDER BY key").all();
  res.json(Object.fromEntries(rows.map((r) => [r.key, r.value])));
});

app.put("/api/settings", auth, (req, res) => {
  const stmt = db.prepare(`
    INSERT INTO settings(key,value)
    VALUES(?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `);

  const tx = db.transaction((data) => {
    for (const [key, value] of Object.entries(data || {})) {
      stmt.run(str(key), typeof value === "string" ? value : JSON.stringify(value));
    }
  });

  tx(req.body);

  res.json({ ok: true });
});

/* -------------------------------------------------------
   XRAY CONFIG
------------------------------------------------------- */

app.get("/api/config", auth, (req, res) => {
  const inbounds = db.prepare("SELECT * FROM inbounds").all();
  const clients = db.prepare("SELECT * FROM clients WHERE enabled=1").all();
  const outbounds = db.prepare("SELECT * FROM outbounds WHERE enabled=1").all();
  const routing = db.prepare("SELECT * FROM routings WHERE enabled=1").all();

  res.json({
    generated_at: now(),
    xray_core_running: false,
    note: "Panel configuration skeleton. Xray Core is not started by this MVP.",
    inbounds,
    clients,
    outbounds,
    routing
  });
});

/* -------------------------------------------------------
   API DOCS
------------------------------------------------------- */

app.get("/api/docs", auth, (req, res) => {
  res.json([
    "POST /api/login",
    "GET /api/me",
    "GET /api/stats",
    "GET /api/inbounds",
    "POST /api/inbounds",
    "PUT /api/inbounds/:id",
    "DELETE /api/inbounds/:id",
    "GET /api/clients",
    "POST /api/clients",
    "PUT /api/clients/:id",
    "DELETE /api/clients/:id",
    "GET /api/groups",
    "POST /api/groups",
    "PUT /api/groups/:id",
    "DELETE /api/groups/:id",
    "GET /api/nodes",
    "POST /api/nodes",
    "PUT /api/nodes/:id",
    "DELETE /api/nodes/:id",
    "GET /api/hosts",
    "POST /api/hosts",
    "PUT /api/hosts/:id",
    "DELETE /api/hosts/:id",
    "GET /api/outbounds",
    "POST /api/outbounds",
    "PUT /api/outbounds/:id",
    "DELETE /api/outbounds/:id",
    "GET /api/routing",
    "POST /api/routing",
    "DELETE /api/routing/:id",
    "GET /api/settings",
    "PUT /api/settings",
    "GET /api/config"
  ]);
});

/* -------------------------------------------------------
   SPA
------------------------------------------------------- */

app.use((req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Xray Panel running on port ${PORT}`);
});
