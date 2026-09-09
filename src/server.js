const express = require("express");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-this-password";
const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-to-a-long-random-secret";

const DB_PATH = process.env.DB_PATH || "./data/panel.db";

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   HELPERS
========================================================= */

function now() {
  return new Date().toISOString();
}

function id(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function subscriptionToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function json(value, fallback = {}) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function base64(value) {
  return Buffer.from(value, "utf8").toString("base64");
}

function getBaseUrl(req) {
  const configured =
    process.env.PUBLIC_BASE_URL ||
    getSetting("subscription_base_url", "");

  if (configured) return configured.replace(/\/+$/, "");

  const proto =
    String(req.headers["x-forwarded-proto"] || "https")
      .split(",")[0]
      .trim();

  return `${proto}://${req.get("host")}`;
}

function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();

  if (!cols.some((x) => x.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function getSetting(key, fallback = "") {
  const row = db
    .prepare("SELECT value FROM settings WHERE key = ?")
    .get(key);

  return row ? row.value : fallback;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO settings(key,value)
    VALUES (?,?)
    ON CONFLICT(key)
    DO UPDATE SET value=excluded.value
  `).run(key, String(value ?? ""));
}

function expired(client) {
  if (!client.expiry_at) return false;

  const d = new Date(client.expiry_at);

  return !Number.isNaN(d.getTime()) && d.getTime() <= Date.now();
}

function usable(client) {
  return Boolean(client.enabled) && !expired(client);
}

function hostname(value) {
  if (!value) return "";

  return String(value)
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0];
}

/* =========================================================
   DATABASE
========================================================= */

db.exec(`
CREATE TABLE IF NOT EXISTS inbounds (
  id TEXT PRIMARY KEY,
  remark TEXT NOT NULL,
  protocol TEXT DEFAULT 'vless',
  listen TEXT DEFAULT '0.0.0.0',
  port INTEGER DEFAULT 443,
  network TEXT DEFAULT 'ws',
  security TEXT DEFAULT 'none',
  settings_json TEXT DEFAULT '{}',
  stream_settings_json TEXT DEFAULT '{}',
  sniffing_json TEXT DEFAULT '{}',
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
  subscription_token TEXT DEFAULT '',
  group_id TEXT DEFAULT '',
  comment TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  credential_json TEXT DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY(inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  total_gb REAL DEFAULT 0,
  expiry_at TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT DEFAULT '',
  port INTEGER DEFAULT 443,
  username TEXT DEFAULT '',
  password TEXT DEFAULT '',
  protocol TEXT DEFAULT 'vless',
  status TEXT DEFAULT 'offline',
  config_json TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT DEFAULT '',
  port INTEGER DEFAULT 443,
  sni TEXT DEFAULT '',
  path TEXT DEFAULT '/',
  security TEXT DEFAULT 'tls',
  config_json TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbounds (
  id TEXT PRIMARY KEY,
  tag TEXT NOT NULL,
  protocol TEXT DEFAULT 'freedom',
  settings_json TEXT DEFAULT '{}',
  stream_settings_json TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routings (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  port TEXT DEFAULT '',
  outbound_tag TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  config_json TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT DEFAULT ''
);
`);

/* migrations */

ensureColumn("clients", "subscription_token", "TEXT DEFAULT ''");
ensureColumn("clients", "subscription_id", "TEXT DEFAULT ''");
ensureColumn("clients", "group_id", "TEXT DEFAULT ''");
ensureColumn("clients", "comment", "TEXT DEFAULT ''");
ensureColumn("clients", "credential_json", "TEXT DEFAULT '{}'");
ensureColumn("clients", "enabled", "INTEGER DEFAULT 1");

const oldClients = db
  .prepare(`
    SELECT id FROM clients
    WHERE subscription_token IS NULL OR subscription_token = ''
  `)
  .all();

const updateToken = db.prepare(`
  UPDATE clients
  SET subscription_token = ?
  WHERE id = ?
`);

for (const client of oldClients) {
  updateToken.run(subscriptionToken(), client.id);
}

/* =========================================================
   AUTH
========================================================= */

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
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};

  if (
    username !== ADMIN_USER ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Invalid username or password"
    });
  }

  const token = jwt.sign(
    {
      username,
      role: "admin"
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );

  res.json({
    token,
    username
  });
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    authenticated: true,
    user: req.user
  });
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    time: now()
  });
});

/* =========================================================
   STATS
========================================================= */

app.get("/api/stats", auth, (req, res) => {
  const clients = db
    .prepare("SELECT * FROM clients")
    .all();

  const inbounds = db
    .prepare("SELECT * FROM inbounds")
    .all();

  const groups = db
    .prepare("SELECT * FROM groups")
    .all();

  const nodes = db
    .prepare("SELECT * FROM nodes")
    .all();

  res.json({
    clients: clients.length,
    active_clients: clients.filter(usable).length,
    expired_clients: clients.filter(expired).length,
    inbounds: inbounds.length,
    active_inbounds: inbounds.filter((x) => x.enabled).length,
    groups: groups.length,
    nodes: nodes.length,
    online_nodes: nodes.filter(
      (x) => x.status === "online"
    ).length,
    xray_core_running: false
  });
});

/* =========================================================
   INBOUNDS
========================================================= */

app.get("/api/inbounds", auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT * FROM inbounds
      ORDER BY created_at DESC
    `).all()
  );
});

app.post("/api/inbounds", auth, (req, res) => {
  const body = req.body || {};

  const row = {
    id: id(),
    remark: body.remark || "New Inbound",
    protocol: body.protocol || "vless",
    listen: body.listen || "0.0.0.0",
    port: Number(body.port || 443),
    network: body.network || "ws",
    security: body.security || "none",
    settings_json: JSON.stringify(body.settings || {}),
    stream_settings_json: JSON.stringify(
      body.stream_settings || {}
    ),
    sniffing_json: JSON.stringify(body.sniffing || {}),
    enabled: body.enabled === false ? 0 : 1,
    created_at: now()
  };

  db.prepare(`
    INSERT INTO inbounds
    VALUES (
      @id,@remark,@protocol,@listen,@port,@network,
      @security,@settings_json,@stream_settings_json,
      @sniffing_json,@enabled,@created_at
    )
  `).run(row);

  res.json(row);
});

app.put("/api/inbounds/:id", auth, (req, res) => {
  const body = req.body || {};

  const result = db.prepare(`
    UPDATE inbounds
    SET
      remark=?,
      protocol=?,
      listen=?,
      port=?,
      network=?,
      security=?,
      settings_json=?,
      stream_settings_json=?,
      sniffing_json=?,
      enabled=?
    WHERE id=?
  `).run(
    body.remark || "Inbound",
    body.protocol || "vless",
    body.listen || "0.0.0.0",
    Number(body.port || 443),
    body.network || "ws",
    body.security || "none",
    JSON.stringify(body.settings || {}),
    JSON.stringify(body.stream_settings || {}),
    JSON.stringify(body.sniffing || {}),
    body.enabled === false ? 0 : 1,
    req.params.id
  );

  if (!result.changes) {
    return res.status(404).json({ error: "Inbound not found" });
  }

  res.json({ ok: true });
});

app.delete("/api/inbounds/:id", auth, (req, res) => {
  const result = db
    .prepare("DELETE FROM inbounds WHERE id=?")
    .run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({ error: "Inbound not found" });
  }

  res.json({ ok: true });
});

app.patch("/api/inbounds/:id/toggle", auth, (req, res) => {
  db.prepare(`
    UPDATE inbounds
    SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END
    WHERE id=?
  `).run(req.params.id);

  res.json({ ok: true });
});

/* =========================================================
   CLIENTS
========================================================= */

app.get("/api/clients", auth, (req, res) => {
  const clients = db.prepare(`
    SELECT
      c.*,
      i.remark AS inbound_remark,
      i.protocol AS inbound_protocol,
      i.port AS inbound_port,
      i.network AS inbound_network,
      i.security AS inbound_security,
      g.name AS group_name
    FROM clients c
    LEFT JOIN inbounds i ON i.id=c.inbound_id
    LEFT JOIN groups g ON g.id=c.group_id
    ORDER BY c.created_at DESC
  `).all();

  res.json(
    clients.map((c) => ({
      ...c,
      expired: expired(c),
      usable: usable(c)
    }))
  );
});

app.post("/api/clients", auth, (req, res) => {
  const body = req.body || {};

  if (!body.inbound_id) {
    return res.status(400).json({
      error: "Inbound is required"
    });
  }

  const client = {
    id: id(),
    inbound_id: body.inbound_id,
    email: body.email || `client-${Date.now()}`,
    uuid:
      body.uuid ||
      crypto.randomUUID(),
    flow: body.flow || "",
    total_gb: Number(body.total_gb || 0),
    expiry_at: body.expiry_at || "",
    reset_days: Number(body.reset_days || 0),
    limit_ip: Number(body.limit_ip || 0),
    telegram_id: body.telegram_id || "",
    subscription_id: body.subscription_id || "",
    subscription_token:
      body.subscription_token || subscriptionToken(),
    group_id: body.group_id || "",
    comment: body.comment || "",
    enabled: body.enabled === false ? 0 : 1,
    credential_json: JSON.stringify(
      body.credential || {}
    ),
    created_at: now()
  };

  db.prepare(`
    INSERT INTO clients (
      id,inbound_id,email,uuid,flow,total_gb,
      expiry_at,reset_days,limit_ip,telegram_id,
      subscription_id,subscription_token,group_id,
      comment,enabled,credential_json,created_at
    )
    VALUES (
      @id,@inbound_id,@email,@uuid,@flow,@total_gb,
      @expiry_at,@reset_days,@limit_ip,@telegram_id,
      @subscription_id,@subscription_token,@group_id,
      @comment,@enabled,@credential_json,@created_at
    )
  `).run(client);

  res.json(client);
});

app.put("/api/clients/:id", auth, (req, res) => {
  const body = req.body || {};

  const old = db
    .prepare("SELECT * FROM clients WHERE id=?")
    .get(req.params.id);

  if (!old) {
    return res.status(404).json({
      error: "Client not found"
    });
  }

  db.prepare(`
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
      enabled=?,
      credential_json=?
    WHERE id=?
  `).run(
    body.inbound_id || old.inbound_id,
    body.email || old.email,
    body.uuid || old.uuid,
    body.flow ?? old.flow,
    Number(body.total_gb ?? old.total_gb),
    body.expiry_at ?? old.expiry_at,
    Number(body.reset_days ?? old.reset_days),
    Number(body.limit_ip ?? old.limit_ip),
    body.telegram_id ?? old.telegram_id,
    body.subscription_id ?? old.subscription_id,
    body.group_id ?? old.group_id,
    body.comment ?? old.comment,
    body.enabled === false ? 0 : 1,
    JSON.stringify(body.credential || json(old.credential_json)),
    req.params.id
  );

  res.json({ ok: true });
});

app.delete("/api/clients/:id", auth, (req, res) => {
  const result = db
    .prepare("DELETE FROM clients WHERE id=?")
    .run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Client not found"
    });
  }

  res.json({ ok: true });
});

app.patch("/api/clients/:id/toggle", auth, (req, res) => {
  db.prepare(`
    UPDATE clients
    SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END
    WHERE id=?
  `).run(req.params.id);

  res.json({ ok: true });
});

/* =========================================================
   SUBSCRIPTION ENGINE
========================================================= */

function getClientSubscription(client, req) {
  const inbound = db
    .prepare("SELECT * FROM inbounds WHERE id=?")
    .get(client.inbound_id);

  if (!inbound) return [];

  const settings = json(inbound.settings_json);
  const stream = json(inbound.stream_settings_json);

  const protocol =
    String(inbound.protocol || "vless").toLowerCase();

  const network =
    stream.network ||
    inbound.network ||
    "tcp";

  const security =
    stream.security ||
    inbound.security ||
    "none";

  let address =
    stream.server ||
    stream.address ||
    settings.address ||
    getSetting("subscription_server", "");

  if (!address) {
    address = req.hostname;
  }

  address = hostname(address);

  const port = Number(
    stream.port ||
    inbound.port ||
    443
  );

  let pathValue = "/";
  let hostHeader = "";
  let sni = "";

  const ws =
    stream.wsSettings ||
    stream.ws ||
    {};

  const grpc =
    stream.grpcSettings ||
    stream.grpc ||
    {};

  pathValue =
    ws.path ||
    stream.path ||
    "/";

  hostHeader =
    ws.host ||
    stream.host ||
    "";

  sni =
    stream.serverName ||
    stream.sni ||
    hostHeader ||
    address;

  const configs = [];

  if (protocol === "vless") {
    const params = new URLSearchParams();

    params.set("type", network);
    params.set("security", security);

    if (network === "ws") {
      params.set("path", pathValue || "/");

      if (hostHeader) {
        params.set("host", hostHeader);
      }
    }

    if (network === "grpc") {
      params.set(
        "serviceName",
        grpc.serviceName || ""
      );
    }

    if (security === "tls") {
      params.set("sni", sni);
    }

    if (client.flow) {
      params.set("flow", client.flow);
    }

    const remark =
      client.email || "Xray Client";

    configs.push(
      `vless://${client.uuid}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark)}`
    );
  }

  if (protocol === "vmess") {
    const vmess = {
      v: "2",
      ps: client.email || "Xray Client",
      add: address,
      port: String(port),
      id: client.uuid,
      aid: "0",
      scy: "auto",
      net: network,
      type: "none",
      host: hostHeader,
      path: pathValue,
      tls: security === "tls" ? "tls" : ""
    };

    configs.push(
      `vmess://${base64(JSON.stringify(vmess))}`
    );
  }

  if (protocol === "trojan") {
    const params = new URLSearchParams();

    params.set("type", network);
    params.set("security", security);

    if (network === "ws") {
      params.set("path", pathValue || "/");

      if (hostHeader) {
        params.set("host", hostHeader);
      }
    }

    if (security === "tls") {
      params.set("sni", sni);
    }

    configs.push(
      `trojan://${encodeURIComponent(client.uuid)}@${address}:${port}?${params.toString()}#${encodeURIComponent(client.email || "Trojan Client")}`
    );
  }

  return configs;
}

/* panel API */

app.get(
  "/api/clients/:id/subscription",
  auth,
  (req, res) => {
    const client = db
      .prepare("SELECT * FROM clients WHERE id=?")
      .get(req.params.id);

    if (!client) {
      return res.status(404).json({
        error: "Client not found"
      });
    }

    const url =
      `${getBaseUrl(req)}/sub/${client.subscription_token}`;

    const configs =
      getClientSubscription(client, req);

    res.json({
      client: {
        id: client.id,
        email: client.email,
        uuid: client.uuid,
        enabled: Boolean(client.enabled),
        expired: expired(client)
      },
      url,
      token: client.subscription_token,
      configs,
      config_count: configs.length,
      active: usable(client)
    });
  }
);

/* regenerate */

app.post(
  "/api/clients/:id/subscription/regenerate",
  auth,
  (req, res) => {
    const client = db
      .prepare("SELECT * FROM clients WHERE id=?")
      .get(req.params.id);

    if (!client) {
      return res.status(404).json({
        error: "Client not found"
      });
    }

    const token = subscriptionToken();

    db.prepare(`
      UPDATE clients
      SET subscription_token=?
      WHERE id=?
    `).run(token, client.id);

    res.json({
      ok: true,
      token,
      url:
        `${getBaseUrl(req)}/sub/${token}`
    });
  }
);

/* =========================================================
   PUBLIC SUBSCRIPTION
========================================================= */

app.get("/sub/:token", (req, res) => {
  const client = db
    .prepare(`
      SELECT * FROM clients
      WHERE subscription_token=?
    `)
    .get(req.params.token);

  if (!client) {
    return res.status(404).send("Subscription not found");
  }

  if (!usable(client)) {
    res.set("Cache-Control", "no-store");

    return res.status(403).send(
      "Subscription disabled or expired"
    );
  }

  const configs =
    getClientSubscription(client, req);

  if (!configs.length) {
    return res.status(404).send(
      "No configuration available"
    );
  }

  /*
    Standard subscription response:
    base64 encoded configuration list
  */

  const content = base64(
    configs.join("\n")
  );

  res.set({
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "Profile-Title":
      client.email || "Xray Subscription",
    "Profile-Update-Interval": "12",
    "Subscription-Userinfo":
      `upload=0; download=0; total=${Math.round(
        Number(client.total_gb || 0) * 1073741824
      )}; expire=${
        client.expiry_at
          ? Math.floor(
              new Date(client.expiry_at).getTime() / 1000
            )
          : 0
      }`
  });

  res.send(content);
});

/* pretty info page */

app.get("/sub/:token/info", (req, res) => {
  const client = db
    .prepare(`
      SELECT c.*, i.protocol, i.network, i.security
      FROM clients c
      LEFT JOIN inbounds i
      ON i.id=c.inbound_id
      WHERE c.subscription_token=?
    `)
    .get(req.params.token);

  if (!client) {
    return res.status(404).send("Subscription not found");
  }

  const active = usable(client);

  res.send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Subscription</title>
<style>
*{box-sizing:border-box}
body{
 margin:0;
 min-height:100vh;
 display:flex;
 align-items:center;
 justify-content:center;
 font-family:Inter,Arial,sans-serif;
 color:#eafff0;
 background:
 radial-gradient(circle at 20% 20%,rgba(0,255,120,.12),transparent 30%),
 radial-gradient(circle at 80% 80%,rgba(0,255,120,.08),transparent 30%),
 #030605;
}
.card{
 width:min(560px,92%);
 padding:34px;
 border:1px solid rgba(0,255,120,.2);
 border-radius:28px;
 background:rgba(7,14,10,.82);
 box-shadow:0 0 80px rgba(0,255,100,.12);
 backdrop-filter:blur(20px);
}
.logo{
 width:64px;height:64px;
 border-radius:18px;
 display:flex;
 align-items:center;
 justify-content:center;
 font-size:28px;
 background:#06130b;
 border:1px solid #19ff76;
 color:#19ff76;
 box-shadow:0 0 30px rgba(25,255,118,.3);
}
h1{margin:22px 0 8px}
.muted{color:#789082}
.status{
 display:inline-block;
 margin-top:10px;
 padding:7px 13px;
 border-radius:20px;
 background:${active ? "rgba(0,255,120,.12)" : "rgba(255,60,60,.12)"};
 color:${active ? "#19ff76" : "#ff6666"};
}
.row{
 margin-top:24px;
 padding:17px;
 border-radius:17px;
 background:#08110c;
 border:1px solid #102219;
}
.label{
 font-size:11px;
 text-transform:uppercase;
 letter-spacing:1.5px;
 color:#62806d;
 margin-bottom:7px;
}
.value{
 word-break:break-all;
 color:#dffff0;
}
</style>
</head>
<body>
<div class="card">
<div class="logo">✦</div>
<h1>${escapeHtml(client.email)}</h1>
<div class="muted">Xray Subscription</div>
<div class="status">${active ? "● ACTIVE" : "● DISABLED / EXPIRED"}</div>

<div class="row">
<div class="label">Protocol</div>
<div class="value">${escapeHtml(client.protocol || "-").toUpperCase()}</div>
</div>

<div class="row">
<div class="label">Network</div>
<div class="value">${escapeHtml(client.network || "-").toUpperCase()}</div>
</div>

<div class="row">
<div class="label">Subscription</div>
<div class="value">${escapeHtml(
    `${getBaseUrl(req)}/sub/${client.subscription_token}`
  )}</div>
</div>
</div>
</body>
</html>
  `);
});

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* =========================================================
   GROUPS
========================================================= */

app.get("/api/groups", auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT * FROM groups
      ORDER BY created_at DESC
    `).all()
  );
});

app.post("/api/groups", auth, (req, res) => {
  const b = req.body || {};

  const row = {
    id: id(),
    name: b.name || "New Group",
    description: b.description || "",
    total_gb: Number(b.total_gb || 0),
    expiry_at: b.expiry_at || "",
    enabled: b.enabled === false ? 0 : 1,
    created_at: now()
  };

  db.prepare(`
    INSERT INTO groups
    VALUES (
      @id,@name,@description,@total_gb,
      @expiry_at,@enabled,@created_at
    )
  `).run(row);

  res.json(row);
});

app.put("/api/groups/:id", auth, (req, res) => {
  const b = req.body || {};

  db.prepare(`
    UPDATE groups
    SET name=?,description=?,total_gb=?,
        expiry_at=?,enabled=?
    WHERE id=?
  `).run(
    b.name || "Group",
    b.description || "",
    Number(b.total_gb || 0),
    b.expiry_at || "",
    b.enabled === false ? 0 : 1,
    req.params.id
  );

  res.json({ ok: true });
});

app.delete("/api/groups/:id", auth, (req, res) => {
  db.prepare("DELETE FROM groups WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});

/* =========================================================
   NODES
========================================================= */

app.get("/api/nodes", auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT * FROM nodes
      ORDER BY created_at DESC
    `).all()
  );
});

app.post("/api/nodes", auth, (req, res) => {
  const b = req.body || {};

  const row = {
    id: id(),
    name: b.name || "Node",
    address: b.address || "",
    port: Number(b.port || 443),
    username: b.username || "",
    password: b.password || "",
    protocol: b.protocol || "vless",
    status: b.status || "offline",
    config_json: JSON.stringify(b.config || {}),
    created_at: now()
  };

  db.prepare(`
    INSERT INTO nodes
    VALUES (
      @id,@name,@address,@port,@username,
      @password,@protocol,@status,@config_json,@created_at
    )
  `).run(row);

  res.json(row);
});

app.put("/api/nodes/:id", auth, (req, res) => {
  const b = req.body || {};

  db.prepare(`
    UPDATE nodes SET
      name=?,address=?,port=?,username=?,
      password=?,protocol=?,status=?,config_json=?
    WHERE id=?
  `).run(
    b.name || "Node",
    b.address || "",
    Number(b.port || 443),
    b.username || "",
    b.password || "",
    b.protocol || "vless",
    b.status || "offline",
    JSON.stringify(b.config || {}),
    req.params.id
  );

  res.json({ ok: true });
});

app.delete("/api/nodes/:id", auth, (req, res) => {
  db.prepare("DELETE FROM nodes WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});

/* =========================================================
   HOSTS
========================================================= */

app.get("/api/hosts", auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT * FROM hosts
      ORDER BY created_at DESC
    `).all()
  );
});

app.post("/api/hosts", auth, (req, res) => {
  const b = req.body || {};

  const row = {
    id: id(),
    name: b.name || "Host",
    address: b.address || "",
    port: Number(b.port || 443),
    sni: b.sni || "",
    path: b.path || "/",
    security: b.security || "tls",
    config_json: JSON.stringify(b.config || {}),
    created_at: now()
  };

  db.prepare(`
    INSERT INTO hosts
    VALUES (
      @id,@name,@address,@port,@sni,
      @path,@security,@config_json,@created_at
    )
  `).run(row);

  res.json(row);
});

app.put("/api/hosts/:id", auth, (req, res) => {
  const b = req.body || {};

  db.prepare(`
    UPDATE hosts SET
      name=?,address=?,port=?,sni=?,
      path=?,security=?,config_json=?
    WHERE id=?
  `).run(
    b.name || "Host",
    b.address || "",
    Number(b.port || 443),
    b.sni || "",
    b.path || "/",
    b.security || "tls",
    JSON.stringify(b.config || {}),
    req.params.id
  );

  res.json({ ok: true });
});

app.delete("/api/hosts/:id", auth, (req, res) => {
  db.prepare("DELETE FROM hosts WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});

/* =========================================================
   OUTBOUNDS
========================================================= */

app.get("/api/outbounds", auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT * FROM outbounds
      ORDER BY created_at DESC
    `).all()
  );
});

app.post("/api/outbounds", auth, (req, res) => {
  const b = req.body || {};

  const row = {
    id: id(),
    tag: b.tag || "direct",
    protocol: b.protocol || "freedom",
    settings_json: JSON.stringify(b.settings || {}),
    stream_settings_json: JSON.stringify(
      b.stream_settings || {}
    ),
    created_at: now()
  };

  db.prepare(`
    INSERT INTO outbounds
    VALUES (
      @id,@tag,@protocol,@settings_json,
      @stream_settings_json,@created_at
    )
  `).run(row);

  res.json(row);
});

app.put("/api/outbounds/:id", auth, (req, res) => {
  const b = req.body || {};

  db.prepare(`
    UPDATE outbounds SET
      tag=?,protocol=?,settings_json=?,
      stream_settings_json=?
    WHERE id=?
  `).run(
    b.tag || "direct",
    b.protocol || "freedom",
    JSON.stringify(b.settings || {}),
    JSON.stringify(b.stream_settings || {}),
    req.params.id
  );

  res.json({ ok: true });
});

app.delete("/api/outbounds/:id", auth, (req, res) => {
  db.prepare("DELETE FROM outbounds WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});

/* =========================================================
   ROUTING
========================================================= */

app.get("/api/routing", auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT * FROM routings
      ORDER BY created_at DESC
    `).all()
  );
});

app.post("/api/routing", auth, (req, res) => {
  const b = req.body || {};

  const row = {
    id: id(),
    name: b.name || "Rule",
    domain: b.domain || "",
    ip: b.ip || "",
    port: b.port || "",
    outbound_tag: b.outbound_tag || "",
    enabled: b.enabled === false ? 0 : 1,
    config_json: JSON.stringify(b.config || {}),
    created_at: now()
  };

  db.prepare(`
    INSERT INTO routings
    VALUES (
      @id,@name,@domain,@ip,@port,
      @outbound_tag,@enabled,@config_json,@created_at
    )
  `).run(row);

  res.json(row);
});

app.delete("/api/routing/:id", auth, (req, res) => {
  db.prepare("DELETE FROM routings WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});

/* =========================================================
   SETTINGS
========================================================= */

app.get("/api/settings", auth, (req, res) => {
  const rows = db
    .prepare("SELECT key,value FROM settings")
    .all();

  const result = {};

  for (const row of rows) {
    result[row.key] = row.value;
  }

  result.subscription_base_url =
    result.subscription_base_url || "";

  result.subscription_server =
    result.subscription_server || "";

  res.json(result);
});

app.put("/api/settings", auth, (req, res) => {
  const body = req.body || {};

  for (const [key, value] of Object.entries(body)) {
    setSetting(key, value);
  }

  res.json({ ok: true });
});

/* =========================================================
   CONFIG
========================================================= */

app.get("/api/config", auth, (req, res) => {
  res.json({
    xray_core_running: false,
    subscription_enabled: true,
    database: "sqlite",
    note:
      "Management panel and subscription engine are active. Xray Core is not started by this MVP."
  });
});

/* =========================================================
   API DOCS
========================================================= */

app.get("/api/docs", auth, (req, res) => {
  res.json({
    auth: {
      login: "POST /api/login",
      me: "GET /api/me"
    },
    subscription: {
      get:
        "GET /api/clients/:id/subscription",
      regenerate:
        "POST /api/clients/:id/subscription/regenerate",
      public:
        "GET /sub/:token",
      info:
        "GET /sub/:token/info"
    },
    resources: [
      "/api/inbounds",
      "/api/clients",
      "/api/groups",
      "/api/nodes",
      "/api/hosts",
      "/api/outbounds",
      "/api/routing",
      "/api/settings"
    ]
  });
});

/* =========================================================
   FRONTEND
========================================================= */

const publicDir = path.join(__dirname, "..", "public");

app.use(express.static(publicDir));

app.get("*", (req, res, next) => {
  if (
    req.path.startsWith("/api/") ||
    req.path.startsWith("/sub/")
  ) {
    return next();
  }

  res.sendFile(
    path.join(publicDir, "index.html")
  );
});

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "Internal server error"
  });
});

app.listen(PORT, HOST, () => {
  console.log(
    `Xray Panel listening on ${HOST}:${PORT}`
  );
});
