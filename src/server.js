const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || "./data/panel.db";

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "change-this-password";

const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-to-a-long-random-secret";

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL || "";

const dbFile = path.resolve(DB_PATH);

fs.mkdirSync(path.dirname(dbFile), {
  recursive: true
});

const db = new Database(dbFile);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

function now() {
  return new Date().toISOString();
}

function makeId() {
  return crypto.randomUUID();
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function parseJSON(value, fallback = {}) {
  try {
    if (!value) return fallback;
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function cleanUrl(value) {
  return String(value || "").replace(/\/+$/, "");
}

function bool(value) {
  return value ? 1 : 0;
}

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS inbounds (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  remark TEXT DEFAULT '',
  protocol TEXT NOT NULL DEFAULT 'vless',
  listen TEXT DEFAULT '0.0.0.0',
  port INTEGER NOT NULL DEFAULT 443,
  network TEXT DEFAULT 'ws',
  security TEXT DEFAULT 'tls',
  public_address TEXT DEFAULT '',
  settings_json TEXT DEFAULT '{}',
  stream_settings_json TEXT DEFAULT '{}',
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

  FOREIGN KEY(inbound_id)
  REFERENCES inbounds(id)
  ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT DEFAULT '',
  port INTEGER DEFAULT 443,
  protocol TEXT DEFAULT 'vless',
  username TEXT DEFAULT '',
  password TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT DEFAULT '',
  port INTEGER DEFAULT 443,
  sni TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbounds (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'freedom',
  settings_json TEXT DEFAULT '{}',
  stream_settings_json TEXT DEFAULT '{}',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routings (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT DEFAULT 'field',
  domain TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  outbound_tag TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT DEFAULT ''
);
`);

function ensureColumn(table, column, definition) {
  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .map((x) => x.name);

  if (!columns.includes(column)) {
    db.exec(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    );
  }
}

ensureColumn(
  "inbounds",
  "public_address",
  "TEXT DEFAULT ''"
);

ensureColumn(
  "clients",
  "subscription_token",
  "TEXT DEFAULT ''"
);

ensureColumn(
  "clients",
  "subscription_id",
  "TEXT DEFAULT ''"
);

ensureColumn(
  "clients",
  "credential_json",
  "TEXT DEFAULT '{}'"
);

ensureColumn(
  "clients",
  "group_id",
  "TEXT DEFAULT ''"
);

/* Give old clients subscription tokens */
const oldClients = db
  .prepare(`
    SELECT id
    FROM clients
    WHERE subscription_token IS NULL
       OR subscription_token = ''
  `)
  .all();

const updateToken = db.prepare(`
  UPDATE clients
  SET subscription_token = ?
  WHERE id = ?
`);

const tokenTransaction = db.transaction(() => {
  for (const client of oldClients) {
    updateToken.run(makeToken(), client.id);
  }
});

tokenTransaction();

/* =========================
   BASE URL
========================= */

function getBaseUrl(req) {
  if (PUBLIC_BASE_URL) {
    return cleanUrl(PUBLIC_BASE_URL);
  }

  const configured = db
    .prepare(`
      SELECT value
      FROM settings
      WHERE key = 'public_base_url'
    `)
    .get();

  if (configured?.value) {
    return cleanUrl(configured.value);
  }

  const proto = String(
    req.headers["x-forwarded-proto"] ||
      req.protocol ||
      "http"
  ).split(",")[0];

  const host = req.get("host");

  return `${proto}://${host}`;
}

/* =========================
   AUTH
========================= */

function auth(req, res, next) {
  const authorization =
    req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  const token = authorization.slice(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {
  const {
    username,
    password
  } = req.body || {};

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
      username
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
    username: req.user.username
  });
});

/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    time: now()
  });
});

/* =========================
   STATS
========================= */

app.get("/api/stats", auth, (req, res) => {
  const count = (table) =>
    db
      .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
      .get().count;

  res.json({
    inbounds: count("inbounds"),
    clients: count("clients"),
    groups: count("groups"),
    nodes: count("nodes"),
    hosts: count("hosts"),
    outbounds: count("outbounds"),
    routings: count("routings"),

    active_clients: db
      .prepare(`
        SELECT COUNT(*) AS count
        FROM clients
        WHERE enabled = 1
      `)
      .get().count,

    xray_core_running: false
  });
});

/* =========================
   INBOUNDS
========================= */

app.get("/api/inbounds", auth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT *
      FROM inbounds
      ORDER BY created_at DESC
    `)
    .all();

  res.json(rows);
});

app.post("/api/inbounds", auth, (req, res) => {
  const b = req.body || {};
  const inboundId = makeId();

  db.prepare(`
    INSERT INTO inbounds (
      id,
      name,
      remark,
      protocol,
      listen,
      port,
      network,
      security,
      public_address,
      settings_json,
      stream_settings_json,
      enabled,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    inboundId,
    b.name || "New Inbound",
    b.remark || "",
    b.protocol || "vless",
    b.listen || "0.0.0.0",
    Number(b.port || 443),
    b.network || "ws",
    b.security || "tls",
    b.public_address || "",
    JSON.stringify(
      b.settings ||
        parseJSON(b.settings_json, {})
    ),
    JSON.stringify(
      b.stream_settings ||
        parseJSON(b.stream_settings_json, {})
    ),
    bool(b.enabled !== false),
    now()
  );

  res.json(
    db
      .prepare(
        `SELECT * FROM inbounds WHERE id = ?`
      )
      .get(inboundId)
  );
});

app.put("/api/inbounds/:id", auth, (req, res) => {
  const b = req.body || {};

  db.prepare(`
    UPDATE inbounds
    SET
      name = ?,
      remark = ?,
      protocol = ?,
      listen = ?,
      port = ?,
      network = ?,
      security = ?,
      public_address = ?,
      settings_json = ?,
      stream_settings_json = ?,
      enabled = ?
    WHERE id = ?
  `).run(
    b.name || "Inbound",
    b.remark || "",
    b.protocol || "vless",
    b.listen || "0.0.0.0",
    Number(b.port || 443),
    b.network || "ws",
    b.security || "tls",
    b.public_address || "",
    JSON.stringify(
      b.settings ||
        parseJSON(b.settings_json, {})
    ),
    JSON.stringify(
      b.stream_settings ||
        parseJSON(b.stream_settings_json, {})
    ),
    bool(b.enabled !== false),
    req.params.id
  );

  res.json(
    db
      .prepare(
        `SELECT * FROM inbounds WHERE id = ?`
      )
      .get(req.params.id)
  );
});

app.delete("/api/inbounds/:id", auth, (req, res) => {
  db.prepare(
    `DELETE FROM inbounds WHERE id = ?`
  ).run(req.params.id);

  res.json({
    ok: true
  });
});

app.patch(
  "/api/inbounds/:id/toggle",
  auth,
  (req, res) => {
    db.prepare(`
      UPDATE inbounds
      SET enabled = 1 - enabled
      WHERE id = ?
    `).run(req.params.id);

    res.json(
      db
        .prepare(
          `SELECT * FROM inbounds WHERE id = ?`
        )
        .get(req.params.id)
    );
  }
);

/* =========================
   CLIENTS
========================= */

app.get("/api/clients", auth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT
        c.*,
        i.name AS inbound_name,
        i.protocol AS inbound_protocol
      FROM clients c
      LEFT JOIN inbounds i
        ON i.id = c.inbound_id
      ORDER BY c.created_at DESC
    `)
    .all();

  res.json(rows);
});

app.post("/api/clients", auth, (req, res) => {
  const b = req.body || {};

  const clientId = makeId();
  const subscriptionToken =
    b.subscription_token || makeToken();

  const clientUuid =
    b.uuid || crypto.randomUUID();

  db.prepare(`
    INSERT INTO clients (
      id,
      inbound_id,
      email,
      uuid,
      flow,
      total_gb,
      expiry_at,
      reset_days,
      limit_ip,
      telegram_id,
      subscription_id,
      subscription_token,
      group_id,
      comment,
      enabled,
      credential_json,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    clientId,
    b.inbound_id,
    b.email || "client",
    clientUuid,
    b.flow || "",
    Number(b.total_gb || 0),
    b.expiry_at || "",
    Number(b.reset_days || 0),
    Number(b.limit_ip || 0),
    b.telegram_id || "",
    b.subscription_id || "",
    subscriptionToken,
    b.group_id || "",
    b.comment || "",
    bool(b.enabled !== false),
    JSON.stringify(
      b.credential ||
        parseJSON(b.credential_json, {})
    ),
    now()
  );

  res.json(
    db
      .prepare(
        `SELECT * FROM clients WHERE id = ?`
      )
      .get(clientId)
  );
});

app.put("/api/clients/:id", auth, (req, res) => {
  const b = req.body || {};

  db.prepare(`
    UPDATE clients
    SET
      inbound_id = ?,
      email = ?,
      uuid = ?,
      flow = ?,
      total_gb = ?,
      expiry_at = ?,
      reset_days = ?,
      limit_ip = ?,
      telegram_id = ?,
      subscription_id = ?,
      group_id = ?,
      comment = ?,
      enabled = ?,
      credential_json = ?
    WHERE id = ?
  `).run(
    b.inbound_id,
    b.email || "client",
    b.uuid || crypto.randomUUID(),
    b.flow || "",
    Number(b.total_gb || 0),
    b.expiry_at || "",
    Number(b.reset_days || 0),
    Number(b.limit_ip || 0),
    b.telegram_id || "",
    b.subscription_id || "",
    b.group_id || "",
    b.comment || "",
    bool(b.enabled !== false),
    JSON.stringify(
      b.credential ||
        parseJSON(b.credential_json, {})
    ),
    req.params.id
  );

  res.json(
    db
      .prepare(
        `SELECT * FROM clients WHERE id = ?`
      )
      .get(req.params.id)
  );
});

app.delete("/api/clients/:id", auth, (req, res) => {
  db.prepare(
    `DELETE FROM clients WHERE id = ?`
  ).run(req.params.id);

  res.json({
    ok: true
  });
});

app.patch(
  "/api/clients/:id/toggle",
  auth,
  (req, res) => {
    db.prepare(`
      UPDATE clients
      SET enabled = 1 - enabled
      WHERE id = ?
    `).run(req.params.id);

    res.json(
      db
        .prepare(
          `SELECT * FROM clients WHERE id = ?`
        )
        .get(req.params.id)
    );
  }
);

/* =========================
   SUBSCRIPTION HELPERS
========================= */

function parseTransport(inbound) {
  const stream =
    parseJSON(
      inbound.stream_settings_json,
      {}
    );

  return {
    stream,

    ws:
      stream.wsSettings ||
      stream.ws ||
      {},

    grpc:
      stream.grpcSettings ||
      stream.grpc ||
      {},

    tcp:
      stream.tcpSettings ||
      stream.tcp ||
      {},

    tls:
      stream.tlsSettings ||
      stream.tls ||
      {},

    reality:
      stream.realitySettings ||
      stream.reality ||
      {}
  };
}

function getPublicHost(req, inbound, transport) {
  if (inbound.public_address) {
    return inbound.public_address;
  }

  const possible = [
    transport.ws.host,
    transport.tls.serverName,
    transport.reality.serverName,
    inbound.listen
  ];

  for (const value of possible) {
    if (
      value &&
      ![
        "0.0.0.0",
        "::",
        "127.0.0.1",
        "localhost"
      ].includes(String(value))
    ) {
      return String(value);
    }
  }

  try {
    return new URL(getBaseUrl(req)).hostname;
  } catch {
    return req.hostname;
  }
}

function queryString(params) {
  const q = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (
      value !== undefined &&
      value !== null &&
      String(value) !== ""
    ) {
      q.set(key, String(value));
    }
  }

  return q.toString();
}

/* =========================
   VLESS
========================= */

function generateVless(req, inbound, client) {
  const transport = parseTransport(inbound);

  const host = getPublicHost(
    req,
    inbound,
    transport
  );

  const network =
    inbound.network ||
    transport.stream.network ||
    "tcp";

  const security =
    inbound.security ||
    transport.stream.security ||
    "none";

  const params = {
    encryption: "none",
    type: network,
    security
  };

  if (client.flow) {
    params.flow = client.flow;
  }

  if (network === "ws") {
    params.host =
      transport.ws.host || "";

    params.path =
      transport.ws.path || "/";
  }

  if (network === "grpc") {
    params.serviceName =
      transport.grpc.serviceName || "";

    if (transport.grpc.mode) {
      params.mode = transport.grpc.mode;
    }
  }

  if (
    network === "tcp" &&
    transport.tcp.header &&
    transport.tcp.header.type
  ) {
    params.headerType =
      transport.tcp.header.type;
  }

  if (security === "tls") {
    params.sni =
      transport.tls.serverName ||
      "";

    params.fp =
      transport.tls.fingerprint ||
      "";

    if (transport.tls.alpn) {
      params.alpn =
        Array.isArray(transport.tls.alpn)
          ? transport.tls.alpn.join(",")
          : transport.tls.alpn;
    }
  }

  if (security === "reality") {
    params.sni =
      transport.reality.serverName ||
      "";

    params.fp =
      transport.reality.fingerprint ||
      "";

    params.pbk =
      transport.reality.publicKey ||
      transport.reality.pbk ||
      "";

    params.sid =
      transport.reality.shortId ||
      transport.reality.sid ||
      "";

    params.spx =
      transport.reality.spiderX ||
      transport.reality.spx ||
      "";
  }

  const query = queryString(params);

  const name =
    client.email ||
    inbound.remark ||
    inbound.name ||
    "Xray";

  return (
    `vless://${encodeURIComponent(client.uuid)}` +
    `@${host}:${Number(inbound.port)}` +
    `?${query}` +
    `#${encodeURIComponent(name)}`
  );
}

/* =========================
   VMESS
========================= */

function generateVmess(req, inbound, client) {
  const transport = parseTransport(inbound);

  const host = getPublicHost(
    req,
    inbound,
    transport
  );

  const network =
    inbound.network ||
    "tcp";

  const security =
    inbound.security ||
    "none";

  const vmess = {
    v: "2",

    ps:
      client.email ||
      inbound.name ||
      "Xray",

    add: host,

    port: String(
      Number(inbound.port)
    ),

    id: client.uuid,

    aid: "0",

    scy: "auto",

    net: network,

    type: "none",

    host:
      transport.ws.host || "",

    path:
      transport.ws.path || "",

    tls:
      security === "tls"
        ? "tls"
        : "",

    sni:
      transport.tls.serverName ||
      "",

    alpn:
      Array.isArray(transport.tls.alpn)
        ? transport.tls.alpn.join(",")
        : (
            transport.tls.alpn ||
            ""
          )
  };

  if (network === "grpc") {
    vmess.path =
      transport.grpc.serviceName || "";
  }

  return (
    "vmess://" +
    Buffer
      .from(JSON.stringify(vmess))
      .toString("base64")
  );
}

/* =========================
   TROJAN
========================= */

function generateTrojan(req, inbound, client) {
  const transport = parseTransport(inbound);

  const host = getPublicHost(
    req,
    inbound,
    transport
  );

  const credentials =
    parseJSON(
      client.credential_json,
      {}
    );

  const password =
    credentials.password ||
    client.uuid;

  const network =
    inbound.network ||
    "tcp";

  const security =
    inbound.security ||
    "tls";

  const params = {
    type: network,
    security
  };

  if (network === "ws") {
    params.host =
      transport.ws.host || "";

    params.path =
      transport.ws.path || "/";
  }

  if (network === "grpc") {
    params.serviceName =
      transport.grpc.serviceName || "";
  }

  if (security === "tls") {
    params.sni =
      transport.tls.serverName || "";
  }

  return (
    `trojan://${encodeURIComponent(password)}` +
    `@${host}:${Number(inbound.port)}` +
    `?${queryString(params)}` +
    `#${encodeURIComponent(
      client.email || inbound.name
    )}`
  );
}

/* =========================
   GENERATE CONFIG
========================= */

function generateConfig(req, inbound, client) {
  const protocol =
    String(inbound.protocol || "")
      .toLowerCase();

  switch (protocol) {
    case "vless":
      return generateVless(
        req,
        inbound,
        client
      );

    case "vmess":
      return generateVmess(
        req,
        inbound,
        client
      );

    case "trojan":
      return generateTrojan(
        req,
        inbound,
        client
      );

    default:
      throw new Error(
        `Unsupported protocol: ${protocol}`
      );
  }
}

/* =========================
   GET CLIENT SUBSCRIPTION
========================= */

app.get(
  "/api/clients/:id/subscription",
  auth,
  (req, res) => {
    const client = db
      .prepare(`
        SELECT
          c.*,
          i.name AS inbound_name,
          i.remark AS inbound_remark,
          i.protocol,
          i.port,
          i.network,
          i.security,
          i.listen,
          i.public_address,
          i.settings_json,
          i.stream_settings_json
        FROM clients c
        JOIN inbounds i
          ON i.id = c.inbound_id
        WHERE c.id = ?
      `)
      .get(req.params.id);

    if (!client) {
      return res.status(404).json({
        error: "Client not found"
      });
    }

    if (
      !client.subscription_token
    ) {
      const newToken = makeToken();

      db.prepare(`
        UPDATE clients
        SET subscription_token = ?
        WHERE id = ?
      `).run(
        newToken,
        client.id
      );

      client.subscription_token =
        newToken;
    }

    try {
      const uri = generateConfig(
        req,
        client,
        client
      );

      const base = getBaseUrl(req);

      res.json({
        url:
          `${base}/sub/` +
          client.subscription_token,

        info_url:
          `${base}/sub/` +
          client.subscription_token +
          "/info",

        plain_url:
          `${base}/sub/` +
          client.subscription_token +
          "?format=plain",

        protocol:
          client.protocol,

        uri,

        client: {
          id: client.id,
          email: client.email,
          uuid: client.uuid,
          enabled:
            Boolean(client.enabled),

          total_gb:
            Number(client.total_gb || 0),

          expiry_at:
            client.expiry_at || ""
        }
      });
    } catch (error) {
      res.status(400).json({
        error: error.message
      });
    }
  }
);

/* =========================
   RAW CONFIG
========================= */

app.get(
  "/api/clients/:id/config",
  auth,
  (req, res) => {
    const client = db
      .prepare(`
        SELECT
          c.*,
          i.*
        FROM clients c
        JOIN inbounds i
          ON i.id = c.inbound_id
        WHERE c.id = ?
      `)
      .get(req.params.id);

    if (!client) {
      return res.status(404).json({
        error: "Client not found"
      });
    }

    try {
      res.json({
        uri:
          generateConfig(
            req,
            client,
            client
          )
      });
    } catch (error) {
      res.status(400).json({
        error: error.message
      });
    }
  }
);

/* =========================
   REGENERATE SUBSCRIPTION
========================= */

app.post(
  "/api/clients/:id/subscription/regenerate",
  auth,
  (req, res) => {
    const client = db
      .prepare(`
        SELECT *
        FROM clients
        WHERE id = ?
      `)
      .get(req.params.id);

    if (!client) {
      return res.status(404).json({
        error: "Client not found"
      });
    }

    const newToken = makeToken();

    db.prepare(`
      UPDATE clients
      SET subscription_token = ?
      WHERE id = ?
    `).run(
      newToken,
      client.id
    );

    res.json({
      ok: true,

      subscription_token:
        newToken,

      url:
        `${getBaseUrl(req)}/sub/` +
        newToken
    });
  }
);

/* =========================
   PUBLIC SUBSCRIPTION
========================= */

app.get(
  "/sub/:token",
  (req, res) => {
    const client = db
      .prepare(`
        SELECT
          c.*,
          i.name AS inbound_name,
          i.remark AS inbound_remark,
          i.protocol,
          i.port,
          i.network,
          i.security,
          i.listen,
          i.public_address,
          i.settings_json,
          i.stream_settings_json
        FROM clients c
        JOIN inbounds i
          ON i.id = c.inbound_id
        WHERE c.subscription_token = ?
      `)
      .get(req.params.token);

    if (!client) {
      return res
        .status(404)
        .type("text")
        .send("Subscription not found");
    }

    if (!client.enabled) {
      return res
        .status(403)
        .type("text")
        .send("Subscription disabled");
    }

    if (
      client.expiry_at &&
      !Number.isNaN(
        Date.parse(client.expiry_at)
      ) &&
      Date.parse(client.expiry_at) <
        Date.now()
    ) {
      return res
        .status(403)
        .type("text")
        .send("Subscription expired");
    }

    try {
      const uri = generateConfig(
        req,
        client,
        client
      );

      res.set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate"
      );

      res.set(
        "Content-Disposition",
        "inline"
      );

      /*
       * Most Xray clients expect a
       * Base64 encoded subscription.
       *
       * Add ?format=plain when debugging.
       */

      if (
        String(req.query.format)
          .toLowerCase() === "plain"
      ) {
        return res
          .type("text/plain")
          .send(uri + "\n");
      }

      const subscription =
        Buffer
          .from(uri + "\n")
          .toString("base64");

      return res
        .type("text/plain")
        .send(subscription);
    } catch (error) {
      return res
        .status(400)
        .type("text")
        .send(error.message);
    }
  }
);

/* =========================
   SUBSCRIPTION INFO PAGE
========================= */

app.get(
  "/sub/:token/info",
  (req, res) => {
    const client = db
      .prepare(`
        SELECT
          c.*,
          i.name AS inbound_name,
          i.protocol,
          i.port,
          i.network,
          i.security,
          i.public_address,
          i.stream_settings_json
        FROM clients c
        JOIN inbounds i
          ON i.id = c.inbound_id
        WHERE c.subscription_token = ?
      `)
      .get(req.params.token);

    if (!client) {
      return res
        .status(404)
        .send("Subscription not found");
    }

    let uri = "";

    try {
      uri = generateConfig(
        req,
        client,
        client
      );
    } catch (error) {
      uri = error.message;
    }

    const url =
      `${getBaseUrl(req)}/sub/` +
      client.subscription_token;

    function escapeHtml(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    res.type("html").send(`
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>
  ${escapeHtml(client.email)}
  · Subscription
</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;

  min-height: 100vh;

  display: grid;

  place-items: center;

  padding: 20px;

  background:
    radial-gradient(
      circle at 20% 0,
      #0b351a,
      transparent 35%
    ),
    #030604;

  color: #eafff0;

  font-family:
    Inter,
    system-ui,
    Arial,
    sans-serif;
}

.card {
  width: min(760px, 95vw);

  background: #09100c;

  border:
    1px solid #1c4528;

  border-radius: 24px;

  padding: 30px;

  box-shadow:
    0 0 80px
    rgba(50,255,120,.12);
}

.logo {
  color: #49ff8b;

  font-weight: 900;

  font-size: 14px;

  letter-spacing: 2px;
}

h1 {
  margin:
    10px
    0
    5px;

  font-size: 30px;
}

.muted {
  color: #82988a;
}

.badge {
  display: inline-block;

  margin-top: 14px;

  padding:
    6px
    11px;

  border-radius: 999px;

  color: #68ff9d;

  background: #0a2715;

  border:
    1px solid #216b39;
}

.box {
  margin-top: 18px;

  padding: 15px;

  background: #030604;

  border:
    1px solid #17351f;

  border-radius: 14px;

  word-break: break-all;

  color: #aaffc1;
}

button,
a {
  display: inline-block;

  margin-top: 12px;

  padding:
    11px
    15px;

  border-radius: 11px;

  border: 0;

  background: #49ff8b;

  color: #031009;

  font-weight: 900;

  text-decoration: none;

  cursor: pointer;
}

</style>

</head>

<body>

<main class="card">

<div class="logo">
NEON XRAY
</div>

<h1>
${escapeHtml(client.email)}
</h1>

<div class="muted">
Your Xray subscription is ready.
</div>

<div class="badge">
${escapeHtml(client.protocol)}
</div>

<div class="box" id="url">
${escapeHtml(url)}
</div>

<button
  onclick="
    navigator.clipboard.writeText(
      document.getElementById('url').innerText
    )
  "
>
Copy Subscription URL
</button>

<a href="${escapeHtml(url)}">
Open Subscription
</a>

<div class="box">

<strong>
Generated Config
</strong>

<br><br>

${escapeHtml(uri)}

</div>

<div class="muted">

Traffic:
${escapeHtml(client.total_gb || 0)}
GB

&nbsp; · &nbsp;

Expiry:
${escapeHtml(client.expiry_at || "Unlimited")}

</div>

</main>

</body>

</html>
`);
  }
);

/* =========================
   GENERIC CRUD
========================= */

function createCrud(
  endpoint,
  table,
  fields
) {
  app.get(
    `/api/${endpoint}`,
    auth,
    (req, res) => {
      res.json(
        db
          .prepare(`
            SELECT *
            FROM ${table}
            ORDER BY created_at DESC
          `)
          .all()
      );
    }
  );

  app.post(
    `/api/${endpoint}`,
    auth,
    (req, res) => {
      const body = req.body || {};
      const itemId = makeId();

      const values =
        fields.map(
          (field) =>
            body[field] ?? ""
        );

      const placeholders =
        fields
          .map(() => "?")
          .join(",");

      db.prepare(`
        INSERT INTO ${table}
        (
          id,
          ${fields.join(",")},
          created_at
        )
        VALUES
        (
          ?,
          ${placeholders},
          ?
        )
      `).run(
        itemId,
        ...values,
        now()
      );

      res.json(
        db
          .prepare(`
            SELECT *
            FROM ${table}
            WHERE id = ?
          `)
          .get(itemId)
      );
    }
  );

  app.put(
    `/api/${endpoint}/:id`,
    auth,
    (req, res) => {
      const body = req.body || {};

      db.prepare(`
        UPDATE ${table}
        SET
          ${fields
            .map(
              (field) =>
                `${field} = ?`
            )
            .join(",")}
        WHERE id = ?
      `).run(
        ...fields.map(
          (field) =>
            body[field] ?? ""
        ),
        req.params.id
      );

      res.json(
        db
          .prepare(`
            SELECT *
            FROM ${table}
            WHERE id = ?
          `)
          .get(req.params.id)
      );
    }
  );

  app.delete(
    `/api/${endpoint}/:id`,
    auth,
    (req, res) => {
      db.prepare(`
        DELETE FROM ${table}
        WHERE id = ?
      `).run(req.params.id);

      res.json({
        ok: true
      });
    }
  );
}

createCrud(
  "groups",
  "groups",
  [
    "name",
    "description"
  ]
);

createCrud(
  "nodes",
  "nodes",
  [
    "name",
    "address",
    "port",
    "protocol",
    "username",
    "password",
    "enabled"
  ]
);

createCrud(
  "hosts",
  "hosts",
  [
    "name",
    "address",
    "port",
    "sni",
    "enabled"
  ]
);

createCrud(
  "outbounds",
  "outbounds",
  [
    "name",
    "protocol",
    "settings_json",
    "stream_settings_json",
    "enabled"
  ]
);

createCrud(
  "routing",
  "routings",
  [
    "name",
    "type",
    "domain",
    "ip",
    "outbound_tag",
    "enabled"
  ]
);

/* =========================
   SETTINGS
========================= */

app.get(
  "/api/settings",
  auth,
  (req, res) => {
    const rows = db
      .prepare(`
        SELECT key, value
        FROM settings
      `)
      .all();

    res.json(
      Object.fromEntries(
        rows.map((row) => [
          row.key,
          row.value
        ])
      )
    );
  }
);

app.put(
  "/api/settings",
  auth,
  (req, res) => {
    const statement =
      db.prepare(`
        INSERT INTO settings
        (key, value)
        VALUES (?, ?)

        ON CONFLICT(key)
        DO UPDATE SET
          value = excluded.value
      `);

    const transaction =
      db.transaction((data) => {
        for (
          const [key, value]
          of Object.entries(data || {})
        ) {
          statement.run(
            key,
            String(value ?? "")
          );
        }
      });

    transaction(req.body);

    res.json({
      ok: true
    });
  }
);

/* =========================
   CONFIG / DOCS
========================= */

app.get(
  "/api/config",
  auth,
  (req, res) => {
    res.json({
      xray_core_running: false,

      note:
        "This Node.js panel generates and serves Xray subscriptions. Xray Core is not started by this process."
    });
  }
);

app.get(
  "/api/docs",
  auth,
  (req, res) => {
    res.json({
      subscription:
        "GET /sub/:token",

      plain_subscription:
        "GET /sub/:token?format=plain",

      subscription_info:
        "GET /sub/:token/info",

      client_subscription:
        "GET /api/clients/:id/subscription",

      client_config:
        "GET /api/clients/:id/config",

      regenerate:
        "POST /api/clients/:id/subscription/regenerate"
    });
  }
);

/* =========================
   STATIC FRONTEND
========================= */

app.use(
  express.static(
    path.join(
      __dirname,
      "../public"
    )
  )
);

/*
 * IMPORTANT:
 *
 * Express 5 does NOT accept:
 *
 * app.get("*", ...)
 *
 * Therefore we use middleware here.
 */

app.use(
  (req, res, next) => {
    if (req.method !== "GET") {
      return next();
    }

    if (
      req.path.startsWith("/api/")
    ) {
      return res.status(404).json({
        error: "API endpoint not found"
      });
    }

    if (
      req.path.startsWith("/sub/")
    ) {
      return res.status(404).send(
        "Subscription not found"
      );
    }

    return res.sendFile(
      path.join(
        __dirname,
        "../public/index.html"
      )
    );
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, req, res, next) => {
    console.error(err);

    res.status(500).json({
      error:
        "Internal server error"
    });
  }
);

/* =========================
   START
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Xray Panel listening on 0.0.0.0:${PORT}`
    );
  }
);
