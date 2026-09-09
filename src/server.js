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

const DB_PATH =
  process.env.DB_PATH || "./data/panel.db";

/* =========================================================
   DATABASE
========================================================= */

const dbDir = path.dirname(DB_PATH);

if (dbDir !== ".") {
  fs.mkdirSync(dbDir, {
    recursive: true
  });
}

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS inbounds (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  listen TEXT DEFAULT '',
  transport TEXT DEFAULT 'tcp',
  security TEXT DEFAULT 'none',
  remark TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  inbound_id TEXT NOT NULL,
  email TEXT NOT NULL,
  uuid TEXT NOT NULL,
  password TEXT DEFAULT '',
  flow TEXT DEFAULT '',
  total_gb REAL DEFAULT 0,
  expiry_time TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER DEFAULT 443,
  protocol TEXT DEFAULT 'https',
  path TEXT DEFAULT '/',
  sni TEXT DEFAULT '',
  remark TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER DEFAULT 443,
  api_url TEXT DEFAULT '',
  username TEXT DEFAULT '',
  remark TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbounds (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  address TEXT DEFAULT '',
  port INTEGER DEFAULT 0,
  settings TEXT DEFAULT '{}',
  remark TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  port TEXT DEFAULT '',
  protocol TEXT DEFAULT '',
  source TEXT DEFAULT '',
  outbound TEXT NOT NULL,
  enabled INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT DEFAULT ''
);
`);

/* =========================================================
   EXPRESS
========================================================= */

app.use(express.json());

app.use(
  express.urlencoded({
    extended: true
  })
);

app.use(
  express.static(
    path.join(__dirname, "../public")
  )
);

/* =========================================================
   HELPERS
========================================================= */

function now() {
  return new Date().toISOString();
}

function id() {
  return crypto.randomUUID();
}

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
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  const token = header.substring(7);

  try {
    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid token"
    });
  }
}

function clean(value) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value).trim();
}

function boolValue(value, defaultValue = 1) {
  if (value === undefined) {
    return defaultValue;
  }

  if (
    value === true ||
    value === 1 ||
    value === "1" ||
    value === "true"
  ) {
    return 1;
  }

  return 0;
}

function integerValue(value, fallback = 0) {
  const number = Number(value);

  if (!Number.isInteger(number)) {
    return fallback;
  }

  return number;
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "xray-panel"
  });
});

/* =========================================================
   AUTH
========================================================= */

app.post("/api/login", (req, res) => {
  const username =
    clean(req.body.username);

  const password =
    clean(req.body.password);

  if (
    username !== ADMIN_USER ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error:
        "Invalid username or password"
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

/* =========================================================
   INBOUNDS
========================================================= */

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
  const name = clean(req.body.name);
  const protocol =
    clean(req.body.protocol);

  const port =
    integerValue(req.body.port);

  const listen =
    clean(req.body.listen);

  const transport =
    clean(req.body.transport) || "tcp";

  const security =
    clean(req.body.security) || "none";

  const remark =
    clean(req.body.remark);

  if (!name || !protocol) {
    return res.status(400).json({
      error:
        "Name and protocol are required"
    });
  }

  if (
    port < 1 ||
    port > 65535
  ) {
    return res.status(400).json({
      error: "Invalid port"
    });
  }

  const inboundId = id();
  const createdAt = now();

  db.prepare(`
    INSERT INTO inbounds (
      id,
      name,
      protocol,
      port,
      listen,
      transport,
      security,
      remark,
      enabled,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    inboundId,
    name,
    protocol,
    port,
    listen,
    transport,
    security,
    remark,
    1,
    createdAt
  );

  const row = db
    .prepare(
      "SELECT * FROM inbounds WHERE id = ?"
    )
    .get(inboundId);

  res.status(201).json(row);
});

app.put(
  "/api/inbounds/:id",
  auth,
  (req, res) => {
    const existing = db
      .prepare(
        "SELECT * FROM inbounds WHERE id = ?"
      )
      .get(req.params.id);

    if (!existing) {
      return res.status(404).json({
        error: "Inbound not found"
      });
    }

    const name =
      clean(req.body.name) ||
      existing.name;

    const protocol =
      clean(req.body.protocol) ||
      existing.protocol;

    const port =
      req.body.port === undefined
        ? existing.port
        : integerValue(req.body.port);

    const listen =
      req.body.listen === undefined
        ? existing.listen
        : clean(req.body.listen);

    const transport =
      req.body.transport === undefined
        ? existing.transport
        : clean(req.body.transport);

    const security =
      req.body.security === undefined
        ? existing.security
        : clean(req.body.security);

    const remark =
      req.body.remark === undefined
        ? existing.remark
        : clean(req.body.remark);

    const enabled =
      boolValue(
        req.body.enabled,
        existing.enabled
      );

    if (
      port < 1 ||
      port > 65535
    ) {
      return res.status(400).json({
        error: "Invalid port"
      });
    }

    db.prepare(`
      UPDATE inbounds
      SET
        name = ?,
        protocol = ?,
        port = ?,
        listen = ?,
        transport = ?,
        security = ?,
        remark = ?,
        enabled = ?
      WHERE id = ?
    `).run(
      name,
      protocol,
      port,
      listen,
      transport,
      security,
      remark,
      enabled,
      req.params.id
    );

    res.json(
      db
        .prepare(
          "SELECT * FROM inbounds WHERE id = ?"
        )
        .get(req.params.id)
    );
  }
);

app.delete(
  "/api/inbounds/:id",
  auth,
  (req, res) => {
    const transaction =
      db.transaction(() => {
        db.prepare(
          "DELETE FROM clients WHERE inbound_id = ?"
        ).run(req.params.id);

        return db
          .prepare(
            "DELETE FROM inbounds WHERE id = ?"
          )
          .run(req.params.id);
      });

    const result = transaction();

    if (result.changes === 0) {
      return res.status(404).json({
        error: "Inbound not found"
      });
    }

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   CLIENTS
========================================================= */

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
  const inboundId =
    clean(req.body.inbound_id);

  const email =
    clean(req.body.email);

  if (!inboundId || !email) {
    return res.status(400).json({
      error:
        "Inbound and email are required"
    });
  }

  const inbound = db
    .prepare(
      "SELECT * FROM inbounds WHERE id = ?"
    )
    .get(inboundId);

  if (!inbound) {
    return res.status(404).json({
      error: "Inbound not found"
    });
  }

  const clientId = id();
  const uuid =
    clean(req.body.uuid) ||
    crypto.randomUUID();

  const password =
    clean(req.body.password);

  const flow =
    clean(req.body.flow);

  const totalGb =
    Number(req.body.total_gb) || 0;

  const expiryTime =
    clean(req.body.expiry_time);

  const createdAt = now();

  db.prepare(`
    INSERT INTO clients (
      id,
      inbound_id,
      email,
      uuid,
      password,
      flow,
      total_gb,
      expiry_time,
      enabled,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    clientId,
    inboundId,
    email,
    uuid,
    password,
    flow,
    totalGb,
    expiryTime,
    1,
    createdAt
  );

  res.status(201).json(
    db
      .prepare(
        "SELECT * FROM clients WHERE id = ?"
      )
      .get(clientId)
  );
});

app.put(
  "/api/clients/:id",
  auth,
  (req, res) => {
    const existing = db
      .prepare(
        "SELECT * FROM clients WHERE id = ?"
      )
      .get(req.params.id);

    if (!existing) {
      return res.status(404).json({
        error: "Client not found"
      });
    }

    const inboundId =
      req.body.inbound_id === undefined
        ? existing.inbound_id
        : clean(req.body.inbound_id);

    const inbound = db
      .prepare(
        "SELECT * FROM inbounds WHERE id = ?"
      )
      .get(inboundId);

    if (!inbound) {
      return res.status(404).json({
        error: "Inbound not found"
      });
    }

    const email =
      req.body.email === undefined
        ? existing.email
        : clean(req.body.email);

    const uuid =
      req.body.uuid === undefined
        ? existing.uuid
        : clean(req.body.uuid);

    const password =
      req.body.password === undefined
        ? existing.password
        : clean(req.body.password);

    const flow =
      req.body.flow === undefined
        ? existing.flow
        : clean(req.body.flow);

    const totalGb =
      req.body.total_gb === undefined
        ? existing.total_gb
        : Number(req.body.total_gb) || 0;

    const expiryTime =
      req.body.expiry_time === undefined
        ? existing.expiry_time
        : clean(req.body.expiry_time);

    const enabled =
      boolValue(
        req.body.enabled,
        existing.enabled
      );

    db.prepare(`
      UPDATE clients
      SET
        inbound_id = ?,
        email = ?,
        uuid = ?,
        password = ?,
        flow = ?,
        total_gb = ?,
        expiry_time = ?,
        enabled = ?
      WHERE id = ?
    `).run(
      inboundId,
      email,
      uuid,
      password,
      flow,
      totalGb,
      expiryTime,
      enabled,
      req.params.id
    );

    res.json(
      db
        .prepare(
          "SELECT * FROM clients WHERE id = ?"
        )
        .get(req.params.id)
    );
  }
);

app.delete(
  "/api/clients/:id",
  auth,
  (req, res) => {
    const result = db
      .prepare(
        "DELETE FROM clients WHERE id = ?"
      )
      .run(req.params.id);

    if (result.changes === 0) {
      return res.status(404).json({
        error: "Client not found"
      });
    }

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   GENERIC CRUD FACTORY
========================================================= */

function createCrudRoutes({
  route,
  table,
  fields,
  required = []
}) {
  app.get(
    `/api/${route}`,
    auth,
    (req, res) => {
      const rows = db
        .prepare(`
          SELECT *
          FROM ${table}
          ORDER BY created_at DESC
        `)
        .all();

      res.json(rows);
    }
  );

  app.post(
    `/api/${route}`,
    auth,
    (req, res) => {
      for (const field of required) {
        if (!clean(req.body[field])) {
          return res.status(400).json({
            error:
              `${field} is required`
          });
        }
      }

      const newId = id();
      const createdAt = now();

      const columns = [
        "id",
        ...fields,
        "created_at"
      ];

      const values = [
        newId,
        ...fields.map((field) => {
          if (
            field === "port"
          ) {
            return integerValue(
              req.body[field],
              0
            );
          }

          if (
            field === "enabled"
          ) {
            return boolValue(
              req.body[field],
              1
            );
          }

          return clean(
            req.body[field]
          );
        }),
        createdAt
      ];

      const placeholders =
        columns
          .map(() => "?")
          .join(", ");

      db.prepare(`
        INSERT INTO ${table}
        (${columns.join(", ")})
        VALUES (${placeholders})
      `).run(...values);

      const row = db
        .prepare(
          `SELECT * FROM ${table} WHERE id = ?`
        )
        .get(newId);

      res.status(201).json(row);
    }
  );

  app.put(
    `/api/${route}/:id`,
    auth,
    (req, res) => {
      const existing = db
        .prepare(
          `SELECT * FROM ${table} WHERE id = ?`
        )
        .get(req.params.id);

      if (!existing) {
        return res.status(404).json({
          error:
            `${route} item not found`
        });
      }

      const setParts = [];
      const values = [];

      for (const field of fields) {
        if (req.body[field] === undefined) {
          continue;
        }

        let value;

        if (field === "port") {
          value =
            integerValue(
              req.body[field],
              existing[field]
            );
        } else if (
          field === "enabled"
        ) {
          value =
            boolValue(
              req.body[field],
              existing[field]
            );
        } else {
          value =
            clean(req.body[field]);
        }

        setParts.push(
          `${field} = ?`
        );

        values.push(value);
      }

      if (setParts.length === 0) {
        return res.json(existing);
      }

      values.push(req.params.id);

      db.prepare(`
        UPDATE ${table}
        SET ${setParts.join(", ")}
        WHERE id = ?
      `).run(...values);

      const row = db
        .prepare(
          `SELECT * FROM ${table} WHERE id = ?`
        )
        .get(req.params.id);

      res.json(row);
    }
  );

  app.delete(
    `/api/${route}/:id`,
    auth,
    (req, res) => {
      const result = db
        .prepare(
          `DELETE FROM ${table} WHERE id = ?`
        )
        .run(req.params.id);

      if (result.changes === 0) {
        return res.status(404).json({
          error:
            `${route} item not found`
        });
      }

      res.json({
        ok: true
      });
    }
  );
}

/* =========================================================
   HOSTS
========================================================= */

createCrudRoutes({
  route: "hosts",
  table: "hosts",

  fields: [
    "name",
    "address",
    "port",
    "protocol",
    "path",
    "sni",
    "remark",
    "enabled"
  ],

  required: [
    "name",
    "address"
  ]
});

/* =========================================================
   NODES
========================================================= */

createCrudRoutes({
  route: "nodes",
  table: "nodes",

  fields: [
    "name",
    "address",
    "port",
    "api_url",
    "username",
    "remark",
    "enabled"
  ],

  required: [
    "name",
    "address"
  ]
});

/* =========================================================
   GROUPS
========================================================= */

createCrudRoutes({
  route: "groups",
  table: "groups",

  fields: [
    "name",
    "description",
    "enabled"
  ],

  required: [
    "name"
  ]
});

/* =========================================================
   OUTBOUNDS
========================================================= */

createCrudRoutes({
  route: "outbounds",
  table: "outbounds",

  fields: [
    "name",
    "protocol",
    "address",
    "port",
    "settings",
    "remark",
    "enabled"
  ],

  required: [
    "name",
    "protocol"
  ]
});

/* =========================================================
   ROUTING
========================================================= */

createCrudRoutes({
  route: "routing",
  table: "routing_rules",

  fields: [
    "name",
    "domain",
    "ip",
    "port",
    "protocol",
    "source",
    "outbound",
    "enabled"
  ],

  required: [
    "name",
    "outbound"
  ]
});

/* =========================================================
   SETTINGS
========================================================= */

app.get(
  "/api/settings",
  auth,
  (req, res) => {
    const rows = db
      .prepare(`
        SELECT key, value
        FROM settings
        ORDER BY key
      `)
      .all();

    const result = {};

    for (const row of rows) {
      result[row.key] = row.value;
    }

    res.json(result);
  }
);

app.put(
  "/api/settings",
  auth,
  (req, res) => {
    const data =
      req.body || {};

    const transaction =
      db.transaction(() => {
        const statement =
          db.prepare(`
            INSERT INTO settings
            (key, value)
            VALUES (?, ?)
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
          `);

        for (const [key, value] of Object.entries(data)) {
          statement.run(
            clean(key),
            typeof value === "object"
              ? JSON.stringify(value)
              : clean(value)
          );
        }
      });

    transaction();

    const rows = db
      .prepare(`
        SELECT key, value
        FROM settings
        ORDER BY key
      `)
      .all();

    const result = {};

    for (const row of rows) {
      result[row.key] = row.value;
    }

    res.json(result);
  }
);

/* =========================================================
   DASHBOARD STATS
========================================================= */

app.get(
  "/api/stats",
  auth,
  (req, res) => {
    const inbounds =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM inbounds"
        )
        .get().count;

    const clients =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM clients"
        )
        .get().count;

    const activeClients =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM clients WHERE enabled = 1"
        )
        .get().count;

    const hosts =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM hosts"
        )
        .get().count;

    const nodes =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM nodes"
        )
        .get().count;

    const groups =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM groups"
        )
        .get().count;

    const outbounds =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM outbounds"
        )
        .get().count;

    const routingRules =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM routing_rules"
        )
        .get().count;

    res.json({
      inbounds,
      clients,
      activeClients,
      hosts,
      nodes,
      groups,
      outbounds,
      routingRules
    });
  }
);

/* =========================================================
   XRAY CONFIG SKELETON
========================================================= */

app.get(
  "/api/config",
  auth,
  (req, res) => {
    const inbounds =
      db
        .prepare(
          "SELECT * FROM inbounds ORDER BY created_at"
        )
        .all();

    const clients =
      db
        .prepare(
          "SELECT * FROM clients WHERE enabled = 1"
        )
        .all();

    const outbounds =
      db
        .prepare(
          "SELECT * FROM outbounds WHERE enabled = 1"
        )
        .all();

    const routing =
      db
        .prepare(
          "SELECT * FROM routing_rules WHERE enabled = 1"
        )
        .all();

    res.json({
      type:
        "xray-config-skeleton",

      note:
        "This panel stores management data. Xray Core is not started by this MVP.",

      inbounds,
      clients,
      outbounds,
      routing
    });
  }
);

/* =========================================================
   API SUMMARY
========================================================= */

app.get(
  "/api",
  auth,
  (req, res) => {
    res.json({
      name: "Xray Panel API",

      endpoints: {
        auth: [
          "POST /api/login",
          "GET /api/me"
        ],

        dashboard: [
          "GET /api/stats"
        ],

        inbounds: [
          "GET /api/inbounds",
          "POST /api/inbounds",
          "PUT /api/inbounds/:id",
          "DELETE /api/inbounds/:id"
        ],

        clients: [
          "GET /api/clients",
          "POST /api/clients",
          "PUT /api/clients/:id",
          "DELETE /api/clients/:id"
        ],

        hosts: [
          "GET /api/hosts",
          "POST /api/hosts",
          "PUT /api/hosts/:id",
          "DELETE /api/hosts/:id"
        ],

        nodes: [
          "GET /api/nodes",
          "POST /api/nodes",
          "PUT /api/nodes/:id",
          "DELETE /api/nodes/:id"
        ],

        groups: [
          "GET /api/groups",
          "POST /api/groups",
          "PUT /api/groups/:id",
          "DELETE /api/groups/:id"
        ],

        outbounds: [
          "GET /api/outbounds",
          "POST /api/outbounds",
          "PUT /api/outbounds/:id",
          "DELETE /api/outbounds/:id"
        ],

        routing: [
          "GET /api/routing",
          "POST /api/routing",
          "PUT /api/routing/:id",
          "DELETE /api/routing/:id"
        ],

        settings: [
          "GET /api/settings",
          "PUT /api/settings"
        ],

        config: [
          "GET /api/config"
        ]
      }
    });
  }
);

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.use((req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "../public/index.html"
    )
  );
});

/* =========================================================
   SERVER
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Xray Panel running on port ${PORT}`
    );
  }
);
