const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const dataDir = path.join(__dirname, "..", "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, "app.json");

function nowIso() {
  return new Date().toISOString();
}

function loadDb() {
  if (!fs.existsSync(dbPath)) {
    return {
      users: [],
      bots: [],
      counters: { users: 0, bots: 0 },
    };
  }
  const raw = fs.readFileSync(dbPath, "utf8");
  return JSON.parse(raw);
}

function saveDb(state) {
  fs.writeFileSync(dbPath, JSON.stringify(state, null, 2), "utf8");
}

let state = loadDb();

async function run(sql, params = []) {
  const q = sql.trim();
  if (q.startsWith("CREATE TABLE")) {
    return { changes: 0 };
  }

  if (q.startsWith("INSERT INTO users")) {
    const [email, passwordHash, roleFromParams] = params;
    const role = roleFromParams || "admin";
    const exists = state.users.some((u) => u.email === email);
    if (exists) throw new Error("UNIQUE constraint failed: users.email");

    state.counters.users += 1;
    const user = {
      id: state.counters.users,
      email,
      password_hash: passwordHash,
      role,
      created_at: nowIso(),
    };
    state.users.push(user);
    saveDb(state);
    return { lastID: user.id, changes: 1 };
  }

  if (q.startsWith("INSERT INTO bots")) {
    const [name, ownerUserId] = params;
    state.counters.bots += 1;
    const bot = {
      id: state.counters.bots,
      name,
      owner_user_id: ownerUserId,
      status: "active",
      created_at: nowIso(),
    };
    state.bots.push(bot);
    saveDb(state);
    return { lastID: bot.id, changes: 1 };
  }

  throw new Error(`Unsupported run() query: ${sql}`);
}

async function get(sql, params = []) {
  const q = sql.trim();
  if (q.startsWith("SELECT id FROM users WHERE email = ?")) {
    const [email] = params;
    const user = state.users.find((u) => u.email === email);
    return user ? { id: user.id } : undefined;
  }

  if (q.startsWith("SELECT id, email, role FROM users WHERE id = ?")) {
    const [id] = params;
    const user = state.users.find((u) => u.id === id);
    if (!user) return undefined;
    return { id: user.id, email: user.email, role: user.role };
  }

  if (q.startsWith("SELECT * FROM users WHERE email = ?")) {
    const [email] = params;
    return state.users.find((u) => u.email === email);
  }

  throw new Error(`Unsupported get() query: ${sql}`);
}

async function all(sql, params = []) {
  const q = sql.trim();
  if (q.startsWith("SELECT id, email, role, created_at FROM users")) {
    return [...state.users].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  }

  if (q.startsWith("SELECT bots.id, bots.name, bots.status, users.email AS owner_email FROM bots")) {
    const filtered =
      q.includes("WHERE bots.owner_user_id = ?")
        ? state.bots.filter((b) => b.owner_user_id === params[0])
        : state.bots;

    return filtered
      .map((bot) => {
        const owner = state.users.find((u) => u.id === bot.owner_user_id);
        return {
          id: bot.id,
          name: bot.name,
          status: bot.status,
          owner_email: owner ? owner.email : "inconnu",
          created_at: bot.created_at,
        };
      })
      .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
      .map(({ created_at, ...rest }) => rest);
  }

  throw new Error(`Unsupported all() query: ${sql}`);
}

async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS bots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      owner_user_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_user_id) REFERENCES users(id)
    )
  `);

  const adminEmail = process.env.ADMIN_EMAIL || "admin@local.dev";
  const adminPassword = process.env.ADMIN_PASSWORD || "ChangeMe123!";
  const existingAdmin = await get("SELECT id FROM users WHERE email = ?", [adminEmail]);

  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    await run(
      "INSERT INTO users(email, password_hash, role) VALUES (?, ?, 'admin')",
      [adminEmail, passwordHash]
    );
    console.log(`Admin cree: ${adminEmail} (pense a changer le mot de passe)`);
  }
}

module.exports = {
  run,
  get,
  all,
  initDb,
};
