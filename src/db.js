const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
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
      api_tokens: [],
      counters: { users: 0, bots: 0, api_tokens: 0 },
    };
  }
  const raw = fs.readFileSync(dbPath, "utf8");
  const parsed = JSON.parse(raw);
  if (!parsed.api_tokens) parsed.api_tokens = [];
  if (!parsed.counters) parsed.counters = { users: 0, bots: 0, api_tokens: 0 };
  if (typeof parsed.counters.api_tokens !== "number") parsed.counters.api_tokens = 0;
  return parsed;
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
      discord_token: null,
      is_online: false,
      commands: [],
      files: [],
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

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function buildTokenPreview(token) {
  return `${token.slice(0, 12)}...`;
}

async function createApiTokenForUser(user, durationHours, label = "") {
  const rawToken = `bth_${crypto.randomBytes(24).toString("hex")}`;
  const tokenHash = hashToken(rawToken);
  const now = new Date();
  const isAdmin = user.role === "admin";
  const expiresAt = isAdmin ? null : new Date(now.getTime() + durationHours * 60 * 60 * 1000).toISOString();

  state.counters.api_tokens += 1;
  const tokenRecord = {
    id: state.counters.api_tokens,
    user_id: user.id,
    token_hash: tokenHash,
    token_preview: buildTokenPreview(rawToken),
    label: label || "token",
    is_infinite: isAdmin,
    expires_at: expiresAt,
    created_at: now.toISOString(),
  };

  state.api_tokens.push(tokenRecord);
  saveDb(state);

  return {
    plainToken: rawToken,
    record: tokenRecord,
  };
}

async function listApiTokensForUser(userId) {
  return state.api_tokens
    .filter((t) => t.user_id === userId)
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
}

function isTokenExpired(tokenRecord) {
  if (tokenRecord.is_infinite) return false;
  if (!tokenRecord.expires_at) return true;
  return new Date(tokenRecord.expires_at).getTime() <= Date.now();
}

async function getUserByApiToken(rawToken) {
  const tokenHash = hashToken(rawToken);
  const tokenRecord = state.api_tokens.find((t) => t.token_hash === tokenHash);
  if (!tokenRecord) return null;
  if (isTokenExpired(tokenRecord)) return null;

  const user = state.users.find((u) => u.id === tokenRecord.user_id);
  if (!user) return null;
  return { id: user.id, email: user.email, role: user.role, tokenId: tokenRecord.id };
}

async function getBotById(botId) {
  return state.bots.find((b) => b.id === Number(botId)) || null;
}

function canManageBot(user, bot) {
  if (!user || !bot) return false;
  return user.role === "admin" || bot.owner_user_id === user.id;
}

async function getBotForUser(user, botId) {
  const bot = await getBotById(botId);
  if (!bot) return null;
  if (!canManageBot(user, bot)) return null;
  const owner = state.users.find((u) => u.id === bot.owner_user_id);
  return {
    ...bot,
    owner_email: owner ? owner.email : "inconnu",
    token_set: Boolean(bot.discord_token),
  };
}

async function setBotTokenForUser(user, botId, token) {
  const bot = await getBotById(botId);
  if (!bot || !canManageBot(user, bot)) return { ok: false };
  bot.discord_token = String(token || "").trim();
  bot.is_online = Boolean(bot.discord_token);
  bot.status = bot.is_online ? "online" : "offline";
  saveDb(state);
  return { ok: true, bot };
}

async function addBotCommandForUser(user, botId, name, response) {
  const bot = await getBotById(botId);
  if (!bot || !canManageBot(user, bot)) return { ok: false };
  const command = {
    id: `${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    name: String(name || "").trim(),
    response: String(response || "").trim(),
    created_at: nowIso(),
  };
  bot.commands = bot.commands || [];
  bot.commands.push(command);
  saveDb(state);
  return { ok: true, command };
}

async function addBotFileForUser(user, botId, fileInfo) {
  const bot = await getBotById(botId);
  if (!bot || !canManageBot(user, bot)) return { ok: false };
  bot.files = bot.files || [];
  bot.files.push({
    id: `${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    original_name: fileInfo.originalName,
    stored_name: fileInfo.storedName,
    size: fileInfo.size,
    created_at: nowIso(),
  });
  saveDb(state);
  return { ok: true };
}

async function resetUserPasswordByEmail(email, newPasswordHash) {
  const normalized = (email || "").trim().toLowerCase();
  const user = state.users.find((u) => u.email === normalized);
  if (!user) {
    return { ok: false, reason: "not_found" };
  }

  user.password_hash = newPasswordHash;
  saveDb(state);
  return { ok: true, userId: user.id };
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
  const forceReset = String(process.env.ADMIN_FORCE_RESET || "false").toLowerCase() === "true";
  const existingAdmin = await get("SELECT id FROM users WHERE email = ?", [adminEmail]);

  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    await run(
      "INSERT INTO users(email, password_hash, role) VALUES (?, ?, 'admin')",
      [adminEmail, passwordHash]
    );
    console.log(`Admin cree: ${adminEmail} (pense a changer le mot de passe)`);
    return;
  }

  const existingAdminUser = state.users.find((u) => u.email === adminEmail);
  if (!existingAdminUser) return;

  if (existingAdminUser.role !== "admin") {
    existingAdminUser.role = "admin";
  }

  if (forceReset) {
    existingAdminUser.password_hash = await bcrypt.hash(adminPassword, 10);
    saveDb(state);
    console.log(`Mot de passe admin reinitialise pour: ${adminEmail}`);
  } else {
    saveDb(state);
  }
}

module.exports = {
  run,
  get,
  all,
  initDb,
  createApiTokenForUser,
  listApiTokensForUser,
  getUserByApiToken,
  resetUserPasswordByEmail,
  getBotForUser,
  setBotTokenForUser,
  addBotCommandForUser,
  addBotFileForUser,
};
