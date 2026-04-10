require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const {
  initDb,
  get,
  run,
  all,
  createApiTokenForUser,
  listApiTokensForUser,
  getUserByApiToken,
  resetUserPasswordByEmail,
  getBotForUser,
  getBotsWithToken,
  setBotTokenForUser,
  setBotOnlineForUser,
  addBotCommandForUser,
  addBotCommandsBulkForUser,
  addBotFileForUser,
} = require("./db");
const { startBot, stopBot } = require("./bot-runner");

const app = express();
const port = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "views"));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "..", "public")));

const uploadsDir = path.join(__dirname, "..", "public", "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const upload = multer({ dest: uploadsDir });

function parseCommandsFromFileContent(content) {
  const trimmed = String(content || "").trim();
  if (!trimmed) return [];

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const json = JSON.parse(trimmed);
    if (Array.isArray(json)) {
      return json.map((item) => ({ name: item.name, response: item.response }));
    }
    return Object.entries(json).map(([name, response]) => ({ name, response }));
  }

  return trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const sep = line.includes("|") ? "|" : ";";
      const parts = line.split(sep);
      return { name: parts[0], response: parts.slice(1).join(sep) };
    });
}

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(async (req, res, next) => {
  res.locals.currentUser = null;
  res.locals.message = req.session.message || null;
  res.locals.newApiToken = req.session.newApiToken || null;
  delete req.session.message;
  delete req.session.newApiToken;

  if (!req.session.userId) return next();
  const user = await get("SELECT id, email, role FROM users WHERE id = ?", [req.session.userId]);
  if (user) res.locals.currentUser = user;
  return next();
});

function requireAuth(req, res, next) {
  if (!res.locals.currentUser) return res.redirect("/login");
  return next();
}

function requireAdmin(req, res, next) {
  if (!res.locals.currentUser || res.locals.currentUser.role !== "admin") {
    req.session.message = "Acces refuse.";
    return res.redirect("/dashboard");
  }
  return next();
}

app.get("/", (req, res) => {
  return res.render("home");
});

app.get("/login", (req, res) => {
  if (res.locals.currentUser) return res.redirect("/dashboard");
  return res.render("login");
});

app.get("/register", (req, res) => {
  if (res.locals.currentUser) return res.redirect("/dashboard");
  return res.render("register");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    req.session.message = "Email et mot de passe obligatoires.";
    return res.redirect("/login");
  }

  const user = await get("SELECT * FROM users WHERE email = ?", [email.trim().toLowerCase()]);
  if (!user) {
    req.session.message = "Identifiants invalides.";
    return res.redirect("/login");
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    req.session.message = "Identifiants invalides.";
    return res.redirect("/login");
  }

  req.session.userId = user.id;
  req.session.message = "Connexion reussie.";
  return res.redirect("/dashboard");
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = (email || "").trim().toLowerCase();

  if (!normalizedEmail || !password) {
    req.session.message = "Email et mot de passe obligatoires.";
    return res.redirect("/register");
  }

  if (password.length < 8) {
    req.session.message = "Le mot de passe doit faire au moins 8 caracteres.";
    return res.redirect("/register");
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await run("INSERT INTO users(email, password_hash, role) VALUES (?, ?, 'user')", [
      normalizedEmail,
      hash,
    ]);
    req.session.userId = result.lastID;
    req.session.message = "Compte cree avec succes.";
    return res.redirect("/dashboard");
  } catch (error) {
    req.session.message = "Email deja utilise.";
    return res.redirect("/register");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const user = res.locals.currentUser;
  const bots =
    user.role === "admin"
      ? await all(
          "SELECT bots.id, bots.name, bots.status, users.email AS owner_email FROM bots JOIN users ON users.id = bots.owner_user_id ORDER BY bots.created_at DESC"
        )
      : await all(
          "SELECT bots.id, bots.name, bots.status, users.email AS owner_email FROM bots JOIN users ON users.id = bots.owner_user_id WHERE bots.owner_user_id = ? ORDER BY bots.created_at DESC",
          [user.id]
        );

  const tokens = await listApiTokensForUser(user.id);
  return res.render("dashboard", { bots, tokens });
});

app.post("/tokens/create", requireAuth, async (req, res) => {
  const user = res.locals.currentUser;
  const label = (req.body.label || "").trim() || "token";
  const duration = Number(req.body.duration_hours || 24);
  const durationHours = Number.isFinite(duration) && duration > 0 ? duration : 24;

  try {
    const { plainToken } = await createApiTokenForUser(user, durationHours, label);
    req.session.newApiToken = plainToken;
    req.session.message =
      user.role === "admin"
        ? "Token admin cree (sans expiration). Copie-le maintenant."
        : "Token cree avec expiration. Copie-le maintenant.";
  } catch (error) {
    req.session.message = "Erreur pendant la creation du token.";
  }

  return res.redirect("/dashboard");
});

app.get("/api/me", async (req, res) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;

  if (!token) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }

  const user = await getUserByApiToken(token);
  if (!user) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  return res.json({
    id: user.id,
    email: user.email,
    role: user.role,
    auth: "token",
  });
});

app.post("/bots/create", requireAuth, async (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    req.session.message = "Nom du bot obligatoire.";
    return res.redirect("/dashboard");
  }

  await run("INSERT INTO bots(name, owner_user_id, status) VALUES (?, ?, 'active')", [
    name.trim(),
    res.locals.currentUser.id,
  ]);
  req.session.message = "Bot ajoute.";
  return res.redirect("/dashboard");
});

app.get("/bots/:id/manage", requireAuth, async (req, res) => {
  const bot = await getBotForUser(res.locals.currentUser, req.params.id);
  if (!bot) {
    req.session.message = "Bot introuvable ou acces refuse.";
    return res.redirect("/dashboard");
  }
  return res.render("manage-bot", { bot });
});

app.post("/bots/:id/token", requireAuth, async (req, res) => {
  const token = (req.body.discord_token || "").trim();
  if (!token) {
    req.session.message = "Token bot obligatoire.";
    return res.redirect(`/bots/${req.params.id}/manage`);
  }
  const result = await setBotTokenForUser(res.locals.currentUser, req.params.id, token);
  req.session.message = result.ok ? "Token enregistre, bot marque en ligne." : "Impossible de mettre a jour le token.";
  return res.redirect(`/bots/${req.params.id}/manage`);
});

app.post("/bots/:id/start", requireAuth, async (req, res) => {
  const onlineResult = await setBotOnlineForUser(res.locals.currentUser, req.params.id, true);
  if (!onlineResult.ok) {
    req.session.message =
      onlineResult.reason === "missing_token" ? "Ajoute un token avant de lancer le bot." : "Impossible de lancer ce bot.";
    return res.redirect(`/bots/${req.params.id}/manage`);
  }

  const runResult = await startBot(onlineResult.bot);
  req.session.message = runResult.ok
    ? "Bot lance avec succes."
    : `Echec de lancement: ${runResult.message || runResult.reason}`;
  return res.redirect(`/bots/${req.params.id}/manage`);
});

app.post("/bots/:id/stop", requireAuth, async (req, res) => {
  await stopBot(req.params.id);
  req.session.message = "Bot arrete.";
  return res.redirect(`/bots/${req.params.id}/manage`);
});

app.post("/bots/:id/commands/create", requireAuth, async (req, res) => {
  const name = (req.body.name || "").trim();
  const response = (req.body.response || "").trim();
  if (!name || !response) {
    req.session.message = "Nom de commande et reponse obligatoires.";
    return res.redirect(`/bots/${req.params.id}/manage`);
  }
  const result = await addBotCommandForUser(res.locals.currentUser, req.params.id, name, response);
  req.session.message = result.ok ? "Commande ajoutee." : "Impossible d'ajouter la commande.";
  return res.redirect(`/bots/${req.params.id}/manage`);
});

app.post("/bots/:id/commands/import", requireAuth, upload.single("commands_file"), async (req, res) => {
  if (!req.file) {
    req.session.message = "Aucun fichier de commandes recu.";
    return res.redirect(`/bots/${req.params.id}/manage`);
  }

  try {
    const content = fs.readFileSync(req.file.path, "utf8");
    const commands = parseCommandsFromFileContent(content);
    const result = await addBotCommandsBulkForUser(res.locals.currentUser, req.params.id, commands);
    req.session.message =
      result.ok && result.count > 0
        ? `${result.count} commandes importees.`
        : "Aucune commande valide trouvee dans le fichier.";
  } catch (error) {
    req.session.message = "Erreur d'import. Formats acceptes: JSON ou lignes name|response.";
  } finally {
    try {
      fs.unlinkSync(req.file.path);
    } catch (error) {
      // Ignore file cleanup errors.
    }
  }

  return res.redirect(`/bots/${req.params.id}/manage`);
});

app.post("/bots/:id/upload", requireAuth, upload.single("bot_file"), async (req, res) => {
  if (!req.file) {
    req.session.message = "Aucun fichier recu.";
    return res.redirect(`/bots/${req.params.id}/manage`);
  }
  const result = await addBotFileForUser(res.locals.currentUser, req.params.id, {
    originalName: req.file.originalname,
    storedName: req.file.filename,
    size: req.file.size,
  });
  req.session.message = result.ok ? "Fichier upload avec succes." : "Impossible d'uploader ce fichier.";
  return res.redirect(`/bots/${req.params.id}/manage`);
});

app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const users = await all("SELECT id, email, role, created_at FROM users ORDER BY created_at DESC");
  return res.render("admin-users", { users });
});

app.post("/admin/users/create", requireAuth, requireAdmin, async (req, res) => {
  const { email, password, role } = req.body;
  const normalizedEmail = (email || "").trim().toLowerCase();
  const selectedRole = role === "admin" ? "admin" : "user";

  if (!normalizedEmail || !password) {
    req.session.message = "Email et mot de passe obligatoires.";
    return res.redirect("/admin/users");
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await run("INSERT INTO users(email, password_hash, role) VALUES (?, ?, ?)", [
      normalizedEmail,
      hash,
      selectedRole,
    ]);
    req.session.message = "Utilisateur cree.";
  } catch (error) {
    req.session.message = "Impossible de creer l'utilisateur (email deja utilise ?).";
  }
  return res.redirect("/admin/users");
});

app.post("/admin/users/reset-password", requireAuth, requireAdmin, async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const newPassword = req.body.new_password || "";

  if (!email || !newPassword) {
    req.session.message = "Email et nouveau mot de passe obligatoires.";
    return res.redirect("/admin/users");
  }

  if (newPassword.length < 8) {
    req.session.message = "Le nouveau mot de passe doit faire au moins 8 caracteres.";
    return res.redirect("/admin/users");
  }

  try {
    const hash = await bcrypt.hash(newPassword, 10);
    const result = await resetUserPasswordByEmail(email, hash);
    if (!result.ok) {
      req.session.message = "Utilisateur introuvable pour cet email.";
      return res.redirect("/admin/users");
    }

    req.session.message = "Mot de passe utilisateur reinitialise.";
    return res.redirect("/admin/users");
  } catch (error) {
    req.session.message = "Erreur pendant la reinitialisation du mot de passe.";
    return res.redirect("/admin/users");
  }
});

initDb()
  .then(() => {
    getBotsWithToken()
      .then(async (bots) => {
        for (const bot of bots) {
          if (bot.status === "online" || bot.status === "starting") {
            await startBot(bot);
          }
        }
      })
      .catch((error) => {
        console.error("Impossible de relancer les bots:", error.message);
      });
    app.listen(port, () => {
      console.log(`Serveur lance: http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.error("Erreur au demarrage:", error);
    process.exit(1);
  });
