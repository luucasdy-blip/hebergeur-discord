require("dotenv").config();
const path = require("path");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const { initDb, get, run, all } = require("./db");

const app = express();
const port = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "views"));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "..", "public")));

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: path.join(__dirname, "..", "data") }),
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
  delete req.session.message;

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

  return res.render("dashboard", { bots });
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

initDb()
  .then(() => {
    app.listen(port, () => {
      console.log(`Serveur lance: http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.error("Erreur au demarrage:", error);
    process.exit(1);
  });
