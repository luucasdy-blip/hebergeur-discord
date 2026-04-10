# BotHost

Site web Node.js pour heberger et gerer des bots avec:
- authentification email + mot de passe
- compte admin
- gestion des utilisateurs et bots

## Installation locale

1. Installer les dependances:

```bash
npm install
```

2. Creer ton fichier `.env` a partir de `.env.example`

3. Lancer le serveur:

```bash
npm start
```

4. Ouvrir `http://localhost:3000`

## Variables d'environnement

- `PORT`
- `SESSION_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`

## Deploy en ligne

Tu peux deployer sur Render / Railway avec:
- Build command: `npm install`
- Start command: `npm start`
