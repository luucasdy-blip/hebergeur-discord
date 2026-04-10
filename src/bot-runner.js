const { Client, GatewayIntentBits } = require("discord.js");
const { getBotById, setBotRuntimeStatus } = require("./db");

const runningBots = new Map();

async function wireBotHandlers(botId, client) {
  client.on("ready", async () => {
    await setBotRuntimeStatus(botId, "online");
    console.log(`[bot:${botId}] Connecte en tant que ${client.user.tag}`);
  });

  client.on("messageCreate", async (message) => {
    if (message.author.bot) return;
    const bot = await getBotById(botId);
    if (!bot || !Array.isArray(bot.commands)) return;
    const input = message.content.trim();
    const cmd = bot.commands.find((c) => c.name === input);
    if (!cmd) return;
    await message.reply(cmd.response || "Commande sans reponse.");
  });

  client.on("error", async (err) => {
    console.error(`[bot:${botId}] Erreur client:`, err.message);
    await setBotRuntimeStatus(botId, "error");
  });
}

async function startBot(bot) {
  if (!bot || !bot.discord_token) {
    return { ok: false, reason: "missing_token" };
  }
  if (runningBots.has(bot.id)) {
    return { ok: true, alreadyRunning: true };
  }

  const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent],
  });
  await wireBotHandlers(bot.id, client);
  runningBots.set(bot.id, client);

  try {
    await client.login(bot.discord_token);
    await setBotRuntimeStatus(bot.id, "online");
    return { ok: true };
  } catch (error) {
    runningBots.delete(bot.id);
    await setBotRuntimeStatus(bot.id, "error");
    return { ok: false, reason: "login_failed", message: error.message };
  }
}

async function stopBot(botId) {
  const client = runningBots.get(Number(botId));
  if (!client) {
    await setBotRuntimeStatus(Number(botId), "offline");
    return { ok: true, alreadyStopped: true };
  }
  runningBots.delete(Number(botId));
  try {
    await client.destroy();
  } catch (error) {
    // Ignore destroy errors to keep control path simple.
  }
  await setBotRuntimeStatus(Number(botId), "offline");
  return { ok: true };
}

module.exports = {
  startBot,
  stopBot,
};
