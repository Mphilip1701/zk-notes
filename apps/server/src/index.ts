import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { runMigrations } from './db/migrate.js';
import { createPool } from './db/pool.js';
import { purgeRateLimits } from './security/rateLimitStore.js';
import { SessionStore } from './security/sessions.js';

const config = loadConfig();
const db = createPool(config.databaseUrl);
await runMigrations(db, console.log);

const app = createApp({ config, db });
const server = app.listen(config.port, () => {
  console.log(`zk-notes server listening on :${config.port} (${config.env})`);
});

const sessions = new SessionStore(config);
const janitor = setInterval(() => {
  Promise.all([sessions.purgeExpired(db), purgeRateLimits(db)]).catch((e: unknown) =>
    console.error('Cleanup failed', e instanceof Error ? e.message : e),
  );
}, 10 * 60_000);
janitor.unref();

function shutdown(signal: string) {
  console.log(`${signal} received, shutting down`);
  clearInterval(janitor);
  server.close(() => {
    db.end().finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
