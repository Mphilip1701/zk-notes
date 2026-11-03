import { loadConfig } from '../config.js';
import { runMigrations } from './migrate.js';
import { createPool } from './pool.js';

const config = loadConfig();
const db = createPool(config.databaseUrl);
try {
  await runMigrations(db, console.log);
  console.log('Migrations complete');
} finally {
  await db.end();
}
