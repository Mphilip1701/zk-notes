import pg from 'pg';
import { runMigrations } from '../src/db/migrate.js';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://zknotes:zknotes@localhost:5432/zknotes_test';

/** Fresh schema for every test run. */
export default async function setup(): Promise<void> {
  const pool = new pg.Pool({ connectionString: TEST_DATABASE_URL });
  try {
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    await runMigrations(pool);
  } catch (e) {
    throw new Error(
      `Integration tests need PostgreSQL at ${TEST_DATABASE_URL} (set TEST_DATABASE_URL; see README). ${String(e)}`,
    );
  } finally {
    await pool.end();
  }
}
