import type { Db } from './pool.js';
import { withTransaction } from './pool.js';
import { migrations } from './migrations.js';

export async function runMigrations(db: Db, log: (msg: string) => void = () => {}): Promise<void> {
  await withTransaction(db, async (c) => {
    // Serialise concurrent migrators (e.g. several app instances starting at once).
    await c.query('SELECT pg_advisory_xact_lock(727274)');
    await c.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
    );
    const { rows } = await c.query<{ id: string }>('SELECT id FROM schema_migrations');
    const applied = new Set(rows.map((r) => r.id));
    for (const m of migrations) {
      if (applied.has(m.id)) continue;
      log(`Applying migration ${m.id}`);
      await c.query(m.sql);
      await c.query('INSERT INTO schema_migrations (id) VALUES ($1)', [m.id]);
    }
  });
}
