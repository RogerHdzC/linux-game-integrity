import { readFile } from "node:fs/promises";
import { Pool } from "pg";
export async function migrate(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(19283641)");
    await client.query(
      await readFile("infra/postgres/001-initial.sql", "utf8"),
    );
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}
if (require.main === module) {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  migrate(pool)
    .catch(() => {
      console.error("Migration failed");
      process.exitCode = 1;
    })
    .finally(() => pool.end());
}
