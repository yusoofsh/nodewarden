import { DatabaseSync } from 'node:sqlite';

// Minimal D1Database shim over node:sqlite so handler tests run real SQL.
class Statement {
  private values: any[] = [];
  constructor(private readonly db: DatabaseSync, private readonly sql: string) {}
  bind(...values: any[]): this {
    this.values = values.map((v) => (v === undefined ? null : v));
    return this;
  }
  async first<T = any>(column?: string): Promise<T | null> {
    const row = this.db.prepare(this.sql).get(...this.values) as any;
    if (!row) return null;
    return (column ? row[column] : row) as T;
  }
  async all<T = any>(): Promise<{ results: T[]; success: boolean; meta: Record<string, unknown> }> {
    const results = this.db.prepare(this.sql).all(...this.values) as T[];
    return { results, success: true, meta: {} };
  }
  async run(): Promise<{ success: boolean; meta: { changes: number } }> {
    const info = this.db.prepare(this.sql).run(...this.values);
    return { success: true, meta: { changes: Number(info.changes) } };
  }
}

export function createTestDb(): D1Database {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  const shim = {
    prepare: (sql: string) => new Statement(db, sql),
    exec: async (sql: string) => {
      db.exec(sql);
      return { count: 1, duration: 0 };
    },
    batch: async (statements: Statement[]) => {
      const out = [];
      db.exec('BEGIN');
      try {
        for (const s of statements) out.push(await s.run());
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      return out;
    },
  };
  return shim as unknown as D1Database;
}
