// Cloudflare D1's API (the subset the server uses) over Node's built-in SQLite (node:sqlite, Node
// 22.13+): the same SQL, the same result shapes. Statements run synchronously in one process, so
// each one (and each batch, in a transaction) is atomic like on D1.
import { DatabaseSync, type SQLInputValue, type StatementSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import type { D1Result, D1Statement, Db } from "../core/env";

type Bound = { sql: string; values: unknown[] };

function toSqlite(v: unknown): SQLInputValue {
  if (v === undefined) return null;
  if (typeof v === "boolean") return v ? 1 : 0;
  return v as SQLInputValue;
}

class Statement implements D1Statement {
  constructor(
    private readonly db: SqliteDb,
    private readonly bound: Bound,
  ) {}
  bind(...values: unknown[]): D1Statement {
    return new Statement(this.db, { sql: this.bound.sql, values });
  }
  async first<T = Record<string, unknown>>(column?: string): Promise<T | null> {
    const row = this.db.stmt(this.bound.sql).get(...this.bound.values.map(toSqlite)) as Record<string, unknown> | undefined;
    if (!row) return null;
    return (column ? (row[column] as T) : ({ ...row } as T)) ?? null;
  }
  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return this.db.allSync<T>(this.bound);
  }
  async run(): Promise<D1Result> {
    return this.db.runSync(this.bound);
  }
  get raw(): Bound {
    return this.bound;
  }
}

export class SqliteDb implements Db {
  readonly sqlite: DatabaseSync;
  private readonly cache = new Map<string, StatementSync>();

  constructor(file: string) {
    if (file !== ":memory:") fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    this.sqlite = new DatabaseSync(file);
    this.sqlite.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
    if (file !== ":memory:") {
      for (const f of [file, `${file}-wal`, `${file}-shm`]) {
        try {
          fs.chmodSync(f, 0o600);
        } catch {
          // Not made yet.
        }
      }
    }
  }

  stmt(sql: string): StatementSync {
    let s = this.cache.get(sql);
    if (!s) {
      s = this.sqlite.prepare(sql);
      this.cache.set(sql, s);
    }
    return s;
  }

  allSync<T>(b: Bound): D1Result<T> {
    const s = this.stmt(b.sql);
    // Statements that return rows (SELECT, ... RETURNING) are read with all(); others are run.
    if (s.columns().length) return { results: s.all(...b.values.map(toSqlite)).map((r) => ({ ...(r as object) }) as T), success: true, meta: { changes: 0 } };
    const r = s.run(...b.values.map(toSqlite));
    return { results: [], success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
  }

  runSync(b: Bound): D1Result {
    const s = this.stmt(b.sql);
    if (s.columns().length) {
      // A statement with RETURNING: its rows are the changes.
      const rows = s.all(...b.values.map(toSqlite));
      return { results: rows as Record<string, unknown>[], success: true, meta: { changes: rows.length } };
    }
    const r = s.run(...b.values.map(toSqlite));
    return { results: [], success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
  }

  prepare(sql: string): D1Statement {
    return new Statement(this, { sql, values: [] });
  }

  async batch(statements: D1Statement[]): Promise<D1Result[]> {
    const out: D1Result[] = [];
    this.sqlite.exec("BEGIN");
    try {
      for (const st of statements) out.push(this.allSync((st as Statement).raw));
      this.sqlite.exec("COMMIT");
    } catch (e) {
      this.sqlite.exec("ROLLBACK");
      throw e;
    }
    return out;
  }

  /** Applies the migrations not applied yet (migrations/*.sql, in name order), like `wrangler d1 migrations apply`. */
  migrate(dir: string): string[] {
    this.sqlite.exec("CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)");
    const done = new Set((this.sqlite.prepare("SELECT name FROM _migrations").all() as { name: string }[]).map((r) => r.name));
    const applied: string[] = [];
    for (const name of fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
      if (done.has(name)) continue;
      const sql = fs.readFileSync(path.join(dir, name), "utf8");
      this.sqlite.exec("BEGIN");
      try {
        this.sqlite.exec(sql);
        this.sqlite.prepare("INSERT INTO _migrations (name, applied_at) VALUES (?, ?)").run(name, new Date().toISOString());
        this.sqlite.exec("COMMIT");
      } catch (e) {
        this.sqlite.exec("ROLLBACK");
        throw e;
      }
      applied.push(name);
    }
    return applied;
  }
}
