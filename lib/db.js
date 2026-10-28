'use strict';
// Database layer. Same tiny interface for both backends:
//   - Turso (free hosted SQLite, over its HTTP API)   -> used in production when TURSO_URL is set
//   - node:sqlite (a local file)                       -> used for local use and tests
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS galleries (
     id TEXT PRIMARY KEY,
     token TEXT NOT NULL UNIQUE,
     title TEXT NOT NULL,
     mode TEXT NOT NULL DEFAULT 'view',
     pw_hash TEXT,
     expires_at INTEGER,
     revoked INTEGER NOT NULL DEFAULT 0,
     watermark TEXT,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS photos (
     id TEXT PRIMARY KEY,
     gallery_id TEXT NOT NULL,
     name TEXT NOT NULL,
     key TEXT NOT NULL,
     thumb_key TEXT,
     mime TEXT NOT NULL,
     size INTEGER NOT NULL,
     thumb_size INTEGER NOT NULL DEFAULT 0,
     position INTEGER NOT NULL DEFAULT 0,
     created_at INTEGER NOT NULL
   )`,
  `CREATE INDEX IF NOT EXISTS photos_gallery ON photos (gallery_id, position)`,
  `CREATE TABLE IF NOT EXISTS events (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     gallery_id TEXT NOT NULL,
     type TEXT NOT NULL,
     at INTEGER NOT NULL
   )`,
  `CREATE INDEX IF NOT EXISTS events_gallery ON events (gallery_id, type)`,
];

function local(cfg) {
  const { DatabaseSync } = require('node:sqlite');
  fs.mkdirSync(cfg.dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(cfg.dataDir, 'lumen.db'));
  db.exec('PRAGMA journal_mode=WAL;');
  return {
    kind: 'sqlite',
    async all(sql, args = []) { return db.prepare(sql).all(...args).map((r) => ({ ...r })); },
    async run(sql, args = []) { return { changes: Number(db.prepare(sql).run(...args).changes) }; },
    async batch(list) { for (const [s, a] of list) db.prepare(s).run(...(a || [])); },
    close() { db.close(); },
  };
}

function turso(cfg) {
  const base = cfg.tursoUrl.replace(/^libsql:\/\//, 'https://').replace(/\/+$/, '');
  const enc = (v) => {
    if (v === null || v === undefined) return { type: 'null' };
    if (typeof v === 'number') return Number.isInteger(v) ? { type: 'integer', value: String(v) } : { type: 'float', value: v };
    return { type: 'text', value: String(v) };
  };
  const dec = (c) => (c.type === 'null' ? null : (c.type === 'integer' || c.type === 'float') ? Number(c.value) : c.value);
  const exec = (sql, args = []) => ({ type: 'execute', stmt: { sql, args: args.map(enc) } });

  async function pipeline(requests) {
    let lastErr;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const r = await fetch(base + '/v2/pipeline', {
          method: 'POST',
          headers: { authorization: 'Bearer ' + cfg.tursoToken, 'content-type': 'application/json' },
          body: JSON.stringify({ requests: [...requests, { type: 'close' }] }),
        });
        if (!r.ok) {
          const text = (await r.text()).slice(0, 300);
          if (r.status >= 500) { lastErr = new Error(`Turso HTTP ${r.status}: ${text}`); continue; }
          throw new Error(`Turso HTTP ${r.status}: ${text}`);
        }
        const j = await r.json();
        for (const x of j.results) if (x.type === 'error') throw new Error('Turso: ' + (x.error && x.error.message));
        return j.results;
      } catch (e) {
        if (/^Turso/.test(e.message)) throw e;
        lastErr = e; // network error -> retry
      }
    }
    throw lastErr;
  }

  return {
    kind: 'turso',
    async all(sql, args = []) {
      const res = await pipeline([exec(sql, args)]);
      const rs = res[0].response.result;
      const cols = rs.cols.map((c) => c.name);
      return rs.rows.map((row) => Object.fromEntries(row.map((c, i) => [cols[i], dec(c)])));
    },
    async run(sql, args = []) {
      const res = await pipeline([exec(sql, args)]);
      return { changes: Number(res[0].response.result.affected_row_count || 0) };
    },
    async batch(list) { await pipeline(list.map(([s, a]) => exec(s, a))); },
    close() {},
  };
}

async function openDb(cfg) {
  const db = cfg.tursoUrl ? turso(cfg) : local(cfg);
  await db.batch(SCHEMA.map((s) => [s, []]));
  return db;
}

module.exports = { openDb };
