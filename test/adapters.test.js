'use strict';
// Tests for the production adapters (S3-compatible storage + Turso database).
// Real Backblaze/Turso accounts can't be used in automated tests, so:
//  - SigV4 is checked against Amazon's published test vector (independent proof of the signing code)
//  - the full app is run against local mock servers that speak the S3 and Turso (Hrana-over-HTTP) protocols
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { sign, sha256hex } = require('../lib/sigv4');
const { startServer, client, loginOwner, makeImages } = require('./helpers');

const img = makeImages();

test('SigV4 matches the official AWS example (GET Object with Range header)', () => {
  const r = sign({
    method: 'GET', url: 'https://examplebucket.s3.amazonaws.com/test.txt', region: 'us-east-1',
    keyId: 'AKIAIOSFODNN7EXAMPLE', secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    headers: { Range: 'bytes=0-9' }, now: new Date('2013-05-24T00:00:00Z'),
  });
  assert.equal(r.signature, 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
});

test('SigV4 matches the official AWS example (PUT Object with body)', () => {
  const r = sign({
    method: 'PUT', url: 'https://examplebucket.s3.amazonaws.com/test$file.text', region: 'us-east-1',
    keyId: 'AKIAIOSFODNN7EXAMPLE', secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', body: 'Welcome to Amazon S3.',
    headers: { Date: 'Fri, 24 May 2013 00:00:00 GMT', 'x-amz-storage-class': 'REDUCED_REDUNDANCY' }, now: new Date('2013-05-24T00:00:00Z'),
  });
  // AWS documents this signature for the example above
  assert.equal(r.signature, '98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd');
});

function mockS3() {
  const objects = new Map(); const seen = [];
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const auth = req.headers.authorization || '';
    seen.push({ method: req.method, url: req.url, auth });
    // must be authenticated with SigV4 and the declared payload hash must match the real body
    if (!/^AWS4-HMAC-SHA256 Credential=KEYID\/\d{8}\/us-west-004\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/.test(auth)) { res.writeHead(403); return res.end('bad auth'); }
    if (req.headers['x-amz-content-sha256'] !== sha256hex(body)) { res.writeHead(400); return res.end('hash mismatch'); }
    // recompute the signature the same way the server must have
    const { signature } = sign({ method: req.method, url: `http://${req.headers.host}${req.url}`, region: 'us-west-004', keyId: 'KEYID', secret: 'SECRET', body, now: new Date(req.headers['x-amz-date'].replace(/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/, '$1-$2-$3T$4:$5:$6Z')) });
    if (!auth.endsWith(signature)) { res.writeHead(403); return res.end('bad signature'); }
    const key = decodeURIComponent(req.url);
    if (!key.startsWith('/bkt/')) { res.writeHead(404); return res.end(); }
    if (req.method === 'PUT') { objects.set(key, body); res.writeHead(200); return res.end(); }
    if (req.method === 'GET') { if (!objects.has(key)) { res.writeHead(404); return res.end(); } res.writeHead(200); return res.end(objects.get(key)); }
    if (req.method === 'DELETE') { objects.delete(key); res.writeHead(204); return res.end(); }
    res.writeHead(405); res.end();
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, objects, seen, url: `http://127.0.0.1:${server.address().port}` })));
}

test('app stores photos in an S3-compatible bucket (signed requests, private bucket)', async () => {
  const s3 = await mockS3();
  const s = await startServer({ S3_ENDPOINT: s3.url, S3_REGION: 'us-west-004', S3_BUCKET: 'bkt', S3_KEY_ID: 'KEYID', S3_APP_KEY: 'SECRET' });
  try {
    const o = await loginOwner(s.url);
    const me = (await o.owner.get('/api/me')).json;
    assert.equal(me.storage.persistent, true);
    assert.equal(me.warning, null);
    const g = (await o.owner.post('/api/galleries', { title: 'S3 gallery' })).json;
    const up = await o.owner.upload(`/api/galleries/${g.id}/photos?name=x.jpg`, img.jpg);
    assert.equal(up.status, 201, up.text);
    await o.owner.upload(`/api/photos/${up.json.id}/thumb`, img.thumb);
    assert.equal(s3.objects.size, 2, 'original + thumbnail in the bucket');
    assert.ok([...s3.objects.values()].some((b) => b.equals(img.jpg)));

    await o.owner.patch(`/api/galleries/${g.id}`, { password: 's3-gallery-pass', mode: 'view' });
    const v = client(s.url);
    const before = s3.seen.length;
    assert.equal((await v.get(`/api/public/${g.token}/img/${up.json.id}`, { headers: { 'sec-fetch-dest': 'image' } })).status, 401);
    assert.equal(s3.seen.length, before, 'bucket is never touched for unauthenticated visitors');
    await v.post(`/api/public/${g.token}/unlock`, { password: 's3-gallery-pass' });
    const t1 = await v.get(`/api/public/${g.token}/img/${up.json.id}?size=thumb`, { headers: { 'sec-fetch-dest': 'image' } });
    assert.ok(t1.buf.equals(img.thumb)); assert.match(t1.headers.get('cache-control'), /max-age=3600/);
    const gets = s3.seen.filter((x) => x.method === 'GET').length;
    await v.get(`/api/public/${g.token}/img/${up.json.id}?size=thumb`, { headers: { 'sec-fetch-dest': 'image' } });
    assert.equal(s3.seen.filter((x) => x.method === 'GET').length, gets, 'repeat thumbnail views are served from cache (no extra bucket request)');
    const got = await v.get(`/api/public/${g.token}/img/${up.json.id}?size=full`, { headers: { 'sec-fetch-dest': 'image' } });
    assert.ok(got.buf.equals(img.jpg), 'served through the app from the bucket');
    // visitors never see a bucket URL
    const list = await v.get(`/api/public/${g.token}/photos`);
    assert.equal(list.text.includes(s3.url), false); assert.equal(list.text.includes('bkt'), false);

    await o.owner.del(`/api/photos/${up.json.id}`);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(s3.objects.size, 0, 'deleting a photo deletes it from the bucket');
  } finally { await s.stop(); s3.server.close(); }
});

// Minimal Turso/libSQL "Hrana over HTTP" server backed by node:sqlite, to exercise our HTTP adapter.
function mockTurso() {
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(':memory:'); const log = [];
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    if (req.headers.authorization !== 'Bearer TOKEN123') { res.writeHead(401); return res.end('unauthorized'); }
    if (req.method !== 'POST' || req.url !== '/v2/pipeline') { res.writeHead(404); return res.end(); }
    const { requests } = JSON.parse(Buffer.concat(chunks).toString());
    const results = [];
    for (const r of requests) {
      if (r.type === 'close') { results.push({ type: 'ok', response: { type: 'close' } }); continue; }
      try {
        const args = r.stmt.args.map((a) => (a.type === 'null' ? null : a.type === 'integer' ? Number(a.value) : a.value));
        log.push(r.stmt.sql.trim().split(/\s+/)[0].toUpperCase());
        const st = db.prepare(r.stmt.sql);
        if (/^\s*select/i.test(r.stmt.sql)) {
          const rows = st.all(...args);
          const cols = rows.length ? Object.keys(rows[0]) : (st.columns ? st.columns().map((c) => c.name) : []);
          const enc = (v) => (v === null ? { type: 'null' } : typeof v === 'number' ? { type: 'integer', value: String(v) } : { type: 'text', value: String(v) });
          results.push({ type: 'ok', response: { type: 'execute', result: { cols: cols.map((name) => ({ name })), rows: rows.map((row) => cols.map((c) => enc(row[c]))), affected_row_count: 0 } } });
        } else {
          const info = st.run(...args);
          results.push({ type: 'ok', response: { type: 'execute', result: { cols: [], rows: [], affected_row_count: Number(info.changes) } } });
        }
      } catch (e) { results.push({ type: 'error', error: { message: e.message } }); }
    }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ baton: null, results }));
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, db, log, url: `http://127.0.0.1:${server.address().port}` })));
}

test('app runs on a Turso (libSQL over HTTP) database; data lives in the remote DB, not on local disk', async () => {
  const t = await mockTurso();
  let s = await startServer({ TURSO_URL: t.url, TURSO_AUTH_TOKEN: 'TOKEN123' });
  try {
    const o = await loginOwner(s.url);
    assert.equal((await o.owner.get('/api/me')).json.storage.database, 'turso');
    const g = (await o.owner.post('/api/galleries', { title: 'Remote DB' })).json;
    await o.owner.upload(`/api/galleries/${g.id}/photos?name=a.jpg`, img.jpg);
    await o.owner.patch(`/api/galleries/${g.id}`, { password: 'turso-pass-123', mode: 'download', expiresAt: Date.now() + 86400000, watermark: 'Studio' });
    const rows = t.db.prepare('SELECT title, mode, watermark FROM galleries').all();
    assert.equal(rows.length, 1); assert.equal(rows[0].title, 'Remote DB'); assert.equal(rows[0].mode, 'download');
    const full = (await o.owner.get(`/api/galleries/${g.id}`)).json;
    assert.equal(full.photos.length, 1);
    assert.equal(typeof full.expiresAt, 'number', 'integers decode as numbers');
    assert.equal(typeof (await o.owner.get('/api/me')).json.storage.used, 'number');
    assert.equal((await o.owner.get('/api/me')).json.storage.used, img.jpg.length);
    assert.ok(!require('node:fs').existsSync(require('node:path').join(s.dataDir, 'lumen.db')), 'no local database file is used');
    await s.stop();

    // "redeploy": brand-new server process, same remote DB -> everything is still there
    s = await startServer({ TURSO_URL: t.url, TURSO_AUTH_TOKEN: 'TOKEN123' });
    const o2 = await loginOwner(s.url);
    const list = (await o2.owner.get('/api/galleries')).json;
    assert.equal(list.length, 1); assert.equal(list[0].photoCount, 1); assert.equal(list[0].hasPassword, true);
  } finally { await s.stop(); t.server.close(); }
});

test('wrong Turso token fails loudly instead of silently losing data', async () => {
  const t = await mockTurso();
  try { await assert.rejects(startServer({ TURSO_URL: t.url, TURSO_AUTH_TOKEN: 'WRONG' }), /Turso HTTP 401/); }
  finally { t.server.close(); }
});
