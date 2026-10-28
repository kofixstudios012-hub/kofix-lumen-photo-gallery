'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { startServer, client, loginOwner, makeImages, PW, ROOT } = require('./helpers');

const img = makeImages();
const H = { image: { 'sec-fetch-dest': 'image', 'sec-fetch-site': 'same-origin' }, doc: { 'sec-fetch-dest': 'document', 'sec-fetch-site': 'none' }, cross: { 'sec-fetch-dest': 'image', 'sec-fetch-site': 'cross-site' } };

let srv, owner, visitor;
const listFiles = (dir) => (fs.existsSync(dir) ? fs.readdirSync(dir, { recursive: true }).filter((f) => fs.statSync(path.join(dir, f)).isFile()) : []);

test.before(async () => {
  srv = await startServer();
  owner = await loginOwner(srv.url);
  visitor = client(srv.url);
});
test.after(async () => { await srv.stop(); });

async function newGallery(title = 'Test shoot') {
  const r = await owner.owner.post('/api/galleries', { title });
  assert.equal(r.status, 201);
  return r.json;
}
async function addPhoto(g, buf, name) {
  const r = await owner.owner.upload(`/api/galleries/${g.id}/photos?name=${encodeURIComponent(name)}`, buf);
  assert.equal(r.status, 201, r.text);
  const t = await owner.owner.upload(`/api/photos/${r.json.id}/thumb`, img.thumb);
  assert.equal(t.status, 200, t.text);
  return t.json;
}

test('pages are served, mobile-ready, private and not indexable', async () => {
  const c = client(srv.url);
  for (const p of ['/', '/login', '/dashboard', '/g/abcdefghijklmnopqrstuvwx']) {
    const r = await c.get(p);
    assert.equal(r.status, 200, p);
    assert.match(r.text, /<meta name="viewport" content="width=device-width, initial-scale=1/, p + ' has viewport meta');
    assert.match(r.headers.get('x-robots-tag'), /noindex/);
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.doesNotMatch(r.text, /\sstyle="|\son\w+="/, p + ' has no inline style/handlers (CSP)');
  }
  const robots = await c.get('/robots.txt');
  assert.match(robots.text, /Disallow: \//);
  const css = fs.readFileSync(path.join(ROOT, 'public/assets/style.css'), 'utf8');
  assert.match(css, /@media \(max-width: 860px\)/);
  assert.match(css, /@media \(max-width: 520px\)/);
});

test('static file server blocks path traversal and unknown files', async () => {
  const c = client(srv.url);
  for (const p of ['/assets/..%2f..%2fserver.js', '/assets/../server.js', '/../server.js', '/uploads/x', '/data/lumen.db', '/.env', '/package.json']) {
    const r = await c.get(p);
    assert.equal(r.status, 404, p);
  }
});

test('owner API requires sign-in; CSRF header required for changes', async () => {
  const anon = client(srv.url);
  for (const [m, p] of [['GET', '/api/me'], ['GET', '/api/galleries'], ['POST', '/api/galleries'], ['GET', '/api/owner-img/x']]) {
    const r = await anon.req(m, p, { headers: { 'x-lumen': '1' }, json: m === 'POST' ? { title: 'x' } : undefined });
    assert.equal(r.status, 401, `${m} ${p}`);
  }
  const noHeader = await owner.post('/api/galleries', { title: 'no csrf header' });
  assert.equal(noHeader.status, 403);
  const forged = client(srv.url);
  forged.jar.set('x', { name: 'lumen_owner', value: '9999999999999.AAAA', path: '/' });
  assert.equal((await forged.owner.get('/api/me')).status, 401, 'forged cookie rejected');
});

test('upload: JPEG, PNG and WebP are stored, previewed and listed; other files rejected', async () => {
  const g = await newGallery();
  const a = await addPhoto(g, img.jpg, 'a.jpg');
  const b = await addPhoto(g, img.png, 'b.png');
  const c = await addPhoto(g, img.webp, 'c.webp');
  assert.deepEqual([a.mime, b.mime, c.mime], ['image/jpeg', 'image/png', 'image/webp']);
  assert.ok(a.hasThumb);
  const full = await owner.owner.get(`/api/galleries/${g.id}`);
  assert.equal(full.json.photos.length, 3);
  // preview and original round-trip byte for byte
  const o = await owner.owner.get(`/api/owner-img/${a.id}?size=full`);
  assert.equal(o.status, 200);
  assert.ok(o.buf.equals(img.jpg));
  assert.equal(o.headers.get('content-type'), 'image/jpeg');
  // disguised non-image
  const bad = await owner.owner.upload(`/api/galleries/${g.id}/photos?name=evil.jpg`, Buffer.from('<?php echo 1; ?> this is not an image at all'));
  assert.equal(bad.status, 415);
  const svg = await owner.owner.upload(`/api/galleries/${g.id}/photos?name=x.png`, Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'));
  assert.equal(svg.status, 415);
  const gone = await owner.owner.upload(`/api/galleries/nope/photos?name=x.jpg`, img.jpg);
  assert.equal(gone.status, 404);
});

test('storage meter reports real usage; rename, replace and delete work and clean up files', async () => {
  const before = (await owner.owner.get('/api/me')).json.storage.used;
  const g = await newGallery('Meter');
  const p = await addPhoto(g, img.jpg, 'one.jpg');
  const mid = (await owner.owner.get('/api/me')).json.storage;
  assert.equal(mid.used - before, img.jpg.length + img.thumb.length);
  assert.equal(mid.limit, 10 * 1073741824);
  assert.equal(mid.backend, 'Local disk');

  const rn = await owner.owner.patch(`/api/photos/${p.id}`, { name: 'renamed.jpg' });
  assert.equal(rn.json.name, 'renamed.jpg');

  const files1 = listFiles(path.join(srv.dataDir, 'uploads')).length;
  const rep = await owner.owner.upload(`/api/photos/${p.id}/file?name=new.png`, img.png, 'PUT');
  assert.equal(rep.status, 200);
  assert.equal(rep.json.mime, 'image/png');
  assert.equal(rep.json.hasThumb, false, 'thumbnail reset after replace');
  const o = await owner.owner.get(`/api/owner-img/${p.id}?size=full`);
  assert.ok(o.buf.equals(img.png), 'new bytes served');
  assert.ok(listFiles(path.join(srv.dataDir, 'uploads')).length <= files1, 'old file removed from storage');
  assert.equal((await owner.owner.get('/api/me')).json.storage.used - before, img.png.length);

  assert.equal((await owner.owner.del(`/api/photos/${p.id}`)).status, 200);
  assert.equal((await owner.owner.get('/api/me')).json.storage.used, before);
  assert.equal((await owner.owner.get(`/api/owner-img/${p.id}`)).status, 404);
});

test('gallery rename and delete (removes photos from storage)', async () => {
  const g = await newGallery('Old name');
  await addPhoto(g, img.jpg, 'x.jpg');
  const r = await owner.owner.patch(`/api/galleries/${g.id}`, { title: 'New name' });
  assert.equal(r.json.title, 'New name');
  assert.equal((await owner.owner.patch(`/api/galleries/${g.id}`, { title: '  ' })).status, 400);
  const before = listFiles(path.join(srv.dataDir, 'uploads')).length;
  assert.equal((await owner.owner.del(`/api/galleries/${g.id}`)).status, 200);
  assert.equal(listFiles(path.join(srv.dataDir, 'uploads')).length, before - 2);
  assert.equal((await owner.owner.get(`/api/galleries/${g.id}`)).status, 404);
});

test('password-protected link: nothing is exposed before authentication', async () => {
  const g = await newGallery('Secret wedding');
  const p = await addPhoto(g, img.jpg, 'secret.jpg');
  assert.equal((await owner.owner.patch(`/api/galleries/${g.id}`, { password: 'abc' })).status, 400, 'too short');
  const set = await owner.owner.patch(`/api/galleries/${g.id}`, { password: 'hunter2-hunter2', mode: 'full' });
  assert.equal(set.json.hasPassword, true);
  assert.equal(JSON.stringify(set.json).includes('scrypt'), false, 'hash never returned by API');
  const v = client(srv.url);
  const info = await v.get(`/api/public/${g.token}/info`);
  assert.deepEqual(info.json, { needsPassword: true, unlocked: false, title: 'Private gallery' });
  assert.equal(info.text.includes('Secret wedding'), false, 'title hidden before unlock');

  for (const p2 of [`/photos`, `/img/${p.id}?size=full`, `/img/${p.id}?size=thumb`, `/download/${p.id}`, `/zip`]) {
    const r = await v.get(`/api/public/${g.token}${p2}`, { headers: H.image });
    assert.equal(r.status, 401, p2);
    assert.equal(r.buf.includes(img.jpg.subarray(0, 40)), false, 'no image bytes leaked: ' + p2);
  }
  const wrong = await v.post(`/api/public/${g.token}/unlock`, { password: 'nope-nope' });
  assert.equal(wrong.status, 401);
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 401, 'still locked after wrong password');

  const ok = await v.post(`/api/public/${g.token}/unlock`, { password: 'hunter2-hunter2' });
  assert.equal(ok.status, 200);
  const list = await v.get(`/api/public/${g.token}/photos`);
  assert.equal(list.status, 200);
  assert.equal(list.json.title, 'Secret wedding');
  const orig = await v.get(`/api/public/${g.token}/img/${p.id}?size=full`, { headers: H.image });
  assert.ok(orig.buf.equals(img.jpg));
  // the cookie is scoped to this gallery and cannot unlock another one
  const g2 = await newGallery('Other');
  await owner.owner.patch(`/api/galleries/${g2.id}`, { password: 'another-pass-1' });
  assert.equal((await v.get(`/api/public/${g2.token}/photos`)).status, 401);

  // stored hash is a salted scrypt hash, not the password
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(path.join(srv.dataDir, 'lumen.db'), { readOnly: true });
  const row = db.prepare('SELECT pw_hash FROM galleries WHERE id = ?').get(g.id);
  db.close();
  assert.match(row.pw_hash, /^scrypt\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.equal(row.pw_hash.includes('hunter2'), false);
});

test('changing or removing a password updates access immediately', async () => {
  const g = await newGallery('pw changes');
  await addPhoto(g, img.jpg, 'x.jpg');
  await owner.owner.patch(`/api/galleries/${g.id}`, { password: 'first-password' });
  const v = client(srv.url);
  assert.equal((await v.post(`/api/public/${g.token}/unlock`, { password: 'first-password' })).status, 200);
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 200);
  await owner.owner.patch(`/api/galleries/${g.id}`, { password: 'second-password' });
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 401, 'old session dead after password change');
  assert.equal((await v.post(`/api/public/${g.token}/unlock`, { password: 'first-password' })).status, 401, 'old password rejected');
  assert.equal((await v.post(`/api/public/${g.token}/unlock`, { password: 'second-password' })).status, 200);
  await owner.owner.patch(`/api/galleries/${g.id}`, { password: null });
  const anon = client(srv.url);
  assert.equal((await anon.get(`/api/public/${g.token}/photos`)).status, 200, 'no password -> link alone opens it');
});

test('MODE A view-only: no downloads, no direct image URLs', async () => {
  const g = await newGallery('Mode A');
  const p = await addPhoto(g, img.jpg, 'a.jpg');
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'view', password: 'view-only-pass' });
  const v = client(srv.url);
  await v.post(`/api/public/${g.token}/unlock`, { password: 'view-only-pass' });
  const list = await v.get(`/api/public/${g.token}/photos`);
  assert.equal(list.json.mode, 'view');
  assert.equal(list.json.canDownload, false);
  assert.equal(list.text.includes('"key"'), false, 'no storage keys leaked');
  assert.equal((await v.get(`/api/public/${g.token}/download/${p.id}`)).status, 403);
  assert.equal((await v.get(`/api/public/${g.token}/zip`)).status, 403);
  assert.equal((await v.get(`/api/public/${g.token}/img/${p.id}?size=full`, { headers: H.doc })).status, 403, 'opening image URL directly is refused');
  assert.equal((await v.get(`/api/public/${g.token}/img/${p.id}?size=full`, { headers: H.cross })).status, 403, 'hot-linking refused');
  const ok = await v.get(`/api/public/${g.token}/img/${p.id}?size=full`, { headers: H.image });
  assert.equal(ok.status, 200);
  assert.match(ok.headers.get('cache-control'), /no-store/);
  assert.equal(ok.headers.get('content-disposition'), 'inline; filename="photo"');
  // wrong-gallery photo id
  const g2 = await newGallery('Other gallery');
  const p2 = await addPhoto(g2, img.png, 'z.png');
  assert.equal((await v.get(`/api/public/${g.token}/img/${p2.id}?size=full`, { headers: H.image })).status, 404);
});

test('MODE B view & download: single photo + ZIP work, direct image URL still restricted', async () => {
  const g = await newGallery('Mode B');
  const a = await addPhoto(g, img.jpg, 'one.jpg');
  await addPhoto(g, img.png, 'two.png');
  await addPhoto(g, img.webp, 'one.jpg'); // duplicate name on purpose
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'download', password: 'download-pass' });
  const v = client(srv.url);
  assert.equal((await v.get(`/api/public/${g.token}/download/${a.id}`)).status, 401, 'password first');
  assert.equal((await v.get(`/api/public/${g.token}/zip`)).status, 401, 'password first (zip)');
  await v.post(`/api/public/${g.token}/unlock`, { password: 'download-pass' });
  const list = await v.get(`/api/public/${g.token}/photos`);
  assert.equal(list.json.canDownload, true);
  const d = await v.get(`/api/public/${g.token}/download/${a.id}`);
  assert.equal(d.status, 200);
  assert.match(d.headers.get('content-disposition'), /^attachment; filename="one\.jpg"/);
  assert.ok(d.buf.equals(img.jpg));
  assert.equal((await v.get(`/api/public/${g.token}/img/${a.id}?size=full`, { headers: H.doc })).status, 403);

  const z = await v.get(`/api/public/${g.token}/zip`);
  assert.equal(z.status, 200);
  assert.equal(z.headers.get('content-type'), 'application/zip');
  const tmp = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'zip-'));
  fs.writeFileSync(path.join(tmp, 'g.zip'), z.buf);
  execFileSync('unzip', ['-tq', path.join(tmp, 'g.zip')]); // integrity (CRC) check
  execFileSync('unzip', ['-q', path.join(tmp, 'g.zip'), '-d', path.join(tmp, 'out')]);
  const names = fs.readdirSync(path.join(tmp, 'out')).sort();
  assert.deepEqual(names, ['one-2.jpg', 'one.jpg', 'two.png'], 'duplicate names are de-duplicated');
  assert.ok(fs.readFileSync(path.join(tmp, 'out', 'one.jpg')).equals(img.jpg));
  assert.ok(fs.readFileSync(path.join(tmp, 'out', 'two.png')).equals(img.png));
  assert.ok(fs.readFileSync(path.join(tmp, 'out', 'one-2.jpg')).equals(img.webp));
});

test('MODE C full access + owner can change modes at any time', async () => {
  const g = await newGallery('Mode C');
  const p = await addPhoto(g, img.jpg, 'a.jpg');
  const v = client(srv.url);
  const direct = () => v.get(`/api/public/${g.token}/img/${p.id}?size=full`, { headers: H.doc });
  const dl = () => v.get(`/api/public/${g.token}/download/${p.id}`);
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'view' });
  assert.equal((await direct()).status, 403); assert.equal((await dl()).status, 403);
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'full' });
  const r = await direct();
  assert.equal(r.status, 200, 'full access allows opening/saving the image'); assert.ok(r.buf.equals(img.jpg));
  assert.equal((await dl()).status, 200);
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'download' });
  assert.equal((await direct()).status, 403); assert.equal((await dl()).status, 200);
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'view' });
  assert.equal((await dl()).status, 403, 'tightening takes effect immediately');
  assert.equal((await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'everything' })).status, 400);
  // password still enforced in full mode
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'full', password: 'full-access-pw' });
  assert.equal((await client(srv.url).get(`/api/public/${g.token}/img/${p.id}`, { headers: H.doc })).status, 401);
});

test('revoke, restore and new link', async () => {
  const g = await newGallery('Revocable');
  const p = await addPhoto(g, img.jpg, 'a.jpg');
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'full', password: 'revoke-me-pass' });
  const v = client(srv.url);
  await v.post(`/api/public/${g.token}/unlock`, { password: 'revoke-me-pass' });
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 200);

  const rev = await owner.owner.post(`/api/galleries/${g.id}/revoke`);
  assert.equal(rev.json.status, 'revoked');
  const dead = await v.get(`/api/public/${g.token}/photos`);
  assert.equal(dead.status, 404, 'valid session is cut off at once');
  assert.equal((await v.get(`/api/public/${g.token}/img/${p.id}`, { headers: H.image })).status, 404);
  assert.equal((await v.get(`/api/public/${g.token}/zip`)).status, 404);
  assert.equal((await v.post(`/api/public/${g.token}/unlock`, { password: 'revoke-me-pass' })).status, 404);
  const unknown = await v.get(`/api/public/AAAAAAAAAAAAAAAAAAAAAAAA/photos`);
  assert.equal(unknown.text, dead.text, 'revoked looks exactly like unknown');

  assert.equal((await owner.owner.post(`/api/galleries/${g.id}/restore`)).json.status, 'active');
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 200);

  const rot = await owner.owner.post(`/api/galleries/${g.id}/rotate`);
  assert.notEqual(rot.json.token, g.token);
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 404, 'old link dead forever');
  assert.equal((await v.get(`/api/public/${rot.json.token}/photos`)).status, 401, 'old sessions do not carry over to the new link');
  const v2 = client(srv.url);
  await v2.post(`/api/public/${rot.json.token}/unlock`, { password: 'revoke-me-pass' });
  assert.equal((await v2.get(`/api/public/${rot.json.token}/photos`)).status, 200);
});

test('link expiry', async () => {
  const g = await newGallery('Expiring');
  await addPhoto(g, img.jpg, 'a.jpg');
  assert.equal((await owner.owner.patch(`/api/galleries/${g.id}`, { expiresAt: Date.now() - 1000 })).status, 400, 'past date refused');
  const r = await owner.owner.patch(`/api/galleries/${g.id}`, { expiresAt: Date.now() + 1500 });
  assert.equal(r.json.status, 'active');
  const v = client(srv.url);
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 200);
  await new Promise((res) => setTimeout(res, 1700));
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 404, 'expired link stops working');
  assert.equal((await owner.owner.get(`/api/galleries/${g.id}`)).json.status, 'expired');
  await owner.owner.patch(`/api/galleries/${g.id}`, { expiresAt: null });
  assert.equal((await v.get(`/api/public/${g.token}/photos`)).status, 200, 'clearing expiry reopens it');
});

test('access activity counts events and stores no personal data', async () => {
  const g = await newGallery('Stats');
  const p = await addPhoto(g, img.jpg, 'a.jpg');
  await owner.owner.patch(`/api/galleries/${g.id}`, { mode: 'download', password: 'stats-pass-1' });
  const v = client(srv.url);
  await v.post(`/api/public/${g.token}/unlock`, { password: 'bad-bad-bad' });
  await v.post(`/api/public/${g.token}/unlock`, { password: 'stats-pass-1' });
  await v.get(`/api/public/${g.token}/photos`);
  await v.get(`/api/public/${g.token}/photos`);
  await v.get(`/api/public/${g.token}/download/${p.id}`);
  await v.get(`/api/public/${g.token}/zip`);
  const s = (await owner.owner.get(`/api/galleries/${g.id}`)).json.stats;
  assert.equal(s.failedAttempts, 1); assert.equal(s.unlocks, 1); assert.equal(s.opens, 2); assert.equal(s.downloads, 1); assert.equal(s.zips, 1);
  assert.ok(s.lastOpened > 0);
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(path.join(srv.dataDir, 'lumen.db'), { readOnly: true });
  const cols = db.prepare('PRAGMA table_info(events)').all().map((c) => c.name);
  db.close();
  assert.deepEqual(cols, ['id', 'gallery_id', 'type', 'at'], 'events table has no IP / user-agent columns');
});

test('upload limits: file size and storage quota', async () => {
  const small = await startServer({ MAX_UPLOAD_MB: '0.05', STORAGE_LIMIT_GB: String(300000 / 1073741824) });
  try {
    const o = await loginOwner(small.url);
    const g = (await o.owner.post('/api/galleries', { title: 'limits' })).json;
    const tooBig = await o.owner.upload(`/api/galleries/${g.id}/photos?name=big.jpg`, img.big);
    assert.equal(tooBig.status, 413);
    // quota ~300 KB: a couple of ~30-60 KB images fit, then it refuses
    let stored = 0, refused = false;
    for (let i = 0; i < 40 && !refused; i++) {
      const r = await o.owner.upload(`/api/galleries/${g.id}/photos?name=p${i}.png`, img.png);
      if (r.status === 201) stored += img.png.length; else { assert.equal(r.status, 507); refused = true; }
    }
    assert.ok(refused, 'quota enforced');
    assert.ok(stored <= 300000);
    const me = (await o.owner.get('/api/me')).json.storage;
    assert.equal(me.used, stored);
    assert.ok(me.used <= me.limit);
  } finally { await small.stop(); }
});

test('brute force protection: owner login and gallery passwords', async () => {
  const s = await startServer();
  try {
    const bad = client(s.url);
    let last;
    for (let i = 0; i < 9; i++) last = await bad.post('/api/login', { password: 'wrong-' + i }, { headers: { 'x-lumen': '1' } });
    assert.equal(last.status, 429, 'owner login locked after repeated failures');
    assert.equal((await bad.post('/api/login', { password: PW }, { headers: { 'x-lumen': '1' } })).status, 429, 'even the right password is refused while locked');

    const o = await loginOwner(s.url).catch(() => null);
    assert.equal(o, null, 'same IP is locked out of login');
  } finally { await s.stop(); }

  const s2 = await startServer();
  try {
    const o = await loginOwner(s2.url);
    const g = (await o.owner.post('/api/galleries', { title: 'bf' })).json;
    await o.owner.patch(`/api/galleries/${g.id}`, { password: 'the-real-password' });
    const v = client(s2.url);
    const codes = [];
    for (let i = 0; i < 7; i++) codes.push((await v.post(`/api/public/${g.token}/unlock`, { password: 'guess-' + i })).status);
    assert.deepEqual(codes, [401, 401, 401, 401, 401, 401, 429]);
    const r = await v.post(`/api/public/${g.token}/unlock`, { password: 'the-real-password' });
    assert.equal(r.status, 429, 'guessing is throttled; right password refused during lockout');
    assert.ok(r.headers.get('retry-after'));
  } finally { await s2.stop(); }
});

test('visitors cannot reach owner endpoints, raw storage, or enumerate galleries', async () => {
  const g = await newGallery('Private');
  const p = await addPhoto(g, img.jpg, 'a.jpg');
  const v = client(srv.url);
  assert.equal((await v.get(`/api/owner-img/${p.id}?size=full`)).status, 401);
  assert.equal((await v.get('/api/galleries')).status, 401);
  assert.equal((await v.get(`/api/galleries/${g.id}`)).status, 401);
  assert.equal((await v.req('DELETE', `/api/photos/${p.id}`, { headers: { 'x-lumen': '1' } })).status, 401);
  assert.equal((await v.req('POST', `/api/galleries/${g.id}/photos`, { body: img.jpg, headers: { 'x-lumen': '1' } })).status, 401);
  // a visitor session on one gallery is not an owner session
  await owner.owner.patch(`/api/galleries/${g.id}`, { password: 'visitor-pass-1' });
  await v.post(`/api/public/${g.token}/unlock`, { password: 'visitor-pass-1' });
  assert.equal((await v.get('/api/galleries')).status, 401);
  // the internal storage key / database id of the photo is not usable as a token
  assert.equal((await v.get(`/api/public/${g.id}/photos`)).status, 404);
  assert.equal((await v.get('/api/public/x/photos')).status, 404);
  for (const key of listFiles(path.join(srv.dataDir, 'uploads'))) assert.equal((await v.get('/uploads/' + key)).status, 404);
});

test('persistence: galleries, photos, passwords and sessions survive a server restart', async () => {
  const dataDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'lumen-persist-'));
  let s = await startServer({ DATA_DIR: dataDir });
  const o = await loginOwner(s.url);
  const g = (await o.owner.post('/api/galleries', { title: 'Persistent' })).json;
  const up = await o.owner.upload(`/api/galleries/${g.id}/photos?name=keep.jpg`, img.jpg);
  await o.owner.patch(`/api/galleries/${g.id}`, { password: 'persist-pass-1', mode: 'full' });
  const v = client(s.url);
  await v.post(`/api/public/${g.token}/unlock`, { password: 'persist-pass-1' });
  await s.stop();

  s = await startServer({ DATA_DIR: dataDir });
  try {
    const o2 = client(s.url);
    o2.jar = o.jar; // same cookies (same OWNER_PASSWORD -> same derived secret)
    const o3 = client(s.url);
    for (const [k, c] of o.jar) o3.jar.set(k, c);
    const list = await o3.owner.get('/api/galleries');
    assert.equal(list.status, 200, 'owner session survives restart');
    assert.equal(list.json.length, 1);
    assert.equal(list.json[0].photoCount, 1);
    for (const [k, c] of v.jar) o3.jar.set(k, c);
    const pub = await o3.get(`/api/public/${g.token}/photos`);
    assert.equal(pub.status, 200, 'visitor session survives restart');
    const f = await client(s.url).get(`/api/public/${g.token}/photos`);
    assert.equal(f.status, 401, 'password still required');
    const w = client(s.url);
    await w.post(`/api/public/${g.token}/unlock`, { password: 'persist-pass-1' });
    const bytes = await w.get(`/api/public/${g.token}/img/${up.json.id}`, { headers: H.doc });
    assert.ok(bytes.buf.equals(img.jpg), 'original bytes intact after restart');
    assert.equal((await o3.owner.get('/api/me')).json.storage.used, img.jpg.length);
  } finally { await s.stop(); }
});

test('startup refuses a missing or weak owner password', async () => {
  await assert.rejects(startServer({ OWNER_PASSWORD: '' }), /OWNER_PASSWORD/);
  await assert.rejects(startServer({ OWNER_PASSWORD: 'short' }), /OWNER_PASSWORD/);
});

test('front-end scripts are syntactically valid', () => {
  for (const f of ['dashboard.js', 'gallery.js', 'login.js']) execFileSync(process.execPath, ['--check', path.join(ROOT, 'public/assets', f)]);
  for (const f of ['server.js', 'lib/config.js', 'lib/db.js', 'lib/storage.js', 'lib/sigv4.js', 'lib/zip.js']) execFileSync(process.execPath, ['--check', path.join(ROOT, f)]);
});
