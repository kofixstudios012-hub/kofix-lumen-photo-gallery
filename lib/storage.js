'use strict';
// Photo storage drivers. Same interface: put(key, buffer, mime), get(key) -> Buffer|null, del(key).
//   - s3    : any S3-compatible bucket (Backblaze B2 free 10 GB, Cloudflare R2, ...). Bucket stays PRIVATE.
//   - local : files on disk (for running on your own computer; NOT persistent on Render's free plan)
const fs = require('node:fs');
const path = require('node:path');
const { sign } = require('./sigv4');

function local(cfg) {
  const root = path.join(cfg.dataDir, 'uploads');
  fs.mkdirSync(root, { recursive: true });
  const file = (key) => {
    const p = path.resolve(root, key);
    if (!p.startsWith(root + path.sep)) throw new Error('bad key');
    return p;
  };
  return {
    kind: 'local',
    persistent: !cfg.onRender,
    label: 'Local disk',
    async put(key, buf) {
      const p = file(key);
      await fs.promises.mkdir(path.dirname(p), { recursive: true });
      await fs.promises.writeFile(p, buf);
    },
    async get(key) {
      try { return await fs.promises.readFile(file(key)); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    },
    async del(key) { try { await fs.promises.unlink(file(key)); } catch (e) { if (e.code !== 'ENOENT') throw e; } },
  };
}

function s3(cfg) {
  const { endpoint, region, bucket, keyId, appKey } = cfg.s3;
  const urlFor = (key) => `${endpoint}/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;

  async function call(method, key, body, extra = {}) {
    const url = urlFor(key);
    let lastErr;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const { headers } = sign({ method, url, region, keyId, secret: appKey, body });
        const r = await fetch(url, { method, headers: { ...headers, ...extra }, body });
        if (r.status >= 500) { lastErr = new Error(`S3 ${method} ${r.status}`); await new Promise((z) => setTimeout(z, 300 * (attempt + 1))); continue; }
        return r;
      } catch (e) { lastErr = e; await new Promise((z) => setTimeout(z, 300 * (attempt + 1))); }
    }
    throw lastErr;
  }

  return {
    kind: 's3',
    persistent: true,
    label: /backblaze/i.test(endpoint) ? 'Backblaze B2' : 'S3-compatible storage',
    async put(key, buf, mime) {
      const r = await call('PUT', key, buf, { 'content-type': mime });
      if (!r.ok) throw new Error(`Storage upload failed (${r.status}): ${(await r.text()).slice(0, 200)}`);
    },
    async get(key) {
      const r = await call('GET', key);
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`Storage read failed (${r.status})`);
      return Buffer.from(await r.arrayBuffer());
    },
    async del(key) {
      const r = await call('DELETE', key);
      if (!r.ok && r.status !== 404) throw new Error(`Storage delete failed (${r.status})`);
    },
  };
}

module.exports = { createStorage: (cfg) => (cfg.useS3 ? s3(cfg) : local(cfg)) };
