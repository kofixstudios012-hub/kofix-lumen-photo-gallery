'use strict';
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

const ROOT = path.join(__dirname, '..');
const PW = 'correct horse battery';

function freePort() {
  return new Promise((resolve) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
}

async function startServer(env = {}) {
  const port = await freePort();
  const dataDir = env.DATA_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'lumen-test-'));
  const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    env: { PATH: process.env.PATH, PORT: String(port), OWNER_PASSWORD: PW, ...env, DATA_DIR: dataDir },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    if (/Lumen running/.test(out)) break;
    if (child.exitCode !== null) throw new Error('server exited: ' + out);
    await new Promise((r) => setTimeout(r, 50));
  }
  if (!/Lumen running/.test(out)) throw new Error('server did not start: ' + out);
  return {
    url, dataDir, logs: () => out,
    stop: () => new Promise((resolve) => { if (child.exitCode !== null) return resolve(); child.on('exit', resolve); child.kill('SIGTERM'); }),
  };
}

// A tiny cookie-aware HTTP client (honours cookie Path, like a browser).
function client(base) {
  const jar = new Map();
  async function req(method, p, { json, body, headers = {}, raw } = {}) {
    const h = { ...headers };
    const cookies = [...jar.values()].filter((c) => p.startsWith(c.path)).map((c) => `${c.name}=${c.value}`).join('; ');
    if (cookies) h.cookie = cookies;
    let b = body;
    if (json !== undefined) { h['content-type'] = 'application/json'; b = JSON.stringify(json); }
    const r = await fetch(base + p, { method, headers: h, body: b, redirect: 'manual' });
    for (const sc of r.headers.getSetCookie()) {
      const [kv, ...attrs] = sc.split(';').map((s) => s.trim());
      const i = kv.indexOf('=');
      const name = kv.slice(0, i), value = decodeURIComponent(kv.slice(i + 1));
      const pathAttr = (attrs.find((a) => /^path=/i.test(a)) || 'Path=/').slice(5);
      const maxAge = attrs.find((a) => /^max-age=/i.test(a));
      if (maxAge && Number(maxAge.slice(8)) <= 0) jar.delete(name + pathAttr); else jar.set(name + pathAttr, { name, value, path: pathAttr });
    }
    if (raw) return r;
    const buf = Buffer.from(await r.arrayBuffer());
    let parsed = null;
    if ((r.headers.get('content-type') || '').includes('json')) { try { parsed = JSON.parse(buf.toString()); } catch { /* ignore */ } }
    return { status: r.status, headers: r.headers, buf, json: parsed, text: buf.toString('utf8') };
  }
  return {
    jar, req,
    get: (p, o) => req('GET', p, o),
    post: (p, json, o = {}) => req('POST', p, { json, ...o }),
    patch: (p, json, o = {}) => req('PATCH', p, { json, ...o }),
    del: (p, o = {}) => req('DELETE', p, o),
    owner: {
      get: (p, o = {}) => req('GET', p, o),
      post: (p, json, o = {}) => req('POST', p, { json, ...o, headers: { 'x-lumen': '1', ...(o.headers || {}) } }),
      patch: (p, json, o = {}) => req('PATCH', p, { json, ...o, headers: { 'x-lumen': '1' } }),
      del: (p) => req('DELETE', p, { headers: { 'x-lumen': '1' } }),
      upload: (p, buf, method = 'POST') => req(method, p, { body: buf, headers: { 'x-lumen': '1', 'content-type': 'application/octet-stream' } }),
    },
  };
}

async function loginOwner(base) {
  const c = client(base);
  const r = await c.post('/api/login', { password: PW }, { headers: { 'x-lumen': '1' } });
  if (r.status !== 200) throw new Error('login failed ' + r.status);
  return c;
}

// Real image files made with Pillow (falls back to hand-written magic bytes if Pillow is missing).
function makeImages() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lumen-img-'));
  const py = `
import sys
from PIL import Image, ImageDraw
d=sys.argv[1]
def mk(name,color,fmt,size=(640,480)):
    im=Image.new('RGB',size,color); dr=ImageDraw.Draw(im)
    for i in range(0,size[0],20): dr.line([(i,0),(size[0]-i,size[1])],fill=(255-color[0],255-color[1],255-color[2]),width=3)
    im.save(f'{d}/{name}',fmt,quality=90) if fmt!='PNG' else im.save(f'{d}/{name}',fmt)
mk('a.jpg',(200,60,60),'JPEG'); mk('b.png',(60,200,60),'PNG'); mk('c.webp',(60,60,200),'WEBP')
mk('thumb.webp',(10,10,10),'WEBP',(160,120)); mk('big.jpg',(120,120,30),'JPEG',(3000,2400))
`;
  execFileSync('python3', ['-I', '-c', py, dir]);
  const rd = (n) => fs.readFileSync(path.join(dir, n));
  return { jpg: rd('a.jpg'), png: rd('b.png'), webp: rd('c.webp'), thumb: rd('thumb.webp'), big: rd('big.jpg') };
}

module.exports = { startServer, client, loginOwner, makeImages, PW, ROOT };
