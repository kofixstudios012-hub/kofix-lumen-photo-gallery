'use strict';
// Owner dashboard. All user-supplied text is inserted with textContent (never innerHTML).
const $ = (id) => document.getElementById(id);
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'multiple' || k === 'required') el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const fmtBytes = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(0) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB');
const fmtDate = (t) => (t ? new Date(t).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'never');
const MODE_INFO = {
  view: ['View only', 'Password (optional), then a protected full-screen viewer. No downloads, no direct image links.'],
  download: ['View & download', 'Viewer plus single-photo downloads and a ZIP of the whole gallery.'],
  full: ['Full access', 'Everything open: view, download and save. No viewer restrictions.'],
};

let me = null, galleries = [], current = null;

function toast(text, isErr) {
  const t = h('div', { class: 'toast' + (isErr ? ' err' : ''), role: 'status' }, text);
  document.body.append(t);
  setTimeout(() => t.remove(), isErr ? 5000 : 2500);
}
async function api(method, url, body) {
  const r = await fetch(url, { method, headers: { 'x-lumen': '1', ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  if (r.status === 401) { location.href = '/login'; throw new Error('Signed out'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'Request failed');
  return j;
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

// ---------- storage meter ----------
async function loadMe() {
  me = await api('GET', '/api/me');
  const s = me.storage, pct = Math.min(100, (s.used / s.limit) * 100);
  const bar = $('meterbar');
  bar.style.width = pct.toFixed(1) + '%';
  bar.classList.toggle('warn', pct > 90);
  $('metertext').textContent = `${fmtBytes(s.used)} used of ${fmtBytes(s.limit)} · ${fmtBytes(Math.max(0, s.limit - s.used))} free · ${s.backend}`;
  const b = $('banner');
  b.classList.toggle('hidden', !me.warning);
  b.textContent = me.warning || '';
}

// ---------- gallery list ----------
async function loadList() {
  galleries = await api('GET', '/api/galleries');
  const list = $('glist');
  list.replaceChildren(...galleries.map((g) => h('button', { class: 'gitem' + (current && current.id === g.id ? ' on' : ''), onclick: () => openGallery(g.id) },
    h('div', { class: 'cov', style: false, 'data-cover': g.cover || '' }),
    h('div', {}, h('strong', {}, g.title), h('small', {}, `${g.photoCount} photos · ${MODE_INFO[g.mode][0]} `), h('span', { class: 'badge ' + g.status }, g.status)))));
  list.querySelectorAll('.cov').forEach((el) => { const id = el.dataset.cover; if (id) el.style.backgroundImage = `url(/api/owner-img/${id}?size=thumb)`; });
}

$('newform').addEventListener('submit', guard(async (e) => {
  e.preventDefault();
  const g = await api('POST', '/api/galleries', { title: $('newtitle').value });
  $('newtitle').value = '';
  await loadList();
  await openGallery(g.id);
}));
$('logout').addEventListener('click', async () => { await fetch('/api/logout', { method: 'POST', headers: { 'x-lumen': '1' } }); location.href = '/login'; });

// ---------- gallery detail ----------
async function openGallery(id, scroll = true) {
  current = await api('GET', '/api/galleries/' + id);
  renderDetail();
  loadList();
  if (scroll && window.innerWidth < 860) $('detail').scrollIntoView({ behavior: 'smooth' });
}
const shareUrl = (g) => `${location.origin}/g/${g.token}`;

function renderDetail() {
  const g = current;
  const msgPw = h('p', { class: 'msg', role: 'status' });
  const titleIn = h('input', { type: 'text', value: g.title, maxlength: 80, 'aria-label': 'Gallery name' });
  const pwIn = h('input', { type: 'password', placeholder: g.hasPassword ? 'Enter a new password to change it' : 'Set a password (min 6 characters)', autocomplete: 'new-password' });
  const expIn = h('input', { type: 'date', value: g.expiresAt ? new Date(g.expiresAt).toISOString().slice(0, 10) : '' });
  const wmIn = h('input', { type: 'text', value: g.watermark || '', maxlength: 40, placeholder: 'e.g. © Your Studio · Proof' });
  const link = h('input', { type: 'text', value: shareUrl(g), readonly: true, 'aria-label': 'Share link' });

  const patch = guard(async (body, okText) => {
    await api('PATCH', '/api/galleries/' + g.id, body);
    toast(okText || 'Saved');
    await openGallery(g.id, false);
  });

  const modeRadios = ['view', 'download', 'full'].map((m) => h('label', { class: 'mode' },
    h('input', { type: 'radio', name: 'mode', value: m, checked: g.mode === m, onchange: () => patch({ mode: m }, 'Access mode updated') }),
    h('b', {}, MODE_INFO[m][0]), h('span', {}, MODE_INFO[m][1])));

  const s = g.stats;
  const root = $('detail');
  root.replaceChildren(
    h('div', { class: 'panel' },
      h('div', { class: 'row' },
        h('div', { class: 'grow' }, titleIn),
        h('button', { class: 'btn small', onclick: () => patch({ title: titleIn.value }, 'Renamed') }, 'Rename'),
        h('span', { class: 'badge ' + g.status }, g.status)),
    ),
    h('div', { class: 'panel' }, h('h3', {}, 'Share link'),
      h('div', { class: 'linkbox' }, link,
        h('button', { class: 'btn small', onclick: guard(async () => { try { await navigator.clipboard.writeText(link.value); } catch { link.select(); document.execCommand('copy'); } toast('Link copied'); }) }, 'Copy'),
        h('a', { class: 'btn ghost small', href: shareUrl(g), target: '_blank', rel: 'noopener noreferrer' }, 'Open')),
      h('div', { class: 'row', 'data-gap': '1' },
        g.status === 'revoked'
          ? h('button', { class: 'btn small', onclick: guard(async () => { await api('POST', `/api/galleries/${g.id}/restore`); toast('Link restored'); await openGallery(g.id, false); }) }, 'Restore link')
          : h('button', { class: 'btn danger small', onclick: guard(async () => { if (!confirm('Revoke this link now? Visitors lose access immediately.')) return; await api('POST', `/api/galleries/${g.id}/revoke`); toast('Link revoked'); await openGallery(g.id, false); }) }, 'Revoke link'),
        h('button', { class: 'btn ghost small', onclick: guard(async () => { if (!confirm('Create a brand-new link? The old link stops working forever.')) return; await api('POST', `/api/galleries/${g.id}/rotate`); toast('New link created'); await openGallery(g.id, false); }) }, 'Create new link')),
      h('p', { class: 'note' }, 'Anyone with this link ', g.hasPassword ? 'and the password ' : '', 'can open the gallery. Revoking takes effect immediately.')),
    h('div', { class: 'panel' }, h('h3', {}, 'Access mode'), h('div', { class: 'modes' }, modeRadios),
      g.mode === 'view' ? h('p', { class: 'note' }, 'View-only adds real deterrents (no download buttons, no direct image URLs, right-click/drag/print blocked, hides when the window loses focus, optional watermark). No website can fully prevent screenshots or a photo of the screen taken with another phone.') : null),
    h('div', { class: 'panel' }, h('h3', {}, 'Password, expiry & watermark'),
      h('label', { class: 'field' }, h('span', {}, g.hasPassword ? 'Password (currently set)' : 'Password (currently none)'), pwIn),
      h('div', { class: 'row' },
        h('button', { class: 'btn small', onclick: () => { if (!pwIn.value) return toast('Type a password first', true); patch({ password: pwIn.value }, 'Password saved'); } }, g.hasPassword ? 'Change password' : 'Set password'),
        g.hasPassword ? h('button', { class: 'btn danger small', onclick: () => { if (confirm('Remove the password? Anyone with the link can then open the gallery.')) patch({ password: null }, 'Password removed'); } }, 'Remove password') : null),
      h('label', { class: 'field' }, h('span', {}, 'Link expires on (optional)'), expIn),
      h('div', { class: 'row' },
        h('button', { class: 'btn small', onclick: () => { if (!expIn.value) return toast('Pick a date first', true); patch({ expiresAt: new Date(expIn.value + 'T23:59:59').getTime() }, 'Expiry saved'); } }, 'Save expiry'),
        g.expiresAt ? h('button', { class: 'btn ghost small', onclick: () => patch({ expiresAt: null }, 'Expiry cleared') }, 'Clear expiry') : null,
        g.expiresAt ? h('span', { class: 'muted' }, 'Expires ' + fmtDate(g.expiresAt)) : null),
      h('label', { class: 'field' }, h('span', {}, 'Watermark text for view-only mode (optional)'), wmIn),
      h('button', { class: 'btn small', onclick: () => patch({ watermark: wmIn.value }, 'Watermark saved') }, 'Save watermark'),
      msgPw),
    h('div', { class: 'panel' }, h('h3', {}, 'Access activity (no personal data stored)'),
      h('div', { class: 'stats' },
        stat(s.opens, 'Gallery opens'), stat(s.unlocks, 'Password unlocks'), stat(s.failedAttempts, 'Wrong passwords'), stat(s.downloads, 'Photo downloads'), stat(s.zips, 'ZIP downloads')),
      h('p', { class: 'note' }, 'Last opened: ' + fmtDate(s.lastOpened) + '. Visitors’ IP addresses and devices are never saved.')),
    uploadPanel(g),
    h('div', { class: 'panel' }, h('h3', {}, `Photos (${g.photos.length})`), photoGrid(g)),
    h('div', { class: 'panel' }, h('h3', {}, 'Danger zone'),
      h('button', { class: 'btn danger small', onclick: guard(async () => { if (!confirm(`Delete “${g.title}” and all ${g.photos.length} photos permanently?`)) return; await api('DELETE', '/api/galleries/' + g.id); current = null; toast('Gallery deleted'); $('detail').replaceChildren(h('div', { class: 'panel' }, h('p', { class: 'muted' }, 'Gallery deleted.'))); await loadMe(); await loadList(); }) }, 'Delete gallery')),
  );
}
const stat = (n, label) => h('div', { class: 'stat' }, h('b', {}, n), h('small', {}, label));

function photoGrid(g) {
  if (!g.photos.length) return h('p', { class: 'muted' }, 'No photos yet.');
  return h('div', { class: 'pgrid' }, g.photos.map((p) => {
    const im = h('div', { class: 'im' });
    im.style.backgroundImage = `url(/api/owner-img/${p.id}?size=thumb&v=${p.v}${p.hasThumb ? 't' : ''})`;
    const fileIn = h('input', { type: 'file', accept: 'image/jpeg,image/png,image/webp', class: 'hidden', onchange: guard(async (e) => { const f = e.target.files[0]; if (!f) return; await uploadOne(f, { replaceId: p.id }); await refreshAll(); toast('Photo replaced'); }) });
    return h('div', { class: 'ph' }, im, h('div', { class: 'nm', title: p.name }, p.name), h('div', { class: 'muted nm' }, fmtBytes(p.size)),
      h('div', { class: 'ac' },
        h('button', { class: 'btn ghost small', onclick: guard(async () => { const n = prompt('Rename photo', p.name); if (n && n.trim()) { await api('PATCH', '/api/photos/' + p.id, { name: n }); await openGallery(g.id, false); } }) }, 'Rename'),
        h('button', { class: 'btn ghost small', onclick: () => fileIn.click() }, 'Replace'),
        h('button', { class: 'btn danger small', onclick: guard(async () => { if (!confirm('Delete this photo?')) return; await api('DELETE', '/api/photos/' + p.id); await refreshAll(); }) }, 'Delete')),
      fileIn);
  }));
}
async function refreshAll() { await loadMe(); await openGallery(current.id, false); }

// ---------- uploads ----------
const OK_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

function xhrSend(method, url, blob, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open(method, url);
    x.setRequestHeader('x-lumen', '1');
    x.setRequestHeader('content-type', blob.type || 'application/octet-stream');
    if (onProgress) x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    x.onload = () => {
      let j = {}; try { j = JSON.parse(x.responseText); } catch { /* ignore */ }
      if (x.status === 401) { location.href = '/login'; return; }
      x.status >= 200 && x.status < 300 ? resolve(j) : reject(new Error(j.error || `Upload failed (${x.status})`));
    };
    x.onerror = () => reject(new Error('Network error during upload'));
    x.send(blob);
  });
}
async function makeThumb(file) {
  const bmp = await createImageBitmap(file);
  const s = Math.min(1, 640 / Math.max(bmp.width, bmp.height));
  const c = document.createElement('canvas');
  c.width = Math.max(1, Math.round(bmp.width * s)); c.height = Math.max(1, Math.round(bmp.height * s));
  c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
  bmp.close && bmp.close();
  return new Promise((res) => c.toBlob(res, 'image/webp', 0.82));
}
// Uploads one file (new or replacement) plus a small thumbnail. onProgress gets 0..1.
async function uploadOne(file, { replaceId, onProgress } = {}) {
  if (!OK_TYPES.includes(file.type) && !/\.(jpe?g|png|webp)$/i.test(file.name)) throw new Error('Only JPEG, PNG and WebP are supported');
  if (file.size > me.maxUploadBytes) throw new Error(`Too large (max ${fmtBytes(me.maxUploadBytes)})`);
  const name = encodeURIComponent(file.name);
  const photo = replaceId
    ? await xhrSend('PUT', `/api/photos/${replaceId}/file?name=${name}`, file, onProgress)
    : await xhrSend('POST', `/api/galleries/${current.id}/photos?name=${name}`, file, onProgress);
  try {
    const t = await makeThumb(file);
    if (t) await xhrSend('POST', `/api/photos/${photo.id}/thumb`, t);
  } catch { /* thumbnail is optional; the viewer falls back to the full image */ }
  return photo;
}

function uploadPanel(g) {
  const input = h('input', { type: 'file', multiple: true, accept: 'image/jpeg,image/png,image/webp', class: 'hidden' });
  const queue = h('div', { class: 'queue' });
  const drop = h('div', { class: 'drop', tabindex: 0, role: 'button', 'aria-label': 'Choose photos to upload' },
    h('strong', {}, 'Drop photos here or tap to choose'), h('div', { class: 'muted' }, `JPEG, PNG or WebP · up to ${fmtBytes(me.maxUploadBytes)} each`));
  drop.addEventListener('click', () => input.click());
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => start([...e.dataTransfer.files]));
  input.addEventListener('change', () => { start([...input.files]); input.value = ''; });

  async function start(files) {
    if (!files.length) return;
    const jobs = files.map((f) => {
      const img = h('img', { alt: '' }); img.src = URL.createObjectURL(f);
      const bar = h('i', {}); const st = h('span', { class: 'st' }, 'Waiting');
      const row = h('div', { class: 'qi' }, img, h('div', {}, h('div', {}, f.name), h('div', { class: 'pb' }, bar)), st);
      queue.append(row);
      return { f, row, bar, st };
    });
    let i = 0, okCount = 0;
    const worker = async () => {
      while (i < jobs.length) {
        const j = jobs[i++];
        j.st.textContent = 'Uploading';
        try {
          await uploadOne(j.f, { onProgress: (p) => { j.bar.style.width = (p * 100).toFixed(0) + '%'; j.st.textContent = (p * 100).toFixed(0) + '%'; } });
          j.bar.style.width = '100%'; j.row.classList.add('done'); j.st.textContent = 'Done'; okCount++;
        } catch (e) { j.row.classList.add('err'); j.st.textContent = e.message; }
      }
    };
    await Promise.all([worker(), worker()]);
    if (okCount) { await loadMe(); await openGallery(g.id, false); toast(`${okCount} photo${okCount > 1 ? 's' : ''} uploaded`); }
  }
  return h('div', { class: 'panel' }, h('h3', {}, 'Upload photos'), drop, input, queue);
}

(async () => {
  try { await loadMe(); await loadList(); if (galleries[0]) await openGallery(galleries[0].id, false); }
  catch (e) { if (e.message !== 'Signed out') toast(e.message, true); }
})();
