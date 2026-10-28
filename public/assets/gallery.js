'use strict';
// Visitor gallery page. The page itself contains no photo data; everything comes from the API after access is granted.
const $ = (id) => document.getElementById(id);
const token = location.pathname.split('/')[2];
const base = `/api/public/${encodeURIComponent(token)}`;
let data = null, idx = 0;

const show = (id) => { for (const x of ['pwform', 'gone', 'loading']) $(x).classList.toggle('hidden', x !== id); };

async function init() {
  let info;
  try {
    const r = await fetch(base + '/info');
    if (!r.ok) { show('gone'); return; }
    info = await r.json();
  } catch { $('loading').textContent = 'Network error. Please reload.'; return; }
  document.title = info.title;
  if (info.needsPassword && !info.unlocked) {
    show('pwform'); $('pw').focus();
    return;
  }
  await loadGallery();
}

$('pwform').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('pwmsg').textContent = '';
  const r = await fetch(base + '/unlock', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: $('pw').value }) });
  const j = await r.json().catch(() => ({}));
  if (r.ok) { $('pw').value = ''; await loadGallery(); return; }
  if (r.status === 404) { show('gone'); return; }
  $('pwmsg').textContent = j.error || 'Incorrect password';
});

async function loadGallery() {
  const r = await fetch(base + '/photos');
  if (r.status === 401) { show('pwform'); return; }
  if (!r.ok) { show('gone'); return; }
  data = await r.json();
  document.title = data.title;
  $('gate').classList.add('hidden');
  $('view').classList.remove('hidden');
  $('vtitle').textContent = data.title;
  $('vkind').textContent = data.mode === 'view' ? 'View-only gallery' : data.mode === 'download' ? 'Gallery · downloads enabled' : 'Gallery · full access';
  if (data.canDownload) { const z = $('zipbtn'); z.href = base + '/zip'; z.classList.remove('hidden'); }
  if (data.mode !== 'full') enableProtection();
  $('vfoot').textContent = data.photos.length ? `${data.photos.length} photo${data.photos.length === 1 ? '' : 's'}` : 'This gallery is empty.';
  const grid = $('grid');
  grid.replaceChildren(...data.photos.map((p, i) => {
    const b = document.createElement('button');
    b.className = 'tile'; b.type = 'button'; b.setAttribute('aria-label', 'Open photo ' + (i + 1));
    const img = document.createElement('img');
    img.alt = p.name; img.loading = 'lazy'; img.draggable = false;
    img.src = `${base}/img/${p.id}?size=thumb&v=${p.v}`;
    b.append(img);
    if (data.mode !== 'full' && data.watermark) { const w = document.createElement('div'); w.className = 'wm-tile'; applyWatermark(w, data.watermark, 0.18); b.append(w); }
    b.addEventListener('click', () => openLb(i));
    return b;
  }));
}

// ---------- watermark overlay (deterrent only: it is drawn on screen, not burned into the file) ----------
function applyWatermark(el, text, alpha) {
  const safe = text.replace(/[<>&"']/g, '');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="260" height="160"><text x="130" y="80" fill="rgba(255,255,255,${alpha})" stroke="rgba(0,0,0,${alpha})" stroke-width=".5" font-family="Georgia,serif" font-size="18" text-anchor="middle" transform="rotate(-24 130 80)">${safe}</text></svg>`;
  el.style.backgroundImage = `url("data:image/svg+xml;utf8,${encodeURIComponent(svg)}")`;
}

// ---------- lightbox ----------
const lb = $('lb'), lbimg = $('lbimg');
function openLb(i) {
  idx = (i + data.photos.length) % data.photos.length;
  const p = data.photos[idx];
  lbimg.alt = p.name;
  lbimg.draggable = false;
  lbimg.src = `${base}/img/${p.id}?size=full&v=${p.v}`;
  $('lbcnt').textContent = `${idx + 1} / ${data.photos.length}`;
  const dl = $('lbdl');
  if (data.canDownload) { dl.href = `${base}/download/${p.id}`; dl.classList.remove('hidden'); }
  const wm = $('lbwm');
  if (data.mode !== 'full' && data.watermark) { applyWatermark(wm, data.watermark, 0.3); wm.classList.remove('hidden'); } else wm.classList.add('hidden');
  lb.classList.remove('hidden');
  $('lbclose').focus();
}
const closeLb = () => { lb.classList.add('hidden'); lbimg.removeAttribute('src'); };
$('lbclose').addEventListener('click', closeLb);
$('lbprev').addEventListener('click', () => openLb(idx - 1));
$('lbnext').addEventListener('click', () => openLb(idx + 1));
document.addEventListener('keydown', (e) => {
  if (lb.classList.contains('hidden')) return;
  if (e.key === 'Escape') closeLb();
  else if (e.key === 'ArrowLeft') openLb(idx - 1);
  else if (e.key === 'ArrowRight') openLb(idx + 1);
});
let sx = null;
lb.addEventListener('touchstart', (e) => { sx = e.touches[0].clientX; }, { passive: true });
lb.addEventListener('touchend', (e) => {
  if (sx === null) return;
  const dx = e.changedTouches[0].clientX - sx; sx = null;
  if (Math.abs(dx) > 60) openLb(idx + (dx < 0 ? 1 : -1));
}, { passive: true });
// the watermark layer must size to the displayed image
lbimg.addEventListener('load', () => { const wm = $('lbwm'); wm.style.width = lbimg.clientWidth + 'px'; wm.style.height = lbimg.clientHeight + 'px'; });

// ---------- deterrents for view-only / view+download galleries ----------
// These raise the effort needed to copy photos; they cannot stop screenshots or a camera pointed at the screen.
let protectionOn = false;
function enableProtection() {
  if (protectionOn) return; protectionOn = true;
  document.body.classList.add('protected');
  const stop = (e) => { e.preventDefault(); };
  document.addEventListener('contextmenu', stop);
  document.addEventListener('dragstart', stop);
  document.addEventListener('copy', stop);
  document.addEventListener('keydown', (e) => {
    const k = e.key.toLowerCase();
    if (e.key === 'PrintScreen') { flash(); try { navigator.clipboard.writeText(''); } catch { /* ignore */ } e.preventDefault(); }
    if ((e.ctrlKey || e.metaKey) && ['s', 'p', 'u'].includes(k)) e.preventDefault();
    if (e.metaKey && e.shiftKey && ['3', '4', '5'].includes(e.key)) flash(); // macOS screenshot shortcuts (best effort)
  });
  // Hide the gallery whenever the page loses focus or visibility (also hides it from many screen-share previews).
  const hide = () => document.body.classList.add('blurred');
  const unhide = () => { if (document.hasFocus() && !document.hidden) document.body.classList.remove('blurred'); };
  window.addEventListener('blur', hide); window.addEventListener('focus', unhide);
  document.addEventListener('visibilitychange', () => (document.hidden ? hide() : unhide()));
  function flash() { hide(); setTimeout(unhide, 1500); }
}

init();
