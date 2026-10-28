'use strict';
const f = document.getElementById('f');
const msg = document.getElementById('msg');
f.addEventListener('submit', async (e) => {
  e.preventDefault();
  msg.textContent = '';
  const go = document.getElementById('go');
  go.disabled = true;
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lumen': '1' },
      body: JSON.stringify({ password: document.getElementById('pw').value }),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok) { location.href = '/dashboard'; return; }
    msg.textContent = j.error || 'Sign in failed';
  } catch { msg.textContent = 'Network error. Please try again.'; }
  go.disabled = false;
});
