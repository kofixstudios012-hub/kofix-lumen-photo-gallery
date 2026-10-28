'use strict';
// Central configuration. Everything comes from environment variables (or a local .env file).
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Tiny .env loader (no dependency). Real environment variables always win.
try {
  const file = path.join(__dirname, '..', '.env');
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
      if (!m || line.trim().startsWith('#')) continue;
      let v = m[2];
      if (/^(".*"|'.*')$/.test(v)) v = v.slice(1, -1);
      if (process.env[m[1]] === undefined) process.env[m[1]] = v;
    }
  }
} catch { /* ignore */ }

const env = process.env;
const onRender = !!env.RENDER;
const production = env.NODE_ENV === 'production' || onRender;

const cfg = {
  port: Number(env.PORT) || 3000,
  dataDir: path.resolve(env.DATA_DIR || path.join(__dirname, '..', 'data')),
  ownerPassword: env.OWNER_PASSWORD || '',
  maxUploadBytes: Math.floor((Number(env.MAX_UPLOAD_MB) || 25) * 1048576),
  storageLimitBytes: Math.floor((Number(env.STORAGE_LIMIT_GB) || 10) * 1073741824),
  tursoUrl: env.TURSO_URL || '',
  tursoToken: env.TURSO_AUTH_TOKEN || '',
  s3: {
    endpoint: (env.S3_ENDPOINT || '').replace(/\/+$/, ''),
    region: env.S3_REGION || '',
    bucket: env.S3_BUCKET || '',
    keyId: env.S3_KEY_ID || '',
    appKey: env.S3_APP_KEY || '',
  },
  trustProxy: env.TRUST_PROXY === '1' || onRender,
  secureCookies: env.COOKIE_SECURE ? env.COOKIE_SECURE === '1' : production,
  onRender,
  production,
};

cfg.useS3 = !!(cfg.s3.endpoint && cfg.s3.bucket && cfg.s3.keyId && cfg.s3.appKey);
if (cfg.useS3 && !cfg.s3.region) {
  // s3.us-west-004.backblazeb2.com -> us-west-004
  const m = cfg.s3.endpoint.match(/s3\.([a-z0-9-]+)\.backblazeb2\.com/i);
  cfg.s3.region = m ? m[1] : 'us-east-1';
}

// Session secret: explicit if given, otherwise derived from the owner password (stable across restarts).
cfg.sessionSecret = env.SESSION_SECRET
  || crypto.createHash('sha256').update('lumen-session|' + cfg.ownerPassword).digest('hex');

module.exports = cfg;
