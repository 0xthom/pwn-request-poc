# pwn-request-poc

Intentionally vulnerable GitHub Actions lab. Used to validate the exact attack surface of a `pull_request_target` workflow that:

1. Checks out both base and PR code into sibling directories (`base/`, `pr/`)
2. Runs `npm install` on PR code — attacker-controlled postinstall executes here
3. Later steps inject different secrets into env and run scripts from `base/`

**Do not copy this workflow.** It exists so two humans can run it against each other and watch what actually gets captured at each phase.

## Phases

The workflow (`.github/workflows/vulnerable.yml`) has three phases:

| Phase | Step | Secret in env | Attacker-reachable by |
|-------|------|---------------|-----------------------|
| 1 | `npm install` in `pr/` | none (only ambient runner env) | PR's `package.json` postinstall/prepare |
| 2 | `node base/.github/scripts/phase2-analyze.mjs` | `FAKE_PHASE2_TOKEN` | overwriting `base/.github/scripts/phase2-analyze.mjs` from Phase 1 |
| 3 | `node base/.github/scripts/phase3-publish.mjs` | `FAKE_PHASE3_KEY` | overwriting `base/.github/scripts/phase3-publish.mjs` from Phase 1 |

Secrets are per-step: `FAKE_PHASE2_TOKEN` and `FAKE_PHASE3_KEY` never coexist in the same `process.env`. The `env:` block on each step is the only place they enter env.

## How to run the PoC (teammate side)

1. **Fork** this repo to your own account.
2. Pick an exfil channel:
   - Easiest: [webhook.site](https://webhook.site) → copy your unique URL.
   - Alternative: any service you control that logs request bodies.
3. Open a branch on your fork. Apply one of the payloads in [`ATTACK_EXAMPLES.md`](./ATTACK_EXAMPLES.md), substituting your webhook URL.
4. Open a pull request from your fork back to `not-a-rootkit/pwn-request-poc:main`.
5. **First-time contributor gate:** GitHub may hold the workflow pending maintainer approval. The repo owner (Thom) needs to click *Approve and run*.
6. Check the Actions run logs and your webhook to see which secrets landed where.

## What to expect

- **Naive postinstall env dump** → captures ambient runner env only. **No repo secrets.** This is what all four observed content-scope-scripts exploit PRs did.
- **Postinstall that rewrites `../base/.github/scripts/phase2-analyze.mjs`** → `FAKE_PHASE2_TOKEN` exfiltrated when Phase 2 executes the hijacked script.
- **Postinstall that rewrites both phase2 and phase3 scripts** → both tokens exfiltrated. They still arrive in separate callbacks (different steps, different env).

## Cleanup

When you're done:

```bash
gh repo delete not-a-rootkit/pwn-request-poc --yes
```

Or rotate the fake secrets:

```bash
gh secret set FAKE_PHASE2_TOKEN -R not-a-rootkit/pwn-request-poc --body "rotated"
gh secret set FAKE_PHASE3_KEY   -R not-a-rootkit/pwn-request-poc --body "rotated"
```

## Safety notes

- The secrets are fake strings. Nothing real leaks if the PoC works "correctly."
- Because the workflow is real-world vulnerable, anyone on the internet who finds this repo can open a PR and run code on a GitHub-hosted runner under these fake secrets. That's fine — the secrets are worthless — but delete the repo once you're done.
- Don't add this pattern to any real workflow.
