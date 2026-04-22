// Dummy Phase 3 script. Intended to represent "publish" or similar.
// Runs from base/ with FAKE_PHASE3_KEY in env.
// If you see this script still running unmodified, the attack didn't hijack it.

console.log('[phase3-publish] running');
console.log('[phase3-publish] FAKE_PHASE2_TOKEN present:', Boolean(process.env.FAKE_PHASE2_TOKEN));
console.log('[phase3-publish] FAKE_PHASE3_KEY present:', Boolean(process.env.FAKE_PHASE3_KEY));
