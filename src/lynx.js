const { queryLLM } = require('./llm');
const { appendLog, readJson, updatePolicy } = require('./utils');
const path = require('path');

const LYNX_LOG = path.resolve(__dirname, '../data/lynx.log');
const AEGIS_LOG = path.resolve(__dirname, '../data/aegis.log');
const LYNX_POLICY = path.resolve(__dirname, '../data/lynx_policy.json');

async function attemptAttack(targetUrl) {
  // Generate an attack plan via LLM
  const prompt = `You are an offensive agent. Propose a short list of non-destructive reconnaissance actions against: ${targetUrl}`;
  const resp = await queryLLM(prompt, { max_tokens: 200 });
  // Simplified decision: pick an action key from response hash
  // Create a few candidate action keys from LLM variations
  const candidates = [];
  for (let i=0;i<3;i++) {
    candidates.push(`attack:${Buffer.from(resp.text + i).toString('base64').slice(0,8)}`);
  }
  const { chooseAction } = require('./rl');
  const actionKey = chooseAction(LYNX_POLICY, candidates, 0.25);

  // Simulate success probabilistically (baseline 0.35)
  const success = Math.random() < 0.35;
  const entry = { ts: Date.now(), target: targetUrl, action: resp.text, success };
  if (success) {
    appendLog(LYNX_LOG, { ...entry, note: 'Attack succeeded' });
    // reward own policy
    updatePolicy(LYNX_POLICY, actionKey, 1);
  } else {
    appendLog(LYNX_LOG, { ...entry, note: 'Attack failed' });
    updatePolicy(LYNX_POLICY, actionKey, 0);
  }

  // Read AEGIS logs to learn
  const aegisLogs = readJson(AEGIS_LOG) || [];
  if (aegisLogs.length) {
    // send a learning prompt to LLM
    const learnPrompt = `Review these defenses: ${JSON.stringify(aegisLogs.slice(-5))}. Suggest how to bypass them.`;
    await queryLLM(learnPrompt, { max_tokens: 200 });
  }

  return entry;
}

// If run as script: basic loop
if (require.main === module) {
  const url = process.argv[2] || 'http://example.com';
  (async () => {
    console.log('Lynx agent starting for', url);
    for (let i=0;i<5;i++) {
      const res = await attemptAttack(url);
      console.log('Attempt', i+1, res.success ? 'SUCCESS' : 'FAIL');
      await new Promise(r=>setTimeout(r, 500));
    }
    console.log('Lynx finished');
  })();
}

module.exports = { attemptAttack };
