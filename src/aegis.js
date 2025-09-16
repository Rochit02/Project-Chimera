const { queryLLM } = require('./llm');
const { appendLog, readJson, updatePolicy } = require('./utils');
const path = require('path');

const LYNX_LOG = path.resolve(__dirname, '../data/lynx.log');
const AEGIS_LOG = path.resolve(__dirname, '../data/aegis.log');
const AEGIS_POLICY = path.resolve(__dirname, '../data/aegis_policy.json');

async function attemptDefend(targetUrl) {
  // Read Lynx recent attempts
  const lynx = readJson(LYNX_LOG) || [];
  const recent = lynx.slice(-5);
  const prompt = `You are a defensive agent. Given these recent attacks: ${JSON.stringify(recent)}, propose defensive actions for ${targetUrl}`;
  const resp = await queryLLM(prompt, { max_tokens: 200 });
  const candidates = [];
  for (let i=0;i<3;i++) candidates.push(`defend:${Buffer.from(resp.text + i).toString('base64').slice(0,8)}`);
  const { chooseAction } = require('./rl');
  const actionKey = chooseAction(AEGIS_POLICY, candidates, 0.2);

  // Simulate defense success if random < 0.45 or if there are many recent attacks
  const intensity = recent.length;
  const success = Math.random() < (0.45 + Math.min(0.4, intensity*0.04));
  const entry = { ts: Date.now(), target: targetUrl, action: resp.text, success };
  if (success) {
    appendLog(AEGIS_LOG, { ...entry, note: 'Defense succeeded' });
    updatePolicy(AEGIS_POLICY, actionKey, 1);
  } else {
    appendLog(AEGIS_LOG, { ...entry, note: 'Defense failed' });
    updatePolicy(AEGIS_POLICY, actionKey, 0);
  }

  // Learn from successful Lynx attacks
  const lynxSuccesses = (lynx || []).filter(x => x.success).slice(-5);
  if (lynxSuccesses.length) {
    const learnPrompt = `These successful attacks happened: ${JSON.stringify(lynxSuccesses)}. Suggest prevention steps.`;
    await queryLLM(learnPrompt, { max_tokens: 200 });
  }

  return entry;
}

if (require.main === module) {
  const url = process.argv[2] || 'http://example.com';
  (async () => {
    console.log('AEGIS agent starting for', url);
    for (let i=0;i<5;i++) {
      const res = await attemptDefend(url);
      console.log('Defend attempt', i+1, res.success ? 'SUCCESS' : 'FAIL');
      await new Promise(r=>setTimeout(r, 600));
    }
    console.log('AEGIS finished');
  })();
}

module.exports = { attemptDefend };
