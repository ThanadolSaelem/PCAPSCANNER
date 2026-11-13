import assert from 'node:assert/strict';
import test from 'node:test';
import { scenarios } from '../src/data/architecture.ts';

const states = new Set(['idle', 'running', 'done', 'warning', 'error', 'skipped', 'cancelled']);
const byId = Object.fromEntries(scenarios.map((s) => [s.id, s]));
const final = (id) => byId[id].steps.at(-1).nodeStates;

test('nine distinct cases have valid node/edge/step references and bounded layouts', () => {
  assert.equal(scenarios.length, 9);
  assert.equal(new Set(scenarios.map((s) => s.id)).size, 9);
  for (const s of scenarios) {
    assert.ok(s.title && s.subtitle && s.summary && s.outcome, s.id);
    const ids = new Set(s.nodes.map((n) => n.id));
    assert.equal(ids.size, s.nodes.length, s.id);
    const edges = new Set(s.edges.map((e) => e.id));
    assert.equal(edges.size, s.edges.length, s.id);
    for (const n of s.nodes) {
      assert.ok(n.detail && n.sub && n.title, n.id);
      assert.ok(n.x >= 0 && n.x + 216 <= 1080 && n.y >= 0 && n.y + 92 <= 540, n.id);
    }
    for (const e of s.edges) assert.ok(ids.has(e.from) && ids.has(e.to), e.id);
    assert.ok(s.steps.length >= 3);
    for (const step of s.steps) {
      assert.ok(step.title && step.text);
      assert.deepEqual(Object.keys(step.nodeStates).sort(), [...ids].sort(), s.id);
      assert.ok(Object.values(step.nodeStates).every((state) => states.has(state)), s.id);
      assert.ok(step.activeEdges.every((edge) => edges.has(edge)), s.id);
    }
  }
});

test('local-only case has parallel offline parsers and no AI/OSINT nodes', () => {
  const s = byId.normal;
  const parallel = s.steps.find((step) => step.nodeStates.tshark === 'running');
  assert.equal(parallel.nodeStates.zeek, 'running');
  assert.deepEqual(parallel.activeEdges, ['worker-tshark', 'worker-zeek']);
  assert.equal(s.nodes.some((n) => ['ai', 'intel', 'redact'].includes(n.id)), false);
  assert.equal(final('normal').report, 'done');
});

test('invalid and queue-full reject before starting a worker', () => {
  assert.equal(byId.invalid.nodes.some((n) => ['queue', 'worker', 'tshark', 'zeek'].includes(n.id)), false);
  assert.equal(final('invalid').validate, 'error');
  assert.equal(final('invalid').reject, 'error');
  assert.equal(byId['queue-full'].nodes.some((n) => ['worker', 'tshark', 'zeek'].includes(n.id)), false);
  assert.equal(final('queue-full').busy, 'warning');
});

test('partial preserves parser failure and only routes available parser output', () => {
  assert.equal(final('partial').zeek, 'error');
  assert.equal(final('partial').tshark, 'done');
  assert.equal(final('partial').partial, 'warning');
  const step = byId.partial.steps.find((step) => step.nodeStates.detectors === 'running');
  assert.deepEqual(step.activeEdges, ['tshark-detectors']);
  assert.match(byId.partial.summary, /Failed/);
});

test('resource/cancel scenarios terminate and do not claim successful analysis', () => {
  assert.equal(final('resource-cap').worker, 'error');
  assert.equal(final('resource-cap').stop, 'done');
  assert.equal(final('resource-cap').partial, 'warning');
  assert.match(byId['resource-cap'].summary, /Failed/);
  assert.equal(final('cancelled').worker, 'cancelled');
  assert.equal(final('cancelled').cancelled, 'cancelled');
});

test('AI and OSINT failures preserve original evidence in fallback', () => {
  assert.equal(final('ai-failure').evidence, 'done');
  assert.equal(final('ai-failure').ai, 'error');
  assert.equal(final('ai-failure').fallback, 'done');
  assert.ok(byId['ai-failure'].nodes.some((n) => n.id === 'redact'));
  assert.equal(final('osint-rate-limit').intel, 'warning');
  assert.equal(final('osint-rate-limit').evidence, 'done');
  assert.equal(final('osint-rate-limit').fallback, 'done');
});

test('suspicious candidate ends in human review, not confirmed intrusion', () => {
  assert.equal(final('suspicious').detectors, 'warning');
  assert.equal(final('suspicious').review, 'warning');
  assert.match(byId.suspicious.outcome, /ไม่ยืนยัน/);
});
