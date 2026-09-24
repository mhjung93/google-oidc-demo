// lib/mode3_health.js 의 순수 함수. node tests/test_mode3_health_shape.js
import assert from 'node:assert/strict';
import { SENSITIVE_KEYS, shortRoot, rootAge, allowOrigin, buildAaHealth, buildRpHealth, buildWalletHealth } from '../lib/mode3_health.js';
let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
function deepKeys(o, acc = []) { if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) { acc.push(k); deepKeys(v, acc); } return acc; }
const now = '2026-09-25T00:00:00.000Z', chain = { id: '31337', head: '812' };

t('shortRoot: 12자리 + …, 짧으면 그대로', () => { assert.equal(shortRoot('1234567890123456'), '123456789012…'); assert.equal(shortRoot('123'), '123'); });
t('rootAge: head − lastPublished, 체인 없으면 null', () => { assert.equal(rootAge('812', 800n), 12); assert.equal(rootAge(null, 800n), null); assert.equal(rootAge('812', null), null); });
t('allowOrigin: 정확 일치만, 빈 항목 무시', () => {
  assert.equal(allowOrigin('http://a:1', ['http://a:1', '']), true);
  assert.equal(allowOrigin('http://a:1', ['http://a:10']), false);
  assert.equal(allowOrigin(undefined, ['http://a:1']), false);
  assert.equal(allowOrigin('http://a:1', [undefined, null]), false);
});
t('AA health: 역할별 필드와 민감 필드 부재', () => {
  const h = buildAaHealth({ now, chain, root: '9'.repeat(70), epoch: 3, lastPublishedBlock: '800', heartbeatBlocks: 50, pendingLeaves: 1, pendingRps: 0, pendingOpenings: 2, accounts: 4, walletOrigin: 'http://w', rpOrigins: ['http://r'] });
  assert.equal(h.role, 'aa'); assert.equal(h.ok, true); assert.equal(h.root, '999999999999…'); assert.equal(h.rootAge, 12);
  assert.deepEqual(h.rpOrigins, ['http://r']); assert.equal(h.chain.head, '812');
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('AA health: 체인 없음 → chain null, rootAge null', () => { const h = buildAaHealth({ now, chain: null, root: '1', epoch: 0, lastPublishedBlock: '0', heartbeatBlocks: 0, pendingLeaves: 0, pendingRps: 0, pendingOpenings: 0, accounts: 0, walletOrigin: '', rpOrigins: [] }); assert.equal(h.chain, null); assert.equal(h.rootAge, null); });
t('RP health', () => {
  const h = buildRpHealth({ now, chain, status: 'approved', active: true, inactiveReason: null, maxRootAge: 100, rootAge: 3, sessions: 2, predicates: { countries: 5, minAge: 19 }, walletAgentOrigin: 'http://w', ciaUrl: 'http://c' });
  assert.equal(h.role, 'rp'); assert.equal(h.active, true); assert.equal(h.predicates.minAge, 19);
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('wallet health', () => {
  const h = buildWalletHealth({ now, chain, secrets: 'file', registered: true, hasCred: true, sessions: 1, ciaReachable: false, rpOrigin: 'http://r', ciaUrl: 'http://c' });
  assert.equal(h.role, 'wallet'); assert.equal(h.ciaReachable, false);
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('값 형식: string|boolean|number|null|string[] 뿐', () => {
  const h = buildRpHealth({ now, chain, status: 'pending', active: false, inactiveReason: 'registration_pending', maxRootAge: 100, rootAge: null, sessions: 0, predicates: { countries: 0, minAge: 0 }, walletAgentOrigin: 'http://w', ciaUrl: 'http://c' });
  const ok = (v) => v === null || ['string', 'boolean', 'number'].includes(typeof v) || (Array.isArray(v) && v.every((x) => typeof x === 'string')) || (v && typeof v === 'object' && Object.values(v).every(ok));
  assert.ok(ok(h));
});
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
