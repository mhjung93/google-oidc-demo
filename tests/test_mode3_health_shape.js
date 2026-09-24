// lib/mode3_health.js 의 순수 함수. node tests/test_mode3_health_shape.js
import assert from 'node:assert/strict';
import { SENSITIVE_KEYS, shortRoot, rootAge, allowOrigin, toOrigin, originList, bounded, buildAaHealth, buildRpHealth, buildWalletHealth } from '../lib/mode3_health.js';
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
  const h = buildRpHealth({ now, chain, status: 'approved', active: true, inactiveReason: null, maxRootAge: 100, rootAge: 3, sessions: 2, requests: 4, disclosures: 1, predicates: { countries: 5, minAge: 19 }, walletAgentOrigin: 'http://w', ciaUrl: 'http://c' });
  assert.equal(h.role, 'rp'); assert.equal(h.active, true); assert.equal(h.predicates.minAge, 19);
  // 체험 모드 4·5단계 판정용 카운터(설계 §3.2) — 개수만이다.
  assert.equal(h.requests, 4); assert.equal(h.disclosures, 1);
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('RP health: 카운터를 안 넘기면 0', () => {
  const h = buildRpHealth({ now, chain, status: 'pending', active: false, inactiveReason: 'registration_pending', maxRootAge: 100, rootAge: null, sessions: 0, predicates: { countries: 0, minAge: 0 }, walletAgentOrigin: '', ciaUrl: '' });
  assert.equal(h.requests, 0); assert.equal(h.disclosures, 0);
});
t('wallet health', () => {
  const h = buildWalletHealth({ now, chain, secrets: 'file', registered: true, hasCred: true, sessions: 1, txs: 2, disclosedTxs: 1, ciaReachable: false, rpOrigin: 'http://r', ciaUrl: 'http://c' });
  assert.equal(h.role, 'wallet'); assert.equal(h.ciaReachable, false);
  assert.equal(h.txs, 2); assert.equal(h.disclosedTxs, 1);
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('wallet health: 카운터를 안 넘기면 0', () => {
  const h = buildWalletHealth({ now, chain: null, secrets: 'snap', registered: false, hasCred: false, sessions: 0, ciaReachable: true, rpOrigin: '', ciaUrl: '' });
  assert.equal(h.txs, 0); assert.equal(h.disclosedTxs, 0);
});
t('toOrigin·originList: origin 만 남기고 주소가 아니면 버린다', () => {
  assert.equal(toOrigin('http://127.0.0.1:4100/'), 'http://127.0.0.1:4100');
  assert.equal(toOrigin('http://127.0.0.1:4100/cia/x?q=1'), 'http://127.0.0.1:4100');
  assert.equal(toOrigin('없는주소'), null); assert.equal(toOrigin(''), null); assert.equal(toOrigin(undefined), null);
  assert.deepEqual(originList(['http://a.test/', ''], 'http://b.test:3100/x'), ['http://a.test', 'http://b.test:3100']);
  // 정규화한 목록은 브라우저가 보내는 Origin 헤더(경로 없음)와 그대로 맞는다.
  assert.equal(allowOrigin('http://127.0.0.1:4100', originList('http://127.0.0.1:4100/')), true);
});
t('값 형식: string|boolean|number|null|string[] 뿐', () => {
  const h = buildRpHealth({ now, chain, status: 'pending', active: false, inactiveReason: 'registration_pending', maxRootAge: 100, rootAge: null, sessions: 0, predicates: { countries: 0, minAge: 0 }, walletAgentOrigin: 'http://w', ciaUrl: 'http://c' });
  const ok = (v) => v === null || ['string', 'boolean', 'number'].includes(typeof v) || (Array.isArray(v) && v.every((x) => typeof x === 'string')) || (v && typeof v === 'object' && Object.values(v).every(ok));
  assert.ok(ok(h));
});
// bounded: 체인 조회 예산. 넘기면 reject → 서버의 기존 catch 가 chain: null 로 떨어뜨린다.
const passed = await bounded(Promise.resolve('x'), 50);
t('bounded: 예산 안에 끝나면 값 그대로', () => assert.equal(passed, 'x'));
let rejected = null;
await bounded(new Promise(() => {}), 30).catch((e) => { rejected = e.message; });
t('bounded: 예산을 넘기면 timeout 으로 reject', () => assert.equal(rejected, 'timeout'));

if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
