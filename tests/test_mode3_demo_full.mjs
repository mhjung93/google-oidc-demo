// Mode 3 전 구간 데모 각본 — **두 체인**(폐기 체인 :8546 + 응용 체인 :8545), **두 서비스**(일반 + 가상자산거래소). (chain 그룹)
//   node tests/test_mode3_demo_full.mjs
// 2026-10-03 추가. 앱 코드는 V10(2026-10-02)부터 두 체인을 지원하도록 짜여 있었지만 실제 두 노드로 돌려 본 적이 없었다 —
// 이 각본이 처음이다. 폐기 체인 노드(:8546, chainId 31338)는 이 테스트가 스스로 띄우고 끝나면 끈다(이미 떠 있던 노드는 사용자
// 것이므로 chainId 만 확인하고 건드리지 않는다 — tests/helpers/mode3_chain.mjs ensureRevChainNode). :8545 는 미리 떠 있어야 한다.
// 사용자 = testuser(uid 12345, 속성 1990/410). 첫 서비스 = 일반 서비스(정책 기본값), 둘째 = 거래소(허용 국가 KR·JP(=410·392), 최소 나이 19).
// 요청 모양(지갑 login·revalidate·request·tx, RP open)은 tests/test_mode3_demo_stack.mjs 와 같다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { ensureRevChainNode } from './helpers/mode3_chain.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { factoryAt } from '../lib/mode3_onchain.js';
import { MODE3_LOG_ABI, MODE3_MIRROR_ABI } from '../lib/mode3_log.js';
import { sessionLeaf } from '../lib/mode3_revocation.js';

const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const ms = (t0) => `${Date.now() - t0}ms`;

// vkey 는 노드·스택을 띄우기 전에 확인한다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);

const REV_CHAIN_ID = 31338n, APP_CHAIN_ID = 31337n;
const uid = '12345', pwd = 'password123';
const year = new Date().getUTCFullYear();

const node = await ensureRevChainNode({ port: 8546, chainId: Number(REV_CHAIN_ID) });
console.log(`# 폐기 체인 ${node.url} (${node.started ? '이 테스트가 띄움' : '이미 떠 있던 노드 — 끄지 않는다'})`);
let stack = null;
try {
  // 챌린지 TTL 12초 — 새 자격증명 로그인은 거울이 내 리프를 실을 때까지 기다리므로(test_mode3_demo_stack.mjs 와 같은 이유) 넉넉히.
  stack = await startIsolatedMode3Stack({
    twoChains: true, revRpcUrl: node.url,
    rpEnv: { MODE3_CHALLENGE_TTL_MS: '12000' },
    extraRps: [{ name: 'demo-exchange', env: { MODE3_ALLOWED_COUNTRIES: 'KR,JP', MODE3_MIN_AGE: '19', MODE3_CHALLENGE_TTL_MS: '12000' } }],
  });
  const { cia, wallet } = stack;
  const [general, exchange] = stack.rps;
  const revP = cia.revProvider, appP = cia.appProvider;
  const canon = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, revP);
  const mirror = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, appP);

  /** 브라우저의 RP 페이지가 하는 일: rp_info → r_s → 지갑 login(그 서비스 오리진) → RP login. 거울이 뒤처지면 릴레이(withRelay).
   *  pred 를 주면 거래소 술어(나이 ≥ minAge, 국가 ∈ 허용 집합)를 공개하고 RP 에 require 로 요구한다. */
  async function loginViaRp(rp, { pred = false, require = undefined } = {}) {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { r_s, factoryAddress, attrGateAddress } = (await rp.post('/api/mode3/challenge')).body;
    // lo = 스키마의 출생연도 min — RP 는 lo ≥ min 도 요구한다(최종 리뷰 I1, 페이지와 같은 본문).
    const extra = pred ? { disclose: [{ lo: info.predicates.birthYearMin, hi: String(year - Number(info.predicates.minAge)) }, null, null, null], set: { slot: 1, members: info.predicates.allowedCountries } } : {};
    const w = await stack.withRelay(() => wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s, allowAgent: '0', factoryAddress, attrGateAddress, ...extra }, { Origin: rp.origin }));
    if (w.status !== 200) return { walletStatus: w.status, wallet: w.body, r_s };
    const req = require ?? (pred ? { countrySet: true, minAge: true } : undefined);
    const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s, ...(req ? { require: req } : {}) });
    return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body, r_s, info };
  }
  /** 세션 재검증: 거울을 먼저 맞추고(relayIfBehind) 지갑이 만든 π 를 RP 에 낸다. 거울 지연 창을 보일 때는 쓰지 않는다. */
  async function revalidateViaRp(rp, r_s) {
    await stack.relayIfBehind();
    const w = await wallet.post('/wallet/revalidate', { r_s }, { Origin: rp.origin });
    if (w.status !== 200) return { walletStatus: w.status, wallet: w.body };
    const r = await rp.post('/api/mode3/revalidate', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s });
    return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body };
  }
  /** 세션 요청 서명(지갑) — 같은 서명을 상황이 바뀐 뒤 다시 내서 대조하려고 따로 둔다. */
  async function signRequest(rp, r_s, body) {
    const w = await wallet.post('/wallet/request', { r_s, body }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));
    return { r_s, body, sig: w.body.sig };
  }
  const sendRequest = (rp, q) => rp.post('/api/mode3/request', q);
  /** 이 사용자의 CIA 세션 기록에서 Cf_s 집합(새 세션의 Cf_s 를 집어내는 용도 — test_mode3_demo_stack.mjs V8 과 같은 방식). */
  const sessionCfs = async () => new Set((await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s));
  const newCf = async (before) => [...(await sessionCfs())].find((c) => !before.has(c));
  const rootHex = (v) => ethers.zeroPadValue(ethers.toBeHex(v), 32);
  /** leaf(bytes32 hex) 가 캐노니컬 게시 tx(canonTxHash, 폐기 체인)의 calldata 에는 있고(양성 대조), 응용 체인 거울의 어떤 게시 tx
   *  calldata 에도 없음을 단언한다(2026-10-03 리뷰 Minor 2 — 거울은 entryHashes 만 받는다, lib/mode3_log.js). */
  async function assertLeafOnlyOnCanonical(canonTxHash, leaf) {
    const needle = leaf.toLowerCase().slice(2);
    assert.ok((await revP.getTransaction(canonTxHash)).data.toLowerCase().includes(needle), '양성 대조: 캐노니컬 게시 calldata 에 리프가 있다');
    const mirroredTxs = [...new Set((await mirror.queryFilter(mirror.filters.Mirrored(), 0)).map((e) => e.transactionHash))];
    assert.ok(mirroredTxs.length >= 1);
    for (const h of mirroredTxs) assert.ok(!(await appP.getTransaction(h)).data.toLowerCase().includes(needle), `거울 게시 tx ${h} 의 calldata 에 리프 값이 있다`);
  }

  let PPID_G, PPID_X, X1, X1_pk_i, slot1;

  await t('막 0. 무대 확인 — 캐노니컬 로그는 폐기 체인(31338), 거울은 응용 체인(31337)에 있고, 두 서비스·CIA 가 그 구성을 가리킨다', async () => {
    assert.equal((await revP.getNetwork()).chainId, REV_CHAIN_ID);
    assert.equal((await appP.getNetwork()).chainId, APP_CHAIN_ID);
    assert.notEqual(await revP.getCode(cia.logAddress), '0x', '캐노니컬 로그는 폐기 체인에 배포돼 있다');
    assert.notEqual(await appP.getCode(cia.mirrorAddress), '0x', '거울은 응용 체인에 배포돼 있다');
    assert.equal(await mirror.canonicalChainId(), REV_CHAIN_ID);
    assert.equal((await mirror.canonicalLog()).toLowerCase(), cia.logAddress.toLowerCase());
    for (const rp of [general, exchange]) {
      const info = (await rp.get('/api/mode3/rp_info')).body;
      assert.equal(info.mirrorAddress, cia.mirrorAddress, `${rp.origin} 의 거울`);
      assert.equal(info.logAddress, cia.logAddress, `${rp.origin} 의 캐노니컬(표시용)`);
      assert.equal(info.chainId, APP_CHAIN_ID.toString(), `${rp.origin} 는 응용 체인만 본다`);
      assert.equal(info.status, 'approved'); assert.equal(info.active, true);
    }
    const g = (await general.get('/api/mode3/rp_info')).body, x = (await exchange.get('/api/mode3/rp_info')).body;
    assert.notEqual(g.arid, x.arid); assert.notEqual(g.factoryAddress, x.factoryAddress);
    assert.deepEqual(x.predicates.allowedCountries, ['410', '392']); assert.equal(x.predicates.minAge, '19');
    assert.deepEqual(x.predicates.allowedCountryNames, ['KR', 'JP'], 'MODE3_ALLOWED_COUNTRIES=KR,JP 가 410,392 와 같은 정책이 된다');
    const health = (await cia.get('/mode3/health')).body;
    assert.equal(health.mirrors?.[0]?.chainId, '31337', j(health.mirrors));
    assert.equal((await cia.get('/cia/public_keys')).body.canonicalChainId, '31338');
  });

  await t('막 1. 등록·첫 로그인(일반 서비스) — 내 슬롯이 캐노니컬(:8546)에 게시되고, RP 가 거울(:8545) regRoot 로 검증에 성공했다 = 거울이 내 리프를 실은 뒤 로그인이 끝났다', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd })).status, 201);
    const t0 = Date.now();
    const r = await loginViaRp(general);
    console.log(`     첫 로그인(사용자 자격증명 발급 + 거울 대기 + 증명) ${ms(t0)}`);
    assert.equal(r.walletStatus, 200, j(r)); assert.equal(r.wallet.issued, true);
    assert.equal(r.rp?.ok, true, j(r.rp)); assert.match(r.rp.PPID, /^[0-9]+$/);
    PPID_G = r.rp.PPID;
    slot1 = Number((await wallet.get('/wallet/status')).body.slot);
    // 캐노니컬: 내 슬롯에 0 이 아닌 리프가 SlotUpdated 로 올라 있다(폐기 체인의 이벤트).
    const ups = (await canon.queryFilter(canon.filters.SlotUpdated(), 0)).filter((e) => Number(e.args.index) === slot1 && BigInt(e.args.leaf) !== 0n);
    assert.ok(ups.length >= 1, '캐노니컬에 내 슬롯의 등록부 게시가 있어야 한다');
    const pubEpoch = ups[ups.length - 1].args.epoch;
    // 순서를 보장하는 것은 위의 RP 로그인 성공이다 — RP 는 거울 regRoot 로만 검증하므로, 내 슬롯 리프가 든 등록부 root 를 거울이
    // 받기 전에는 로그인이 통과할 수 없다. 아래는 그 상태(거울이 그 게시 epoch 이상의 regRoot 를 받았고 지금 캐노니컬과 같다)를 확인할 뿐
    // 타임스탬프로 순서를 증명하지는 않는다(두 체인 블록 시각은 초 단위).
    const canonReg = await canon.regRoot();
    assert.equal(await mirror.regRoot(), canonReg, '거울 regRoot == 캐노니컬 regRoot');
    const mirrored = await mirror.queryFilter(mirror.filters.Mirrored(), 0);
    assert.ok(mirrored.some((e) => e.args.epoch >= pubEpoch && e.args.regRoot === canonReg), `거울이 epoch ${pubEpoch} 이상의 그 regRoot 를 받았다`);
    // 거울은 root 와 항목 해시만 받는다 — 내 슬롯 리프 값 자체는 캐노니컬 게시 calldata 에만 있고 거울 게시 calldata 에는 없다.
    await assertLeafOnlyOnCanonical(ups[ups.length - 1].transactionHash, ups[ups.length - 1].args.leaf);
  });

  await t('막 2. 여러 서비스 — 거래소 로그인(술어) ok, 두 PPID·계정 주소가 다르고, CIA 세션 기록에는 서비스를 가리키는 필드가 없다', async () => {
    const t0 = Date.now();
    const r = await loginViaRp(exchange, { pred: true });
    console.log(`     거래소 로그인(사용자 자격증명 재사용, 술어 공개) ${ms(t0)}`);
    assert.equal(r.walletStatus, 200, j(r)); assert.equal(r.rp?.ok, true, j(r.rp));
    PPID_X = r.rp.PPID; X1 = r.r_s; X1_pk_i = r.rp.pk_i;
    assert.notEqual(PPID_X, PPID_G, '서비스마다 PPID 가 다르다');
    const g = (await general.get('/api/mode3/rp_info')).body, x = r.info;
    const addrG = await factoryAt(g.factoryAddress, appP).computeAddress(BigInt(PPID_G));
    const addrX = await factoryAt(x.factoryAddress, appP).computeAddress(BigInt(PPID_X));
    assert.notEqual(addrG, addrX, '서비스마다 계정 주소가 다르다');
    // CIA(AA) 의 세션 기록: 둘 이상 있지만 어느 서비스의 것인지 모른다 — 키 집합이 고정돼 있고, 값 어디에도 arid·origin·PPID·계정 주소가 없다.
    const { sessions } = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body;
    assert.ok(sessions.length >= 2, j(sessions));
    const allowed = new Set(['Cf_s', 'max_height', 'chainid', 'allowAgent', 'issuedAt', 'revokedAt', 'expired']);
    const forbidden = [g.arid, x.arid, g.origin, x.origin, PPID_G, PPID_X, addrG, addrX, g.factoryAddress, x.factoryAddress].map((v) => String(v).toLowerCase());
    for (const s of sessions) {
      for (const k of Object.keys(s)) assert.ok(allowed.has(k), `세션 기록에 뜻밖의 필드 ${k}: ${j(s)}`);
      for (const v of Object.values(s)) assert.ok(!forbidden.includes(String(v).toLowerCase()), `세션 기록에 서비스 식별 값: ${j(s)}`);
      assert.equal(s.chainid, '31337');   // 아는 것은 응용 체인뿐
    }
    const blob = j(sessions).toLowerCase();
    for (const v of [g.origin, x.origin, PPID_G, PPID_X, addrG, addrX]) assert.ok(!blob.includes(String(v).toLowerCase()), `세션 기록 어딘가에 ${v}`);
  });

  let TX_X;
  await t('막 3a. 거래소 로그인 술어 — 술어를 만족하는 세션은 집합 root 가 정책과 같고, 술어 없는 성명은 predicate_unmet', async () => {
    const x = (await exchange.get('/api/mode3/rp_info')).body;
    const mine = (await exchange.get('/api/mode3/sessions')).body.sessions.find((s) => s.pk_i === X1_pk_i);   // 세션 키 pk_i 로 찾는다(목록의 r_s 축약 표기에 기대지 않는다)
    assert.ok(mine, '막 2 의 거래소 세션이 목록에 있어야 한다');
    assert.equal(mine.disclosure?.set?.root, x.predicates.allowedCountriesRoot, j(mine));
    const bare = await loginViaRp(exchange, { require: { countrySet: true, minAge: true } });
    assert.equal(bare.walletStatus, 200, j(bare));
    assert.deepEqual(bare.rp, { ok: false, reason: 'predicate_unmet' });
  });

  await t('막 3b. 온체인 출금 — PPID 계정을 충전하고 /wallet/tx 로 value 송금 + 나이 범위·국가 집합 공개; 수신 잔액 증가, Disclosure 가 응용 체인 영수증에 남는다', async () => {
    const x = (await exchange.get('/api/mode3/rp_info')).body;
    const acct = await factoryAt(x.factoryAddress, appP).computeAddress(BigInt(PPID_X));
    const funder = await appP.getSigner(0);
    await (await funder.sendTransaction({ to: acct, value: ethers.parseEther('1') })).wait();
    const recipient = ethers.Wallet.createRandom().address;
    const amount = ethers.parseEther('0.25');
    const before = await appP.getBalance(recipient);
    const disclose = [{ lo: '0', hi: String(year - Number(x.predicates.minAge)) }, null, null, null];
    const set = { slot: 1, members: x.predicates.allowedCountries };
    const t0 = Date.now();
    const tx = await stack.withRelay(() => wallet.post('/wallet/tx', { r_s: X1, to: recipient, value: amount.toString(), disclose, set }, { Origin: exchange.origin }));
    console.log(`     출금 tx(계정 배포 + execute, π 캐시 ${tx.body?.cacheHit}) ${ms(t0)}`);
    assert.equal(tx.status, 200, j(tx.body)); assert.equal(tx.body.ok, true, j(tx.body)); assert.equal(tx.body.deployed, true);
    assert.equal(tx.body.wallet, acct);
    assert.equal(tx.body.executed.value, amount.toString());
    assert.equal(await appP.getBalance(recipient) - before, amount, '수신 주소 잔액이 송금액만큼 늘었다');
    assert.equal(tx.body.onchainDisclosure?.mask, '1', j(tx.body.onchainDisclosure));
    assert.equal(tx.body.onchainDisclosure.hi[0], String(year - 19));
    assert.equal(tx.body.onchainDisclosure.set?.root, x.predicates.allowedCountriesRoot);
    TX_X = tx.body.txHash;
    // 트랜잭션은 응용 체인에만 있다.
    const rc = await appP.getTransactionReceipt(TX_X);
    assert.equal(rc?.status, 1);
    assert.equal(await revP.getTransactionReceipt(TX_X), null, '폐기 체인에는 이 트랜잭션이 없다');
  });

  await t('막 3c. 의심 거래 개봉 — 거래소가 txHash 로 요청 → 관리자 승인 → uid 12345·거래소 PPID; 일반 서비스는 아무것도 알지 못한다', async () => {
    const g = (await general.get('/api/mode3/rp_info')).body, x = (await exchange.get('/api/mode3/rp_info')).body;
    const r = await exchange.post('/api/mode3/open', { txHash: TX_X });
    assert.ok([200, 202].includes(r.status), j(r.body));
    const id = r.body.id;
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).body.status, 'approved');
    const res = await exchange.get(`/api/mode3/open/${id}`);
    assert.equal(res.status, 200, j(res.body));
    assert.equal(res.body.uid, uid); assert.equal(res.body.PPID, PPID_X);
    // 일반 서비스: 같은 개봉 id 로 조회해도 결과를 받지 못하고, 개봉 기록에 일반 서비스 것은 하나도 없다.
    const peek = await general.get(`/api/mode3/open/${id}`);
    assert.notEqual(peek.status, 200, j(peek.body)); assert.equal(peek.body?.uid, undefined, j(peek.body));
    const openings = (await cia.adminGet('/cia/openings')).body.openings;
    assert.ok(openings.length >= 1);
    assert.ok(openings.every((o) => String(o.arid) === String(x.arid)), `개봉 기록은 거래소 것뿐이다: ${j(openings.map((o) => o.arid))}`);
    assert.ok(!openings.some((o) => String(o.arid) === String(g.arid)));
  });

  await t('막 4. salt 시연 — 다음 증명의 s_u 를 덮어쓰면 로그인이 demo_proof_failed, 한 번 쓰면 풀려 다음 로그인은 정상', async () => {
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'prove', s_u: '999999999999999999' })).body.ok, true);
    const bad = await loginViaRp(general);
    assert.equal(bad.walletStatus, 409, j(bad.wallet)); assert.equal(bad.wallet.reason, 'demo_proof_failed'); assert.equal(bad.wallet.demo, 'override:prove');
    const ok = await loginViaRp(general);
    assert.equal(ok.rp?.ok, true, j(ok)); assert.equal(ok.rp.PPID, PPID_G);
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null);
  });

  await t('막 5. 세션 폐기(세션 트리) — 거래소 세션 둘(지갑 버튼·관리자) 폐기 → 게시 전엔 대기(pending) → 게시·중계 뒤 두 세션은 revalidate_required, 일반 서비스 세션은 재검증 후 계속', async () => {
    await stack.relayIfBehind();
    const G = await loginViaRp(general);
    let before = await sessionCfs();
    const XA = await loginViaRp(exchange, { pred: true });
    const cfA = await newCf(before);
    before = await sessionCfs();
    const XB = await loginViaRp(exchange, { pred: true });
    const cfB = await newCf(before);
    for (const s of [G, XA, XB]) assert.equal(s.rp?.ok, true, j(s));
    assert.ok(cfA && cfB, '두 거래소 세션의 Cf_s');
    await stack.relayIfBehind();
    const qG = await signRequest(general, G.r_s, 'g'), qA = await signRequest(exchange, XA.r_s, 'withdraw'), qB = await signRequest(exchange, XB.r_s, 'withdraw');
    for (const [rp, q] of [[general, qG], [exchange, qA], [exchange, qB]]) assert.equal((await sendRequest(rp, q)).body.ok, true, '폐기 전에는 통과');

    const epoch0 = await canon.epoch();
    // XA: 지갑의 세션 폐기 버튼(사용자 서명). AA 가 받아들이면 다음 게시까지 대기열(pending)에 묶인다.
    const rv = await wallet.post('/wallet/session/revoke', { r_s: XA.r_s });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.revoked, true); assert.equal(rv.body.inserted, true);
    assert.ok(rv.body.pending >= 1, `게시 전 대기열: ${j(rv.body)}`);
    // XB: 관리자 경로(지갑 밖) — 지갑은 아직 이 세션을 들고 있다가 재검증에서 revoked_session 을 본다.
    const ra = await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cfB });
    assert.equal(ra.status, 200, j(ra.body)); assert.equal(ra.body.inserted, true);
    assert.equal(await canon.epoch(), epoch0, '세션 폐기는 게시 전까지 캐노니컬에 오르지 않는다');
    assert.equal((await sendRequest(exchange, qA)).body.ok, true, '게시 전에는 서비스가 아직 모른다');

    const pub = await cia.adminPost('/cia/publish');
    assert.equal(pub.body.published, true, j(pub.body));
    // 리프는 캐노니컬 Revoked 이벤트(폐기 체인)에 있다. 거울은 root 만 받는다.
    const evs = await canon.queryFilter(canon.filters.Revoked(), 0);
    const last = evs[evs.length - 1];
    const leaves = last.args.leaves.map((l) => BigInt(l));
    for (const cf of [cfA, cfB]) assert.ok(leaves.includes(await sessionLeaf(BigInt(cf))), `세션 리프(${cf.slice(0, 8)}…)가 캐노니컬 Revoked 에 있다`);
    assert.equal((await sendRequest(exchange, qA)).body.ok, true, '중계 전(거울 지연)에는 거래소가 아직 모른다');
    await stack.relay();
    assert.equal(await mirror.revRoot(), last.args.root, '중계 뒤 거울 revRoot == 캐노니컬 Revoked 의 root');
    // 거울은 항목 해시만 받는다 — 세션 리프 값은 캐노니컬 게시 calldata(양성 대조)에만 있고 거울 게시 calldata 에는 없다.
    for (const cf of [cfA, cfB]) await assertLeafOnlyOnCanonical(last.transactionHash, rootHex(await sessionLeaf(BigInt(cf))));

    for (const q of [qA, qB]) {
      const r = await sendRequest(exchange, q);
      assert.equal(r.status, 401, j(r.body)); assert.equal(r.body.reason, 'revalidate_required', j(r.body));
    }
    const wa = await wallet.post('/wallet/revalidate', { r_s: XA.r_s }, { Origin: exchange.origin });
    assert.equal(wa.status, 404, j(wa.body)); assert.equal(wa.body.reason, 'no_session');   // 지갑 버튼 경로는 지갑이 이미 버렸다
    const wb = await revalidateViaRp(exchange, XB.r_s);
    assert.equal(wb.walletStatus, 403, j(wb)); assert.equal(wb.wallet.reason, 'revoked_session');
    // 일반 서비스 세션: 옛 서명은 root 가 바뀌어 재검증을 요구하지만, 재검증하면 그대로 산다(사용자 자격증명은 살아 있다).
    const rG = await revalidateViaRp(general, G.r_s);
    assert.equal(rG.walletStatus, 200, j(rG)); assert.equal(rG.rp?.ok, true, j(rG.rp));
    assert.equal((await sendRequest(general, await signRequest(general, G.r_s, 'g2'))).body.ok, true);
  });

  let receipt6;
  await t('막 6. 계정 폐기(등록부) — 지갑 self_revoke → 즉시 게시·접수증; 거울 지연 동안 일반 서비스 요청은 통과 → 중계 → 두 서비스 revalidate_required → 지갑 revoked, 새 로그인 account_disabled', async () => {
    const G = await loginViaRp(general);
    const X = await loginViaRp(exchange, { pred: true });
    assert.equal(G.rp?.ok, true, j(G)); assert.equal(X.rp?.ok, true, j(X));
    await stack.relayIfBehind();
    const qG = await signRequest(general, G.r_s, 'g'), qX = await signRequest(exchange, X.r_s, 'x');
    const mirrorReg0 = await mirror.regRoot();
    assert.equal(await canon.regRoot(), mirrorReg0, '전제: 거울이 따라잡은 상태');

    const r = await wallet.post('/wallet/self_revoke', { uid, pwd });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.disabled, true);
    assert.equal(r.body.published, true, j(r.body));
    assert.ok(r.body.receipt?.sig, `접수증: ${j(r.body)}`);
    receipt6 = r.body.receipt;
    assert.equal(receipt6.canonicalChainId, '31338', '접수증은 폐기 체인의 캐노니컬을 가리킨다');
    assert.equal(receipt6.canonicalLogAddress.toLowerCase(), cia.logAddress.toLowerCase());
    assert.notEqual(await canon.regRoot(), mirrorReg0, '캐노니컬 regRoot 는 바뀌었다');
    assert.equal(await mirror.regRoot(), mirrorReg0, '거울은 아직 이전 값');
    assert.equal((await sendRequest(general, qG)).body.ok, true, '거울 지연 창: 일반 서비스는 아직 모른다');

    await stack.relay();
    assert.equal(await mirror.regRoot(), await canon.regRoot());
    for (const [rp, q] of [[general, qG], [exchange, qX]]) {
      const res = await sendRequest(rp, q);
      assert.equal(res.status, 401, j(res.body)); assert.equal(res.body.reason, 'revalidate_required', `${rp.origin}: ${j(res.body)}`);
    }
    const rv = await revalidateViaRp(general, G.r_s);
    assert.equal(rv.walletStatus, 403, j(rv)); assert.equal(rv.wallet.reason, 'revoked');
    const l = await loginViaRp(exchange, { pred: true });
    assert.equal(l.walletStatus, 403, j(l)); assert.equal(l.wallet.reason, 'account_disabled');
  });

  await t('막 7. 접수증 — 제3자 계정이 막 6 의 receipt 를 폐기 체인(:8546) requestRevocation 으로 제출 → pendingSlots == [slot] → /cia/publish → [] · isRetired', async () => {
    assert.ok(receipt6, '막 6 의 접수증');
    const s0 = Number(receipt6.slot);
    assert.equal(s0, slot1, '접수증 슬롯 = 막 1 에서 받은 슬롯');
    // 제3자 = 폐기 체인의 다른 계정(CIA 도 사용자 지갑도 아니다). 이 슬롯은 막 6 의 게시로 이미 0 이다 — 강제의 효과 자체
    // (0 으로 싣지 않은 게시의 거절)는 test/Mode3Log.test.mjs 가 본다. 여기서는 접수증 → 대기열 → 게시의 흐름이 폐기 체인에서 돈다는 것만.
    const third = await revP.getSigner(7);
    const logW = canon.connect(third);
    assert.equal(await canon.isRetired(s0), false, '전제: 아직 은퇴하지 않았다');
    const rc = await (await logW.requestRevocation(s0, receipt6.epochAtRequest, receipt6.requestedAt, receipt6.sig)).wait();
    assert.equal(rc.status, 1);
    assert.equal(await appP.getTransactionReceipt(rc.hash), null, '접수증 제출은 응용 체인이 아니라 폐기 체인에서');
    assert.deepEqual((await canon.pendingSlots()).map(Number), [s0]);
    const pub = await cia.adminPost('/cia/publish', {});
    assert.equal(pub.status, 200, j(pub.body)); assert.equal(pub.body.published, true, j(pub.body));
    assert.deepEqual((await canon.pendingSlots()).map(Number), []);
    assert.equal(await canon.isRetired(s0), true);
  });

  await t('막 8. 복구 — 관리자 set_disabled false → (발급 덮어쓰기 시연: user_cred_failed) → 일반·거래소 재로그인 ok, 새 슬롯, PPID 는 막 1·2 와 같다', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    // 복구 뒤 첫 로그인은 새 사용자 자격증명을 받는다(옛 것은 물렸다) — 그 발급 경로에서 salt 덮어쓰기(scope:'issue')를 한 번 보인다.
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'issue', s_u: '999999999999999999' })).body.ok, true);
    const badSalt = await loginViaRp(general);
    assert.equal(badSalt.walletStatus, 502, j(badSalt.wallet)); assert.equal(badSalt.wallet.reason, 'user_cred_failed', j(badSalt.wallet));
    assert.equal(badSalt.wallet.demo, 'override:issue');
    const t0 = Date.now();
    const g = await loginViaRp(general);
    console.log(`     복구 뒤 첫 로그인(새 슬롯 재발급 + 거울 대기) ${ms(t0)}`);
    assert.equal(g.walletStatus, 200, j(g)); assert.equal(g.rp?.ok, true, j(g.rp)); assert.equal(g.rp.PPID, PPID_G);
    const x = await loginViaRp(exchange, { pred: true });
    assert.equal(x.rp?.ok, true, j(x)); assert.equal(x.rp.PPID, PPID_X);
    const slotNow = Number((await wallet.get('/wallet/status')).body.slot);
    assert.notEqual(slotNow, Number(receipt6.slot), '은퇴한 슬롯은 다시 쓰지 않는다');
    assert.equal((await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid).slot, slotNow, '지갑이 재발급의 새 슬롯을 따랐다');
    assert.equal(await mirror.regRoot(), await canon.regRoot(), '거울이 복구 게시까지 따라잡았다');
  });
} catch (e) {
  failed++;
  console.error(`FAIL 무대 준비\n     ${e.stack ?? e.message}`);
} finally {
  if (stack) await stack.stop();
  await node.stop();
  console.log(`# 정리: 스택 종료${node.started ? ', 이 테스트가 띄운 :8546 노드 종료(포트 비었음 확인)' : ''}`);
}
process.exit(failed === 0 ? 0 : 1);
