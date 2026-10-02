# Mode 3 세션 성명·서비스 인증서 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mode 3 성명이 서비스가 뽑은 `r_s` 를 임베딩하고(공개 입력), 로그인마다 발급돼 세션 안에서만 재사용되며, RP 가 CIA 에 등록해 받은 `cert_s` 를 지갑이 로컬 검증하도록 바꾼다.

**Architecture:** 서명 메시지의 `nonce` 를 `r_s` 로 바꾸고 회로에서 공개 입력으로 올린다(도메인 V3). 서비스 등록·인증서는 새 lib(`lib/mode3_rp_cert.js`)와 CIA 엔드포인트 하나로 닫는다. 지갑 에이전트는 `credentials[arid]` 대신 `sessions[r_s]` 를 들고 `/wallet/login`·`/wallet/revalidate`·`/wallet/request` 셋을 낸다. RP 는 기동 시 자기 등록, `r_s` 발급·소비, 세션 표, `/login`·`/revalidate`·`/request` 를 갖는다. 폐기·게시·컨트랙트는 손대지 않는다.

**Tech Stack:** circom 2.1.9 + circomlib, snarkjs Groth16, circomlibjs(EdDSA-Poseidon), Node.js ESM, express, ethers 6, hardhat 로컬 노드(:8545).

**Spec:** `docs/superpowers/specs/2026-09-15-mode3-session-statement-design.md` (§3 cert_s, §4 r_s, §5 발급, §6 증명, §7 RP 세션, §8 상태). 상위: `2026-09-14-mode3-attribute-credential-design.md`, `2026-09-09-mode3-cia-revocation-design.md`.

## Global Constraints

- 주석·문서·오류 문구는 한글, 기존 파일 문체(짧은 단정문, `—` 대시). 새 의존성 없음.
- **Task 사이에는 chain 그룹이 깨진 상태가 정상이다.** 각 Task 는 자기 테스트만, chain 그룹 12/12 는 Task 5 끝에서, `npm test` 21→22(unit 1개 추가)는 Task 1 끝과 Task 5 끝에서 확인한다.
- 상수(스펙에서 그대로): `DOMAIN_MODE3_CRED_V3 = 93461614427473393731524147n` (ASCII "MODE3CREDV3"); `DOMAIN_MODE3_CERT_S = 365084431357317727016019n` (ASCII "MODE3CERTS"); 서명 메시지 `Poseidon(DOMAIN_MODE3_CRED_V3, C, exptime, chainid, r_s)`; 사용자 서명 메시지 `Poseidon(C_pt.x, C_pt.y, chainid, r_s)`(함수는 그대로, 인자 이름만); `cert_s` 메시지 `Poseidon(DOMAIN_MODE3_CERT_S, arid, originToField(origin))`, `originToField(s) = BigInt('0x' + sha256(utf8(s))) & (2^250 − 1)`; 회로 공개 입력 순서 `[PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y]`(9개); `r_s` 는 RP 가 `randomScalar()` 로 뽑은 `[0, 2^250)` 스칼라, HTTP 에서 10진 문자열; 세션키 서명은 EIP-191 `signMessage`, 로그인·재검증은 `r_s` 10진 문자열 위에, 세션 요청은 `${r_s}:${body}` 위에; RP `r_s` TTL 은 기존 `MODE3_CHALLENGE_TTL_MS`(기본 120000); CIA 상태 `version: 3`(옛 버전 기동 거부), 지갑 상태 `version: 3`(옛 버전은 registration 유지·세션 비움); RP 등록 파일 `MODE3_RP_REGISTRATION_FILE`(기본 `mode3_rp_registration.json`, 0600).
- 응답 이유(reason) 문자열: 지갑 `bad_rp_cert`, `no_session`, `revoked`, `account_disabled`, `issue_failed`, `chain_unavailable`; RP `bad_challenge`, `no_session`, `session_mismatch`, `stale_root`, `expired`, `wrong_chain`, `untrusted_cia`, `wrong_arid`, `bad_proof`, `bad_signature`, `revalidate_required`.
- `build/mode3` 재생성은 Task 2 에서만(`scripts/build_mode3_circuit.sh pot21_final.ptau`).
- :8545 hardhat 과 :4100/:5100/:3100 데모 서버는 사용자 프로세스 — 끄거나 재시작하지 않는다. `.env`, `*_keys.json`, `*_state.json`, `mode3_rp_registration.json` 은 읽지 않는다(격리 헬퍼는 임시 디렉터리).
- 커밋은 사용자 승인 후에만. 각 Task 의 커밋 단계는 "제안 후 승인 시 실행".

---

### Task 1: lib — 도메인 V3, `r_s` 명명, `cert_s` 라이브러리

**Files:**
- Modify: `lib/mode3_credential.js` (`credMessage` 도메인·인자 이름)
- Modify: `lib/mode3_issuance.js` (`issueRequestMessage` 인자 이름·주석)
- Create: `lib/mode3_rp_cert.js`
- Create: `tests/test_mode3_rp_cert.js` (unit)
- Modify: `tests/test_mode3_issuance.js` (`issueRequestMessage` 케이스 이름), `scripts/run_tests.sh` (UNIT 에 추가)

**Interfaces:**
- Produces: `DOMAIN_MODE3_CRED_V3`; `credMessage(C, exptime, chainid, r_s)`(시그니처 동일, 도메인만 V3); `issueRequestMessage(C_pt, chainid, r_s)`(동일); `lib/mode3_rp_cert.js` — `DOMAIN_MODE3_CERT_S`, `originToField(origin) → bigint`, `certSMessage(arid, origin) → bigint`, `signRpCert(prvBuf, { arid, origin }) → { R8x, R8y, S }`(10진 문자열), `verifyRpCert(pkCIA:{x,y}, { arid, origin, cert }) → boolean`. Task 3·4·5 가 쓴다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_mode3_rp_cert.js` 를 만든다.

```js
// 서비스 인증서 cert_s (설계 2026-09-15 §3). 외부 의존 없음.
//   node tests/test_mode3_rp_cert.js
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { randomScalar, SCALAR_MAX } from '../lib/mode3_credential.js';
import { DOMAIN_MODE3_CERT_S, originToField, certSMessage, signRpCert, verifyRpCert } from '../lib/mode3_rp_cert.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const eddsa = await buildEddsa();
const F = eddsa.F;
const prv = Buffer.alloc(32, 9);
const pub = eddsa.prv2pub(prv);
const pkCIA = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };
const arid = randomScalar();
const origin = 'http://127.0.0.1:3100';

await t('도메인 태그는 "MODE3CERTS" 빅엔디언이다', () => {
  assert.equal(DOMAIN_MODE3_CERT_S, BigInt('0x' + Buffer.from('MODE3CERTS').toString('hex')));
});

await t('originToField 는 250비트 미만이고 오리진마다 다르다', () => {
  const a = originToField(origin), b = originToField('http://127.0.0.1:3101');
  assert.ok(a < SCALAR_MAX && b < SCALAR_MAX);
  assert.notEqual(a, b);
  assert.equal(a, originToField(origin), '결정론적');
});

await t('양성: 서명한 (arid, origin) 이 검증된다', async () => {
  const cert = await signRpCert(prv, { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert }), true);
});

await t('음성: origin 이 다르면 거절 (피싱 페이지가 남의 arid 를 끼워 넣는 경우)', async () => {
  const cert = await signRpCert(prv, { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin: 'http://evil.example', cert }), false);
});

await t('음성: arid 가 다르면 거절', async () => {
  const cert = await signRpCert(prv, { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid: arid + 1n, origin, cert }), false);
});

await t('음성: 다른 키의 서명은 거절', async () => {
  const cert = await signRpCert(Buffer.alloc(32, 7), { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert }), false);
});

await t('음성: 형식이 깨진 cert 는 throw 없이 false', async () => {
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert: { R8x: 'x', R8y: '1', S: '1' } }), false);
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert: null }), false);
});

process.exit(failed === 0 ? 0 : 1);
```

`tests/test_mode3_issuance.js` 의 케이스 이름 `'issueRequestMessage 는 (C_pt, chainid, nonce) 를 덮는다 …'` 를 `'issueRequestMessage 는 (C_pt, chainid, r_s) 를 덮는다 — 하나라도 다르면 다른 메시지'` 로 바꾼다(본문은 그대로).

`scripts/run_tests.sh` 의 `UNIT` 배열 끝(`tests/test_mode3_issuance.js` 다음)에 `tests/test_mode3_rp_cert.js` 를 넣는다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_rp_cert.js 2>&1 | tail -3`
Expected: `ERR_MODULE_NOT_FOUND` (lib/mode3_rp_cert.js 없음).

- [ ] **Step 3: `lib/mode3_rp_cert.js` 작성**

```js
// 서비스 인증서 cert_s — 설계 2026-09-15 §3. RP 가 CIA 에 (name, origin) 으로 등록하면 CIA 가 arid 를 배정하고
// (arid, origin) 에 EdDSA-Poseidon 으로 서명한다. 지갑은 로그인 전에 이 서명을 pk_CIA 로 검증하고, 요청을 보낸
// 오리진과 cert 의 오리진이 같은지 본다 — 피싱 페이지가 진짜 서비스의 arid 를 끼워 넣는 것을 막는다.
// cert_s 는 CIA 에 되돌려 보내지 않는다(13장 unobservability).
import { createHash } from 'node:crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX } from './mode3_credential.js';

export const DOMAIN_MODE3_CERT_S = 365084431357317727016019n;   // ASCII "MODE3CERTS" 빅엔디언

let eddsaP = null, psP = null;
const getEddsa = () => (eddsaP ??= buildEddsa());
const getPs = () => (psP ??= buildPoseidon());

/** origin 문자열 → 250비트 필드 원소. sha256 뒤 상위 비트를 잘라 스칼라 상한 규약에 맞춘다. */
export function originToField(origin) {
  if (typeof origin !== 'string' || origin.length === 0) throw new Error('originToField: origin 문자열이 필요하다');
  const h = createHash('sha256').update(origin, 'utf8').digest('hex');
  return BigInt('0x' + h) & (SCALAR_MAX - 1n);
}

export async function certSMessage(arid, origin) {
  if (typeof arid !== 'bigint' || arid < 0n || arid >= SCALAR_MAX) throw new Error('certSMessage: arid 는 [0, 2^250) bigint');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_CERT_S, arid, originToField(origin)]));
}

export async function signRpCert(prvBuf, { arid, origin }) {
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const s = eddsa.signPoseidon(prvBuf, F.e(await certSMessage(arid, origin)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** 형식이 깨져도 throw 하지 않고 false — 지갑의 요청 경로에서 그대로 403 으로 이어진다. */
export async function verifyRpCert(pkCIA, { arid, origin, cert }) {
  try {
    if (!cert || typeof cert !== 'object') return false;
    const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad'); return BigInt(v); };
    const eddsa = await getEddsa();
    const F = eddsa.F;
    const m = F.e(await certSMessage(arid, origin));
    const sig = { R8: [F.e(B(cert.R8x)), F.e(B(cert.R8y))], S: B(cert.S) };
    const pub = [F.e(BigInt(pkCIA.x)), F.e(BigInt(pkCIA.y))];
    return eddsa.verifyPoseidon(m, sig, pub);
  } catch { return false; }
}

export const certToStrings = (c) => ({ R8x: String(c.R8x), R8y: String(c.R8y), S: String(c.S) });
```

- [ ] **Step 4: `lib/mode3_credential.js`·`lib/mode3_issuance.js` 수정**

`lib/mode3_credential.js`: `DOMAIN_MODE3_CRED_V2` 아래에 추가하고 `credMessage` 를 바꾼다.

```js
// 세션 성명(2026-09-15 설계 §5). V2(사용자 nonce 판) 서명이 새 회로에서 재생되지 않게 다른 값.
export const DOMAIN_MODE3_CRED_V3 = 93461614427473393731524147n; // ASCII "MODE3CREDV3" 빅엔디언
```

```js
// circuits/pi_cred.circom 의 msgHasher(DOMAIN_MODE3_CRED_V3, C, exptime, chainid, r_s 순서)와
// 일치해야 한다. exptime 은 Unix 초, chainid 는 폐기 체인 id, r_s 는 서비스가 이 세션을 위해 뽑은 값(설계 2026-09-15 §4).
export async function credMessage(C, exptime, chainid, r_s) {
  for (const [k, v] of [['exptime', exptime], ['chainid', chainid], ['r_s', r_s]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`credMessage: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (r_s >= SCALAR_MAX) throw new Error('credMessage: r_s 는 2^250 미만이어야 한다 (회로 Num2Bits(250))');
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED_V3, C, exptime, chainid, r_s]));
}
```

`lib/mode3_issuance.js` 의 `issueRequestMessage(C_pt, chainid, nonce)` 를 인자 이름 `r_s` 로, 주석을 "발급 요청의 사용자 서명 메시지 = Poseidon(C_pt.x, C_pt.y, chainid, r_s) (설계 2026-09-15 §5 단계 2). r_s 는 서비스가 뽑아 사용자를 거쳐 온 값이다." 로 바꾼다. 검사 오류 문구의 `nonce` → `r_s`.

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_mode3_rp_cert.js 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_mode3_issuance.js 2>&1 | grep -E "^(ok|FAIL)"; bash scripts/run_tests.sh unit 2>&1 | tail -2`
Expected: 두 파일 전부 `ok`; unit 그룹 `통과 9 / 실패 0`.

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add lib/mode3_credential.js lib/mode3_issuance.js lib/mode3_rp_cert.js tests/test_mode3_rp_cert.js tests/test_mode3_issuance.js scripts/run_tests.sh
git commit -m "feat(mode3): 서명 도메인 V3 와 r_s 명명, 서비스 인증서 cert_s 라이브러리"
```

---

### Task 2: 회로 — `r_s` 공개 입력, 도메인 V3, 산출물 재생성

**Files:**
- Modify: `circuits/pi_cred.circom`, `tests/helpers/mode3_fixture.mjs`, `tests/test_pi_cred_witness.mjs`

**Interfaces:**
- Produces: 공개 입력 `[PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y]`; 비공개에서 `nonce` 제거; `buildValidInput()` 이 `r_s` 를 공개 입력 자리에 둠; `build/mode3/*` 재생성(nPublic 9).

- [ ] **Step 1: 픽스처·테스트 수정**

`tests/helpers/mode3_fixture.mjs`: `const nonce = 55555…n;` → `const r_s = 55555555555555555555n;   // 서비스가 뽑은 세션 값. 공개 입력`, `credMessage(C, exptime, chainid, r_s)`, `input` 에서 `nonce: …` 줄을 지우고 공개 입력 블록의 `chainid` 다음에 `r_s: r_s.toString(),` 를 넣는다.

`tests/test_pi_cred_witness.mjs`: `'음성: nonce 를 바꾸면 거부된다 …'` 케이스를 아래로 교체.

```js
await t('음성: r_s 를 바꾸면 거부된다 (서명이 r_s 를 덮는다 — 다른 세션의 성명을 이 세션에 낼 수 없다)', async () => {
  await assert.rejects(() => witness({ ...valid, r_s: (BigInt(valid.r_s) + 1n).toString() }), /Assert Failed/);
});
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_pi_cred_witness.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: `양성` 케이스가 `Signal not found`(r_s 미정의 / nonce 미제공) 로 FAIL.

- [ ] **Step 3: `circuits/pi_cred.circom` 수정**

머리 주석 `①` 줄을 `//   ① CIA가 (C, exptime, chainid, r_s)에 서명했다 — 없으면 아무나 credential을 만든다` 로, `nonce 는 비공개다 …` 줄을 아래로 교체.

```
//   r_s 는 서비스가 이 세션을 위해 뽑은 값이라 **공개 입력**이다 — RP 가 자기가 준 값과 대조한다(설계 2026-09-15 §7).
//   CIA 도 r_s 를 보므로 CIA·RP 기록을 맞대면 uid↔PPID 가 이어진다(§2, 의도된 조건부 추적 가능성).
```

입력 선언에서 비공개 `signal input nonce;` 를 지우고 공개 블록의 `signal input chainid;` 다음에 `signal input r_s;` 를 넣는다. `var DOMAIN_MODE3_CRED_V2 = …` 를 `var DOMAIN_MODE3_CRED_V3 = 93461614427473393731524147;  // ASCII "MODE3CREDV3"` 로. 서명 블록을 교체.

```circom
    // ---- ① CIA 서명 검증 ----
    // r_s 는 공개 입력이지만 스칼라 상한 규약(2^250)은 지킨다 — JS 쪽(credMessage·CIA·RP)이 같은 상한을 강제한다.
    component rsRange = Num2Bits(250);
    rsRange.in <== r_s;
    component msgHasher = Poseidon(5);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V3;
    msgHasher.inputs[1] <== Cf;
    msgHasher.inputs[2] <== exptime;
    msgHasher.inputs[3] <== chainid;
    msgHasher.inputs[4] <== r_s;
```

`component main {public [PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y]} = PiCred(32);`

- [ ] **Step 4: 통과 확인 + 재생성**

Run: `node tests/test_pi_cred_witness.mjs 2>&1 | grep -E "^(ok|FAIL)|비선형"` → 전부 `ok`.
Run: `bash scripts/build_mode3_circuit.sh pot21_final.ptau 2>&1 | tail -2` (수 분) → `완료:`. 확인: `node -e 'console.log(require("./build/mode3/pi_cred_vkey.json").nPublic)'` → `9`.

- [ ] **Step 5: 커밋 (사용자 승인 후)**

```bash
git add circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs
git commit -m "feat(mode3): pi_cred 가 r_s 를 공개 입력으로 받고 도메인 V3 서명을 검증한다 — 공개 입력 9개"
```

---

### Task 3: 지갑·RP 라이브러리 — `r_s` 발급 요청, 9개 공개 입력, `verifyLogin` 의 `r_s`·세션 검증

**Files:**
- Modify: `lib/mode3_wallet.js`, `lib/mode3_rp.js`
- Test: `tests/test_mode3_wallet.mjs`, `tests/test_mode3_rp.mjs` (chain)

**Interfaces:**
- Consumes: Task 1·2.
- Produces: `buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session, chainid, attrs, r_s })` → body `{ uid, C_pt, proof, sig_u, chainid, r_s }`, secrets `{ blind }`; `buildCredentialProof` 가 `credential.r_s` 를 공개 입력에 넣음; `ProofCache` 그대로; `createRpVerifier({ …, chainId })`; `verifyLogin({ proof, publicSignals, sig })` — `challenge` 인자 제거, `publicSignals.length === 9`, `r_s = publicSignals[5]`, σ 는 `r_s` 10진 문자열 위 EIP-191, 반환 `{ ok, PPID, pk_i, r_s, exptime, root }`; `verifySessionRequest({ pk_i, r_s, body, sig }) → boolean`(EIP-191 over `${r_s}:${body}`); 지갑 `signSessionRequest(wallet, r_s, body)`.

- [ ] **Step 1: 테스트 수정**

`tests/test_mode3_wallet.mjs`: `localIssue(C_pt, chainid, nonce, ttlSec)` 의 `nonce` 를 `r_s` 로(응답 필드도 `r_s`); 발급 케이스에서 `const r_s = randomScalar();` 를 만들어 `buildIssueRequest({ …, chainid: 31337n, attrs, r_s })`, `cred = await localIssue(pointFromStrings(req.body.C_pt), 31337n, r_s)`; 단언 `publicSignals.length === 9`, `BigInt(publicSignals[5]) === r_s`, `BigInt(publicSignals[6]) === tree0.getRoot()`. `'buildIssueRequest 는 요청마다 새 nonce 를 뽑고 …'` 케이스를 아래로 교체.

```js
await t('buildIssueRequest 는 r_s 를 그대로 싣고 요청마다 뽑지 않는다 — r_s 는 서비스가 준 값', async () => {
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  const r_s = randomScalar();
  const a = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, r_s });
  assert.equal(a.body.r_s, r_s.toString());
  assert.equal(a.body.nonce, undefined);
  assert.equal(a.secrets.nonce, undefined);
  await assert.rejects(() => buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n }), /r_s/);
});

await t('signSessionRequest 는 (r_s, body) 를 세션키로 서명하고 verifySessionRequest 가 복원한다', async () => {
  const r_s = randomScalar();
  const sig = await signSessionRequest(session.wallet, r_s, 'hello');
  assert.equal(verifySessionRequest({ pk_i: session.pk_i, r_s, body: 'hello', sig }), true);
  assert.equal(verifySessionRequest({ pk_i: session.pk_i, r_s, body: 'hellp', sig }), false);
  assert.equal(verifySessionRequest({ pk_i: session.pk_i, r_s: r_s + 1n, body: 'hello', sig }), false);
});
```

import 에 `randomScalar`(`../lib/mode3_credential.js`), `signSessionRequest`, `verifySessionRequest`(`../lib/mode3_rp.js`) 를 더한다.

`tests/test_mode3_rp.mjs`: `issueWith(key, C_pt, nonce, …)` → `r_s`; `makeLogin` 이 `const r_s = randomScalar();` 를 만들어 발급·서명에 쓰고 `sig: await signChallenge(session.wallet, r_s.toString())`, 반환에 `r_s` 포함, `challenge` 제거. `rp.verifyLogin(L)` 호출은 `{ proof, publicSignals, sig }` 만 쓴다. `'음성 f: 다른 챌린지에 대한 서명 재생은 bad_signature'` 를 아래로 교체.

```js
await t('음성 f: 다른 r_s 위의 서명을 붙이면 bad_signature', async () => {
  const L = await makeLogin();
  const sig = await signChallenge(L.session.wallet, (L.r_s + 1n).toString());
  assert.deepEqual(await rp.verifyLogin({ ...L, sig }), { ok: false, reason: 'bad_signature' });
});

await t('양성: verifyLogin 이 r_s·exptime·root 를 돌려준다 (서버가 세션을 만들 재료)', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true);
  assert.equal(r.r_s, L.r_s);
  assert.equal(r.exptime, BigInt(L.cred.exptime));
  assert.equal(r.root, BigInt(L.publicSignals[6]));
});
```

`'같은 사용자·같은 RP 라도 chainid 가 다르면 PPID 가 다르다'` 케이스의 `issueWith(CIA, …, req.secrets.nonce, 3600n, chainid)` 를 `issueWith(CIA, …, r_s, 3600n, chainid)` 로(케이스 안에서 `const r_s = randomScalar();` 를 루프마다 뽑고 `buildIssueRequest` 에 `r_s` 전달). `malformed` 판정 케이스가 있으면 `publicSignals.length` 8 → 9 로.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet.mjs 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_mode3_rp.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 발급·검증 케이스 FAIL(`r_s` 미지원, `publicSignals.length !== 9` → malformed).

- [ ] **Step 3: `lib/mode3_wallet.js` 수정**

```js
/**
 * Sign(sk_u, (C_pt, chainid, r_s)): 등록된 장기키로 서명 (설계 2026-09-15 §5 단계 2). 메시지는 issueRequestMessage().
 * r_s 는 서비스가 이 세션을 위해 뽑아 준 값이다 — CIA 가 (uid, r_s) 재사용을 거절해 발급 요청 재생을 막는다.
 */
export async function signUserRequest(sk_uHex, C_pt, chainid, r_s) {
  if (typeof chainid !== 'bigint' || typeof r_s !== 'bigint') throw new Error('signUserRequest: chainid·r_s(bigint) 가 필요하다');
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const s = eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), F.e(await issueRequestMessage(C_pt, chainid, r_s)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** §5 단계 1~2. blind 는 여기서 새로 뽑고 secrets 로 돌려준다. r_s 는 서비스가 준 값을 그대로 싣는다. */
export async function buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session, chainid, attrs, r_s }) {
  if (typeof chainid !== 'bigint') throw new Error('buildIssueRequest: chainid(bigint) 가 필요하다');
  if (typeof r_s !== 'bigint') throw new Error('buildIssueRequest: r_s(bigint) 가 필요하다 — 서비스가 준 세션 값');
  const blind = randomScalar();
  const a4 = normalizeAttrs(attrs);
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i: session.pk_i, r_u, attrs: a4 });
  const body = {
    uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof),
    sig_u: await signUserRequest(sk_u, C_pt, chainid, r_s), chainid: chainid.toString(), r_s: r_s.toString(),
  };
  return { body, secrets: { blind } };
}
```

`buildCredentialProof`: 주석의 공개 입력 순서를 9개로, `input` 에서 `nonce: …` 를 지우고 `chainid: …` 다음에 `r_s: BigInt(credential.r_s).toString(),` 를 넣는다. 파일 끝에 추가.

```js
/** 세션 안 후속 요청 서명 (설계 §7). 메시지 = `${r_s}:${body}` 위 EIP-191. */
export function signSessionRequest(wallet, r_s, body) {
  return wallet.signMessage(`${r_s.toString()}:${body}`);
}
```

- [ ] **Step 4: `lib/mode3_rp.js` 수정**

머리 주석 `b.` 줄 아래에 `//   r_s 대조는 서버가 한다(로그인이면 미사용 r_s 소비, 재검증이면 살아 있는 세션) — 검증기는 r_s 를 돌려줄 뿐이다` 를 더한다. `verifyLogin` 을 교체.

```js
  async function verifyLogin({ proof, publicSignals, sig }) {
    if (!Array.isArray(publicSignals) || publicSignals.length !== 9 || !proof || typeof sig !== 'string') {
      return { ok: false, reason: 'malformed' };
    }
    let ps;
    try { ps = publicSignals.map((s) => BigInt(s)); } catch { return { ok: false, reason: 'malformed' }; }
    const [PPID, aridIn, pk_i, exptime, chainIn, r_s, revRoot, ciaX, ciaY] = ps;

    const v = await chainView();                                   // a
    if (!v) return { ok: false, reason: 'chain_unavailable' };
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // c
    if (BigInt(Math.floor(now() / 1000)) > exptime) return { ok: false, reason: 'expired' };   // d
    if (chainIn !== chainId) return { ok: false, reason: 'wrong_chain' };
    if (ciaX !== BigInt(pkCIA.x) || ciaY !== BigInt(pkCIA.y)) return { ok: false, reason: 'untrusted_cia' };
    if (aridIn !== BigInt(arid)) return { ok: false, reason: 'wrong_arid' };

    let proofOk = false;                                           // e
    try { proofOk = await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { proofOk = false; }
    if (!proofOk) return { ok: false, reason: 'bad_proof' };

    let signer;                                                    // f — σ 는 r_s(10진) 위
    try { signer = BigInt(ethers.verifyMessage(r_s.toString(), sig)); } catch { return { ok: false, reason: 'bad_signature' }; }
    if (signer !== pk_i) return { ok: false, reason: 'bad_signature' };

    return { ok: true, PPID, pk_i, r_s, exptime, root: revRoot };  // g — 서버가 세션을 만든다
  }
```

파일 끝에 추가.

```js
/** 세션 요청 σ 검증 (설계 §7). lib/mode3_wallet.js 의 signSessionRequest 와 메시지 규약을 공유한다. */
export function verifySessionRequest({ pk_i, r_s, body, sig }) {
  try { return BigInt(ethers.verifyMessage(`${r_s.toString()}:${body}`, sig)) === BigInt(pk_i); }
  catch { return false; }
}
```

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_mode3_wallet.mjs 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_mode3_rp.mjs 2>&1 | grep -E "^(ok|FAIL)"` → 전부 `ok`.

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add lib/mode3_wallet.js lib/mode3_rp.js tests/test_mode3_wallet.mjs tests/test_mode3_rp.mjs
git commit -m "feat(mode3): 지갑이 서비스의 r_s 로 발급 요청·증명을 만들고 RP 검증기가 r_s 를 돌려준다 — 세션 요청 서명"
```

---

### Task 4: CIA — `register_rp`/`cert_s`, `r_s`, 상태 v3

**Files:**
- Modify: `cia.js`
- Modify: `tests/helpers/isolated_cia.mjs` (`registerRp(origin)` 헬퍼 추가)
- Test: `tests/test_cia_register_issue.mjs`, `tests/test_cia_startup.mjs`, `tests/test_cia_issue_race.mjs` (chain)

**Interfaces:**
- Consumes: Task 1 (`credMessage` V3, `issueRequestMessage`, `signRpCert`).
- Produces: `POST /cia/register_rp { name, origin }` → 201 `{ arid, name, origin, cert_s:{R8x,R8y,S} }`(같은 origin 재등록은 200 으로 기존 `arid` 재서명); `POST /cia/issue` 본문 `{ uid, C_pt, proof, sig_u, chainid, r_s }` → `{ C, exptime, chainid, r_s, sigma, pk_CIA }`, 409 오류문에 `r_s`; 상태 `{ version: 3, accounts, issued, used_rs: uid → [r_s], rps: arid → {name, origin, at}, revoked, pending, epoch }`; `GET /cia/public_keys` 그대로; 헬퍼 `cia.registerRp(origin) → { arid, cert_s }`.

- [ ] **Step 1: 테스트 수정**

`tests/test_cia_register_issue.mjs`: `issueRequest(u, overrides, { chainid, nonce, attrs })` 의 `nonce` 옵션·본문 키를 `r_s` 로(기본 `randomScalar()`), `signUser(…, chainid, r_s)`; 발급 양성 케이스 단언 `cred.r_s === body.r_s`; `'issue: 같은 nonce 재사용은 409 …'` 케이스의 옵션·정규식을 `r_s`(`/r_s/`) 로; 형식 오류 본문의 `nonce: '1'` → `r_s: '1'`. 새 케이스를 `'register: cm_u 등록, 장기키 발급'` 앞에 추가.

```js
  await t('register_rp: (name, origin) 으로 arid 와 cert_s 를 받고, 같은 origin 재등록은 같은 arid', async () => {
    const r = await cia.post('/cia/register_rp', { name: 'demo-rp', origin: 'http://127.0.0.1:3100' });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.match(r.body.arid, /^[0-9]+$/);
    assert.ok(BigInt(r.body.arid) < SCALAR_MAX);
    const keys = (await cia.get('/cia/public_keys')).body;
    assert.equal(await verifyRpCert({ x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) }, { arid: BigInt(r.body.arid), origin: 'http://127.0.0.1:3100', cert: r.body.cert_s }), true);
    const again = await cia.post('/cia/register_rp', { name: 'demo-rp', origin: 'http://127.0.0.1:3100' });
    assert.equal(again.status, 200);
    assert.equal(again.body.arid, r.body.arid);
    assert.equal((await cia.post('/cia/register_rp', { name: 'x' })).status, 400);
  });
```

import 에 `SCALAR_MAX`(`../lib/mode3_credential.js`), `verifyRpCert`(`../lib/mode3_rp_cert.js`) 를 더한다. 기존의 TTL=1 초 케이스들(만료 뒤 같은 본문 → 409 `/nonce/`)은 `/r_s/` 로.

`tests/test_cia_startup.mjs`·`tests/test_cia_issue_race.mjs`: 발급 본문의 `nonce` → `r_s`(값은 그대로 `randomScalar()`), `signUserRequest(…, 31337n, r_s)`.

`tests/helpers/isolated_cia.mjs`: 반환 객체에 `registerRp: (origin, name = 'test-rp') => fetch(`${base}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, origin }) }).then(json).then((r) => { if (r.status !== 201 && r.status !== 200) throw new Error('register_rp 실패: ' + JSON.stringify(r.body)); return { arid: r.body.arid, cert_s: r.body.cert_s, origin: r.body.origin }; }),` 를 더한다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_cia_register_issue.mjs 2>&1 | grep -E "^(ok|FAIL)" | head -20`
Expected: `register_rp` 케이스 404 로 FAIL, 발급 케이스 400(`nonce required`) 로 FAIL.

- [ ] **Step 3: `cia.js` 수정**

import 에 `signRpCert` (`./lib/mode3_rp_cert.js`) 와 `randomScalar`(`./lib/mode3_credential.js`) 를 더한다. 상태 블록:

```js
// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled }
// issued:    uid → [ { leaf(10진), C(10진), exptime(10진 Unix 초) } ]
// used_rs:   uid → [ r_s(10진) ]   발급 요청 재생 방지. **정리하지 않는다**(만료 뒤 지우면 옛 본문 재생으로 TTL 연장)
// rps:       arid → { name, origin, at }   서비스 등록(설계 2026-09-15 §3). cert_s 는 저장하지 않고 요청 때 재서명
// revoked / pending / epoch
// version 3 (2026-09-15): nonces → used_rs, rps 추가. v2 이하는 옛 서명 형식이라 읽지 않는다.
const STATE_VERSION = 3;
function defaultState() { return { version: STATE_VERSION, accounts: {}, issued: {}, used_rs: {}, rps: {}, revoked: [], pending: [], epoch: 0 }; }
```

`loadState` 의 버전 거부 문구를 `옛 credential 형식(nonce/max_height)` 로, `state.nonces ??= {}` 를 `state.used_rs ??= {}; state.rps ??= {};` 로.

`/cia/register` 라우트 **앞**에 추가.

```js
// §3(2026-09-15) 서비스 등록. arid 는 CIA 가 배정한다(Mode 2 의 rid 와 같은 방식). 같은 origin 이 다시 오면 같은 arid 를
// 돌려줘 RP 재기동 뒤에도 가명이 바뀌지 않게 한다. 승인 절차는 없다(데모, §9 한계).
app.post('/cia/register_rp', async (req, res) => {
  try {
    const { name, origin } = req.body ?? {};
    if (typeof name !== 'string' || name.length === 0 || typeof origin !== 'string' || !/^https?:\/\/[^/\s]+$/.test(origin)) {
      return res.status(400).json({ error: 'name, origin(http(s)://host[:port], 경로 없음) required' });
    }
    let arid = Object.keys(state.rps).find((a) => state.rps[a].origin === origin);
    let created = false;
    if (!arid) {
      arid = randomScalar().toString();
      state.rps[arid] = { name, origin, at: new Date().toISOString() };
      persist();
      created = true;
    }
    const cert_s = await signRpCert(ciaPrv, { arid: BigInt(arid), origin });
    res.status(created ? 201 : 200).json({ arid, name: state.rps[arid].name, origin, cert_s });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

`/cia/issue`: 본문 구조분해·형식 검사·오류문·변수명에서 `nonce` → `r_s`(`nonceBig` → `rsBig`, `nonceStr` → `rsStr`, `state.nonces` → `state.used_rs`, `'nonce already used'` → `'r_s already used'`, `'nonce must be < 2^250'` → `'r_s must be < 2^250'`), `credMessage(C, exptime, BigInt(chainStr), rsBig)`, 응답 `r_s: rsStr`. 머리 주석의 `(uid, nonce)` → `(uid, r_s)`, "설계 2026-09-15 §5".

- [ ] **Step 4: 통과 확인**

Run: 세 파일 각각 `node tests/test_cia_*.mjs 2>&1 | grep -E "^(ok|FAIL)"` → 전부 `ok`.

- [ ] **Step 5: 커밋 (사용자 승인 후)**

```bash
git add cia.js tests/helpers/isolated_cia.mjs tests/test_cia_register_issue.mjs tests/test_cia_startup.mjs tests/test_cia_issue_race.mjs
git commit -m "feat(mode3): CIA 가 서비스를 등록해 cert_s 를 내주고 r_s 를 성명에 서명한다 — 상태 v3"
```

---

### Task 5: 서버·페이지·격리 테스트 — 지갑 세션, RP 등록·세션·재검증, 데모 스택

**Files:**
- Modify: `mode3_wallet_agent.js`, `mode3_rp.js`, `mode3/wallet.html`, `mode3/rp.html`
- Modify: `tests/helpers/isolated_mode3_stack.mjs`
- Test: `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_demo_stack.mjs`, `tests/test_mode3_e2e.mjs` (chain)

**Interfaces:**
- Consumes: Task 3·4.
- Produces (지갑): `POST /wallet/login { arid, origin, cert_s, r_s }` → 200 `{ proof, publicSignals, sig, pk_i, r_s, root, issued: true, timings }`, 403 `bad_rp_cert`/`account_disabled`, 502 `issue_failed`, 503 `chain_unavailable`; `POST /wallet/revalidate { r_s, skipSync? }` → 200 `{ proof, publicSignals, sig, pk_i, r_s, root, cacheHit, timings }`, 404 `no_session`, 403 `revoked`; `POST /wallet/request { r_s, body }` → `{ sig, pk_i }`, 404 `no_session`; `GET /wallet/status` 가 `sessions` 를 보여줌; 상태 `version: 3`, `sessions[r_s]`.
- Produces (RP): 기동 시 `mode3_rp_registration.json` 없으면 CIA 에 등록; `GET /api/mode3/rp_info` → `{ arid, origin, cert_s, logAddress, walletAgentOrigin, pkCiaSource, chainId }`; `POST /api/mode3/challenge` → `{ r_s, expiresAt }`; `POST /api/mode3/login { proof, publicSignals, sig }` → `{ ok, PPID, pk_i, r_s, root }`; `POST /api/mode3/revalidate` 같은 본문 → `{ ok, r_s, root }`, 401 `no_session`/`session_mismatch`; `POST /api/mode3/request { r_s, body, sig }` → `{ ok, echo }`, 401 `no_session`/`bad_signature`/`revalidate_required`; `GET /api/mode3/sessions`.
- 격리 헬퍼: RP 에 `MODE3_RP_REGISTRATION_FILE=<tmp>/mode3_rp_registration.json`, `MODE3_RP_PUBLIC_ORIGIN=<rpOrigin>` 을 넘기고 `MODE3_RP_ARID` 핀은 지운다.

- [ ] **Step 1: 테스트 수정**

`tests/test_mode3_demo_stack.mjs` 의 `loginViaRp` 와 각본을 교체한다(각본 4′ 자기 폐기 케이스와 challenge 음성 케이스는 새 API 에 맞춰 아래처럼).

```js
/** 브라우저의 RP 페이지가 하는 일을 그대로: rp_info → r_s → 지갑 login → RP login. 세션 r_s 를 돌려준다. */
async function loginViaRp() {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const { r_s } = (await rp.post('/api/mode3/challenge')).body;
  const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, r_s }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body, r_s };
  const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body, r_s };
}
/** 세션 재검증: 지갑이 같은 성명으로 (root 가 바뀌었으면 새) π 를 만들어 RP 에 낸다. */
async function revalidateViaRp(r_s, { skipSync = false } = {}) {
  const w = await wallet.post('/wallet/revalidate', { r_s, skipSync }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body };
  const r = await rp.post('/api/mode3/revalidate', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body };
}
```

각본:

```js
  await t('rp_info: arid·origin·cert_s·logAddress·walletAgentOrigin·chainId, pk_CIA 는 TOFU', async () => {
    const r = await rp.get('/api/mode3/rp_info');
    assert.equal(r.status, 200);
    assert.match(r.body.arid, /^[0-9]+$/);
    assert.equal(r.body.origin, rp.origin);
    assert.ok(r.body.cert_s?.S);
    assert.equal(r.body.logAddress, cia.logAddress);
    assert.equal(r.body.walletAgentOrigin, wallet.origin);
    assert.equal(r.body.pkCiaSource, 'tofu');
  });

  await t('1. 등록', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['19', '410', '0', '0'] })).status, 201);
  });

  let PPID1, S1;
  await t('2. 로그인: 발급(issued=true) + RP ok, PPID, 세션 생성', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rpStatus, 200);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.match(r.rp.PPID, /^[0-9]+$/);
    assert.equal(r.rp.r_s, r.r_s);
    PPID1 = r.rp.PPID; S1 = r.r_s;
  });

  await t('3. 세션 재검증(root 같음): 캐시 π 재사용, RP ok', async () => {
    const r = await revalidateViaRp(S1);
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.cacheHit, true);
    assert.equal(r.rp.ok, true, j(r.rp));
  });

  await t("3'. 세션 요청: 세션키 서명이 RP 에서 검증된다", async () => {
    const w = await wallet.post('/wallet/request', { r_s: S1, body: 'hello' }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));
    const r = await rp.post('/api/mode3/request', { r_s: S1, body: 'hello', sig: w.body.sig });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.ok, true);
    const bad = await rp.post('/api/mode3/request', { r_s: S1, body: 'hellp', sig: w.body.sig });
    assert.equal(bad.status, 401); assert.equal(bad.body.reason, 'bad_signature');
  });

  await t("3''. 로그인 다시: 새 세션 = 새 발급, PPID 동일", async () => {
    const r = await loginViaRp();
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
    assert.notEqual(r.r_s, S1);
  });

  await t('같은 r_s 로 /login 을 다시 내면 bad_challenge (r_s 는 로그인 때 소비된다)', async () => {
    const w = await wallet.post('/wallet/revalidate', { r_s: S1, skipSync: true }, { Origin: rp.origin });
    const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig });
    assert.equal(r.status, 401); assert.equal(r.body.reason, 'bad_challenge');
  });

  await t('4. 계정 폐기 + 게시', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
  });

  await t('5. 동기화 생략 재검증 → RP stale_root; 세션 요청은 revalidate_required', async () => {
    const r = await revalidateViaRp(S1, { skipSync: true });
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.rp.ok, false); assert.equal(r.rp.reason, 'stale_root');
    const w = await wallet.post('/wallet/request', { r_s: S1, body: 'x' }, { Origin: rp.origin });
    const q = await rp.post('/api/mode3/request', { r_s: S1, body: 'x', sig: w.body.sig });
    assert.equal(q.status, 401); assert.equal(q.body.reason, 'revalidate_required');
  });

  await t('6. 동기화 재검증 → 지갑 403 revoked; 새 로그인 → 지갑 403 account_disabled', async () => {
    const r = await revalidateViaRp(S1);
    assert.equal(r.walletStatus, 403, j(r)); assert.equal(r.wallet.reason, 'revoked');
    const l = await loginViaRp();
    assert.equal(l.walletStatus, 403, j(l)); assert.equal(l.wallet.reason, 'account_disabled');
  });

  await t('7. 복구', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
  });

  await t('8. 로그인: 재발급 + RP ok, PPID 동일', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
  });

  await t("4'. 사용자 자기 폐기(비밀번호) → 게시 → 재검증 stale_root → 지갑 revoked → 관리자 복구 → PPID 동일", async () => {
    const before = await loginViaRp();
    assert.equal(before.rp.ok, true, j(before));
    const r = await cia.post('/cia/account/self_revoke', { uid, pwd: 'password123' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.disabled, true);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const stale = await revalidateViaRp(before.r_s, { skipSync: true });
    assert.equal(stale.rp.ok, false); assert.equal(stale.rp.reason, 'stale_root');
    const denied = await revalidateViaRp(before.r_s);
    assert.equal(denied.walletStatus, 403, j(denied)); assert.equal(denied.wallet.reason, 'revoked');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const again = await loginViaRp();
    assert.equal(again.rp.ok, true, j(again)); assert.equal(again.rp.PPID, PPID1);
  });

  await t('bad_rp_cert: cert_s 의 origin 과 다른 origin 을 주장하면 지갑이 403', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { r_s } = (await rp.post('/api/mode3/challenge')).body;
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: 'http://evil.example', cert_s: info.cert_s, r_s }, { Origin: rp.origin });
    assert.equal(w.status, 403); assert.equal(w.body.reason, 'bad_rp_cert');
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: { ...info.cert_s, S: '1' }, r_s }, { Origin: rp.origin });
    assert.equal(w2.status, 403); assert.equal(w2.body.reason, 'bad_rp_cert');
  });

  await t('r_s 음성: 미발급 r_s → RP bad_challenge, 만료(TTL 6s) → bad_challenge', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const bogus = '123456789';
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, r_s: bogus }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));   // 지갑은 r_s 의 출처를 모른다 — RP 가 거절한다
    const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig });
    assert.equal(r.status, 401); assert.equal(r.body.reason, 'bad_challenge');
    const { r_s } = (await rp.post('/api/mode3/challenge')).body;
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, r_s }, { Origin: rp.origin });
    await new Promise((res) => setTimeout(res, 6500));
    const r2 = await rp.post('/api/mode3/login', { proof: w2.body.proof, publicSignals: w2.body.publicSignals, sig: w2.body.sig });
    assert.equal(r2.status, 401); assert.equal(r2.body.reason, 'bad_challenge');
  });

  await t('login 입력 검증: 필드 누락 → 400', async () => {
    assert.equal((await rp.post('/api/mode3/login', { proof: {} })).status, 400);
  });
```

페이지 서빙 케이스는 그대로(`'Mode 3 로그인'` 마커 유지).

`tests/test_mode3_wallet_agent.mjs`: 로그인 헬퍼가 `cia.registerRp(stack.rpOriginForWallet)` 로 `{arid, cert_s}` 를 받아 `/wallet/login { arid, origin, cert_s, r_s }` 를 보내고, 검증기는 `createRpVerifier({ …, arid: BigInt(arid), chainId: 31337n })`, `verify(body)` 는 `verifyLogin({ proof, publicSignals, sig })`. 케이스 대응: `'두 번째 로그인: 캐시 히트 …'` → `'재검증: 캐시 히트(cacheHit=true), publicSignals 동일, σ 만 새로'`(`/wallet/revalidate { r_s }`); `'계정 폐기 + 게시 → skipSync 로그인 …'` → `/wallet/revalidate { r_s, skipSync: true }` → stale_root; `'동기화 로그인: 폐기 감지 → …'` → 재검증 403 `revoked` + 새 로그인 403 `account_disabled`; `'입력 검증: arid 비10진 / challenge 없음 → 400'` → `r_s 없음 / cert_s 없음 → 400`; `'status: credential 이 exptime …'` → `s.body.sessions[r_s].exptime`. 새 케이스: `'revalidate: 모르는 r_s 는 404 no_session'`, `'request: 세션키 서명 반환'`.

`tests/test_mode3_e2e.mjs`(라이브러리 e2e): `newSessionAndIssue()` 가 `const r_s = randomScalar();` 를 뽑아 `buildIssueRequest({ …, r_s })`, `loginRound`/`submit` 의 서명을 `signChallenge(session.wallet, r_s.toString())`, `verifyLogin({ proof, publicSignals, sig })`, 검증기에 `chainId: 31337n`, `arid` 는 `cia.registerRp('http://127.0.0.1:1')` 로 받은 값(라이브러리 경로라 cert 검증은 없음 — 등록만으로 arid 확보). 케이스 의미는 유지(캐시 히트 = 같은 r_s 세션의 재증명).

`tests/helpers/isolated_mode3_stack.mjs`: `PINNED_ENV` 에서 `MODE3_RP_ARID: ''` 를 지우고 `MODE3_RP_REGISTRATION_FILE: ''` 를 넣는다(빈 값 = 기본 경로가 아니라 아래 env 로 덮음). RP 기동 env 에 `MODE3_RP_REGISTRATION_FILE: path.join(dir, 'mode3_rp_registration.json'), MODE3_RP_PUBLIC_ORIGIN: rpOrigin,` 를 더한다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet_agent.mjs 2>&1 | grep -E "^(ok|FAIL)" | head`
Expected: 로그인 케이스 400(`challenge 필요`) 로 FAIL.

- [ ] **Step 3: `mode3_wallet_agent.js` 수정**

머리 주석에 "로그인마다 발급된다(설계 2026-09-15 §5) — 성명은 세션(r_s) 단위이고 세션 안에서만 재사용한다." 추가. import 에 `signSessionRequest`(`./lib/mode3_wallet.js`), `verifyRpCert`(`./lib/mode3_rp_cert.js`) 를 더한다. 상태·캐시 블록 교체.

```js
// ---- 상태 ----
// registration: { uid, s_u, r_u, cm_u:{x,y}, sk_u, attrs:[4개 10진] }   §6.1. 한 번
// sessions:     r_s → { arid, credential:{C,exptime,chainid,r_s,sigma,pk_CIA}, blind, sessionPrivKey, pk_i, issuedAt }
// version 3 (2026-09-15): credentials[arid] → sessions[r_s]. 옛 파일은 등록만 살리고 세션은 비운다.
const WALLET_STATE_VERSION = 3;
let state = readJson(STATE_FILE, { version: WALLET_STATE_VERSION, registration: null, sessions: {} });
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }
if (state.version !== WALLET_STATE_VERSION) {
  console.warn(`[wallet] 상태 파일 버전 ${state.version} → ${WALLET_STATE_VERSION}: 세션·credential 을 비운다(옛 형식). 등록은 유지.`);
  state = { version: WALLET_STATE_VERSION, registration: state.registration ?? null, sessions: {} };
  persist();
}
function pruneSessions() {
  const now = nowSec();
  for (const [k, s] of Object.entries(state.sessions)) if (BigInt(s.credential.exptime) < now) delete state.sessions[k];
}

const cache = new ProofCache();   // (root, r_s) → {proof, publicSignals}. 메모리만
let lastSync = null;              // { root, head }

// pk_CIA — cert_s 검증용. env 가 있으면 그것, 없으면 CIA 에서 한 번 받아 고정(TOFU, RP 와 같은 규칙).
let pkCiaP = null;
function pkCia() {
  return (pkCiaP ??= (async () => {
    const { MODE3_PK_CIA_X: x, MODE3_PK_CIA_Y: y } = process.env;
    if (x && y) return { x: BigInt(x), y: BigInt(y) };
    const r = await fetch(`${CIA_URL}/cia/public_keys`);
    if (!r.ok) throw new Error(`CIA 에서 pk_CIA 를 받지 못했다 (${r.status})`);
    const k = await r.json();
    return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y) };
  })().catch((e) => { pkCiaP = null; throw e; }));
}
```

`issueCredential(arid)` → `issueCredential(arid, r_s)`: `buildIssueRequest({ …, chainid: await chainId(), attrs: …, r_s })`, 성공 시 `state.sessions[r_s.toString()] = { arid, credential: r.body, blind: …, sessionPrivKey: …, pk_i: …, issuedAt: … }`.

`/wallet/status`: `credentials` 대신 `sessions` (`r_s → { arid, exptime, chainid, sessionAddress, issuedAt }`), `cachedProofRoot` 는 지운다.

CORS 를 `/wallet/login`·`/wallet/revalidate`·`/wallet/request` 셋에 건다(`app.options` 도 셋).

`/wallet/login` 을 교체.

```js
app.post('/wallet/login', loginCors, async (req, res) => {
  try {
    const { arid, origin, cert_s, r_s } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !isDec(r_s)) return res.status(400).json({ error: 'arid, origin, cert_s, r_s 필요' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const rs = BigInt(r_s);
    if (rs >= SCALAR_MAX) return res.status(400).json({ error: 'r_s 는 2^250 미만' });

    // 서비스 인증(설계 §3·§4): cert_s 가 pk_CIA 서명이고, 요청을 보낸 오리진이 cert 의 오리진과 같아야 한다.
    // 피싱 페이지는 진짜 서비스의 (arid, cert_s) 를 그대로 보여줄 수는 있어도 그 오리진에서 요청을 보낼 수는 없다.
    let pk;
    try { pk = await pkCia(); } catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    const reqOrigin = req.get('Origin');
    if (reqOrigin !== origin || !(await verifyRpCert(pk, { arid: BigInt(arid), origin, cert: cert_s }))) {
      return res.status(403).json({ reason: 'bad_rp_cert' });
    }

    const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString() };

    pruneSessions();
    t = Date.now();
    const r = await issueCredential(arid, rs);      // 로그인마다 발급(설계 §5)
    timings.issueMs = Date.now() - t;
    if (r.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
    if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, timings });
    const out = await proveSession(rs.toString(), synced, timings);
    res.json({ ...out, issued: true, timings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/** 세션의 성명으로 현재 root 에 대한 π 를 만든다(캐시). 폐기됐으면 throw('revoked'). */
async function proveSession(rsKey, synced, timings) {
  const s = state.sessions[rsKey];
  const reg = state.registration;
  const sessionWallet = new ethers.Wallet(s.sessionPrivKey);
  let cached = cache.get(synced.root, rsKey);
  const cacheHit = Boolean(cached);
  if (!cached) {
    if (synced.tree.has(await credLeaf(BigInt(s.credential.C)))) throw Object.assign(new Error('revoked'), { reason: 'revoked' });
    const t = Date.now();
    cached = await buildCredentialProof({
      uid: BigInt(reg.uid), arid: BigInt(s.arid), s_u: BigInt(reg.s_u), blind: BigInt(s.blind), pk_i: BigInt(s.pk_i),
      attrs: (reg.attrs ?? []).map(BigInt),
      credential: s.credential, pk_CIA: { x: BigInt(s.credential.pk_CIA.x), y: BigInt(s.credential.pk_CIA.y) }, tree: synced.tree,
    });
    timings.proveMs = Date.now() - t;
    cache.set(synced.root, rsKey, cached);
  }
  const sig = await signChallenge(sessionWallet, rsKey);
  return { proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root: synced.root.toString(), cacheHit };
}

app.post('/wallet/revalidate', loginCors, async (req, res) => {
  try {
    const { r_s, skipSync } = req.body ?? {};
    if (!isDec(r_s)) return res.status(400).json({ error: 'r_s 필요' });
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
    // 시연용: 동기화를 건너뛰고 마지막 root 의 π 를 그대로 재제출한다(RP 의 stale_root 거절을 보이기 위해).
    if (skipSync) {
      if (!lastSync) return res.status(409).json({ reason: 'no_cached_proof' });
      const cached = cache.get(BigInt(lastSync.root), rsKey);
      if (!cached) return res.status(409).json({ reason: 'no_cached_proof' });
      const sig = await signChallenge(new ethers.Wallet(s.sessionPrivKey), rsKey);
      return res.json({ proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root: lastSync.root, cacheHit: true, timings });
    }
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString() };
    try {
      const out = await proveSession(rsKey, synced, timings);
      res.json({ ...out, timings });
    } catch (e) {
      if (e.reason === 'revoked') { delete state.sessions[rsKey]; persist(); return res.status(403).json({ reason: 'revoked', timings }); }
      throw e;
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/wallet/request', loginCors, async (req, res) => {
  try {
    const { r_s, body } = req.body ?? {};
    if (!isDec(r_s) || typeof body !== 'string') return res.status(400).json({ error: 'r_s, body(string) 필요' });
    const s = state.sessions[BigInt(r_s).toString()];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    const sig = await signSessionRequest(new ethers.Wallet(s.sessionPrivKey), BigInt(r_s), body);
    res.json({ sig, pk_i: s.pk_i });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

`SCALAR_MAX` 를 `./lib/mode3_credential.js` 에서 import 한다. `lastProof` 변수는 지운다.

- [ ] **Step 4: `mode3_rp.js` 수정**

`ARID` env 를 지우고 등록 파일 로직을 넣는다(`resolvePkCia` 뒤).

```js
// ---- 서비스 등록(설계 2026-09-15 §3) ----
// 처음 기동에서 CIA 에 (name, origin) 으로 등록해 arid 와 cert_s 를 받아 파일에 둔다. 재기동은 파일을 쓴다.
// origin 은 이 RP 페이지가 열리는 오리진 — 지갑이 요청의 Origin 헤더와 대조한다.
const REG_FILE = process.env.MODE3_RP_REGISTRATION_FILE || path.join(__dirname, 'mode3_rp_registration.json');
const PUBLIC_ORIGIN = process.env.MODE3_RP_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const RP_NAME = process.env.MODE3_RP_NAME || 'demo-rp';
async function resolveRegistration() {
  let reg = readJson(REG_FILE, null);
  if (reg && reg.origin !== PUBLIC_ORIGIN) { console.warn(`[rp] 등록 파일의 origin(${reg.origin}) 이 현재(${PUBLIC_ORIGIN}) 와 달라 다시 등록한다`); reg = null; }
  if (!reg) {
    const r = await fetch(`${CIA_URL}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: RP_NAME, origin: PUBLIC_ORIGIN }) });
    if (!r.ok) throw new Error(`CIA 등록 실패 (${r.status})`);
    const b = await r.json();
    reg = { arid: b.arid, origin: b.origin, cert_s: b.cert_s, issuedAt: new Date().toISOString() };
    writeJsonAtomic(REG_FILE, reg, 0o600);
    console.log(`[rp] CIA 에 등록: arid=${reg.arid} origin=${reg.origin} → ${REG_FILE}`);
  }
  if (!(await verifyRpCert(pkCIA, { arid: BigInt(reg.arid), origin: reg.origin, cert: reg.cert_s }))) {
    throw new Error('등록 파일의 cert_s 가 현재 pk_CIA 로 검증되지 않는다 — CIA 키가 바뀌었으면 파일을 지우고 재기동');
  }
  return reg;
}
const registration = await resolveRegistration();
const ARID = registration.arid;
```

import 에 `readJson, writeJsonAtomic`(`./lib/mode3_state.js`), `verifyRpCert`(`./lib/mode3_rp_cert.js`), `randomScalar`(`./lib/mode3_credential.js`), `verifySessionRequest`(`./lib/mode3_rp.js`) 를 더한다. `challenges` 블록을 `r_s` 로.

```js
// ---- r_s: 메모리, TTL, 로그인 때 1회 소비. 소비된 r_s 는 세션 식별자가 된다(설계 §7) ----
const challenges = new Map();   // r_s(10진) → expiresAt(ms)
const sessions = new Map();     // r_s(10진) → { PPID, pk_i, exptime, root, at }
function sweepChallenges() { const now = Date.now(); for (const [c, exp] of challenges) if (exp < now) challenges.delete(c); }
function issueChallenge() {
  sweepChallenges();
  const r_s = randomScalar().toString();
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(r_s, expiresAt);
  return { r_s, expiresAt };
}
function consumeChallenge(r_s) {
  const exp = challenges.get(r_s);
  if (exp === undefined) return false;
  challenges.delete(r_s);
  return Date.now() <= exp;
}
```

라우트:

```js
app.get('/api/mode3/rp_info', (req, res) => {
  res.json({ arid: ARID, origin: registration.origin, cert_s: registration.cert_s, logAddress: LOG_ADDRESS, walletAgentOrigin: WALLET_ORIGIN, pkCiaSource: pkCIA.source, chainId: chainId.toString() });
});
app.post('/api/mode3/challenge', (req, res) => res.json(issueChallenge()));

async function verifyBody(req, res) {
  const { proof, publicSignals, sig } = req.body ?? {};
  if (!proof || !Array.isArray(publicSignals) || typeof sig !== 'string') { res.status(400).json({ ok: false, reason: 'malformed' }); return null; }
  return verifier.verifyLogin({ proof, publicSignals, sig });
}

app.post('/api/mode3/login', async (req, res) => {
  try {
    const { publicSignals } = req.body ?? {};
    const rsStr = Array.isArray(publicSignals) && publicSignals.length === 9 ? String(BigInt(publicSignals[5])) : null;
    if (!rsStr) return res.status(400).json({ ok: false, reason: 'malformed' });
    if (!consumeChallenge(rsStr)) return res.status(401).json({ ok: false, reason: 'bad_challenge' });   // 검증 전에 소비
    const v = await verifyBody(req, res); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    sessions.set(rsStr, { PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), exptime: v.exptime.toString(), root: v.root.toString(), at: new Date().toISOString() });
    logins.push({ PPID: v.PPID.toString(), at: new Date().toISOString(), root: v.root.toString(), r_s: rsStr });
    res.json({ ok: true, PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), r_s: rsStr, root: v.root.toString() });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.post('/api/mode3/revalidate', async (req, res) => {
  try {
    const { publicSignals } = req.body ?? {};
    const rsStr = Array.isArray(publicSignals) && publicSignals.length === 9 ? String(BigInt(publicSignals[5])) : null;
    if (!rsStr) return res.status(400).json({ ok: false, reason: 'malformed' });
    const s = sessions.get(rsStr);
    if (!s) return res.status(401).json({ ok: false, reason: 'no_session' });
    const v = await verifyBody(req, res); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    if (v.PPID.toString() !== s.PPID || v.pk_i.toString() !== s.pk_i) return res.status(401).json({ ok: false, reason: 'session_mismatch' });
    s.root = v.root.toString();
    res.json({ ok: true, r_s: rsStr, root: s.root });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.post('/api/mode3/request', async (req, res) => {
  try {
    const { r_s, body, sig } = req.body ?? {};
    if (typeof r_s !== 'string' || typeof body !== 'string' || typeof sig !== 'string') return res.status(400).json({ ok: false, reason: 'malformed' });
    const s = sessions.get(r_s);
    if (!s) return res.status(401).json({ ok: false, reason: 'no_session' });
    if (BigInt(Math.floor(Date.now() / 1000)) > BigInt(s.exptime)) { sessions.delete(r_s); return res.status(401).json({ ok: false, reason: 'expired' }); }
    // 폐기가 효력을 갖는 지점: root 가 바뀌었으면 세션은 재검증 전까지 요청을 받지 않는다.
    const view = await verifier.refreshChainView().catch(() => null);
    if (!view) return res.status(503).json({ ok: false, reason: 'chain_unavailable' });
    if (view.root.toString() !== s.root) return res.status(401).json({ ok: false, reason: 'revalidate_required' });
    if (!verifySessionRequest({ pk_i: s.pk_i, r_s, body, sig })) return res.status(401).json({ ok: false, reason: 'bad_signature' });
    res.json({ ok: true, echo: body, PPID: s.PPID });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.get('/api/mode3/logins', (req, res) => res.json({ logins }));
app.get('/api/mode3/sessions', (req, res) => res.json({ sessions: [...sessions.entries()].map(([r_s, s]) => ({ r_s, ...s })) }));
```

기동 로그의 `arid=${ARID}` 유지, `origin=${registration.origin}` 추가.

`mode3/rp.html`: 로그인 흐름을 `challenge → { r_s }` → 지갑 `/wallet/login { arid: info.arid, origin: info.origin, cert_s: info.cert_s, r_s }` → RP `/api/mode3/login { proof, publicSignals, sig }` 로 바꾸고, 성공 시 `currentSession = rb.r_s` 를 저장. 버튼을 더한다: "세션 재검증"(`/wallet/revalidate { r_s: currentSession, skipSync }` → `/api/mode3/revalidate`), "세션 요청"(`/wallet/request { r_s, body: 'hello' }` → `/api/mode3/request`). "동기화 생략" 체크박스는 재검증 버튼에 붙인다. `rpInfo` 줄에 `origin`·`cert_s` 유무를 표시. 로그인 기록에 `r_s` 앞 8자리.

`mode3/wallet.html`: 상태 표시를 `sessions (r_s 별)` 로(`arid`, `exptime`, `chainid`, 세션 주소).

- [ ] **Step 5: 통과 확인 + 전체**

Run: 세 테스트 파일 각각 → 전부 `ok`. `bash scripts/run_tests.sh chain 2>&1 | tail -4` → `통과 12 / 실패 0`. `npm test 2>&1 | tail -3` → `통과 22 / 실패 0`.

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add mode3_wallet_agent.js mode3_rp.js mode3/wallet.html mode3/rp.html tests/helpers/isolated_mode3_stack.mjs tests/test_mode3_wallet_agent.mjs tests/test_mode3_demo_stack.mjs tests/test_mode3_e2e.mjs
git commit -m "feat(mode3): 로그인마다 발급되는 세션 성명 — RP 가 CIA 에 등록해 cert_s 를 내고, 지갑이 검증하며, 세션 재검증·요청"
```

---

### Task 6: 데모 문서

**Files:**
- Modify: `docs/MODE3_DEMO.md`

- [ ] **Step 1: 기동·등록 설명**

"처음 한 번" 4번 뒤에 추가: `5. RP(mode3_rp.js)는 첫 기동에서 CIA 에 자기 오리진으로 등록해 arid 와 cert_s 를 받아 mode3_rp_registration.json 에 둔다. CIA 키를 바꾸거나 cia_state.json 을 지웠으면 이 파일도 지운다.` "매번: 기동 순서" 아래 문장에 "RP 는 CIA 등록 파일이 없으면 CIA 에 등록하므로 CIA 가 먼저 떠 있어야 한다" 를 더한다. 상태 파일 표에 `mode3_rp_registration.json` 행 추가(RP).

- [ ] **Step 2: 각본 표 교체**

```markdown
| # | 어디서 | 조작 | 기대 |
|---|---|---|---|
| 1 | 지갑 | 등록 (`12345` / `password123`, 속성 4칸 기본값) | `등록됨` |
| 2 | RP | Mode 3 로그인 | `새 발급=true`, 로그인 성공, PPID, 세션 r_s |
| 3 | RP | 세션 재검증 | `캐시 히트=true`, 증명 0 ms, ok |
| 3′ | RP | 세션 요청 | 세션키 서명 검증 ok |
| 3″ | RP | 로그인 (다시) | 새 세션 = `새 발급=true`, **같은 PPID** |
| 4 | 관리자 | 계정 폐기 → 게시 | `published:true`, epoch +1 |
| 4′ | 사용자 페이지 → 관리자 | (4 대신) 내 계정 폐기 → 게시 | `disabled:true`, 이후 5~8 동일 |
| 5 | RP | "동기화 생략" 체크 → 세션 재검증 | 거절 `stale_root`. 세션 요청은 `revalidate_required` |
| 6 | RP | 체크 해제 → 세션 재검증 → 로그인 | 지갑 `revoked` → 새 로그인은 `account_disabled` |
| 7 | 관리자 | 복구 | `disabled:false` |
| 8 | RP | 로그인 | `새 발급=true`, 성공, **PPID 가 2 와 같다** |
```

표 아래 문단: "성명은 로그인마다 새로 발급되고(설계 2026-09-15 §5) 세션 r_s 안에서만 재사용된다. RP 는 r_s 를 로그인 때 한 번 소비하고 그 뒤 세션 식별자로 쓴다. 폐기는 재검증에서 효력을 갖는다."

- [ ] **Step 3: 하지 말 것**

한 줄 추가: `- **옛 상태 파일(cia_state.json version 2 이하, mode3_wallet_state.json version 2 이하)을 새 서버에 물리지 않는다.** CIA 는 기동을 거부하고 지갑은 세션을 비운다.`

- [ ] **Step 4: 확인·커밋 (사용자 승인 후)**

Run: `grep -n "register_rp\|mode3_rp_registration\|세션 재검증\|revalidate_required" docs/MODE3_DEMO.md` → 각 1개 이상.

```bash
git add docs/MODE3_DEMO.md
git commit -m "docs(mode3): 데모 문서 — RP 등록, 세션 재검증·요청 각본, 상태 파일 v3 주의"
```

---

## 자체 점검

- **스펙 대응:** §3 등록·cert_s → Task 1(lib)·4(CIA)·5(RP 기동); §4 r_s 전달·cert 검증 → Task 5(지갑); §5 발급 → Task 1·3·4; §6 회로 → Task 2; §7 로그인·재검증·세션 요청 → Task 3(검증기)·5(서버); §8 상태 → Task 4·5; §9 한계는 스펙에만; §11 발표 자료는 코드 밖.
- **이름 일관성:** `r_s`(10진 문자열 HTTP, bigint lib), `cert_s:{R8x,R8y,S}`, `publicSignals[5] = r_s`, `[6] = revRoot`, 응답 이유 문자열은 Global Constraints 목록과 동일, `credential.r_s` 필드, 지갑 `sessions[r_s]`, RP `sessions` Map — Task 3·4·5 에서 같은 이름.
- **테스트 순서:** demo_stack 의 S1 세션은 4번 폐기 뒤 5·6 에서 stale/revoked 로 쓰인 뒤 지갑이 지운다; 4′ 는 새 세션을 만든 뒤 진행. e2e 의 캐시 히트 케이스는 같은 r_s 세션의 재증명이므로 의미 유지.
- **미정 항목:** 없음.
