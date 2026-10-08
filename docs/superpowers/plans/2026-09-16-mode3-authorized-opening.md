# Mode 3 승인된 개봉(2-of-2 트레이스 태그) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 로그인마다 지갑이 서비스의 2-of-2 조합 키로 uid 를 암호화한 트레이스 태그를 증명 공개 입력에 넣고, 서비스 등록에 운영자 승인과 서비스 키 둘을 두며, 서비스 부분 복호 + 운영자 승인 + CIA 복호로 세션 하나의 uid 를 여는 개봉 절차를 만든다. CIA 의 로그인당 저장(`used_rs`)은 없앤다.

**Architecture:** 태그는 해시 ElGamal(`c1 = r·B8`, `c2 = uid + Poseidon(r·pk_trace)`)이고 회로 조건 ⑤ 로 검증된다(공개 입력 9 → 14). 조합 키 `pk_trace = X_svc + x_AA,s·B8` 는 승인 시 CIA 가 만들고 `cert_s` V2 메시지에 실린다 — 지갑은 인증서의 키로만 암호화한다. 서비스 등록은 pending → 운영자 승인 → `cert_s` 이고, RP 는 승인 전에는 대기 상태로 뜬다. 개봉은 `/cia/open/request`(트랜스크립트 + `D_svc` + 서명) → 운영자 승인 시 복호 → `/cia/open/:id`. 새 lib 둘(`lib/mode3_trace.js`, `lib/mode3_opening.js`), 회로 템플릿 하나(`circuits/lib/mode3_trace_tag.circom`).

**Tech Stack:** circom 2.1.9 + circomlib(`escalarmulfix`, `escalarmulany`, `poseidon`), snarkjs Groth16, circomlibjs(babyjub·EdDSA-Poseidon), Node.js ESM, express, ethers 6, hardhat 로컬 노드(:8545).

**Spec:** `docs/superpowers/specs/2026-09-16-mode3-authorized-opening-design.md` (§2 위협 모형, §3 등록 승인·두 키, §4 태그·회로·로그인, §5 로그인 로그, §6 개봉, §7 상태, §8 한계). 상위: `2026-09-15-mode3-session-statement-design.md`, `2026-09-14-mode3-attribute-credential-design.md`, `2026-09-09-mode3-cia-revocation-design.md`.

## Global Constraints

- 주석·문서·오류 문구는 한글, 기존 파일 문체(짧은 단정문, `—` 대시). 새 의존성 없음.
- **Task 사이에는 chain 그룹이 깨진 상태가 정상이다.** 각 Task 는 자기 테스트만, chain 그룹 13/13 은 Task 5 끝에서, `npm test`(unit 11 + circuit 13) 는 Task 2 끝과 Task 5 끝에서 확인한다.
- 상수(스펙에서 그대로): `B8 = [5299619240641551281634865583518297030282874472190772894086521144482721001553n, 16950150798460657717958625567821834550301663161624707787222815936182638968203n]`(circomlib `eddsaposeidon.circom` 의 BASE8 = circomlibjs `Base8`); `DOMAIN_MODE3_CERT_S_V2 = 93461614427473338116100914n`(ASCII "MODE3CERTS2" 빅엔디언, 기존 `DOMAIN_MODE3_CERT_S = 365084431357317727016019n` 은 남긴다); `cert_s` V2 메시지 `Poseidon(DOMAIN_MODE3_CERT_S_V2, arid, originToField(origin), pk_trace.x, pk_trace.y)`; 태그 `c1 = r·B8`, `K = r·pk_trace`, `c2 = (uid + Poseidon(K.x, K.y)) mod p`, `r ∈ [1, 2^250)`; 조합 키 `pk_trace = X_svc + x_AA·B8`, 조각 스칼라 `< 2^250`; 회로 공개 입력 순서 `[PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2]`(14개); 개봉 요청 메시지 `mode3-open:${arid}:${r_s}:${PPID}:${D_svc.x}:${ts}`, 결과 메시지 `mode3-open-result:${id}:${ts}`(둘 다 EIP-191 `signMessage`, `ts` 는 Unix 초 10진, 신선도 ±300초); `pk_service` 는 소문자 checksum 무관 비교를 위해 `ethers.getAddress()` 로 정규화한 문자열; CIA 상태 `version: 4`(v3 는 마이그레이션, v2 이하 기동 거부), 지갑 상태 `version: 4`(옛 버전은 registration 유지·세션 비움), RP 등록 파일 `version: 2`(키 없는 옛 파일은 버리고 재등록).
- 응답 이유(reason/error) 문자열: `register_rp` 409 `service_key_mismatch`, 403 `denied`, 400 `X_svc is not a valid subgroup point`; 개봉 `unknown_service`(404), `not_approved`(403), `stale`(401), `bad_signature`(401), `wrong_arid`(403), `untrusted_cia`(403), `wrong_trace_key`(403), `bad_proof`(403), `no_record` 는 쓰지 않는다(CIA 기록이 없으므로); 개봉 상태 `pending`·`approved`·`denied`·`failed`; RP `wrong_trace_key`, `registration_pending`(503); 지갑 `bad_rp_cert`(기존).
- 새 env: `MODE3_VKEY_PATH`(CIA, 기본 `build/mode3/pi_cred_vkey.json`), `MODE3_RP_LOGIN_LOG`(기본 `mode3_rp_logins.jsonl`), `MODE3_RP_REGISTRATION_POLL_MS`(기본 5000).
- `build/mode3` 재생성은 Task 2 에서만(`bash scripts/build_mode3_circuit.sh pot21_final.ptau`). 다른 기계의 `build/mode3` 재복사는 문서에만 적는다.
- :8545 hardhat 과 :4100/:5100/:3100 데모 서버는 사용자 프로세스 — 끄거나 재시작하지 않는다. `.env`, `*_keys.json`, `*_state.json`, `mode3_rp_registration.json`, `mode3_rp_logins.jsonl` 은 읽지 않는다(격리 헬퍼는 임시 디렉터리).
- 커밋은 사용자 승인 후에만. 각 Task 의 커밋 단계는 "제안 후 승인 시 실행".

---

### Task 1: lib — 트레이스 태그, `cert_s` V2, 개봉 메시지

**Files:**
- Create: `lib/mode3_trace.js`
- Modify: `lib/mode3_rp_cert.js` (V2 도메인, `pk_trace` 를 메시지에)
- Create: `lib/mode3_opening.js`
- Create: `tests/test_mode3_trace.js`, `tests/test_mode3_opening.js` (unit)
- Modify: `tests/test_mode3_rp_cert.js`, `scripts/run_tests.sh` (UNIT 에 2개 추가)

**Interfaces:**
- Produces (`lib/mode3_trace.js`): `B8`(bigint 배열 2); `isTracePoint(o:{x,y bigint}) → Promise<boolean>`(정규 인코딩·곡선·부분군·항등원 아님); `createShare() → Promise<{ x: bigint, X: {x,y} }>`; `combinePublicKey(A:{x,y}, B:{x,y}) → Promise<{x,y}>`; `randomTraceScalar() → bigint`(`[1, 2^250)`); `encryptTag(pk_trace:{x,y}, uid:bigint, r?:bigint) → Promise<{ c1:{x,y}, c2:bigint, r:bigint }>`; `partialDecrypt(x:bigint, c1:{x,y}) → Promise<{x,y}>`; `combineDecrypt(c2:bigint, D_a:{x,y}, D_b:{x,y}) → Promise<bigint>`. 모든 점은 `{x, y}` bigint 객체.
- Produces (`lib/mode3_rp_cert.js`): `DOMAIN_MODE3_CERT_S_V2`; `certSMessage(arid, origin, pk_trace) → bigint`; `signRpCert(prvBuf, { arid, origin, pk_trace })`; `verifyRpCert(pkCIA, { arid, origin, pk_trace, cert }) → boolean`. `pk_trace` 는 `{x,y}` (bigint 또는 10진 문자열 — 함수 안에서 `BigInt()`).
- Produces (`lib/mode3_opening.js`): `openRequestMessage({ arid, r_s, PPID, D_svc, ts }) → string`; `openResultMessage(id, ts) → string`; `signOpenRequest(wallet, fields) → Promise<string>`; `signOpenResult(wallet, id, ts) → Promise<string>`; `recoverSigner(message, sig) → string|null`(체크섬 주소 또는 null); `isFreshTs(ts, nowMs = Date.now(), skewSec = 300) → boolean`. Task 4·5 가 쓴다.

- [ ] **Step 1: 실패하는 테스트 작성 — 태그**

`tests/test_mode3_trace.js`:

```js
// 2-of-2 트레이스 태그 (설계 2026-09-16 §4.1). 외부 의존 없음.
//   node tests/test_mode3_trace.js
import assert from 'node:assert/strict';
import { buildBabyjub } from 'circomlibjs';
import { SCALAR_MAX } from '../lib/mode3_credential.js';
import { B8, isTracePoint, createShare, combinePublicKey, randomTraceScalar, encryptTag, partialDecrypt, combineDecrypt } from '../lib/mode3_trace.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const bj = await buildBabyjub();
const F = bj.F;
const uid = 12345n;

await t('B8 는 circomlibjs Base8 이고 부분군 점이다', async () => {
  assert.equal(B8[0], F.toObject(bj.Base8[0])); assert.equal(B8[1], F.toObject(bj.Base8[1]));
  assert.equal(await isTracePoint({ x: B8[0], y: B8[1] }), true);
});

await t('isTracePoint: 항등원·곡선 밖·비정규 인코딩은 false', async () => {
  assert.equal(await isTracePoint({ x: 0n, y: 1n }), false, '항등원 X_svc 면 CIA 조각만으로 복호된다');
  assert.equal(await isTracePoint({ x: 1n, y: 1n }), false);
  assert.equal(await isTracePoint({ x: B8[0] + F.p, y: B8[1] }), false);
  assert.equal(await isTracePoint({ x: '1', y: 1n }), false);
});

await t('createShare: x < 2^250, X = x·B8', async () => {
  const s = await createShare();
  assert.ok(s.x > 0n && s.x < SCALAR_MAX);
  const P = bj.mulPointEscalar(bj.Base8, s.x);
  assert.equal(s.X.x, F.toObject(P[0])); assert.equal(s.X.y, F.toObject(P[1]));
});

await t('양성: 두 조각의 부분 복호를 더하면 uid 가 나온다', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const tag = await encryptTag(pk, uid);
  assert.ok(tag.r > 0n && tag.r < SCALAR_MAX);
  const D_svc = await partialDecrypt(svc.x, tag.c1);
  const D_aa = await partialDecrypt(aa.x, tag.c1);
  assert.equal(await combineDecrypt(tag.c2, D_svc, D_aa), uid);
  assert.equal(await combineDecrypt(tag.c2, D_aa, D_svc), uid, '순서 무관');
});

await t('음성: 조각 하나로는 uid 가 나오지 않는다', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const tag = await encryptTag(pk, uid);
  const D_svc = await partialDecrypt(svc.x, tag.c1);
  const zero = { x: 0n, y: 1n };
  assert.notEqual(await combineDecrypt(tag.c2, D_svc, zero), uid);
  const D_wrong = await partialDecrypt((await createShare()).x, tag.c1);
  assert.notEqual(await combineDecrypt(tag.c2, D_svc, D_wrong), uid);
});

await t('태그는 r 마다 다르고, 같은 r 이면 결정적', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const a = await encryptTag(pk, uid), b = await encryptTag(pk, uid);
  assert.notEqual(a.c2, b.c2);
  const c = await encryptTag(pk, uid, a.r);
  assert.equal(c.c2, a.c2); assert.equal(c.c1.x, a.c1.x);
});

await t('encryptTag 는 r = 0, r ≥ 2^250, 상한 밖 uid 를 거절한다', async () => {
  const pk = await combinePublicKey((await createShare()).X, (await createShare()).X);
  await assert.rejects(() => encryptTag(pk, uid, 0n), /r/);
  await assert.rejects(() => encryptTag(pk, uid, SCALAR_MAX), /r/);
  await assert.rejects(() => encryptTag(pk, SCALAR_MAX, 5n), /uid/);
  assert.ok(randomTraceScalar() > 0n);
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_trace.js`
Expected: `ERR_MODULE_NOT_FOUND` (`lib/mode3_trace.js` 없음)

- [ ] **Step 3: `lib/mode3_trace.js` 작성**

```js
// 2-of-2 트레이스 태그 — 설계 2026-09-16 §4.1.
//   pk_trace = (x_svc + x_AA)·B8          서비스 조각 + CIA 조각. 승인 때 CIA 가 만들어 cert_s 에 싣는다
//   c1 = r·B8,  K = r·pk_trace,  c2 = uid + Poseidon(K.x, K.y)      지갑이 로그인마다 새 r 로
//   복호: K = x_svc·c1 + x_AA·c1 — 두 부분 복호를 더해야 K 가 나온다. 어느 조각 하나로는 안 된다
// 해시 ElGamal 인 이유: uid 를 점으로 인코딩하면 복호 뒤 이산로그가 필요하고 회로에 점 덧셈이 더 든다.
// 회로 판은 circuits/lib/mode3_trace_tag.circom — 같은 B8, 같은 Poseidon(2), 같은 250비트 상한.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX } from './mode3_credential.js';

/** circomlib eddsaposeidon.circom 의 BASE8 = circomlibjs Base8. pk_CIA 와 같은 부분군의 생성원. */
export const B8 = Object.freeze([
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
]);

let bjP = null, psP = null;
const getBj = () => (bjP ??= buildBabyjub());
const getPs = () => (psP ??= buildPoseidon());
const toObj = (bj, P) => ({ x: bj.F.toObject(P[0]), y: bj.F.toObject(P[1]) });
const fromObj = (bj, o) => [bj.F.e(o.x), bj.F.e(o.y)];

function checkScalar(v, name) {
  if (typeof v !== 'bigint' || v < 0n || v >= SCALAR_MAX) throw new Error(`${name} 는 [0, 2^250) bigint`);
}

/** 정규 인코딩·곡선 위·소수 위수 부분군·항등원 아님. 항등원 X_svc 를 받으면 pk_trace 가 CIA 조각만으로 열린다. */
export async function isTracePoint(o) {
  const bj = await getBj();
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const p = bj.F.p;
  if (o.x < 0n || o.x >= p || o.y < 0n || o.y >= p) return false;
  if (o.x === 0n && o.y === 1n) return false;
  const P = fromObj(bj, o);
  return bj.inCurve(P) && bj.inSubgroup(P);
}

/** [1, 2^250) 균일. 0 은 다시 뽑는다 — c1 이 항등원이면 태그가 uid 를 그대로 드러낸다. */
export function randomTraceScalar() {
  for (;;) {
    let v = 0n;
    for (const b of randomBytes(32)) v = (v << 8n) | BigInt(b);
    v &= SCALAR_MAX - 1n;
    if (v !== 0n) return v;
  }
}

/** 조각 하나: 비밀 x 와 공개 X = x·B8. 서비스(x_svc)와 CIA(x_AA,s)가 각자 만든다. */
export async function createShare() {
  const bj = await getBj();
  const x = randomTraceScalar();
  return { x, X: toObj(bj, bj.mulPointEscalar(bj.Base8, x)) };
}

export async function combinePublicKey(A, B) {
  const bj = await getBj();
  return toObj(bj, bj.addPoint(fromObj(bj, A), fromObj(bj, B)));
}

async function maskOf(K) {
  const ps = await getPs();
  return ps.F.toObject(ps([K.x, K.y]));
}

export async function encryptTag(pk_trace, uid, r = randomTraceScalar()) {
  checkScalar(uid, 'uid');
  if (typeof r !== 'bigint' || r <= 0n || r >= SCALAR_MAX) throw new Error('r 는 [1, 2^250) bigint');
  const bj = await getBj();
  const c1 = toObj(bj, bj.mulPointEscalar(bj.Base8, r));
  const K = toObj(bj, bj.mulPointEscalar(fromObj(bj, pk_trace), r));
  const c2 = (uid + await maskOf(K)) % bj.F.p;
  return { c1, c2, r };
}

/** 조각 x 로 c1 을 곱한다. 서비스는 D_svc = x_svc·c1 을 개봉 요청에 싣고, CIA 는 승인 때 x_AA·c1 을 더한다. */
export async function partialDecrypt(x, c1) {
  checkScalar(x, 'x');
  const bj = await getBj();
  return toObj(bj, bj.mulPointEscalar(fromObj(bj, c1), x));
}

export async function combineDecrypt(c2, D_a, D_b) {
  const bj = await getBj();
  const K = toObj(bj, bj.addPoint(fromObj(bj, D_a), fromObj(bj, D_b)));
  const p = bj.F.p;
  return (((c2 - await maskOf(K)) % p) + p) % p;
}
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_trace.js`
Expected: 7건 `ok`

- [ ] **Step 5: `cert_s` V2 — 테스트 수정**

`tests/test_mode3_rp_cert.js` 를 다음으로 바꾼다(기존 케이스 + `pk_trace` 3건).

```js
// 서비스 인증서 cert_s V2 (설계 2026-09-16 §3) — (arid, origin, pk_trace) 를 덮는다. 외부 의존 없음.
//   node tests/test_mode3_rp_cert.js
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { randomScalar, SCALAR_MAX } from '../lib/mode3_credential.js';
import { DOMAIN_MODE3_CERT_S, DOMAIN_MODE3_CERT_S_V2, originToField, certSMessage, signRpCert, verifyRpCert } from '../lib/mode3_rp_cert.js';
import { createShare, combinePublicKey } from '../lib/mode3_trace.js';

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
const pk_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);
const other_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);

await t('도메인 태그: V1 "MODE3CERTS", V2 "MODE3CERTS2" 빅엔디언', () => {
  assert.equal(DOMAIN_MODE3_CERT_S, BigInt('0x' + Buffer.from('MODE3CERTS').toString('hex')));
  assert.equal(DOMAIN_MODE3_CERT_S_V2, BigInt('0x' + Buffer.from('MODE3CERTS2').toString('hex')));
});

await t('originToField 는 250비트 미만이고 오리진마다 다르다', () => {
  const a = originToField(origin), b = originToField('http://127.0.0.1:3101');
  assert.ok(a < SCALAR_MAX && b < SCALAR_MAX);
  assert.notEqual(a, b);
  assert.equal(a, originToField(origin), '결정론적');
});

await t('certSMessage 는 pk_trace 를 덮는다 (다른 키면 다른 메시지), 문자열 좌표도 받는다', async () => {
  const m = await certSMessage(arid, origin, pk_trace);
  assert.notEqual(m, await certSMessage(arid, origin, other_trace));
  assert.equal(m, await certSMessage(arid, origin, { x: pk_trace.x.toString(), y: pk_trace.y.toString() }));
});

await t('양성: 서명한 (arid, origin, pk_trace) 가 검증된다', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert }), true);
});

await t('음성: pk_trace 가 다르면 거절 (서비스가 자기만 아는 키를 지갑에 주는 공격)', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace: other_trace, cert }), false);
});

await t('음성: origin 이 다르면 거절 (피싱 페이지가 남의 arid 를 끼워 넣는 경우)', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin: 'http://evil.example', pk_trace, cert }), false);
});

await t('음성: arid 가 다르면 거절', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid: arid + 1n, origin, pk_trace, cert }), false);
});

await t('음성: 다른 키의 서명은 거절', async () => {
  const cert = await signRpCert(Buffer.alloc(32, 7), { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert }), false);
});

await t('음성: 형식이 깨진 cert·pk_trace 는 throw 없이 false', async () => {
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert: { R8x: 'x', R8y: '1', S: '1' } }), false);
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert: null }), false);
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace: null, cert }), false);
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace: { x: 'abc', y: '1' }, cert }), false);
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 6: 실패 확인**

Run: `node tests/test_mode3_rp_cert.js`
Expected: `DOMAIN_MODE3_CERT_S_V2` import 가 undefined 라 첫 케이스 FAIL, 이후 서명 케이스도 FAIL(메시지가 `pk_trace` 를 안 덮음)

- [ ] **Step 7: `lib/mode3_rp_cert.js` 수정**

머리 주석과 `certSMessage`·`signRpCert`·`verifyRpCert` 를 바꾼다. `originToField` 는 그대로.

```js
// 서비스 인증서 cert_s — 설계 2026-09-15 §3, 2026-09-16 §3(V2). RP 가 CIA 에 등록하고 운영자가 승인하면 CIA 가
// arid 를 배정하고 (arid, origin, pk_trace) 에 EdDSA-Poseidon 으로 서명한다. 지갑은 로그인 전에 이 서명을 pk_CIA 로
// 검증하고, 요청을 보낸 오리진과 cert 의 오리진이 같은지 본다 — 피싱 페이지가 진짜 서비스의 arid 를 끼워 넣는 것을 막는다.
// pk_trace 가 메시지에 있는 이유: 서비스가 자기만 아는 키를 지갑에 주면 서비스 혼자 태그를 복호한다(2026-09-16 §2).
// 지갑은 인증서에 실린 pk_trace 로만 암호화한다. cert_s 는 CIA 에 되돌려 보내지 않는다(13장 unobservability).
import { createHash } from 'node:crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX } from './mode3_credential.js';

export const DOMAIN_MODE3_CERT_S = 365084431357317727016019n;       // ASCII "MODE3CERTS" — V1(pk_trace 없음). 더 이상 서명하지 않는다
export const DOMAIN_MODE3_CERT_S_V2 = 93461614427473338116100914n;   // ASCII "MODE3CERTS2" 빅엔디언

let eddsaP = null, psP = null;
const getEddsa = () => (eddsaP ??= buildEddsa());
const getPs = () => (psP ??= buildPoseidon());

/** origin 문자열 → 250비트 필드 원소. sha256 뒤 상위 비트를 잘라 스칼라 상한 규약에 맞춘다. */
export function originToField(origin) {
  if (typeof origin !== 'string' || origin.length === 0) throw new Error('originToField: origin 문자열이 필요하다');
  const h = createHash('sha256').update(origin, 'utf8').digest('hex');
  return BigInt('0x' + h) & (SCALAR_MAX - 1n);
}

function tracePoint(pk_trace) {
  const B = (v) => {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'string' && /^[0-9]+$/.test(v)) return BigInt(v);
    throw new Error('certSMessage: pk_trace 좌표는 bigint 또는 10진 문자열');
  };
  if (!pk_trace || typeof pk_trace !== 'object') throw new Error('certSMessage: pk_trace{x,y} 가 필요하다');
  return { x: B(pk_trace.x), y: B(pk_trace.y) };
}

export async function certSMessage(arid, origin, pk_trace) {
  if (typeof arid !== 'bigint' || arid < 0n || arid >= SCALAR_MAX) throw new Error('certSMessage: arid 는 [0, 2^250) bigint');
  const pt = tracePoint(pk_trace);
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_CERT_S_V2, arid, originToField(origin), pt.x, pt.y]));
}

export async function signRpCert(prvBuf, { arid, origin, pk_trace }) {
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const s = eddsa.signPoseidon(prvBuf, F.e(await certSMessage(arid, origin, pk_trace)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** 형식이 깨져도 throw 하지 않고 false — 지갑의 요청 경로에서 그대로 403 으로 이어진다. */
export async function verifyRpCert(pkCIA, { arid, origin, pk_trace, cert }) {
  try {
    if (!cert || typeof cert !== 'object') return false;
    const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad'); return BigInt(v); };
    const eddsa = await getEddsa();
    const F = eddsa.F;
    const m = F.e(await certSMessage(arid, origin, pk_trace));
    const sig = { R8: [F.e(B(cert.R8x)), F.e(B(cert.R8y))], S: B(cert.S) };
    const pub = [F.e(BigInt(pkCIA.x)), F.e(BigInt(pkCIA.y))];
    return eddsa.verifyPoseidon(m, sig, pub);
  } catch { return false; }
}
```

- [ ] **Step 8: 통과 확인**

Run: `node tests/test_mode3_rp_cert.js`
Expected: 9건 `ok`

- [ ] **Step 9: 개봉 메시지 — 테스트**

`tests/test_mode3_opening.js`:

```js
// 개봉 요청·결과 메시지와 서명 (설계 2026-09-16 §6). 외부 의존 없음.
//   node tests/test_mode3_opening.js
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { openRequestMessage, openResultMessage, signOpenRequest, signOpenResult, recoverSigner, isFreshTs } from '../lib/mode3_opening.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const svc = ethers.Wallet.createRandom();
const fields = { arid: '22222', r_s: '55555', PPID: '99999', D_svc: { x: '123', y: '456' }, ts: '1789000000' };

await t('메시지 형식은 스펙 §6 그대로', () => {
  assert.equal(openRequestMessage(fields), 'mode3-open:22222:55555:99999:123:1789000000');
  assert.equal(openResultMessage('abcd', '1789000001'), 'mode3-open-result:abcd:1789000001');
});

await t('서명한 요청은 서비스 주소로 복원되고, 필드 하나가 바뀌면 다른 주소가 나온다', async () => {
  const sig = await signOpenRequest(svc, fields);
  assert.equal(recoverSigner(openRequestMessage(fields), sig), svc.address);
  assert.notEqual(recoverSigner(openRequestMessage({ ...fields, ts: '1789000001' }), sig), svc.address);
  const rsig = await signOpenResult(svc, 'abcd', '1789000001');
  assert.equal(recoverSigner(openResultMessage('abcd', '1789000001'), rsig), svc.address);
});

await t('깨진 서명은 throw 없이 null', () => {
  assert.equal(recoverSigner('x', '0x00'), null);
  assert.equal(recoverSigner('x', 'not-a-sig'), null);
});

await t('isFreshTs: ±300초 안이면 true, 밖·비수치는 false', () => {
  const now = 1789000000_000;
  assert.equal(isFreshTs('1789000000', now), true);
  assert.equal(isFreshTs('1788999701', now), true);
  assert.equal(isFreshTs('1788999699', now), false);
  assert.equal(isFreshTs('1789000301', now), false);
  assert.equal(isFreshTs('abc', now), false);
  assert.equal(isFreshTs(1789000000, now), false, '10진 문자열만');
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 10: 실패 확인**

Run: `node tests/test_mode3_opening.js`
Expected: `ERR_MODULE_NOT_FOUND`

- [ ] **Step 11: `lib/mode3_opening.js` 작성**

```js
// 개봉 요청·결과의 메시지 규약과 서명 — 설계 2026-09-16 §6. 서비스는 secp256k1 서명키(pk_service = 이더리움 주소)로
// EIP-191 personal sign 한다(세션 요청 서명과 같은 스킴). CIA 는 ethers.verifyMessage 로 주소를 복원해 등록부와 대조한다.
// ts 가 메시지에 있어 가로챈 요청을 그대로 재전송해도 5분 뒤엔 죽는다.
import { ethers } from 'ethers';

const dec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);

export function openRequestMessage({ arid, r_s, PPID, D_svc, ts }) {
  return `mode3-open:${arid}:${r_s}:${PPID}:${D_svc.x}:${ts}`;
}
export function openResultMessage(id, ts) {
  return `mode3-open-result:${id}:${ts}`;
}
export function signOpenRequest(wallet, fields) { return wallet.signMessage(openRequestMessage(fields)); }
export function signOpenResult(wallet, id, ts) { return wallet.signMessage(openResultMessage(id, ts)); }

/** 체크섬 주소 또는 null. */
export function recoverSigner(message, sig) {
  try { return ethers.verifyMessage(message, sig); } catch { return null; }
}

/** ts(Unix 초, 10진 문자열)가 now ±skewSec 안인가. */
export function isFreshTs(ts, nowMs = Date.now(), skewSec = 300) {
  if (!dec(ts)) return false;
  const d = Number(ts) - Math.floor(nowMs / 1000);
  return Math.abs(d) <= skewSec;
}
```

- [ ] **Step 12: 통과 확인, UNIT 그룹 등록**

`scripts/run_tests.sh` 의 `UNIT=(` 배열 끝(`tests/test_mode3_rp_cert.js` 다음)에 두 줄 추가:

```
  tests/test_mode3_trace.js
  tests/test_mode3_opening.js
```

Run: `node tests/test_mode3_opening.js && bash scripts/run_tests.sh unit`
Expected: 4건 `ok`; unit `통과 11 / 실패 0`

- [ ] **Step 13: 커밋 (제안 후 승인 시 실행)**

```bash
git add lib/mode3_trace.js lib/mode3_opening.js lib/mode3_rp_cert.js tests/test_mode3_trace.js tests/test_mode3_opening.js tests/test_mode3_rp_cert.js scripts/run_tests.sh
git commit -m "feat(mode3): 트레이스 태그 lib, cert_s V2(pk_trace), 개봉 메시지 규약"
```

---

### Task 2: 회로 — 조건 ⑤ 태그, 공개 입력 14개, 산출물 재생성

**Files:**
- Create: `circuits/lib/mode3_trace_tag.circom`
- Modify: `circuits/pi_cred.circom`
- Modify: `tests/helpers/mode3_fixture.mjs`, `tests/test_pi_cred_witness.mjs`
- Regenerate: `build/mode3/*` (`scripts/build_mode3_circuit.sh pot21_final.ptau`)

**Interfaces:**
- Consumes: Task 1 의 `createShare`, `combinePublicKey`, `encryptTag`, `partialDecrypt`, `combineDecrypt`.
- Produces: 회로 비공개 입력 `r` 추가; 공개 입력 14개(순서는 Global Constraints); `buildValidInput()` 이 `{ input, C, pk_trace, shares: { svc, aa }, tag }` 를 돌려준다(`shares.*` 는 `{x, X}`); `build/mode3/pi_cred_vkey.json` 의 `nPublic` 이 14.

- [ ] **Step 1: 픽스처에 태그 추가**

`tests/helpers/mode3_fixture.mjs` — import 에 추가:

```js
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';
import { buildBabyjub } from 'circomlibjs';
```

`buildValidInput()` 안, `const r_s = 55555555555555555555n;` 다음에:

```js
  // 트레이스 태그(설계 2026-09-16 §4.1). 조각은 테스트 고정값 — 실제 키가 아니다. r 도 고정(음성 케이스가 재현되게).
  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, 88888888888888888888n);
```

`input` 객체에 `pk_CIA_y` 다음으로:

```js
    r: tag.r.toString(),
    pk_trace_x: pk_trace.x.toString(),
    pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(),
    tag_c1_y: tag.c1.y.toString(),
    tag_c2: tag.c2.toString(),
```

`return { input, C };` → `return { input, C, pk_trace, shares, tag };`

- [ ] **Step 2: witness 테스트에 태그 케이스 추가**

`tests/test_pi_cred_witness.mjs` — import 에 `import { partialDecrypt, combineDecrypt } from '../lib/mode3_trace.js';` 를 더하고, `const { input: valid, C: validC } = await buildValidInput();` 를 `const { input: valid, C: validC, shares, tag } = await buildValidInput();` 로 바꾼다. `'음성: pk_i를 바꾸면 거부된다'` 케이스 다음에 추가:

```js
await t('⑤ 양성: 회로가 받아들인 태그는 두 조각으로 uid 로 열린다 (JS encryptTag 와 회로 계산이 일치)', async () => {
  await witness(valid);   // 공개 입력 tag_* 가 회로 계산과 같아야 통과한다
  const D_svc = await partialDecrypt(shares.svc.x, tag.c1);
  const D_aa = await partialDecrypt(shares.aa.x, tag.c1);
  assert.equal(await combineDecrypt(tag.c2, D_svc, D_aa), BigInt(valid.uid));
});

await t('⑤ 음성: c2 를 바꾸면 거부된다 (평문이 커밋 안의 uid 와 다르다)', async () => {
  await assert.rejects(() => witness({ ...valid, tag_c2: (BigInt(valid.tag_c2) + 1n).toString() }), /Assert Failed/);
});

await t('⑤ 음성: pk_trace 를 바꾸면 거부된다 (다른 키로 만든 태그는 이 키의 태그가 아니다)', async () => {
  // c1 은 r 만의 함수라 그대로이고 K 가 달라져 c2 가 안 맞는다.
  await assert.rejects(() => witness({ ...valid, pk_trace_x: shares.svc.X.x.toString(), pk_trace_y: shares.svc.X.y.toString() }), /Assert Failed/);
});

await t('⑤ 음성: c1 을 바꾸면 거부된다 (c1 = r·B8 를 회로가 계산한다)', async () => {
  await assert.rejects(() => witness({ ...valid, tag_c1_x: shares.svc.X.x.toString(), tag_c1_y: shares.svc.X.y.toString() }), /Assert Failed/);
});

await t('⑤ 음성: r 을 바꾸면 거부된다 (c1·c2 둘 다 어긋난다)', async () => {
  await assert.rejects(() => witness({ ...valid, r: (BigInt(valid.r) + 1n).toString() }), /Assert Failed/);
});
```

- [ ] **Step 3: 실패 확인**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: 컴파일은 되지만(회로가 아직 옛 것) 양성 케이스가 "Too many values for input signal" 류로 FAIL

- [ ] **Step 4: 태그 템플릿 작성**

`circuits/lib/mode3_trace_tag.circom`:

```circom
pragma circom 2.0.0;

include "poseidon.circom";
include "bitify.circom";
include "escalarmulfix.circom";
include "escalarmulany.circom";

// 2-of-2 트레이스 태그 — 설계 2026-09-16 §4.1/§4.2 (조건 ⑤).
//   c1 = r·B8,  K = r·pk_trace,  c2 = uid + Poseidon(K.x, K.y)
// pk_trace 는 공개 입력이다 — 서비스가 자기 등록 파일의 값과 대조한다(대조하지 않으면 사용자가 아무 키로나
// 암호화한 태그를 낼 수 있다). 평문 uid 는 커밋을 여는 것과 같은 신호라 "이 태그를 열면 이 성명의 uid 가 나온다"가
// 회로로 보증된다(검증 가능 암호화). JS 판은 lib/mode3_trace.js — 같은 B8, 같은 Poseidon(2), 같은 250비트 상한.
// pk_trace 의 곡선·부분군 검사는 넣지 않는다: 그 값은 CIA 가 승인 때 검사한 X_svc 에 자기 조각을 더한 것이고,
// 서비스가 자기 값과 같은지 대조한다.
template TraceTag() {
    signal input r;
    signal input uid;
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal output c1x;
    signal output c1y;
    signal output c2;

    var N = 250;
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component bits = Num2Bits(N);
    bits.in <== r;

    component mFix = EscalarMulFix(N, BASE8);
    component mAny = EscalarMulAny(N);
    for (var i = 0; i < N; i++) {
        mFix.e[i] <== bits.out[i];
        mAny.e[i] <== bits.out[i];
    }
    mAny.p[0] <== pk_trace_x;
    mAny.p[1] <== pk_trace_y;

    c1x <== mFix.out[0];
    c1y <== mFix.out[1];

    component h = Poseidon(2);
    h.inputs[0] <== mAny.out[0];
    h.inputs[1] <== mAny.out[1];
    c2 <== uid + h.out;
}
```

- [ ] **Step 5: `pi_cred.circom` 수정**

include 에 `include "lib/mode3_trace_tag.circom";` 추가. 머리 주석의 네 항목 아래에 한 줄:

```
//   ⑤ tag = Enc(pk_trace, uid) 가 잘 만들어졌다  — 없으면 개봉이 엉뚱한 값을 연다 (2026-09-16 §4)
```

비공개 입력 `attrs[4]` 다음에 `signal input r;   // 태그 무작위값(로그인마다 새로)`. 공개 입력 `pk_CIA_y` 다음에:

```circom
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal input tag_c1_x;
    signal input tag_c1_y;
    signal input tag_c2;
```

④ 블록 뒤(`nm.root <== revRoot;` 다음)에:

```circom
    // ---- ⑤ 트레이스 태그 ----
    // uid 는 ② 의 커밋 개봉과 ③ 의 PPID 유도에 쓴 바로 그 신호다 — 태그를 열면 이 성명의 uid 가 나온다.
    component tag = TraceTag();
    tag.r <== r;
    tag.uid <== uid;
    tag.pk_trace_x <== pk_trace_x;
    tag.pk_trace_y <== pk_trace_y;
    tag_c1_x === tag.c1x;
    tag_c1_y === tag.c1y;
    tag_c2 === tag.c2;
```

`component main` 을:

```circom
// 공개 입력의 순서는 lib/mode3_wallet.js·lib/mode3_rp.js·cia.js(개봉) 가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 와 pk_trace_x/y 는 공개 입력이다. 검증자는 반드시 전자를 고정된 CIA 키와, 후자를 자기 등록 파일의
// 조합 키와 비교해야 한다 (설계 §5, 2026-09-16 §4.2).
component main {public [
    PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2
]} = PiCred(32);
```

- [ ] **Step 6: witness 테스트 통과 확인, 제약 수 기록**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: 기존 케이스 + ⑤ 5건 전부 `ok`. 마지막 줄 `## pi_cred 비선형 제약: N` 의 N 을 적어 둔다(스펙 §4.2 예상 26~29k). Task 6 에서 기반 설계 §11.1 표에 넣는다.

- [ ] **Step 7: 산출물 재생성**

Run: `bash scripts/build_mode3_circuit.sh pot21_final.ptau` (수 분)
Expected: `완료: build/mode3/pi_cred_final.zkey, …`. 확인: `node -e "console.log(JSON.parse(require('fs').readFileSync('build/mode3/pi_cred_vkey.json','utf8')).nPublic)"` → `14`

- [ ] **Step 8: 증명 시간 실측(픽스처 입력으로 10회)**

임시 스크립트를 저장소 밖(`/tmp`)에 두지 말고 아래를 `node --input-type=module` 로 바로 실행한다(파일 생성 없음):

```bash
node --input-type=module -e "
import * as snarkjs from 'snarkjs';
import fs from 'node:fs';
import { buildValidInput } from './tests/helpers/mode3_fixture.mjs';
const { input } = await buildValidInput();
const vkey = JSON.parse(fs.readFileSync('build/mode3/pi_cred_vkey.json','utf8'));
const P=[], V=[];
for (let i=0;i<10;i++){ const a=performance.now(); const {proof,publicSignals}=await snarkjs.groth16.fullProve(input,'build/mode3/pi_cred_js/pi_cred.wasm','build/mode3/pi_cred_final.zkey'); const b=performance.now(); if(!(await snarkjs.groth16.verify(vkey,publicSignals,proof))) throw new Error('verify'); P.push(b-a); V.push(performance.now()-b); }
const med=(x)=>[...x].sort((p,q)=>p-q)[5];
console.log('prove ms median', med(P).toFixed(1), 'verify ms median', med(V).toFixed(1), 'zkey bytes', fs.statSync('build/mode3/pi_cred_final.zkey').size);
process.exit(0);"
```

Expected: `prove ms median …` 출력. 값을 Step 6 의 제약 수와 함께 적어 둔다(Task 6).

- [ ] **Step 9: circuit 그룹 확인**

Run: `bash scripts/run_tests.sh circuit`
Expected: `통과 13 / 실패 0`

- [ ] **Step 10: 커밋 (제안 후 승인 시 실행)**

```bash
git add circuits/lib/mode3_trace_tag.circom circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs
git commit -m "feat(mode3): 회로 조건 ⑤ 트레이스 태그 — 공개 입력 14개, 산출물 재생성"
```

---

### Task 3: 지갑·RP 라이브러리 — `pk_trace` 로 태그, 14개 공개 입력, `wrong_trace_key`

**Files:**
- Modify: `lib/mode3_wallet.js` (`buildCredentialProof` 에 `pk_trace`)
- Modify: `lib/mode3_rp.js` (`createRpVerifier` 에 `pkTrace`, 14개, `wrong_trace_key`)
- Modify: `tests/test_mode3_wallet.mjs`, `tests/test_mode3_rp.mjs`, `tests/test_mode3_e2e.mjs` (chain)

**Interfaces:**
- Consumes: Task 1 `encryptTag`, `createShare`, `combinePublicKey`, `partialDecrypt`, `combineDecrypt`; Task 2 산출물.
- Produces: `buildCredentialProof({ …, pk_trace:{x,y} })` → `{ proof, publicSignals(14), revRoot, tag:{ c1:{x,y}, c2 } }`(`pk_trace` 없으면 throw); `createRpVerifier({ …, pkTrace:{x,y} })`(없으면 throw); `verifyLogin` 결과에 `tag: { c1x, c1y, c2 }`(bigint) 추가. Task 4·5 가 쓴다.

- [ ] **Step 1: 지갑 lib 테스트 수정**

`tests/test_mode3_wallet.mjs` — import 에 `import { createShare, combinePublicKey, partialDecrypt, combineDecrypt } from '../lib/mode3_trace.js';`. `let reg, session, req, cred, tree0;` 앞에:

```js
const svcShare = await createShare(), aaShare = await createShare();
const pk_trace = await combinePublicKey(svcShare.X, aaShare.X);
```

`'발급 요청 → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증된다'` 케이스에서 `buildCredentialProof({ … tree: tree0 })` 호출에 `pk_trace` 를 넣고, `assert.equal(publicSignals.length, 9);` 를 `14` 로 바꾸고, `assert.ok(await snarkjs.groth16.verify(...))` 앞에:

```js
  assert.equal(BigInt(publicSignals[9]), pk_trace.x); assert.equal(BigInt(publicSignals[10]), pk_trace.y);
  assert.equal(BigInt(publicSignals[11]), tag.c1.x); assert.equal(BigInt(publicSignals[13]), tag.c2);
  // 태그는 두 조각으로 이 성명의 uid 로 열린다 (검증 가능 암호화)
  assert.equal(await combineDecrypt(tag.c2, await partialDecrypt(svcShare.x, tag.c1), await partialDecrypt(aaShare.x, tag.c1)), uid);
```

(구조 분해를 `const { proof, publicSignals, revRoot, tag } = await buildCredentialProof(...)` 로.) `'내 credential 이 폐기되면 …'` 케이스의 `buildCredentialProof` 호출에도 `pk_trace` 추가. 새 케이스 하나:

```js
await t('buildCredentialProof 는 pk_trace 없이는 throw — 태그 없는 성명은 이제 없다', async () => {
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n], credential: cred, pk_CIA, tree: tree0 }),
    /pk_trace/,
  );
});
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet.mjs`
Expected: 증명 케이스 FAIL(`r`·`pk_trace_*` 입력 누락으로 witness 계산 실패)

- [ ] **Step 3: `lib/mode3_wallet.js` 수정**

import 에 `import { encryptTag } from './mode3_trace.js';`. `buildCredentialProof` 를:

```js
/**
 * §5 — 공개 입력 순서 [PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y,
 * tag_c1_x, tag_c1_y, tag_c2] 는 회로가 정한다. pk_trace 는 인증서 cert_s 에 실린 서비스의 조합 키다(2026-09-16 §3) —
 * 호출자는 검증된 인증서의 값만 넘겨야 한다. 태그의 r 은 여기서 새로 뽑는다(재검증으로 새 π 를 만들면 태그도 바뀐다).
 */
export async function buildCredentialProof({ uid, arid, s_u, blind, pk_i, attrs, credential, pk_CIA, pk_trace, tree, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH }) {
  if (typeof pk_trace?.x !== 'bigint' || typeof pk_trace?.y !== 'bigint') throw new Error('buildCredentialProof: pk_trace{x,y}(bigint) 가 필요하다 — cert_s 에 실린 서비스 조합 키');
  const PPID = await ppid({ uid, arid, s_u, chainid: BigInt(credential.chainid) });
  const C = BigInt(credential.C);
  const a4 = normalizeAttrs(attrs);
  const w = await tree.getNonMembershipWitness(await credLeaf(C));   // 폐기됐으면 여기서 throw ("is a member")
  const tag = await encryptTag(pk_trace, uid);
  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind: blind.toString(),
    attrs: a4.map(String),
    S: credential.sigma.S, R8x: credential.sigma.R8x, R8y: credential.sigma.R8y,
    lowValue: String(w.lowValue), lowNextIndex: String(w.lowNextIndex), lowNextValue: String(w.lowNextValue),
    pathElements: w.pathElements.map(String), pathIndices: w.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    exptime: BigInt(credential.exptime).toString(), chainid: BigInt(credential.chainid).toString(),
    r_s: BigInt(credential.r_s).toString(), revRoot: tree.getRoot().toString(),
    pk_CIA_x: pk_CIA.x.toString(), pk_CIA_y: pk_CIA.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, revRoot: tree.getRoot(), tag: { c1: tag.c1, c2: tag.c2 } };
}
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_wallet.mjs`
Expected: 전부 `ok`

- [ ] **Step 5: RP 검증기 테스트 수정**

`tests/test_mode3_rp.mjs` — import 에 `import { createShare, combinePublicKey } from '../lib/mode3_trace.js';`. `const uid = …` 줄 다음에:

```js
const svcShare = await createShare(), aaShare = await createShare();
const pk_trace = await combinePublicKey(svcShare.X, aaShare.X);
const other_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);
```

`makeLogin` 의 옵션에 `useTrace = pk_trace` 를 더하고 `buildCredentialProof({ …, pk_CIA: key.pub, pk_trace: useTrace, tree })`. `createRpVerifier` 네 군데(`rp`, 두 `rp2`) 모두 `pkTrace: pk_trace` 추가. `'같은 사용자·같은 RP 라도 chainid 가 다르면 …'` 케이스의 `buildCredentialProof` 에도 `pk_trace`. 새 케이스 2건(`'음성 arid: …'` 다음):

```js
await t('음성 d″: 다른 조합 키로 만든 태그는 wrong_trace_key (서비스가 자기 키와 대조한다)', async () => {
  const L = await makeLogin({ useTrace: other_trace });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'wrong_trace_key' });
});

await t('양성: verifyLogin 이 태그를 돌려준다 (서비스가 로그에 남길 재료)', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true);
  assert.equal(r.tag.c1x, BigInt(L.publicSignals[11])); assert.equal(r.tag.c2, BigInt(L.publicSignals[13]));
});

await t('createRpVerifier 는 pkTrace 없이는 throw', () => {
  assert.throws(() => createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n }), /pkTrace/);
});
```

- [ ] **Step 6: 실패 확인**

Run: `node tests/test_mode3_rp.mjs`
Expected: 양성이 `malformed`(길이 9 검사)로 FAIL, `pkTrace` 케이스 FAIL

- [ ] **Step 7: `lib/mode3_rp.js` 수정**

머리 주석 `d.` 줄 뒤에 `//      pk_trace 일치    ← 자기 조합 키로 만든 태그인가 (2026-09-16 §4.3 d')`. `createRpVerifier` 시그니처에 `pkTrace` 를 더하고 첫 줄 검사 다음에:

```js
  if (typeof pkTrace?.x !== 'bigint' || typeof pkTrace?.y !== 'bigint') throw new Error('createRpVerifier: pkTrace{x,y}(bigint) 가 필요하다 — 등록 파일의 조합 키');
```

`verifyLogin` 의 길이 검사 `!== 9` → `!== 14`, 구조 분해:

```js
    const [PPID, aridIn, pk_i, exptime, chainIn, r_s, revRoot, ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = ps;
```

`wrong_arid` 줄 다음에:

```js
    if (traceX !== pkTrace.x || traceY !== pkTrace.y) return { ok: false, reason: 'wrong_trace_key' };   // d'
```

반환을 `return { ok: true, PPID, pk_i, r_s, exptime, root: revRoot, tag: { c1x, c1y, c2 } };`.

- [ ] **Step 8: 통과 확인**

Run: `node tests/test_mode3_rp.mjs`
Expected: 전부 `ok`

- [ ] **Step 9: e2e 테스트 수정**

`tests/test_mode3_e2e.mjs` — import 에 `import { createShare, combinePublicKey } from '../lib/mode3_trace.js';`. `const rp = createRpVerifier(...)` 앞에 `const pk_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);` 를 두고 `createRpVerifier({ …, pkTrace: pk_trace })`, 두 `buildCredentialProof` 호출(`loginRound`, 폐기 후 rejects 케이스)에 `pk_trace` 추가. `cia.registerRp('http://127.0.0.1:1')` 는 그대로 둔다(Task 4 에서 헬퍼가 승인까지 대행하도록 바뀐다 — 이 Task 에서는 아직 옛 CIA 라 그대로 동작한다).

Run: `node tests/test_mode3_e2e.mjs`
Expected: 전부 `ok`

- [ ] **Step 10: 커밋 (제안 후 승인 시 실행)**

```bash
git add lib/mode3_wallet.js lib/mode3_rp.js tests/test_mode3_wallet.mjs tests/test_mode3_rp.mjs tests/test_mode3_e2e.mjs
git commit -m "feat(mode3): 지갑이 pk_trace 로 태그를 만들고 RP 가 자기 조합 키와 대조한다 — 공개 입력 14개"
```

---

### Task 4: CIA — 등록 승인·두 키·조합 키, `used_rs` 제거·상태 v4, 개봉 엔드포인트

**Files:**
- Modify: `cia.js`
- Modify: `tests/helpers/isolated_cia.mjs` (`registerRp` 가 키 생성·승인 대행, `adminGet` 추가)
- Modify: `tests/test_cia_register_issue.mjs`, `tests/test_cia_startup.mjs`
- Create: `tests/test_cia_opening.mjs` (chain), `scripts/run_tests.sh` CHAIN 에 추가

**Interfaces:**
- Consumes: Task 1 (`isTracePoint`, `createShare`, `combinePublicKey`, `partialDecrypt`, `combineDecrypt`, `signRpCert` V2, `openRequestMessage`, `openResultMessage`, `recoverSigner`, `isFreshTs`); Task 2 vkey(14).
- Produces (HTTP): `POST /cia/register_rp {name, origin, pk_service, X_svc:{x,y}}` → 202 `{arid, status:'pending'}` / 200 `{arid, origin, pk_trace:{x,y}, cert_s}` / 403 `{arid, status:'denied'}` / 409 `{error:'service_key_mismatch'}`; `GET /cia/rps`(admin) → `{ rps: [{arid, name, origin, pk_service, X_svc, pk_trace|null, status, requestedAt, decidedAt|null}] }`; `POST /cia/rps/:arid/approve|deny`(admin) → `{arid, status}`; `POST /cia/open/request {arid, publicSignals[14], proof, D_svc:{x,y}, ts, sig}` → 202 `{id, status:'pending'}`(중복이면 200 같은 id); `GET /cia/openings`(admin) → `{ openings: [...] }`(uid 는 approved 항목에만); `POST /cia/openings/:id/approve|deny`(admin) → `{id, status}`; `GET /cia/open/:id?ts=&sig=` → 202/403/200 `{ id, status, uid, PPID, r_s, decidedAt }`. 헬퍼: `cia.registerRp(origin, name?, keys?) → { arid, origin, cert_s, pk_trace:{x,y bigint}, serviceWallet(ethers.Wallet), share:{x, X} }`; `cia.adminGet(p)`.

- [ ] **Step 1: 헬퍼 수정 (`tests/helpers/isolated_cia.mjs`)**

import 에 `import { createShare } from '../../lib/mode3_trace.js';`. 반환 객체의 `registerRp` 를 다음으로 바꾸고 `adminGet` 을 더한다:

```js
    adminGet: (p) => fetch(`${base}${p}`, { headers: adminHeaders }).then(json),
    // 서비스 등록 + 운영자 승인 대행(설계 2026-09-16 §3). keys 를 주면 그 키로(재등록·불일치 테스트용).
    async registerRp(origin, name = 'test-rp', keys = null) {
      const serviceWallet = keys?.serviceWallet ?? ethers.Wallet.createRandom();
      const share = keys?.share ?? await createShare();
      const body = { name, origin, pk_service: serviceWallet.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
      const post = () => fetch(`${base}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json);
      let r = await post();
      if (r.status === 202) {
        const a = await fetch(`${base}/cia/rps/${r.body.arid}/approve`, { method: 'POST', headers: adminHeaders }).then(json);
        if (a.status !== 200) throw new Error('approve 실패: ' + JSON.stringify(a.body));
        r = await post();
      }
      if (r.status !== 200) throw new Error('register_rp 실패: ' + JSON.stringify(r.body));
      return { arid: r.body.arid, origin: r.body.origin, cert_s: r.body.cert_s, pk_trace: { x: BigInt(r.body.pk_trace.x), y: BigInt(r.body.pk_trace.y) }, serviceWallet, share };
    },
```

- [ ] **Step 2: 등록·발급 테스트 수정 (`tests/test_cia_register_issue.mjs`)**

import 에 `import { createShare } from '../lib/mode3_trace.js';`. `'register_rp: …'` 케이스를 다음 두 케이스로 교체:

```js
  await t('register_rp: 등록은 pending 202 → 승인 → 같은 키로 재호출하면 200 에 pk_trace·cert_s(V2), 같은 origin 은 같은 arid', async () => {
    const w = ethers.Wallet.createRandom(); const share = await createShare();
    const body = { name: 'demo-rp', origin: 'http://127.0.0.1:3100', pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
    const r = await cia.post('/cia/register_rp', body);
    assert.equal(r.status, 202, JSON.stringify(r.body)); assert.equal(r.body.status, 'pending');
    assert.match(r.body.arid, /^[0-9]+$/); assert.ok(BigInt(r.body.arid) < SCALAR_MAX);
    assert.equal(r.body.cert_s, undefined, '승인 전에는 인증서가 없다');
    const again = await cia.post('/cia/register_rp', body);
    assert.equal(again.status, 202); assert.equal(again.body.arid, r.body.arid);
    const list = await cia.adminGet('/cia/rps');
    assert.equal(list.status, 200);
    const mine = list.body.rps.find((e) => e.arid === r.body.arid);
    assert.equal(mine.status, 'pending'); assert.equal(mine.pk_trace, null); assert.equal(mine.pk_service, w.address);
    assert.equal((await cia.adminPost(`/cia/rps/${r.body.arid}/approve`)).status, 200);
    const ok = await cia.post('/cia/register_rp', body);
    assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.equal(ok.body.arid, r.body.arid);
    const keys = (await cia.get('/cia/public_keys')).body;
    const pk_trace = { x: BigInt(ok.body.pk_trace.x), y: BigInt(ok.body.pk_trace.y) };
    assert.equal(await verifyRpCert({ x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) }, { arid: BigInt(ok.body.arid), origin: body.origin, pk_trace, cert: ok.body.cert_s }), true);
    // pk_trace = X_svc + x_AA·B8 — 서비스 조각이 들어 있어야 한다(같은 점이면 CIA 혼자 아는 키)
    assert.notEqual(ok.body.pk_trace.x, body.X_svc.x);
    assert.equal((await cia.adminPost(`/cia/rps/${r.body.arid}/approve`)).status, 409, '이미 결정된 항목은 409');
  });

  await t('register_rp: 다른 키로 같은 origin 은 409, 거절된 origin 은 403, 항등원·형식 오류는 400, 없는 arid 승인은 404', async () => {
    const origin = 'http://127.0.0.1:3101';
    const w = ethers.Wallet.createRandom(); const share = await createShare();
    const base = { name: 'x', origin, pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
    assert.equal((await cia.post('/cia/register_rp', { ...base, X_svc: { x: '0', y: '1' } })).status, 400);
    assert.equal((await cia.post('/cia/register_rp', { ...base, X_svc: { x: '1', y: '1' } })).status, 400);
    assert.equal((await cia.post('/cia/register_rp', { ...base, pk_service: 'nope' })).status, 400);
    assert.equal((await cia.post('/cia/register_rp', { name: 'x' })).status, 400);
    const r = await cia.post('/cia/register_rp', base);
    assert.equal(r.status, 202, JSON.stringify(r.body));
    const other = await cia.post('/cia/register_rp', { ...base, pk_service: ethers.Wallet.createRandom().address });
    assert.equal(other.status, 409); assert.equal(other.body.error, 'service_key_mismatch');
    assert.equal((await cia.adminPost('/cia/rps/123/approve')).status, 404);
    assert.equal((await cia.adminPost(`/cia/rps/${r.body.arid}/deny`)).status, 200);
    const denied = await cia.post('/cia/register_rp', base);
    assert.equal(denied.status, 403); assert.equal(denied.body.status, 'denied');
    assert.equal((await cia.adminGet('/cia/rps')).body.rps.find((e) => e.arid === r.body.arid).status, 'denied');
  });
```

`'issue: 같은 r_s 재사용은 409, …'` 케이스에서 `// 같은 r_s 로 다른 C_pt 를 내도 409 …` 부터 `assert.match(r1.body.error, /r_s/);` 까지 4줄을 다음으로 교체하고 케이스 이름을 `'issue: 같은 r_s 로 다른 C_pt 는 200 (CIA 는 로그인당 기록이 없다 — 재생은 RP 가 막는다), 허용 목록 밖 chainid 는 400, …'` 로:

```js
    // CIA 는 r_s 를 기록하지 않는다(2026-09-16 §4.4) — 같은 r_s 로 다른 C_pt 를 내면 200 이다. 재생 방지는 RP 의 r_s 소비다.
    const replay = await issueRequest(user, {}, { r_s: first.r_s });
    assert.equal((await cia.post('/cia/issue', replay.body)).status, 200);
```

파일 머리의 주석(`// 사용자 서명은 (C_pt, chainid, r_s) 를 덮는다 — … 영구 집합이 막는다`) 을 `// 사용자 서명은 (C_pt, chainid, r_s) 를 덮는다. CIA 는 r_s 를 기록하지 않는다 — 옛 본문 재생으로 얻는 σ 는 RP 에서 bad_challenge 다(2026-09-16 §4.4).` 로. `'I3: 만료 뒤 같은 본문 재전송은 409 …'` 케이스는 이름을 `'I3: 만료 뒤 같은 본문 재전송은 200 (CIA 기록 없음 — 옛 r_s 의 성명은 RP 가 거절한다)'` 로 바꾸고 마지막 두 assert 를 `assert.equal(second.status, 200, JSON.stringify(second.body));` 하나로.

- [ ] **Step 3: 기동 테스트에 v3 마이그레이션 케이스 추가 (`tests/test_cia_startup.mjs`)**

파일 끝 `try { … } finally` 블록 안, 마지막 케이스 뒤에(기존 케이스들이 `startIsolatedCia({ env: { CIA_STATE_FILE: … } })` 로 상태 파일을 물리는 패턴을 그대로 쓴다):

```js
  await t('v3 상태 파일은 v4 로 마이그레이션된다 — used_rs 버림, rps 는 approved·조각 없음, openings 빈 배열', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v3-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ version: 3, accounts: {}, issued: {}, used_rs: { '12345': ['1', '2'] }, rps: { '777': { name: 'old', origin: 'http://127.0.0.1:3100', at: '2026-09-15T00:00:00.000Z' } }, revoked: [], pending: [], epoch: 0 }), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      assert.equal(saved.version, 4); assert.equal(saved.used_rs, undefined); assert.deepEqual(saved.openings, []);
      const e = (await cia.adminGet('/cia/rps')).body.rps.find((x) => x.arid === '777');
      assert.equal(e.status, 'approved'); assert.equal(e.pk_trace, null); assert.equal(e.pk_service, null);
      // 옛 등록이 키를 내며 재등록하면 그때 조각을 만들고 200
      const w = ethers.Wallet.createRandom(); const share = await createShare();
      const r = await cia.post('/cia/register_rp', { name: 'old', origin: 'http://127.0.0.1:3100', pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } });
      assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.arid, '777'); assert.ok(r.body.pk_trace?.x);
    } finally { await cia.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
```

(파일 상단에 `fs`·`os`·`path`·`ethers`·`createShare` import 가 없으면 추가한다: `import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { ethers } from 'ethers'; import { createShare } from '../lib/mode3_trace.js';`.)

- [ ] **Step 4: 개봉 테스트 작성 (`tests/test_cia_opening.mjs`)**

```js
// 승인된 개봉 — 격리 CIA + :8545 + build/mode3 (설계 2026-09-16 §6). (chain 그룹)
//   node tests/test_cia_opening.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, VKEY_PATH } from '../lib/mode3_wallet.js';
import { createShare, combinePublicKey, partialDecrypt } from '../lib/mode3_trace.js';
import { signOpenRequest, signOpenResult } from '../lib/mode3_opening.js';

const j = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH}`);
const provider = getProvider();
const cia = await startIsolatedCia();
const uid = 12345n;
const nowTs = () => Math.floor(Date.now() / 1000).toString();

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const S1 = await cia.registerRp('http://127.0.0.1:3101', 's1');
  const S2 = await cia.registerRp('http://127.0.0.1:3102', 's2');

  // 사용자 등록·발급·증명(지갑 lib 그대로)
  const reg = await createRegistration();
  const r0 = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: { x: reg.cm_u.x.toString(), y: reg.cm_u.y.toString() } });
  assert.equal(r0.status, 201, j(r0.body));
  const sk_u = r0.body.sk_u;
  async function loginTranscript(svc, pk_trace = svc.pk_trace) {
    const session = createSessionKey();
    const r_s = randomScalar();
    const req = await buildIssueRequest({ uid, arid: BigInt(svc.arid), s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, attrs: [0n, 0n, 0n, 0n], r_s });
    const issued = await cia.post('/cia/issue', req.body);
    assert.equal(issued.status, 200, j(issued.body));
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    const { proof, publicSignals, tag } = await buildCredentialProof({ uid, arid: BigInt(svc.arid), s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs: [0n, 0n, 0n, 0n], credential: issued.body, pk_CIA, pk_trace, tree });
    return { proof, publicSignals, tag, r_s: r_s.toString(), PPID: publicSignals[0] };
  }
  async function openRequest(svc, T, { share = svc.share, wallet = svc.serviceWallet, ts = nowTs(), arid = svc.arid } = {}) {
    const D = await partialDecrypt(share.x, T.tag.c1);
    const D_svc = { x: D.x.toString(), y: D.y.toString() };
    const sig = await signOpenRequest(wallet, { arid, r_s: T.r_s, PPID: T.PPID, D_svc, ts });
    return cia.post('/cia/open/request', { arid, publicSignals: T.publicSignals, proof: T.proof, D_svc, ts, sig });
  }
  async function fetchResult(svc, id, { wallet = svc.serviceWallet, ts = nowTs() } = {}) {
    const sig = await signOpenResult(wallet, id, ts);
    return cia.get(`/cia/open/${id}?ts=${ts}&sig=${encodeURIComponent(sig)}`);
  }

  let T1, id1;
  await t('정상 경로: 요청 202 pending(uid 없음) → 승인 → 결과 200 에 uid', async () => {
    T1 = await loginTranscript(S1);
    const r = await openRequest(S1, T1);
    assert.equal(r.status, 202, j(r.body)); assert.equal(r.body.status, 'pending'); id1 = r.body.id;
    const list = (await cia.adminGet('/cia/openings')).body.openings;
    const mine = list.find((o) => o.id === id1);
    assert.equal(mine.status, 'pending'); assert.equal(mine.uid, undefined, '승인 전에는 uid 가 계산되지 않는다');
    assert.equal((await fetchResult(S1, id1)).status, 202);
    const a = await cia.adminPost(`/cia/openings/${id1}/approve`);
    assert.equal(a.status, 200, j(a.body)); assert.equal(a.body.status, 'approved');
    const res = await fetchResult(S1, id1);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, '12345'); assert.equal(res.body.PPID, T1.PPID); assert.equal(res.body.r_s, T1.r_s);
    assert.equal((await cia.adminGet('/cia/openings')).body.openings.find((o) => o.id === id1).uid, '12345', '감사 기록에 uid');
  });

  await t('같은 (arid, r_s) 재요청은 새 id 를 만들지 않는다 (200, 같은 id)', async () => {
    const r = await openRequest(S1, T1);
    assert.equal(r.status, 200); assert.equal(r.body.id, id1);
  });

  await t('거절 → 결과 403 denied', async () => {
    const T = await loginTranscript(S1);
    const { body: { id } } = await openRequest(S1, T);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/deny`)).status, 200);
    const res = await fetchResult(S1, id);
    assert.equal(res.status, 403); assert.equal(res.body.status, 'denied');
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).status, 409, '결정된 항목은 다시 결정할 수 없다');
  });

  await t('틀린 D_svc(다른 조각) → 승인 시 failed, 결과 403', async () => {
    const T = await loginTranscript(S1);
    const { body: { id } } = await openRequest(S1, T, { share: await createShare() });
    const a = await cia.adminPost(`/cia/openings/${id}/approve`);
    assert.equal(a.status, 200); assert.equal(a.body.status, 'failed');
    assert.equal((await fetchResult(S1, id)).status, 403);
  });

  await t('남의 트랜스크립트: S2 가 S1 의 세션을 열려 하면 wrong_arid 403 (유출된 로그로는 못 연다)', async () => {
    const r = await openRequest(S2, T1, { share: S2.share, wallet: S2.serviceWallet, arid: S2.arid });
    assert.equal(r.status, 403); assert.equal(r.body.error, 'wrong_arid');
  });

  await t('자기 arid 로 남의 조합 키 태그: wrong_trace_key 403', async () => {
    const fake = await combinePublicKey((await createShare()).X, (await createShare()).X);
    const T = await loginTranscript(S1, fake);
    const r = await openRequest(S1, T);
    assert.equal(r.status, 403); assert.equal(r.body.error, 'wrong_trace_key');
  });

  await t('서명·신선도·형식: 다른 키 서명 401, 오래된 ts 401, 손댄 증명 403, 승인 안 된 서비스 403, 미등록 arid 404', async () => {
    const T = await loginTranscript(S1);
    assert.equal((await openRequest(S1, T, { wallet: ethers.Wallet.createRandom() })).body.error, 'bad_signature');
    const stale = await openRequest(S1, T, { ts: (Number(nowTs()) - 600).toString() });
    assert.equal(stale.status, 401); assert.equal(stale.body.error, 'stale');
    const bad = JSON.parse(JSON.stringify(T.proof)); bad.pi_a[0] = (BigInt(bad.pi_a[0]) + 1n).toString();
    const r = await openRequest(S1, { ...T, proof: bad });
    assert.equal(r.status, 403); assert.equal(r.body.error, 'bad_proof');
    // 승인 안 된 서비스: 직접 pending 으로 등록만
    const w = ethers.Wallet.createRandom(); const share = await createShare();
    const p = await cia.post('/cia/register_rp', { name: 's3', origin: 'http://127.0.0.1:3103', pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } });
    assert.equal(p.status, 202);
    const na = await openRequest(S1, T, { wallet: w, share, arid: p.body.arid });
    assert.equal(na.status, 403); assert.equal(na.body.error, 'not_approved');
    assert.equal((await openRequest(S1, T, { arid: '999' })).status, 404);
  });

  await t('결과 수령: 다른 서비스의 서명이면 401, 오래된 ts 401, 없는 id 404', async () => {
    assert.equal((await fetchResult(S1, id1, { wallet: S2.serviceWallet })).status, 401);
    assert.equal((await fetchResult(S1, id1, { ts: (Number(nowTs()) - 600).toString() })).status, 401);
    assert.equal((await fetchResult(S1, 'deadbeef')).status, 404);
  });

  await t('admin 엔드포인트는 시크릿 없이 401', async () => {
    assert.equal((await cia.get('/cia/openings')).status, 401);
    assert.equal((await cia.post(`/cia/openings/${id1}/approve`)).status, 401);
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
```

`scripts/run_tests.sh` 의 `CHAIN=(` 배열에서 `tests/test_cia_issue_race.mjs` 다음 줄에 `tests/test_cia_opening.mjs` 추가.

- [ ] **Step 5: 실패 확인**

Run: `node tests/test_cia_register_issue.mjs; node tests/test_cia_opening.mjs`
Expected: 첫 파일은 `register_rp` 케이스가 201/`pk_trace` 없음으로 FAIL; 두 번째는 `registerRp` 가 202 를 못 받고 `register_rp 실패` 로 종료

- [ ] **Step 6: `cia.js` — 상태 v4·마이그레이션·`used_rs` 제거**

import 추가:

```js
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { isTracePoint, createShare, combinePublicKey, partialDecrypt, combineDecrypt } from './lib/mode3_trace.js';
import { openRequestMessage, openResultMessage, recoverSigner, isFreshTs } from './lib/mode3_opening.js';
```

상수에 `const VKEY_PATH = process.env.MODE3_VKEY_PATH || path.join(__dirname, 'build', 'mode3', 'pi_cred_vkey.json');`.

상태 주석·버전·기본값을:

```js
// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled }
// issued:    uid → [ { leaf(10진), C(10진), exptime(10진 Unix 초) } ]
// rps:       arid → { name, origin, pk_service(체크섬 주소)|null, X_svc:{x,y}|null, x_AA|null, pk_trace:{x,y}|null,
//                     status: pending|approved|denied, requestedAt, decidedAt|null }   서비스 등록(2026-09-16 §3)
//            x_AA 는 CIA 조각 — 밖으로 나가지 않는다. 잃으면 그 서비스의 과거 태그는 영원히 열 수 없다(§8 4번)
// openings:  [ { id, arid, r_s, PPID, c1:{x,y}, c2, D_svc:{x,y}, status: pending|approved|denied|failed, requestedAt,
//                decidedAt|null, uid? } ]   영구 감사 기록(§6). uid 는 approved 에만
// revoked / pending / epoch
// version 4 (2026-09-16): used_rs 삭제(CIA 는 로그인당 기록이 없다 — §4.4), rps 에 키·상태, openings 추가.
// v3 는 마이그레이션한다(사용자 쪽 서명 형식이 안 바뀌었다). v2 이하는 옛 서명 형식이라 읽지 않는다.
const STATE_VERSION = 4;
```

`defaultState()` 를 `{ version: STATE_VERSION, accounts: {}, issued: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }` 로. `loadState()` 의 버전 검사 블록을:

```js
  if (state.version === 3) {
    console.warn('[cia] 상태 파일 v3 → v4 마이그레이션: used_rs 버림, 기존 서비스 등록은 approved(조각 없음)로 둔다');
    delete state.used_rs;
    for (const e of Object.values(state.rps ?? {})) {
      e.pk_service ??= null; e.X_svc ??= null; e.x_AA ??= null; e.pk_trace ??= null;
      e.status ??= 'approved'; e.requestedAt ??= e.at ?? new Date().toISOString(); e.decidedAt ??= e.requestedAt;
    }
    state.openings ??= [];
    state.version = STATE_VERSION;
    persist();
  }
  if (state.version !== STATE_VERSION) {
    console.error(`[cia] 기동 거부: 상태 파일 버전 ${state.version} (기대 ${STATE_VERSION}). v2 이하는 옛 credential 형식이라 ` +
      `새 회로에서 검증되지 않으므로 마이그레이션하지 않는다 — 재시연 세트(로그 재배포 → 상태 파일 삭제)로 새로 시작할 것.`);
    process.exit(1);
  }
  state.rps ??= {}; state.openings ??= [];
```

`/cia/issue` 에서 `used_rs` 관련 네 곳을 지운다: `const used = (state.used_rs[uid] ??= []);` 와 그 아래 `if (used.includes(rsStr)) …` 두 줄(주석 포함), 기록 직전 재확인의 `if ((state.used_rs[uid] ??= []).includes(rsStr)) …` 한 줄, `state.used_rs[uid].push(rsStr);` 한 줄. 검사 순서 주석 `→ (uid, r_s) 미사용` 을 지우고, 재확인 주석에서 `r_s 는 성공했을 때만 기록한다 — …` 문장을 `r_s 는 기록하지 않는다(2026-09-16 §4.4) — 재생은 RP 의 소비가 막는다.` 로 바꾼다. `rsStr` 은 응답에 쓰므로 남긴다.

- [ ] **Step 7: `cia.js` — 등록 승인과 두 키**

`/cia/register_rp` 를 통째로 교체:

```js
// §3(2026-09-16) 서비스 등록 — pending 으로 받고 운영자가 승인하면 CIA 조각을 만들어 조합 키 pk_trace 와 cert_s(V2)를
// 낸다. 같은 origin·같은 키의 재호출은 현재 상태를 돌려준다(상태 조회를 겸한다). arid 는 요청 시점에 배정한다.
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
app.post('/cia/register_rp', async (req, res) => {
  try {
    const { name, origin, pk_service, X_svc } = req.body ?? {};
    if (typeof name !== 'string' || name.length === 0 || typeof origin !== 'string' || !/^https?:\/\/[^/\s]+$/.test(origin) || !isAddr(pk_service) || !isPt(X_svc)) {
      return res.status(400).json({ error: 'name, origin(http(s)://host[:port], 경로 없음), pk_service(주소), X_svc{x,y} required' });
    }
    const addr = ethers.getAddress(pk_service);
    const Xs = pointFromStrings(X_svc);
    // 항등원·부분군 밖은 거절 — 항등원 X_svc 면 pk_trace 가 CIA 조각만으로 열린다(§2).
    if (!(await isTracePoint(Xs))) return res.status(400).json({ error: 'X_svc is not a valid subgroup point' });
    let arid = Object.keys(state.rps).find((a) => state.rps[a].origin === origin);
    let e = arid ? state.rps[arid] : null;
    if (e && e.pk_service === null) {
      // v3 에서 넘어온 등록(키 없음): 키를 내면 채운다. 승인은 이미 난 것으로 본다(§7).
      e.pk_service = addr; e.X_svc = { x: X_svc.x, y: X_svc.y }; persist();
    }
    if (e && (e.pk_service !== addr || e.X_svc.x !== X_svc.x || e.X_svc.y !== X_svc.y)) {
      return res.status(409).json({ error: 'service_key_mismatch' });
    }
    if (!e) {
      arid = randomScalar().toString();
      e = state.rps[arid] = { name, origin, pk_service: addr, X_svc: { x: X_svc.x, y: X_svc.y }, x_AA: null, pk_trace: null, status: 'pending', requestedAt: new Date().toISOString(), decidedAt: null };
      persist();
    }
    if (e.status === 'denied') return res.status(403).json({ arid, status: 'denied' });
    if (e.status === 'pending') return res.status(202).json({ arid, status: 'pending' });
    if (!e.pk_trace) await makeShare(arid);   // v3 마이그레이션 항목이 키를 낸 첫 호출
    const cert_s = await signRpCert(ciaPrv, { arid: BigInt(arid), origin, pk_trace: e.pk_trace });
    res.json({ arid, name: e.name, origin, pk_trace: e.pk_trace, cert_s });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/** CIA 조각을 만들어 조합 키를 채운다. 승인 때 한 번. */
async function makeShare(arid) {
  const e = state.rps[arid];
  const share = await createShare();
  const pk = await combinePublicKey(pointFromStrings(e.X_svc), share.X);
  e.x_AA = share.x.toString();
  e.pk_trace = { x: pk.x.toString(), y: pk.y.toString() };
  persist();
}

const rpView = (arid, e) => ({ arid, name: e.name, origin: e.origin, pk_service: e.pk_service, X_svc: e.X_svc, pk_trace: e.pk_trace, status: e.status, requestedAt: e.requestedAt, decidedAt: e.decidedAt });
app.get('/cia/rps', requireAdmin, (req, res) => res.json({ rps: Object.entries(state.rps).map(([a, e]) => rpView(a, e)) }));
app.post('/cia/rps/:arid/approve', requireAdmin, async (req, res) => {
  try {
    const e = state.rps[req.params.arid];
    if (!e) return res.status(404).json({ error: 'unknown service' });
    if (e.status !== 'pending') return res.status(409).json({ error: `already ${e.status}` });
    if (!e.X_svc) return res.status(409).json({ error: 'no service key registered' });
    e.status = 'approved'; e.decidedAt = new Date().toISOString();
    await makeShare(req.params.arid);
    res.json({ arid: req.params.arid, status: e.status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/cia/rps/:arid/deny', requireAdmin, (req, res) => {
  const e = state.rps[req.params.arid];
  if (!e) return res.status(404).json({ error: 'unknown service' });
  if (e.status !== 'pending') return res.status(409).json({ error: `already ${e.status}` });
  e.status = 'denied'; e.decidedAt = new Date().toISOString(); persist();
  res.json({ arid: req.params.arid, status: e.status });
});
```

- [ ] **Step 8: `cia.js` — 개봉 엔드포인트**

`app.get('/cia/state', …)` 앞에:

```js
// ---- §6(2026-09-16) 승인된 개봉 ----
// 요청: 서비스가 트랜스크립트(공개 입력 14개 + π)와 자기 부분 복호 D_svc 를 서비스 서명키로 서명해 낸다. CIA 는 서명·신선도·
// arid·pk_trace·Groth16 을 검증하고 pending 으로 둔다 — 트랜스크립트 검증이 없으면 서비스가 임의 암호문을 내 CIA 를 복호
// 오라클로 쓸 수 있고, arid 대조가 없으면 유출된 남의 로그로 연다. 승인 시점에야 CIA 조각을 더해 uid 를 계산한다.
let vkeyP = null;
function loadVkey() {
  return (vkeyP ??= (async () => JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8')))().catch((e) => { vkeyP = null; throw e; }));
}
const findOpening = (id) => state.openings.find((o) => o.id === id);
app.post('/cia/open/request', async (req, res) => {
  try {
    const { arid, publicSignals, proof, D_svc, ts, sig } = req.body ?? {};
    if (!isDec(arid) || !Array.isArray(publicSignals) || publicSignals.length !== 14 || !publicSignals.every(isDec) || !proof || !isPt(D_svc) || !isDec(ts) || typeof sig !== 'string') {
      return res.status(400).json({ error: 'arid, publicSignals[14], proof, D_svc{x,y}, ts, sig required' });
    }
    const e = state.rps[arid];
    if (!e) return res.status(404).json({ error: 'unknown_service' });
    if (e.status !== 'approved' || !e.pk_service || !e.pk_trace) return res.status(403).json({ error: 'not_approved' });
    if (!isFreshTs(ts)) return res.status(401).json({ error: 'stale' });
    const [PPID, aridIn, , , , r_s, , ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = publicSignals;
    if (recoverSigner(openRequestMessage({ arid, r_s, PPID, D_svc, ts }), sig) !== e.pk_service) return res.status(401).json({ error: 'bad_signature' });
    if (aridIn !== arid) return res.status(403).json({ error: 'wrong_arid' });
    const pk = S(ciaPub);
    if (ciaX !== pk.x || ciaY !== pk.y) return res.status(403).json({ error: 'untrusted_cia' });
    if (traceX !== e.pk_trace.x || traceY !== e.pk_trace.y) return res.status(403).json({ error: 'wrong_trace_key' });
    let vkey;
    try { vkey = await loadVkey(); } catch (err) { return res.status(503).json({ error: `vkey unavailable: ${err.message}` }); }
    let ok = false;
    try { ok = await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { ok = false; }
    if (!ok) return res.status(403).json({ error: 'bad_proof' });
    const dup = state.openings.find((o) => o.arid === arid && o.r_s === r_s && o.status === 'pending');
    if (dup) return res.status(200).json({ id: dup.id, status: dup.status });
    const id = randomBytes(32).toString('hex');
    state.openings.push({ id, arid, r_s, PPID, c1: { x: c1x, y: c1y }, c2, D_svc: { x: D_svc.x, y: D_svc.y }, status: 'pending', requestedAt: new Date().toISOString(), decidedAt: null });
    persist();
    res.status(202).json({ id, status: 'pending' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/cia/openings', requireAdmin, (req, res) => res.json({ openings: state.openings }));
app.post('/cia/openings/:id/approve', requireAdmin, async (req, res) => {
  try {
    const o = findOpening(req.params.id);
    if (!o) return res.status(404).json({ error: 'unknown opening' });
    if (o.status !== 'pending') return res.status(409).json({ error: `already ${o.status}` });
    const e = state.rps[o.arid];
    const D_aa = await partialDecrypt(BigInt(e.x_AA), pointFromStrings(o.c1));
    const uid = (await combineDecrypt(BigInt(o.c2), pointFromStrings(o.D_svc), D_aa)).toString();
    o.decidedAt = new Date().toISOString();
    if (state.accounts[uid]) { o.status = 'approved'; o.uid = uid; }
    else { o.status = 'failed'; }   // D_svc 가 틀렸다 — 서비스 자신의 요청만 망친다(§6)
    persist();
    res.json({ id: o.id, status: o.status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/cia/openings/:id/deny', requireAdmin, (req, res) => {
  const o = findOpening(req.params.id);
  if (!o) return res.status(404).json({ error: 'unknown opening' });
  if (o.status !== 'pending') return res.status(409).json({ error: `already ${o.status}` });
  o.status = 'denied'; o.decidedAt = new Date().toISOString(); persist();
  res.json({ id: o.id, status: o.status });
});
app.get('/cia/open/:id', (req, res) => {
  const { ts, sig } = req.query ?? {};
  const o = findOpening(req.params.id);
  if (!o) return res.status(404).json({ error: 'unknown opening' });
  if (!isDec(ts) || typeof sig !== 'string') return res.status(400).json({ error: 'ts, sig required' });
  if (!isFreshTs(ts)) return res.status(401).json({ error: 'stale' });
  const e = state.rps[o.arid];
  if (recoverSigner(openResultMessage(o.id, ts), sig) !== e.pk_service) return res.status(401).json({ error: 'bad_signature' });
  if (o.status === 'pending') return res.status(202).json({ id: o.id, status: o.status });
  if (o.status !== 'approved') return res.status(403).json({ id: o.id, status: o.status });
  res.json({ id: o.id, status: o.status, uid: o.uid, PPID: o.PPID, r_s: o.r_s, decidedAt: o.decidedAt });
});
```

기동 로그 줄에 `vkey=${fs.existsSync(VKEY_PATH) ? 'ok' : 'missing'}` 를 더한다.

- [ ] **Step 9: 통과 확인**

Run: `node tests/test_cia_register_issue.mjs && node tests/test_cia_startup.mjs && node tests/test_cia_opening.mjs && node tests/test_cia_issue_race.mjs && node tests/test_mode3_e2e.mjs`
Expected: 전부 `ok`(e2e 는 헬퍼가 승인을 대행한다)

- [ ] **Step 10: 커밋 (제안 후 승인 시 실행)**

```bash
git add cia.js tests/helpers/isolated_cia.mjs tests/test_cia_register_issue.mjs tests/test_cia_startup.mjs tests/test_cia_opening.mjs scripts/run_tests.sh
git commit -m "feat(mode3): CIA — 서비스 등록 승인·조합 키·cert_s V2, used_rs 제거(상태 v4), 승인된 개봉 엔드포인트"
```

---

### Task 5: 서버·페이지·격리 스택 — 지갑 태그, RP 두 키·대기 기동·로그·개봉, 관리자 승인 UI

**Files:**
- Modify: `mode3_wallet_agent.js`, `mode3_rp.js`, `mode3/cia_admin.html`, `mode3/rp.html`
- Modify: `tests/helpers/isolated_mode3_stack.mjs`, `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_demo_stack.mjs`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: Task 1~4 전부. 지갑 `/wallet/login` 본문 `{ arid, origin, cert_s, pk_trace:{x,y}, r_s }`; RP `rp_info` 에 `status`·`pk_trace`; RP `/api/mode3/open {PPID}` → CIA 응답 그대로(+`id`), `/api/mode3/open/:id` → CIA 결과 그대로.
- Produces: 데모 스택 헬퍼가 RP 등록을 승인해 활성 상태로 돌려준다.

- [ ] **Step 1: 지갑 에이전트**

`mode3_wallet_agent.js`: 상태 주석의 `sessions:` 줄을 `sessions:     r_s → { arid, pk_trace:{x,y}, credential:{…}, blind, sessionPrivKey, pk_i, issuedAt }` 로, `// version 3 …` 다음에 `// version 4 (2026-09-16): 세션에 pk_trace(인증서의 조합 키). 옛 파일은 등록만 살리고 세션은 비운다.`, `WALLET_STATE_VERSION = 4`. `issueCredential(arid, r_s)` → `issueCredential(arid, r_s, pk_trace)` 로 바꾸고 세션 객체에 `pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }` 추가. `/wallet/login`:

```js
    const { arid, origin, cert_s, pk_trace, r_s } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y) || !isDec(r_s)) return res.status(400).json({ error: 'arid, origin, cert_s, pk_trace{x,y}, r_s 필요' });
```

cert 검증 주석에 `// pk_trace 는 인증서가 덮는다 — 서비스가 자기만 아는 키를 주면 서비스 혼자 태그를 연다(2026-09-16 §2).` 를 더하고 `verifyRpCert(pk, { arid: BigInt(arid), origin, pk_trace, cert: cert_s })`. `issueCredential(arid, rs)` → `issueCredential(arid, rs, { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) })`. `proveSession` 의 `buildCredentialProof` 에 `pk_trace: { x: BigInt(s.pk_trace.x), y: BigInt(s.pk_trace.y) }`. `/wallet/status` 의 세션 항목에 `pk_trace: e.pk_trace`.

- [ ] **Step 2: RP 서버**

`mode3_rp.js` 의 등록 블록을 통째로 교체(`const REG_FILE …` 부터 `const ARID = registration.arid;` 까지):

```js
// ---- 서비스 등록(설계 2026-09-16 §3) ----
// 키 둘: secp256k1 서명키(pk_service, 개봉 요청)와 Baby Jubjub 조각(x_svc, 태그). 첫 기동에서 만들어 파일에 두고 CIA 에
// 등록한다. CIA 는 pending 으로 받고 운영자가 승인하면 조합 키 pk_trace 와 cert_s 를 준다 — 그때까지는 대기 상태로 뜬다.
const REG_FILE = process.env.MODE3_RP_REGISTRATION_FILE || path.join(__dirname, 'mode3_rp_registration.json');
const REG_VERSION = 2;
const PUBLIC_ORIGIN = process.env.MODE3_RP_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const RP_NAME = process.env.MODE3_RP_NAME || 'demo-rp';
const POLL_MS = Number(process.env.MODE3_RP_REGISTRATION_POLL_MS) || 5000;
const LOGIN_LOG = process.env.MODE3_RP_LOGIN_LOG || path.join(__dirname, 'mode3_rp_logins.jsonl');

let reg = readJson(REG_FILE, null);
if (reg && (reg.version !== REG_VERSION || reg.origin !== PUBLIC_ORIGIN)) {
  console.warn(`[rp] 등록 파일이 옛 형식이거나 origin(${reg.origin}) 이 현재(${PUBLIC_ORIGIN}) 와 달라 새로 등록한다`);
  reg = null;
}
if (!reg) {
  const w = ethers.Wallet.createRandom();
  const share = await createShare();
  reg = { version: REG_VERSION, origin: PUBLIC_ORIGIN, pk_service: w.address, sk_service: w.privateKey, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() }, x_svc: share.x.toString(), status: 'pending', arid: null, pk_trace: null, cert_s: null, issuedAt: null };
  writeJsonAtomic(REG_FILE, reg, 0o600);
}
const serviceWallet = new ethers.Wallet(reg.sk_service);

/** CIA 에 등록/조회. 200 이면 파일을 채우고 true. 202 면 false. 403 이면 throw. */
async function registerOnce() {
  const r = await fetch(`${CIA_URL}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: RP_NAME, origin: PUBLIC_ORIGIN, pk_service: reg.pk_service, X_svc: reg.X_svc }) });
  const b = await r.json().catch(() => ({}));
  if (r.status === 202) { reg.arid = b.arid; reg.status = 'pending'; writeJsonAtomic(REG_FILE, reg, 0o600); return false; }
  if (r.status === 403) { reg.arid = b.arid; reg.status = 'denied'; writeJsonAtomic(REG_FILE, reg, 0o600); throw new Error(`CIA 가 등록을 거절했다 (arid=${b.arid})`); }
  if (r.status !== 200) throw new Error(`CIA 등록 실패 (${r.status}) ${JSON.stringify(b)}`);
  const pk_trace = { x: BigInt(b.pk_trace.x), y: BigInt(b.pk_trace.y) };
  if (!(await verifyRpCert(pkCIA, { arid: BigInt(b.arid), origin: PUBLIC_ORIGIN, pk_trace, cert: b.cert_s }))) throw new Error('CIA 가 준 cert_s 가 pk_CIA 로 검증되지 않는다');
  reg = { ...reg, arid: b.arid, status: 'approved', pk_trace: b.pk_trace, cert_s: b.cert_s, issuedAt: new Date().toISOString() };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] CIA 등록 승인됨: arid=${reg.arid} origin=${reg.origin} → ${REG_FILE}`);
  return true;
}

const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
const chainId = (await provider.getNetwork()).chainId;
let verifier = null;   // 승인 뒤에만 만든다 — arid 와 pk_trace 가 있어야 한다
function activate() {
  verifier = createRpVerifier({ provider, logAddress: LOG_ADDRESS, vkey, pkCIA, arid: BigInt(reg.arid), chainId, pkTrace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) } });
}
if (reg.status === 'approved' && reg.cert_s) {
  if (!(await verifyRpCert(pkCIA, { arid: BigInt(reg.arid), origin: reg.origin, pk_trace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) }, cert: reg.cert_s }))) {
    throw new Error('등록 파일의 cert_s 가 현재 pk_CIA 로 검증되지 않는다 — CIA 키가 바뀌었으면 파일을 지우고 재기동');
  }
  activate();
} else {
  if (await registerOnce()) activate();
  else {
    console.log(`[rp] 등록 대기 (arid=${reg.arid}) — CIA 관리자 페이지에서 승인하면 ${POLL_MS} ms 안에 활성화된다`);
    const timer = setInterval(async () => {
      try { if (await registerOnce()) { activate(); clearInterval(timer); } }
      catch (e) { console.error(`[rp] ${e.message}`); clearInterval(timer); }
    }, POLL_MS);
    timer.unref();
  }
}
const ARID = () => reg.arid;
```

import 에 `import { createShare, partialDecrypt } from './lib/mode3_trace.js';` 와 `import { signOpenRequest, signOpenResult } from './lib/mode3_opening.js';`. `createRpVerifier` 의 옛 호출(`const verifier = createRpVerifier(...)`)과 `const chainId`·`vkey`·`provider` 의 옛 선언은 위 블록이 대신하므로 지운다.

`rp_info`:

```js
app.get('/api/mode3/rp_info', (req, res) => {
  res.json({ status: reg.status, arid: reg.arid, origin: reg.origin, cert_s: reg.cert_s, pk_trace: reg.pk_trace, logAddress: LOG_ADDRESS, walletAgentOrigin: WALLET_ORIGIN, pkCiaSource: pkCIA.source, chainId: chainId.toString() });
});
```

대기 중 거절: `app.post('/api/mode3/challenge', …)`·`login`·`revalidate`·`request` 네 핸들러 맨 앞에 `if (!verifier) return res.status(503).json({ ok: false, reason: 'registration_pending' });` (challenge 는 `{ reason: 'registration_pending' }`). `rsFromSignals` 의 `length === 9` → `14`. 로그인 성공 시 `logins.push(...)` 다음에:

```js
    // §5 로그인 로그 — 전체 r_s 와 트랜스크립트(태그 포함). 개봉 요청의 재료다. 조회 API 로는 내지 않는다.
    fs.appendFileSync(LOGIN_LOG, JSON.stringify({ at: new Date().toISOString(), PPID: v.PPID.toString(), r_s: rsStr, pk_i: v.pk_i.toString(), exptime: v.exptime.toString(), root: v.root.toString(), publicSignals, proof: req.body.proof }) + '\n', { mode: 0o600 });
```

`rsShort` 위 주석을 `// r_s 전문은 내지 않는다 — (PPID, 시각) 과 함께 서비스의 사용자 활동 기록이다(설계 2026-09-16 §5).` 로. 개봉 엔드포인트(`/api/mode3/logins` 앞):

```js
// ---- §6 개봉(데모용, 인증 없음) ----
function lastTranscriptOf(PPID) {
  if (!fs.existsSync(LOGIN_LOG)) return null;
  const lines = fs.readFileSync(LOGIN_LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  return lines.reverse().find((l) => l.PPID === PPID) ?? null;
}
app.post('/api/mode3/open', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: 'registration_pending' });
    const { PPID } = req.body ?? {};
    if (typeof PPID !== 'string') return res.status(400).json({ ok: false, reason: 'malformed' });
    const T = lastTranscriptOf(PPID);
    if (!T) return res.status(404).json({ ok: false, reason: 'no_transcript' });
    const c1 = { x: BigInt(T.publicSignals[11]), y: BigInt(T.publicSignals[12]) };
    const D = await partialDecrypt(BigInt(reg.x_svc), c1);
    const D_svc = { x: D.x.toString(), y: D.y.toString() };
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = await signOpenRequest(serviceWallet, { arid: reg.arid, r_s: T.r_s, PPID, D_svc, ts });
    const r = await fetch(`${CIA_URL}/cia/open/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ arid: reg.arid, publicSignals: T.publicSignals, proof: T.proof, D_svc, ts, sig }) });
    res.status(r.status).json(await r.json().catch(() => ({})));
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
app.get('/api/mode3/open/:id', async (req, res) => {
  try {
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = await signOpenResult(serviceWallet, req.params.id, ts);
    const r = await fetch(`${CIA_URL}/cia/open/${encodeURIComponent(req.params.id)}?ts=${ts}&sig=${encodeURIComponent(sig)}`);
    res.status(r.status).json(await r.json().catch(() => ({})));
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
```

기동 로그의 `arid=${ARID}` → `arid=${reg.arid ?? '-'} status=${reg.status}`.

- [ ] **Step 3: 관리자 페이지**

`mode3/cia_admin.html` 의 `<pre id="out">` 앞에 두 fieldset 추가:

```html
  <fieldset>
    <legend>등록된 서비스 <button id="rpsBtn">목록</button></legend>
    <p class="muted">승인하면 CIA 조각을 만들어 조합 키 pk_trace 와 cert_s 를 낸다(설계 2026-09-16 §3). 거절은 되돌릴 수 없다.</p>
    <div id="rps">-</div>
  </fieldset>

  <fieldset>
    <legend>개봉 요청 <button id="openingsBtn">목록</button></legend>
    <p class="muted">승인 시점에 CIA 조각으로 복호해 uid 를 기록한다(§6). pending 항목에는 uid 가 없다.</p>
    <div id="openings">-</div>
  </fieldset>
```

스크립트에 추가:

```js
    async function adminJson(method, path) {
      const r = await fetch(path, { method, headers: { 'X-CIA-Admin-Secret': $('secret').value } });
      return { status: r.status, body: await r.json().catch(() => null) };
    }
    function row(cells) { return `<tr>${cells.map((c) => `<td style="padding:2px 8px">${c}</td>`).join('')}</tr>`; }
    async function loadRps() {
      const r = await adminJson('GET', '/cia/rps');
      if (r.status !== 200) { $('rps').textContent = `${r.status}`; return; }
      $('rps').innerHTML = `<table>${r.body.rps.map((e) => row([e.status, e.name, e.origin, `${e.arid.slice(0, 10)}…`,
        e.status === 'pending' ? `<button data-a="${e.arid}" data-act="approve">승인</button> <button data-a="${e.arid}" data-act="deny">거절</button>` : (e.decidedAt ?? '')])).join('')}</table>`;
      $('rps').querySelectorAll('button').forEach((b) => b.addEventListener('click', async () => { await call('POST', `/cia/rps/${b.dataset.a}/${b.dataset.act}`); loadRps(); }));
    }
    async function loadOpenings() {
      const r = await adminJson('GET', '/cia/openings');
      if (r.status !== 200) { $('openings').textContent = `${r.status}`; return; }
      $('openings').innerHTML = r.body.openings.length ? `<table>${r.body.openings.map((o) => row([o.status, o.requestedAt, `arid ${o.arid.slice(0, 10)}…`, `PPID ${o.PPID.slice(0, 10)}…`, o.uid ?? '',
        o.status === 'pending' ? `<button data-i="${o.id}" data-act="approve">승인</button> <button data-i="${o.id}" data-act="deny">거절</button>` : ''])).join('')}</table>` : '(없음)';
      $('openings').querySelectorAll('button').forEach((b) => b.addEventListener('click', async () => { await call('POST', `/cia/openings/${b.dataset.i}/${b.dataset.act}`); loadOpenings(); }));
    }
    $('rpsBtn').addEventListener('click', loadRps);
    $('openingsBtn').addEventListener('click', loadOpenings);
```

- [ ] **Step 4: RP 페이지**

`mode3/rp.html`: `loadInfo()` 를

```js
    async function loadInfo() {
      info = await (await fetch('/api/mode3/rp_info')).json();
      const pending = info.status !== 'approved';
      $('rpInfo').textContent = pending
        ? `등록 대기 중 (arid=${info.arid ?? '-'}) — CIA 관리자 페이지(/admin)에서 승인하면 활성화된다. 5초마다 확인.`
        : `arid=${info.arid}   origin=${info.origin}   cert_s=있음   pk_trace=있음   RevocationLog=${info.logAddress}   지갑 에이전트=${info.walletAgentOrigin}   pk_CIA=${info.pkCiaSource}   chainId=${info.chainId}`;
      $('loginBtn').disabled = pending;
      if (pending) setTimeout(loadInfo, 5000);
    }
```

로그인 요청 본문에 `pk_trace: info.pk_trace` 추가(`{ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s }`). 로그인 기록 fieldset 에:

```html
    <p class="muted">개봉 요청(설계 2026-09-16 §6): PPID <input id="openPpid" size="24" /> <button id="openBtn">요청</button> <button id="openPollBtn" disabled>결과 확인</button></p>
    <pre id="openLog">-</pre>
```

스크립트:

```js
    let openingId = null;
    $('openBtn').addEventListener('click', async () => {
      const PPID = $('openPpid').value.trim();
      const r = await post('/api/mode3/open', { PPID }); const b = await r.json().catch(() => ({}));
      $('openLog').textContent = `요청 → ${r.status} ${JSON.stringify(b)}`;
      openingId = b.id ?? null; $('openPollBtn').disabled = !openingId;
    });
    $('openPollBtn').addEventListener('click', async () => {
      const r = await fetch(`/api/mode3/open/${openingId}`); const b = await r.json().catch(() => ({}));
      $('openLog').textContent += `\n결과 → ${r.status} ${JSON.stringify(b)}`;
    });
```

로그인 성공 뒤 `setSession(...)` 다음에 `if (rb.ok) $('openPpid').value = rb.PPID;`.

- [ ] **Step 5: 격리 스택 헬퍼**

`tests/helpers/isolated_mode3_stack.mjs`: `PINNED_ENV` 에 `MODE3_RP_REGISTRATION_POLL_MS: '300', MODE3_RP_LOGIN_LOG: ''` 추가. RP env 에 `MODE3_RP_LOGIN_LOG: path.join(dir, 'mode3_rp_logins.jsonl')`. RP spawn 뒤(`rp = client(rpOrigin, rpLog);` 다음):

```js
      // 등록 승인 대행(2026-09-16 §3): RP 는 pending 으로 떠 있다. 관리자 시크릿으로 승인하고 활성화를 기다린다.
      const deadline = Date.now() + 20_000;
      let approved = false;
      while (Date.now() < deadline) {
        const list = (await cia.adminGet('/cia/rps')).body?.rps ?? [];
        const mine = list.find((e) => e.origin === rpOrigin);
        if (mine?.status === 'pending') await cia.adminPost(`/cia/rps/${mine.arid}/approve`);
        if ((await rp.get('/api/mode3/rp_info')).body?.status === 'approved') { approved = true; break; }
        await new Promise((r) => setTimeout(r, 200));
      }
      if (!approved) throw new Error(`RP 등록 승인·활성화 실패\n${rp.log()}`);
```

`stop()` 앞에 `rpOriginForWallet` 옆에 아무것도 더하지 않는다.

- [ ] **Step 6: 지갑 에이전트 테스트**

`tests/test_mode3_wallet_agent.mjs`: `const { arid, cert_s, origin } = await cia.registerRp(...)` → `const { arid, cert_s, origin, pk_trace } = await cia.registerRp(stack.rpOriginForWallet);`, `createRpVerifier({ …, pkTrace: pk_trace })`, `login` 본문에 `pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }`. `publicSignals.length, 9` → `14`. `'입력 검증: …'` 케이스에 `pk_trace` 누락 400 한 줄 추가. 새 케이스:

```js
  await t('bad_rp_cert: 인증서와 다른 pk_trace 를 주면 403 (서비스 혼자 아는 키로 바꿔치기)', async () => {
    const r = await login(newRs(), { pk_trace: { x: '1', y: '2' } });
    assert.equal(r.status, 403); assert.equal(r.body.reason, 'bad_rp_cert');
  });
```

- [ ] **Step 7: 데모 스택 테스트**

`tests/test_mode3_demo_stack.mjs`: `loginViaRp` 의 지갑 본문에 `pk_trace: info.pk_trace`; `rp_info` 케이스에 `assert.equal(r.body.status, 'approved'); assert.ok(r.body.pk_trace?.x);`. `bad_rp_cert`·`duplicate_session`·`r_s 음성` 케이스의 지갑 본문에도 `pk_trace: info.pk_trace`. `session_mismatch` 케이스의 `buildCredentialProof` 에 `pk_trace: { x: BigInt(info.pk_trace.x), y: BigInt(info.pk_trace.y) }`. 새 케이스 둘(`'1. 등록'` 앞과 `'8. 로그인 …'` 뒤):

```js
  await t('0. 서비스 등록 승인: 관리자 목록에 approved 이고 조합 키가 있다 (헬퍼가 승인을 대행했다)', async () => {
    const list = (await cia.adminGet('/cia/rps')).body.rps;
    const mine = list.find((e) => e.origin === rp.origin);
    assert.equal(mine.status, 'approved'); assert.ok(mine.pk_trace?.x);
    assert.equal((await rp.get('/api/mode3/rp_info')).body.status, 'approved');
  });
```

```js
  await t('9. 개봉: RP 가 PPID 로 요청 → 관리자 승인 → RP 가 uid 를 받는다; 거절이면 403', async () => {
    const r = await rp.post('/api/mode3/open', { PPID: PPID1 });
    assert.equal(r.status, 202, j(r.body)); const id = r.body.id;
    assert.equal((await rp.get(`/api/mode3/open/${id}`)).status, 202);
    const pend = (await cia.adminGet('/cia/openings')).body.openings.find((o) => o.id === id);
    assert.equal(pend.status, 'pending'); assert.equal(pend.uid, undefined);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).body.status, 'approved');
    const res = await rp.get(`/api/mode3/open/${id}`);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, uid); assert.equal(res.body.PPID, PPID1);
    const r2 = await rp.post('/api/mode3/open', { PPID: PPID1 });   // 같은 PPID 의 최신 트랜스크립트로 새 요청(r_s 가 다르면 새 id)
    assert.ok([200, 202].includes(r2.status), j(r2.body));
    if (r2.body.id !== id) {
      assert.equal((await cia.adminPost(`/cia/openings/${r2.body.id}/deny`)).body.status, 'denied');
      assert.equal((await rp.get(`/api/mode3/open/${r2.body.id}`)).status, 403);
    }
    assert.equal((await rp.post('/api/mode3/open', { PPID: '1' })).status, 404);
  });
```

`.gitignore` 의 `mode3_rp_registration.json` 다음 줄에 `mode3_rp_logins.jsonl`.

- [ ] **Step 8: chain 그룹·npm test 확인**

Run: `bash scripts/run_tests.sh chain && npm test`
Expected: chain `통과 13 / 실패 0`; `npm test` unit 11 + circuit 13 통과. 실패하면 로그(`stack.rp.log()` 는 테스트 실패 메시지에 포함)로 원인을 잡는다.

- [ ] **Step 9: 커밋 (제안 후 승인 시 실행)**

```bash
git add mode3_wallet_agent.js mode3_rp.js mode3/cia_admin.html mode3/rp.html tests/helpers/isolated_mode3_stack.mjs tests/test_mode3_wallet_agent.mjs tests/test_mode3_demo_stack.mjs .gitignore
git commit -m "feat(mode3): 지갑 태그·인증서 V2, RP 두 키·등록 대기·로그인 로그·개봉 요청, 관리자 승인 UI"
```

---

### Task 6: 문서 — 데모 각본, 상태 v4, 실측값

**Files:**
- Modify: `docs/MODE3_DEMO.md`
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§11.1 표에 행 추가)

- [ ] **Step 1: `docs/MODE3_DEMO.md`**

"처음 한 번" 5 를:

```
5. RP(mode3_rp.js)는 첫 기동에서 서명키·태그 조각을 만들어 CIA 에 등록하고 **등록 대기** 상태로 뜬다. CIA 관리자 페이지
   (`/admin` → 등록된 서비스 → 승인)에서 승인하면 5초 안에 arid·pk_trace·cert_s 를 받아 mode3_rp_registration.json 에 두고
   활성화된다. CIA 키를 바꾸거나 cia_state.json 을 지웠으면 이 파일도 지운다(그러면 새 키로 다시 승인받아야 한다).
```

선택 env 줄에 `MODE3_VKEY_PATH`(CIA 의 개봉 검증용 vkey, 기본 `build/mode3/pi_cred_vkey.json`), `MODE3_RP_LOGIN_LOG`(RP 로그인 로그, 기본 `mode3_rp_logins.jsonl`, 0600 — 개봉 요청의 재료라 비밀로 둔다) 추가. "매번: 기동 순서" 아래 문단을 `RP 는 등록 파일이 없거나 승인 전이면 CIA 에 등록/조회하므로 CIA 가 먼저 떠 있어야 한다.` 로. 시연 각본 표 맨 앞에 `| 0 | 관리자 | 등록된 서비스 → 승인 (RP 첫 기동 뒤 한 번) | RP 페이지가 "등록 대기" → 활성 |`, 맨 뒤에 `| 9 | RP → 관리자 → RP | 로그인 기록 아래 PPID 로 "개봉 요청" → 관리자 "개봉 요청 → 승인" → RP "결과 확인" | 202 pending → approved → uid=12345 |`. 표 아래 설명에:

```
9 는 승인된 개봉(설계 2026-09-16 §6)이다. 로그인마다 지갑이 서비스의 조합 키 pk_trace 로 uid 를 암호화한 태그를 증명에 넣고
(조건 ⑤), 서비스는 자기 조각으로 반만 풀어 CIA 에 낸다. 운영자가 승인하면 CIA 가 자기 조각으로 마저 풀어 uid 를 돌려준다 —
서비스 혼자도, CIA 혼자도 열 수 없고, 열리는 것은 그 세션의 uid 하나다. CIA 는 로그인당 아무것도 저장하지 않는다.
```

"하지 말 것" 첫 항목을 `옛 상태 파일(cia_state.json version 2 이하, mode3_wallet_state.json version 3 이하, 키 없는 mode3_rp_registration.json)` 으로 바꾸고 `cia_state.json v3 는 기동 시 v4 로 마이그레이션된다(used_rs 는 버려지고 기존 서비스 등록은 승인된 것으로 남는다).` 를 덧붙인다. 재시연 세트에 `mode3_rp_registration.json 삭제`·`mode3_rp_logins.jsonl 삭제` 추가. 테스트 절에 `개봉은 tests/test_cia_opening.mjs(CIA 단독)와 test_mode3_demo_stack.mjs 시나리오 9(전 구간)로 고정돼 있다.`

- [ ] **Step 2: 실측값 표**

`docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` §11.1 표에 열을 하나 더하지 말고, 표 아래에 문단을 추가한다(Task 2 Step 6·8 의 값을 넣는다):

```
**2026-09-16 트레이스 태그(조건 ⑤) 추가 후:** 비선형 제약 <Task 2 Step 6 값>(2026-09-15 의 22,224 에서 +<차이>), 증명
시간 중앙값 <Step 8 값> ms, 검증 <값> ms, zkey <값> MB, 공개 입력 14개. 예상(2026-09-16 설계 §4.2 5~7k)과 대조: <한 줄>.
```

- [ ] **Step 3: 커밋 (제안 후 승인 시 실행)**

```bash
git add docs/MODE3_DEMO.md docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "docs(mode3): 데모 각본 0(등록 승인)·9(개봉), 상태 v4, 태그 회로 실측값"
```

---

## 자체 점검

**스펙 대조.** §2 위협 모형 → 코드 변경 없음(논문 반영은 §11, 이 계획 밖). §3 두 키·pending/approved/denied·조합 키·cert V2·RP 대기 기동·폴링·관리자 표 → Task 1(cert V2), 4(CIA), 5(RP·UI). §4.1 태그 → Task 1. §4.2 회로·공개 입력 14·비용 실측 → Task 2. §4.3 인증 요구에 `pk_trace`·지갑 검증·`wrong_trace_key`·재검증 시 새 r → Task 3(lib), 5(지갑·RP). §4.4 `used_rs` 제거 → Task 4. §5 로그인 로그 jsonl → Task 5. §6 개봉 3단계·검사 순서·중복 id·복호는 승인 시·failed·`ts` → Task 4(CIA), 5(RP 데모 경로·UI). §7 상태 v4 마이그레이션·지갑 v4·등록 파일 v2 → Task 4·5. §8 한계 → 문서. §10 구현 범위의 파일 목록과 일치. §11 논문·발표 반영은 이 계획 밖(구현 뒤 별도).

**자리표시자.** 없음. Task 6 Step 2 의 `<…>` 는 Task 2 실측값을 옮기는 자리이며 실행 시 채운다.

**타입 일관성.** `pk_trace` 는 lib 경계에서 `{x,y}` bigint, HTTP·상태 파일에서 10진 문자열 — 지갑·RP 서버가 `BigInt()` 로 바꿔 lib 에 넘긴다(Task 5). `createRpVerifier` 옵션 이름은 `pkTrace`(기존 `pkCIA` 와 같은 camel), `buildCredentialProof` 파라미터는 `pk_trace`(기존 `pk_CIA` 와 같은 snake) — 각 파일의 기존 관례를 따른다. 개봉 메시지의 `D_svc.x` 는 10진 문자열이고 CIA 는 `pointFromStrings` 로 읽는다. 공개 입력 인덱스: 9·10 `pk_trace`, 11·12 `c1`, 13 `c2` — RP `lastTranscriptOf` 와 CIA `open/request` 구조 분해가 같은 인덱스를 쓴다.

**Task 간 깨짐.** Task 2 뒤 chain 그룹은 `buildCredentialProof` 입력 누락으로 깨진다(정상). Task 3 뒤 `registerRp` 헬퍼는 아직 옛 CIA 와 맞는다. Task 4 뒤 데모 스택(RP 서버)은 등록이 202 라 `test_mode3_demo_stack`·`test_mode3_wallet_agent` 가 깨진다 — Task 5 가 복구한다.
