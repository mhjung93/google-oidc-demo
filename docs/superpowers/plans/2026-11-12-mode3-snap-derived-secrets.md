# 스냅 시드 유도 비밀 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 스냅이 s_u·sk_u 를 `snap_getEntropy` 에서 유도하고, 같은 비밀로 다시 등록하면 기존 등록이 돌아오게 해 MetaMask 재설치(시드 복원) 뒤에도 같은 PPID 로 로그인되게 한다.

**Architecture:** 스냅(`snap-mode3/src`)이 유도를 맡고 `getSalt` 로 속성 도구에 salt 를 준다. IdP `registerAccount`·`/cia/auth/code` 는 (auid, pk_u) 가 저장값과 같은 재등록을 "복구"로 받는다(201 `restored:true`). 지갑 팝업은 에이전트에 등록이 있는데 스냅이 비었으면 유도 비밀로 기존 `/wallet/register/resume` 을 불러 스냅을 채운다(에이전트 상태까지 없으면 평소 등록 경로가 IdP 복구로 이어진다).

**Tech Stack:** MetaMask Snaps(`snap_getEntropy`), Node(express) IdP·에이전트, 정적 HTML 페이지, Playwright(브라우저 테스트), circomlibjs(Poseidon·EdDSA, 기존).

**Spec:** `docs/superpowers/specs/2026-11-12-mode3-snap-derived-secrets-design.md`

## Global Constraints

- 회로·컨트랙트·PPID 식을 바꾸지 않는다. `npm run zk:*`·회로 재빌드 금지. 새 의존성 금지.
- 유도 salt 문자열은 정확히 `'zkd/mode3/s_u/v1'`, `'zkd/mode3/sk_u/v1'`. `s_u = 1 + (BigInt(entropy) mod (2^250 − 1))`(10진 문자열), `sk_u` = 엔트로피 32바이트의 소문자 hex 64자(`0x` 없음).
- 스냅 매니페스트: `initialPermissions` 에 `"snap_getEntropy": {}`, 버전 `0.2.0`. 번들은 `cd snap-mode3 && npm run build` 로 다시 만든다(shasum 갱신, `dist/` 는 git 추적).
- 파일 모드·웹 모드 동작은 바꾸지 않는다(`SECRETS !== 'snap'` 경로 그대로).
- 주석·문구는 기존 문체(한국어, 날짜 `2026-11-12` 표기)를 따른다. 새 사유 문자열은 `mode3/common/strings.js` reasons 에 ko·en 둘 다.
- 테스트 진입점은 `scripts/run_tests.sh` 그룹(`snap`, `chain`, `browser`). 새 테스트 파일을 만들면 그룹 목록에 넣는다(이 계획은 기존 파일에 케이스를 더한다).
- `.env`·`*_state.json`·`*_keys.json`·`role.env` 를 읽거나 출력하지 않는다. git 은 경로 지정 `git add` 만.
- **Ruling P1(스펙 §4.1 정정):** IdP 복구 응답 상태는 200 이 아니라 **201**(`{slot, schemaHash, uid, provider, restored:true}`) — 에이전트·헬퍼가 201 만 등록 성공으로 본다. 스펙 문구는 Task 5 에서 고친다.
- **Ruling P2(스펙 §4.2 정정):** "에이전트에 등록이 있을 때 같은 비밀이면 기존 등록을 돌려준다" 는 이미 있는 `POST /wallet/register/resume`(s_u·sk_u 를 받아 auid·pk_u 대조 후 기존 등록 반환)으로 충족한다 — `/wallet/register` 는 바꾸지 않는다. 스펙 문구는 Task 5 에서 고친다.
- **Ruling P3(비범위 명시):** 스냅에는 등록이 남고 에이전트 상태만 잃은 경우(codeRegister 의 Snap `register` 가 `already_registered`)는 이번에 다루지 않는다 — 스펙 §4.4 결과는 "스냅이 빈 경우"와 "둘 다 없는 경우" 두 가지다.

## Review Focus

1. 유도값과 다른 salt 를 가진 **옛 무작위 등록**(스냅 0.1.0 시절)에서 스냅 상태만 지운 경우 — 복구 시도는 `secrets_mismatch` 로 멈추고 지금처럼 안내해야 한다(다른 계정을 덮어쓰지 않음). → Task 3 테스트 "다른 시드면 복구하지 않는다".
2. 폐기(disabled)된 계정을 같은 비밀로 재등록 — 되살리지 않고 409 `account_disabled`. → Task 2 테스트.
3. 재등록 요청의 auid 는 같지만 pk_u 가 다른 경우(다른 SRP, 같은 salt 를 손으로 넣은 옛 기록) — 409, 슬롯·계정 불변. → Task 2 테스트.
4. 속성 도구에서 MetaMask 가 없거나 거절 — salt 칸이 비어 있고 사유가 보이며 "커밋먼트 만들기"가 진행되지 않아야 한다. → Task 4 테스트(window.ethereum 제거 페이지).
5. 복구 직후 첫 로그인에서 스냅에 동의·C_u 가 없음 — 새 C_u 발급·로그인 성공, PPID 동일. → Task 3 테스트(R1·R2 모두 PPID 비교).

---

### Task 1: 스냅 유도(`snap_getEntropy`) + `getSalt` + 매니페스트·시뮬레이터

**Files:**
- Modify: `snap-mode3/src/crypto.js` (createRegistrationSecrets·randomScalar → 유도 함수)
- Modify: `snap-mode3/src/index.js:11` (import), `:110-138` (register·prepareRegister), `:140` 근처(새 `getSalt`)
- Modify: `snap-mode3/snap.manifest.json` (권한·버전 — shasum 은 Step 7 의 빌드가 갱신)
- Modify: `snap-mode3/test/rpc.test.mjs` (스텁에 `snap_getEntropy`, 새 케이스, 352행 케이스 교체)
- Modify: `tests/helpers/snap_sim.mjs` (`getSalt`, 결정적 비밀 — 실제 스냅과 같은 입출력)
- Modify: `snap-mode3/dist/bundle.js`, `snap-mode3/dist/bundle.js.map` (빌드 산출물)

**Interfaces:**
- Produces (`snap-mode3/src/crypto.js`):
  - `export const ENTROPY_SALT_S_U = 'zkd/mode3/s_u/v1'`, `export const ENTROPY_SALT_SK_U = 'zkd/mode3/sk_u/v1'`
  - `export function saltFromEntropy(hex: string): string` — `0x`+64hex → s_u 10진 문자열 ∈ [1, 2^250−1]
  - `export function skFromEntropy(hex: string): string` — `0x`+64hex → 소문자 64 hex
  - `export async function deriveRegistrationSecrets(): Promise<{ s_u: string, sk_u: string }>` — 전역 `snap.request` 로 엔트로피 두 번
- Produces (스냅 RPC): `getSalt({}) → { s_u }`(등록 여부 무관), `register({uid, s_u?})` 는 s_u 가 주어지면 유도값과 같아야 함(다르면 `salt_not_derived: …` 로 throw)
- Produces (`tests/helpers/snap_sim.mjs`): `createSnapSim({ srp = 'zkd-test-srp-1' } = {})`, `sim.getSalt()`

- [ ] **Step 1: rpc.test 스텁에 엔트로피를 넣고 실패하는 케이스를 쓴다**

`snap-mode3/test/rpc.test.mjs` 의 `globalThis.snap = { request: … }` 안, `snap_dialog` 분기 뒤에 추가:

```js
    if (method === 'snap_getEntropy') {
      // MetaMask 는 (SRP, 스냅 ID, salt) 로 결정적 32바이트를 준다 — 스텁은 SRP 대역 문자열과 salt 의 SHA-256.
      if (params?.version !== 1 || typeof params?.salt !== 'string') throw new Error('stub: snap_getEntropy 는 { version: 1, salt }');
      return '0x' + createHash('sha256').update(`${entropy.srp}|${params.salt}`).digest('hex');
    }
```

파일 위쪽 import 에 `import { createHash } from 'node:crypto';` 와, `store` 정의 옆에 `const entropy = { srp: 'srp-A' };   // 테스트가 바꿔 "다른 SRP" 를 흉내 낸다` 를 둔다.

352행 케이스(`register({ uid, s_u }): 사용자가 정한 salt …`)를 통째로 아래 둘로 바꾼다:

```js
await t('유도(2026-11-12): 같은 SRP 면 register·prepareRegister·getSalt 가 같은 s_u·sk_u, 다른 SRP 면 다르다; reset 뒤에도 같다', async () => {
  entropy.srp = 'srp-A';
  const g = await call('getSalt', {});
  assert.match(g.s_u, /^[0-9]+$/); assert.ok(BigInt(g.s_u) >= 1n && BigInt(g.s_u) < (1n << 250n));
  assert.equal(store.state?.registration ?? null, null, 'getSalt 는 상태를 만들지 않는다');
  const r = await call('register', { uid: '7' });
  assert.equal(r.s_u, g.s_u); assert.match(r.sk_u, /^[0-9a-f]{64}$/);
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  const p = await call('prepareRegister', {});
  assert.equal(p.s_u, r.s_u, 'reset 뒤 보류 등록도 같은 s_u'); assert.equal(p.sk_u, r.sk_u, '같은 sk_u');
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  entropy.srp = 'srp-B';
  const b = await call('register', { uid: '7' });
  assert.notEqual(b.s_u, r.s_u, '다른 SRP 면 다른 s_u'); assert.notEqual(b.sk_u, r.sk_u);
  assert.equal((await call('getSalt', {})).s_u, b.s_u, '등록 뒤에도 getSalt 는 같은 값');
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  entropy.srp = 'srp-A';
});

await t('register({ uid, s_u }): s_u 는 유도값과 같을 때만 받는다 — 다르면 salt_not_derived 이고 아무것도 저장하지 않는다', async () => {
  const { s_u } = await call('getSalt', {});
  await assert.rejects(() => call('register', { uid: '7', s_u: '123456789' }), /salt_not_derived/);
  await assert.rejects(() => call('register', { uid: '7', s_u: 'abc' }), /salt_not_derived/);
  assert.equal(store.state?.registration ?? null, null);
  const r = await call('register', { uid: '7', s_u: ` 0${s_u} ` });
  assert.equal(r.s_u, s_u, '공백·앞자리 0 은 정규화 뒤 비교');
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
});

await t('saltFromEntropy·skFromEntropy: 경계값과 형식 오류', async () => {
  const { saltFromEntropy, skFromEntropy } = await import('../src/crypto.js');
  assert.equal(saltFromEntropy('0x' + '00'.repeat(32)), '1', '0 → 1(0 은 쓰지 않는다)');
  const max = (1n << 256n) - 1n; assert.equal(saltFromEntropy('0x' + 'ff'.repeat(32)), (1n + (max % ((1n << 250n) - 1n))).toString());
  assert.equal(skFromEntropy('0x' + 'AB'.repeat(32)), 'ab'.repeat(32));
  for (const bad of ['', '0x', '0x1234', 'zz'.repeat(32), '0x' + 'g'.repeat(64)]) {
    assert.throws(() => saltFromEntropy(bad), /bad_entropy/); assert.throws(() => skFromEntropy(bad), /bad_entropy/);
  }
});
```

- [ ] **Step 2: 실패 확인**

Run: `bash scripts/run_tests.sh snap`
Expected: FAIL — `getSalt` 모르는 method, `saltFromEntropy` 없음(import 실패), 유도 케이스의 s_u 불일치.

- [ ] **Step 3: crypto.js 를 유도로 바꾼다**

`snap-mode3/src/crypto.js` 의 `randomScalar`·`createRegistrationSecrets` 를 지우고(다른 사용처 없음 — `grep -rn "randomScalar\|createRegistrationSecrets" snap-mode3/src tests/helpers/ethereum_stub.js` 로 확인) 아래로 대체한다. 파일 첫 주석 블록 끝에 한 줄 덧붙인다: `// 2026-11-12(스펙 snap-derived-secrets): s_u·sk_u 는 무작위가 아니라 snap_getEntropy(SRP·스냅 ID 로 결정적)에서 유도한다 — 같은 시드면 같은 PPID 로 복구된다.`

```js
export const ENTROPY_SALT_S_U = 'zkd/mode3/s_u/v1';
export const ENTROPY_SALT_SK_U = 'zkd/mode3/sk_u/v1';
const entropyBig = (hex) => {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hex)) throw new Error('bad_entropy: snap_getEntropy 결과는 0x + 64자 16진이어야 한다');
  return BigInt(hex);
};
/** 엔트로피 → s_u ∈ [1, 2^250 − 1](10진 문자열). 0 은 쓰지 않는다(register 의 기존 범위 검사와 같다). */
export function saltFromEntropy(hex) { return (1n + (entropyBig(hex) % (SCALAR_MAX - 1n))).toString(); }
/** 엔트로피 → sk_u(소문자 64자 16진, 지금 형식과 같다 — EdDSA-Poseidon 은 아무 32바이트나 받는다). */
export function skFromEntropy(hex) { entropyBig(hex); return hex.slice(2).toLowerCase(); }
/** 등록 한 벌을 시드에서 — 같은 SRP·같은 스냅 ID 면 언제나 같은 값. salt 문자열의 v1 은 유도 규칙의 버전이다(규칙을 바꾸면 v2). */
export async function deriveRegistrationSecrets() {
  const get = (salt) => snap.request({ method: 'snap_getEntropy', params: { version: 1, salt } });
  return { s_u: saltFromEntropy(await get(ENTROPY_SALT_S_U)), sk_u: skFromEntropy(await get(ENTROPY_SALT_SK_U)) };
}
```

- [ ] **Step 4: index.js 의 register·prepareRegister·getSalt**

`import { createRegistrationSecrets, ATTR_MAX, SCALAR_MAX } from './crypto.js';` → `import { deriveRegistrationSecrets, ATTR_MAX, SCALAR_MAX } from './crypto.js';`
(`tests/helpers/ethereum_stub.js` 의 cryptoImport 정규식은 이름 목록과 무관하므로 그대로 맞는다.)

`case 'register'` 본문의 `const secrets = createRegistrationSecrets();` 부터 s_u 처리 블록 끝까지를 다음으로 바꾼다(주석의 2026-11-10 문단은 이 주석으로 대체):

```js
      // 2026-11-12(스펙 snap-derived-secrets S1·S2): s_u·sk_u 는 시드에서 유도한다. 속성 도구가 getSalt 로 받은 salt 를 다시 실어 보내면
      // 유도값과 같은지만 본다 — 다르면(옛 기록의 직접 입력 salt) 등록하지 않는다. 시드로 복구할 수 없는 계정이 섞이지 않게.
      const secrets = await deriveRegistrationSecrets();
      if (params.s_u !== undefined && params.s_u !== null && params.s_u !== '') {
        const su = String(params.s_u).trim();
        if (!isDec(su) || BigInt(su).toString() !== secrets.s_u) fail('salt_not_derived: salt 는 이 스냅이 시드에서 유도한 값이어야 한다(속성 도구 "스냅에서 가져오기")');
      }
```

`case 'prepareRegister'` 의 `const secrets = createRegistrationSecrets();` → `const secrets = await deriveRegistrationSecrets();`

`case 'showSalt'` 블록 바로 앞에 추가:

```js
    // 속성 도구용(2026-11-12, 스펙 §2.3): 등록 전에도 시드에서 유도한 s_u 를 돌려준다. 등록 여부와 무관하게 같은 값이고 상태를 바꾸지 않는다.
    // 부를 수 있는 오리진은 다른 RPC 와 같이 지갑 오리진(:5100)뿐이다 — 속성 도구(/attr.html)도 그 오리진에서 서빙된다.
    case 'getSalt': {
      const { s_u } = await deriveRegistrationSecrets();
      return { s_u };
    }
```

- [ ] **Step 5: 매니페스트 권한·버전**

`snap-mode3/snap.manifest.json`: `"version": "0.1.0"` → `"0.2.0"`, `initialPermissions` 에 `"snap_getEntropy": {}` 추가(키 순서는 `endowment:rpc`, `snap_dialog`, `snap_getEntropy`, `snap_manageState`). `snap-mode3/package.json` 에 version 필드가 있으면 같이 `0.2.0`(mm-snap 이 두 값의 일치를 검사한다).

- [ ] **Step 6: 테스트 통과 확인**

Run: `bash scripts/run_tests.sh snap`
Expected: PASS(전 케이스). 예전 케이스 "register({ uid }): … 상태에 s_u·sk_u" 등은 유도값으로도 그대로 통과해야 한다.

- [ ] **Step 7: 번들 재빌드**

Run: `cd snap-mode3 && npm run build`
Expected: `dist/bundle.js`·`dist/bundle.js.map` 갱신, `snap.manifest.json` 의 `source.shasum` 갱신, 빌드 성공(manifest 검증 경고 없음). 경고가 나면 그 문구를 보고하고 멈춘다.

- [ ] **Step 8: snap_sim 을 같은 입출력으로**

`tests/helpers/snap_sim.mjs`: `createSnapSim()` → `createSnapSim({ srp = 'zkd-test-srp-1' } = {})`. 결정적 비밀 함수를 파일 안에 둔다(실제 스냅과 같은 규칙 — 브라우저 스텁과 같은 SHA-256 대역):

```js
import { createHash } from 'node:crypto';
import { saltFromEntropy, skFromEntropy, ENTROPY_SALT_S_U, ENTROPY_SALT_SK_U } from '../../snap-mode3/src/crypto.js';
/** 실제 스냅의 deriveRegistrationSecrets 와 같은 규칙 — snap_getEntropy 대역은 sha256(`${srp}|${salt}`). */
export const stubEntropy = (srp, salt) => '0x' + createHash('sha256').update(`${srp}|${salt}`).digest('hex');
export const derivedSecrets = (srp) => ({ s_u: saltFromEntropy(stubEntropy(srp, ENTROPY_SALT_S_U)), sk_u: skFromEntropy(stubEntropy(srp, ENTROPY_SALT_SK_U)) });
```

`register({ uid })`: `createRegistration(BigInt(uidStr))` 대신 `const { s_u, sk_u } = derivedSecrets(srp);` 로 상태를 채우고 같은 모양을 돌려준다(`s_u` 인자 검사는 실제 스냅과 같은 `salt_not_derived`). `prepareRegister()`: `registrationSecretsFromSeed(randomBytes)` 대신 `derivedSecrets(srp)`. `getSalt()` 추가 → `{ s_u: derivedSecrets(srp).s_u }`. 쓰지 않게 된 import(`createRegistration`, `registrationSecretsFromSeed`, `randomBytes`)는 지운다.

`snap-mode3/src/crypto.js` 는 import 가 없는 순수 ESM 이라 Node 에서 그대로 import 된다(전역 `snap` 은 `deriveRegistrationSecrets` 를 부를 때만 필요).

- [ ] **Step 9: 시뮬레이터 사용 테스트 확인**

Run: 임시 hardhat(:8545)을 CLAUDE.md 규칙대로 띄운 뒤 `node tests/test_mode3_wallet_snap.mjs && node tests/test_mode3_wallet_snap_oidc.mjs`
Expected: PASS. 시뮬레이터 하나로 같은 uid 를 두 번 등록하는 케이스가 있으면 이제 같은 비밀이라 IdP 가 Task 2 전에는 409 를 준다 — 그런 케이스가 실패하면 그 케이스에만 `createSnapSim({ srp: '<케이스별 문자열>' })` 를 주고 Ruling 으로 기록한다.

- [ ] **Step 10: 커밋**

```bash
git add snap-mode3/src/crypto.js snap-mode3/src/index.js snap-mode3/snap.manifest.json snap-mode3/package.json snap-mode3/dist/bundle.js snap-mode3/dist/bundle.js.map snap-mode3/test/rpc.test.mjs tests/helpers/snap_sim.mjs
git commit -m "feat(snap): s_u·sk_u 를 snap_getEntropy 에서 유도(0.2.0), getSalt, register 의 salt 는 유도값만(스펙 snap-derived-secrets §2)"
```
(package.json 이 바뀌지 않았으면 경로에서 뺀다.)

---

### Task 2: IdP — 같은 비밀 재등록 = 복구

**Files:**
- Modify: `cia.js:977-980` 근처 아님 — `/cia/auth/code` 의 `purpose === 'register'` 분기(현재 `if (a.pk_u) return res.status(409)…`, 약 1024행), `registerAccount`(약 1080-1100행), `/cia/register` 응답(약 1073행)
- Test: `tests/test_cia_register_issue.mjs`(새 케이스), `tests/test_cia_accounts.mjs:159-160`(기존 단언 변경 + 새 단언)

**Interfaces:**
- Produces: `registerAccount(...)` 성공 결과 `{ slot, restored?: true }`. `/cia/register` 201 본문에 복구일 때만 `restored: true`(새 등록은 키 없음 — 기존 키 목록 단언을 깨지 않는다).
- Produces: `/cia/auth/code`(`purpose:'register'`) — 이미 등록된 계정이라도 `auid === a.auid` 면 200 등록 코드, 다르면 409 `already_registered`.

- [ ] **Step 1: 실패하는 테스트**

`tests/test_cia_register_issue.mjs` 의 `'register: 잘못된 비밀번호는 401, 재등록은 409'` 케이스 바로 뒤에 추가(파일 상단 import 에 `createRegistration`, `signRegistration` 이 없으면 `../lib/mode3_wallet.js` 에서 가져오고, `pointToStrings` 가 없으면 `const pts = (p) => ({ x: p.x.toString(), y: p.y.toString() });` 를 쓴다):

```js
  await t('복구(2026-11-12, 스펙 snap-derived-secrets S3): 같은 auid·pk_u·서명으로 재등록하면 201 restored·같은 slot, 슬롯을 새로 잡지 않는다; 하나라도 다르면 409; disabled 면 409 account_disabled', async () => {
    const seed = Buffer.alloc(32, 7);
    const su = await cia.post('/cia/signup', { id: 'restore-1', pwd: 'restore-pw-1' }); assert.equal(su.status, 201, JSON.stringify(su.body));
    const uidR = su.body.uid;
    const reg = await createRegistration(BigInt(uidR), seed);
    const body = async (r) => ({ uid: uidR, pwd: 'restore-pw-1', auid: r.auid.toString(), pk_u: { x: r.pk_u.x.toString(), y: r.pk_u.y.toString() }, sig_reg: await signRegistration(r.sk_u, BigInt(uidR), r.auid) });
    const first = await cia.post('/cia/register', await body(reg));
    assert.equal(first.status, 201, JSON.stringify(first.body)); assert.equal(first.body.restored, undefined, '새 등록에는 restored 가 없다');
    const nextBefore = (await cia.get('/cia/state')).body;
    const again = await cia.post('/cia/register', await body(reg));
    assert.equal(again.status, 201, JSON.stringify(again.body)); assert.equal(again.body.restored, true); assert.equal(again.body.slot, first.body.slot);
    assert.deepEqual((await cia.get('/cia/state')).body, nextBefore, '복구는 상태(등록부·epoch)를 바꾸지 않는다');
    // 같은 uid, 다른 비밀(다른 SRP) — auid·pk_u 가 다르다
    const other = await createRegistration(BigInt(uidR), Buffer.alloc(32, 8));
    assert.equal((await cia.post('/cia/register', await body(other))).status, 409);
    // auid 는 같고 pk_u 만 다름 — 서명은 그 다른 키로
    const mixed = { ...(await body(reg)), pk_u: { x: other.pk_u.x.toString(), y: other.pk_u.y.toString() }, sig_reg: await signRegistration(other.sk_u, BigInt(uidR), reg.auid) };
    assert.equal((await cia.post('/cia/register', mixed)).status, 409, 'pk_u 가 다르면 복구가 아니다');
    // 같은 auid·pk_u 지만 서명이 틀림
    const badSig = { ...(await body(reg)), sig_reg: await signRegistration(other.sk_u, BigInt(uidR), reg.auid) };
    assert.equal((await cia.post('/cia/register', badSig)).status, 400);
    // 폐기된 계정은 되살리지 않는다
    assert.equal((await cia.post('/cia/self_revoke', { uid: uidR, pwd: 'restore-pw-1' })).status, 200);
    const dis = await cia.post('/cia/register', await body(reg));
    assert.equal(dis.status, 409, JSON.stringify(dis.body)); assert.equal(dis.body.reason, 'account_disabled');
  });
```

(`/cia/signup`·`/cia/self_revoke` 의 실제 본문 모양은 같은 파일·`test_cia_accounts.mjs` 의 기존 호출과 맞춘다 — 이 파일의 self_revoke 케이스가 쓰는 필드 이름을 그대로 쓴다. `/cia/state` 가 없으면 `cia.adminGet('/cia/accounts')` 의 해당 계정 `slot` 과 등록부 크기로 비교한다.)

`tests/test_cia_accounts.mjs` 159-160행(`const again = …; assert.equal(again.status, 409 …)`)을 다음으로 바꾼다:

```js
      // 2026-11-12(스펙 snap-derived-secrets S3): 이미 등록된 계정도 같은 auid 면 등록 코드를 준다(복구 — 같은 비밀로 다시 등록). 다른 auid 면 409.
      const again = await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'password-r1', purpose: 'register', auid: reg.auid.toString() });
      assert.equal(again.status, 200, j(again.body)); assert.equal(again.body.purpose, 'register');
      const diff = await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'password-r1', purpose: 'register', auid: other.auid.toString() });
      assert.equal(diff.status, 409, j(diff.body)); assert.equal(diff.body.reason, 'already_registered');
      const rr = await cia8.post('/cia/register', { uid: uid8, code: again.body.code, auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg: await signRegistration(reg.sk_u, BigInt(uid8), reg.auid) });
      assert.equal(rr.status, 201, j(rr.body)); assert.equal(rr.body.restored, true); assert.equal(rr.body.slot, r1.body.slot);
      assert.match(rr.body.issue_code, /^[0-9a-f]{64}$/, '복구도 등록 코드 경로면 발급 코드를 준다');
```

(이 뒤의 `issueV11(… overrides: { auth_code: r1.body.issue_code })` 는 그대로 — r1 의 발급 코드는 아직 쓰이지 않았다.)

- [ ] **Step 2: 실패 확인**

Run: 임시 hardhat(:8545) 위에서 `node tests/test_cia_register_issue.mjs; node tests/test_cia_accounts.mjs`
Expected: 새 복구 케이스 FAIL(재등록이 409), accounts 의 auth/code 케이스 FAIL(again 409).

- [ ] **Step 3: registerAccount 구현**

`registerAccount` 의 첫 `if (state.accounts[uid]?.pk_u) return fail(409, { error: 'already registered' });` 를 다음으로 바꾼다:

```js
  // 복구(2026-11-12, 스펙 snap-derived-secrets S3): 스냅 비밀이 시드에서 유도되므로, MetaMask 를 다시 깐 사용자는 같은 (auid, pk_u) 로 다시 등록한다.
  // 저장값과 둘 다 같고 sig_reg 가 그 pk_u 로 맞으면 슬롯을 새로 잡지 않고 기존 등록을 돌려준다(상태 변경·게시 없음). 하나라도 다르면 지금처럼 409.
  // 로그인 수단(비밀번호·코드·Google)과 같은 시드가 둘 다 있어야 하므로 공격면은 그대로다. 폐기된 계정은 되살리지 않는다.
  const prev = state.accounts[uid];
  const sameKeys = Boolean(prev?.pk_u) && isPt(pk_u) && String(prev.auid) === String(auid) && String(prev.pk_u.x) === String(pk_u.x) && String(prev.pk_u.y) === String(pk_u.y);
  if (prev?.pk_u && !sameKeys) return fail(409, { error: 'already registered' });
  if (sameKeys && prev.disabled) return fail(409, { error: 'account disabled', reason: 'account_disabled' });
```

그리고 서명 검증(`if (!ok) return fail(400, …)`) 뒤의 경합 재검사 줄을 다음으로 바꾼다:

```js
  if (sameKeys) {
    if (beforeCommit && !beforeCommit()) return fail(401, { error: 'bad_code', reason: 'bad_code' });
    return { slot: prev.slot, restored: true };
  }
  if (state.accounts[uid]?.pk_u) return fail(409, { error: 'already registered' });   // await 사이 경합
```

(`String(auid)` 비교는 정규형 문제를 피하려고 `BigInt(auid).toString()` 으로 맞춘다: `String(prev.auid) === BigInt(auid).toString()` — `isDec(auid)` 는 이미 위에서 검사됐다. pk_u 도 `BigInt(pk_u.x).toString()` 비교.)

- [ ] **Step 4: /cia/register 응답과 /cia/auth/code**

`/cia/register` 끝의 `res.status(201).json({ slot: made.slot, schemaHash: ATTR_SCHEMA_HASH, uid, provider, ...(issue_code ? { issue_code } : {}) });` 에 `...(made.restored ? { restored: true } : {})` 를 더한다. provider 는 복구일 때 `state.accounts[uid].provider ?? provider` 를 쓴다(아이디 계정을 Google 경로로 복구하는 일은 uid 가 달라 생기지 않지만 저장값이 정본).

`/cia/auth/code` 의 `if (a.pk_u) return res.status(409)…` 를 다음으로 바꾼다(auid 검사 줄 뒤로 옮긴다):

```js
    if (!isDec(auid)) return res.status(400).json({ error: 'auid required', reason: 'bad_auid' });
    // 2026-11-12(스펙 snap-derived-secrets S3): 이미 등록된 계정도 같은 auid 면 등록 코드를 준다 — 복구(같은 비밀로 다시 등록). 다르면 409.
    if (a.pk_u && String(a.auid) !== BigInt(auid).toString()) return res.status(409).json({ error: 'already registered', reason: 'already_registered' });
```

(원래 순서는 409 → auid 검사였다. 이제 auid 가 없으면 400 `bad_auid` 가 먼저다 — 기존 테스트 `noAuid` 는 미등록 계정이라 영향 없다.)

`/cia/user/register_code`(auid 를 받지 않는 `/user` 경로)는 그대로 둔다.

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_cia_register_issue.mjs && node tests/test_cia_accounts.mjs && node tests/test_cia_oidc_register.mjs`
Expected: 모두 PASS. (`test_cia_oidc_register.mjs` 에 "같은 Google 계정 재등록 409" 류 단언이 있고 그 요청이 같은 키를 재사용한다면 이제 201 restored 가 맞다 — 그 단언만 의도에 맞게 고치고 Ruling 으로 기록.)

- [ ] **Step 6: 커밋**

```bash
git add cia.js tests/test_cia_register_issue.mjs tests/test_cia_accounts.mjs
git commit -m "feat(idp): 같은 auid·pk_u·서명의 재등록은 복구(201 restored, 같은 slot), 인증 창 등록 코드도 같은 auid 면 발급, 폐기 계정은 409(스펙 snap-derived-secrets S3)"
```

---

### Task 3: 지갑 팝업 복구 + 브라우저 스텁 엔트로피 + 브라우저 테스트

**Files:**
- Modify: `tests/helpers/ethereum_stub.js` (`snap_getEntropy`, `STUB_SRP`, `buildInitScript({…, srp})`)
- Modify: `mode3/wallet.html` (새 `restoreSnapIfEmpty`, processAuthorize 두 곳에서 호출, `handleRegisterMessage` 의 `snap_empty` 분기)
- Modify: `mode3/common/strings.js` (reason `snap_restore_mismatch`)
- Test: `tests/test_mode3_browser.mjs`(USER_SALT 를 유도값으로, 복구 케이스 R1·R2), `tests/test_mode3_wallet_snap_oidc_browser.mjs`(Google R1)

**Interfaces:**
- Consumes: Task 1 의 `getSalt`/유도 규칙, `tests/helpers/snap_sim.mjs` 의 `derivedSecrets(srp)`; Task 2 의 IdP 복구.
- Produces (`tests/helpers/ethereum_stub.js`): `export const STUB_SRP = 'zkd-test-srp-1'`; `buildInitScript({ snapId, account, chainId, srp = STUB_SRP })` — 페이지의 `snap_getEntropy` 는 `'0x' + sha256(`${srp}|${salt}`)`(snap_sim 의 `stubEntropy` 와 같은 값).
- Produces (`mode3/wallet.html`): `async function restoreSnapIfEmpty({ step, log }) → null | { ok: true } | { ok: false, reason, detail? }`

- [ ] **Step 1: 스텁에 엔트로피**

`tests/helpers/ethereum_stub.js`: `export const STUB_SRP = 'zkd-test-srp-1';` 추가, `buildInitScript({ snapId, account, chainId, srp = STUB_SRP })`, 스크립트 안 `const SRP = ${JSON.stringify(srp)};`, `window.snap.request` 에 분기 추가:

```js
      if (method === 'snap_getEntropy') {
        // MetaMask 는 (SRP, 스냅 ID, salt) 로 결정적 32바이트를 준다 — 스텁은 SRP 대역 문자열과 salt 의 SHA-256(tests/helpers/snap_sim.mjs stubEntropy 와 같은 값).
        if (!params || params.version !== 1 || typeof params.salt !== 'string') throw new Error('ethereum_stub: snap_getEntropy 는 { version: 1, salt }');
        const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(SRP + '|' + params.salt)));
        return '0x' + Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
      }
```

`snaps` 객체의 `version: '0.1.0'` → `'0.2.0'`.

- [ ] **Step 2: 브라우저 테스트의 USER_SALT 를 유도값으로**

`tests/test_mode3_browser.mjs` 69행 `const USER_SALT = '1234…';` → 
```js
  // 2026-11-12(스펙 snap-derived-secrets): salt 는 스냅이 시드에서 유도한다 — 스텁 SRP(STUB_SRP)의 유도값이 곧 이 사용자의 salt 다.
  const USER_SALT = derivedSecrets(STUB_SRP).s_u;
```
import 에 `import { derivedSecrets } from './helpers/snap_sim.mjs';` 와 `STUB_SRP`(ethereum_stub.js)를 더한다. 이 단계만으로 기존 케이스가 그대로 통과해야 한다(등록 때 기록의 s_u 가 유도값과 같으므로 `salt_not_derived` 가 나지 않는다).

Run: 임시 hardhat 위에서 `node tests/test_mode3_browser.mjs`
Expected: 기존 34 케이스 PASS(복구 케이스는 아직 없음). 실패하면 원인을 고치기 전에 보고(이 단계는 동작 변경이 없어야 한다).

- [ ] **Step 3: 실패하는 복구 케이스 R1·R2**

`tests/test_mode3_browser.mjs` 에서 첫 등록·로그인 케이스(`첫 로그인 = 지갑 등록(2026-11-09)…`) 이후, 속성 변경 케이스들 앞의 적당한 위치(다른 케이스가 스냅 상태에 기대지 않는 지점 — 실행해 보고 정한다)에 추가:

```js
  // 2026-11-12(스펙 snap-derived-secrets §4): 같은 SRP 로 MetaMask 를 다시 깔면 스냅이 같은 비밀을 유도한다 — 등록이 돌아오고 PPID 가 같다.
  const ppids = async () => (await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.filter((l) => l.PPID).map((l) => l.PPID);
  await t('복구 R1: 스냅 상태만 잃음(MetaMask 재설치) → RP 로그인이 유도 비밀로 스냅 등록을 되살리고 같은 PPID 로 로그인', async () => {
    const before = await ppids(); const known = new Set(before);
    snapState = null;   // MetaMask 재설치 — 확장의 암호화 저장소가 비었다
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await awaitPopupClosed(popup);
    assert.equal(snapState.registration?.uid, uid, '스냅 등록이 돌아왔다'); assert.equal(snapState.registration?.s_u, USER_SALT);
    assert.equal(snapState.registration?.auid, AUID);
    const after = await ppids();
    assert.equal(after.length, before.length + 1, '로그인 한 번이 더 기록됐다');
    assert.deepEqual(new Set(after), known, '새 PPID 가 생기지 않았다 — 같은 PPID');
  });
  await t('복구 R2: 스냅·에이전트 상태 둘 다 잃음(새 PC) → 등록 모드 인증 창 → IdP 가 같은 비밀 재등록을 복구로 받아 같은 PPID', async () => {
    const before = await ppids(); const known = new Set(before);
    snapState = null;
    assert.equal((await wallet.post('/wallet/reset', { confirm: true })).status, 200);
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    assert.equal(new URL(popup.url()).searchParams.get('purpose'), 'register', '에이전트가 비어 등록 모드로 간다');
    const demoId = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === String(uid)).id ?? String(uid);
    await popup.fill('#authUid', demoId); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', String(AUID)); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await awaitPopupClosed(popup);
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.registered, true); assert.equal(String(st.uid), String(uid)); assert.equal(st.auid, AUID);
    const after = await ppids();
    assert.equal(after.length, before.length + 1); assert.deepEqual(new Set(after), known, '같은 PPID');
  });
  await t('다른 SRP 의 스냅으로는 복구하지 않는다 — 스냅이 비었고 에이전트 등록과 비밀이 다르면 snap_restore_mismatch 로 멈춘다', async () => {
    const saved = snapState;
    snapState = null;
    await context.addInitScript({ content: 'window.__srpOverride = "other-srp";' });   // 아래 Step 4 의 훅 — 이 컨텍스트의 새 페이지부터 적용
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(popup);
    await waitText(rpPage, '#verdict', '이 스냅의 비밀이 등록과 다릅니다', 120_000);
    assert.notEqual(snapState?.registration?.uid, uid, '다른 계정 등록을 만들지 않았다');
    await context.addInitScript({ content: 'window.__srpOverride = null;' });
    snapState = saved;
  });
```

(마지막 케이스가 쓰는 `window.__srpOverride` 는 Step 4 에서 스텁에 넣는다: 엔트로피 계산이 `(window.__srpOverride || SRP)` 를 쓴다. `addInitScript` 는 누적되므로 두 번째 스크립트가 나중에 실행돼 null 로 되돌린다. 기대 문구는 Step 6 의 ko title 과 같아야 한다.)

- [ ] **Step 4: 스텁 훅**

`ethereum_stub.js` 의 엔트로피 분기에서 `SRP + '|'` 를 `(window.__srpOverride || SRP) + '|'` 로 바꾼다(테스트 전용 훅 — 실제 MetaMask 에는 없다는 주석 한 줄).

- [ ] **Step 5: 실패 확인**

Run: `node tests/test_mode3_browser.mjs`
Expected: R1 FAIL(팝업이 `registration_incomplete`/"등록이 반만 됐다"로 끝남), R2 FAIL 또는 Task 2 가 들어가 있으면 PASS 일 수 있다(R2 는 IdP 복구만으로 통과하는 경로 — PASS 면 그대로 기록), mismatch 케이스 FAIL.

- [ ] **Step 6: wallet.html 복구 함수**

`googleRegister` 함수 바로 뒤에 추가:

```js
    /** 스냅 복구(2026-11-12, 스펙 snap-derived-secrets §4.3): 에이전트에는 등록이 있는데 스냅이 비었으면(MetaMask 재설치) 스냅이 시드에서 같은 비밀을
     *  다시 유도하므로, 보류 등록으로 그 비밀을 받아 에이전트 /wallet/register/resume 로 대조하고(auid·pk_u) 맞으면 스냅에 등록을 채운다.
     *  할 일이 없으면 null, 복구했으면 { ok:true }, 비밀이 다르면(옛 무작위 등록·다른 SRP) { ok:false, reason:'snap_restore_mismatch' }. */
    async function restoreSnapIfEmpty({ step, log }) {
      let st = null;
      try { st = await (await fetch('/wallet/status')).json(); } catch { return null; }   // 못 읽으면 지금처럼 진행 — 뒤 단계가 다시 거른다
      if (!st?.registered) return null;
      const info = await invokeSnap('getPublicInfo', {});
      if (info?.registered) return null;
      step('스냅이 비어 있다 — 시드에서 같은 비밀을 다시 만들어 등록을 되살리는 중…');
      const prep = await invokeSnap('prepareRegister', {});
      if (!prep || prep.denied) return { ok: false, reason: 'user_denied' };
      const { status, body: b } = await postJson('/wallet/register/resume', { s_u: prep.s_u, sk_u: prep.sk_u });
      if (status !== 200) {
        log(errText(status, b));
        return { ok: false, reason: b.reason === 'secrets_mismatch' ? 'snap_restore_mismatch' : (b.reason ?? 'wallet_error'), detail: b.detail ?? null };
      }
      await invokeSnap('storeRegistration', { attrs: b.attrs, slot: b.slot, auid: b.auid, uid: b.uid, provider: b.provider });
      step('스냅 등록을 되살렸다.');
      return { ok: true };
    }
```

processAuthorize 의 두 곳에 호출을 넣는다:

1. 재승인 분기 `if (!(await connect())) return;` 바로 뒤:
```js
          const rs = await restoreSnapIfEmpty({ step, log });
          if (rs && !rs.ok) { step('스냅 복구 실패 — 재승인하지 않는다.'); return reply(rs); }
```
2. 본 로그인의 `if (!(await connect())) return;` (바로 다음 줄이 `const sync = await syncAttrsFromRecord(...)`) 바로 뒤:
```js
        const rs = await restoreSnapIfEmpty({ step, log });   // 2026-11-12: 스냅만 비었으면(MetaMask 재설치) 증인 전에 등록을 되살린다
        if (rs && !rs.ok) { step('스냅 복구 실패 — 로그인하지 않는다.'); return reply(rs); }
```

`handleRegisterMessage` 의 `if (info && !info.registered) { step('에이전트에는 등록이 있지만 이 스냅은 비어 있습니다 — …'); return reply({ … 'snap_empty' }); }` 를 다음으로 바꾼다:
```js
          if (info && !info.registered) {
            // 2026-11-12(스펙 snap-derived-secrets §4.3): 스냅만 비었으면 시드 유도 비밀로 되살린다(예전엔 재시연 세트로 둘 다 비우라고 안내했다).
            const rs = await restoreSnapIfEmpty({ step, log });
            if (rs?.ok) { step('등록을 되살렸다 — 창을 닫는다.'); return reply({ ok: true, restored: true }); }
            return reply(rs ?? { ok: false, reason: 'already_registered', detail: 'snap_empty' });
          }
```

- [ ] **Step 7: 사유 문자열**

`mode3/common/strings.js` 의 reasons 에서 `snap_other_account:` 줄 바로 뒤에:
```js
    snap_restore_mismatch: { where: 'wallet', ko: { title: '이 스냅의 비밀이 등록과 다릅니다', cause: '스냅이 시드에서 만든 비밀이 이 PC 에 등록된 zkID 계정의 비밀과 다릅니다 — 다른 시드(SRP)의 MetaMask 이거나, 시드 유도 전에 등록한 계정입니다.', action: '등록할 때의 시드로 MetaMask 를 복원하세요. 시드 유도 전에 등록한 계정은 속성 도구 백업의 salt 로만 되찾을 수 있습니다.' }, en: { title: "This Snap's secrets don't match the registration", cause: 'The secrets this Snap derives from its seed differ from the zkID account registered on this PC — a MetaMask with a different seed (SRP), or an account registered before seed derivation.', action: 'Restore MetaMask with the seed used at registration. Accounts registered before seed derivation can only be recovered from the attribute tool backup salt.' } },
```

- [ ] **Step 8: Google R1 케이스**

`tests/test_mode3_wallet_snap_oidc_browser.mjs` 에서 Google 래퍼로 등록·로그인한 케이스 뒤(그 파일의 `/wallet/reset` 케이스보다 앞)에 추가 — 그 파일의 기존 로그인 헬퍼·GIS 스텁 클릭 방식을 그대로 쓴다:

```js
  await t('복구 R1(Google, 2026-11-12): 스냅 상태만 잃으면 RP "Google 계정으로 로그인" 이 유도 비밀로 스냅을 되살리고 같은 PPID', async () => {
    // 이 파일의 앞 케이스가 Google 계정으로 등록·로그인한 상태여야 한다(에이전트 provider=google)
    const ppids = async () => (await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.filter((l) => l.PPID).map((l) => l.PPID);
    const before = await ppids();
    snapState = null;
    // 이 파일의 Google 래퍼 로그인 순서(RP 로그인 창 → googleLoginBtn → 팝업 GIS 스텁 클릭)를 그대로 쓴다
    await googleWrapperLogin();   // 없으면 이 파일의 기존 래퍼 케이스 본문을 함수로 뽑아 쓴다(Ruling 으로 기록)
    assert.equal(snapState.registration?.provider, 'google');
    const after = await ppids();
    assert.equal(after.length, before.length + 1); assert.deepEqual(new Set(after), new Set(before), '같은 PPID');
  });
```

(`googleWrapperLogin` 은 그 파일의 기존 래퍼 케이스("RP 의 Google 계정으로 로그인 = 래퍼" 류)의 클릭·대기 순서를 함수로 뽑은 것이다. 뽑을 때 기존 케이스도 그 함수를 쓰게 바꿔 중복을 남기지 않는다.)

- [ ] **Step 9: 통과 확인**

Run: `bash scripts/run_tests.sh browser`
Expected: 4 파일 모두 PASS(test_mode3_browser 는 34+3, oidc_browser 는 9+1).

- [ ] **Step 10: 커밋**

```bash
git add tests/helpers/ethereum_stub.js mode3/wallet.html mode3/common/strings.js tests/test_mode3_browser.mjs tests/test_mode3_wallet_snap_oidc_browser.mjs
git commit -m "feat(mode3): 스냅만 비면 로그인 팝업이 시드 유도 비밀로 등록을 되살린다(/wallet/register/resume), 둘 다 없으면 IdP 복구로 같은 PPID(스펙 snap-derived-secrets §4)"
```

---

### Task 4: 속성 도구 — salt 는 "스냅에서 가져오기"

**Files:**
- Modify: `mode3/attr.html` (salt 칸 읽기 전용, `#saltFromSnapBtn`, `saltGenBtn` 제거, 불일치 경고 `#saltWarn`)
- Modify: `mode3/common/strings.js` (attr_salt_hint 갱신, attr_salt_from_snap_btn, attr_salt_not_derived, reason `snap_unavailable` 재사용 확인)
- Test: `tests/test_mode3_browser.mjs:636-712` (속성 도구 두 케이스)

**Interfaces:**
- Consumes: 스냅 RPC `getSalt` (Task 1), 에이전트 `GET /wallet/config` → `{ snapId }`(기존), 브라우저 스텁(Task 3).
- Produces: `#saltFromSnapBtn` 클릭 → `#salt` 에 유도 s_u, 실패 시 `#formVerdict` 에 사유. 기록을 열 때 `rec.s_u !== 스냅 salt` 면 `#saltWarn` 표시(스냅을 읽을 수 있을 때만 — 자동으로 MetaMask 를 부르지 않고, 가져오기 뒤에 비교).

- [ ] **Step 1: 테스트를 새 동작으로 바꾼다(실패)**

636행 케이스에서
```js
    await p.fill('#uid', String(uid)); await p.click('#saltGenBtn');
    const gen = await p.inputValue('#salt'); assert.match(gen, /^[0-9]+$/); assert.ok(BigInt(gen) < (1n << 250n));
    await p.fill('#salt', USER_SALT);   // 지갑 등록 때 넣은 것과 같은 salt
```
를 다음으로:
```js
    // 2026-11-12(스펙 snap-derived-secrets S2): salt 는 직접 넣지 않는다 — "스냅에서 가져오기" 가 시드 유도 salt 를 채운다.
    assert.equal(await p.$('#saltGenBtn'), null, '"salt 새로 뽑기" 는 없다');
    assert.equal(await p.getAttribute('#salt', 'readonly'), '', 'salt 칸은 읽기 전용');
    await p.fill('#uid', String(uid)); await p.click('#saltFromSnapBtn');
    await p.waitForFunction(() => document.getElementById('salt').value !== '');
    assert.equal(await p.inputValue('#salt'), USER_SALT, '스냅이 유도한 salt(지갑 등록 때와 같은 값)');
```
같은 케이스 666행의 요청 허용 정규식에 `\/wallet\/config` 를 더한다(가져오기가 snapId 를 읽는다):
```js
    const okReq = (u) => /\/attr\.html|\/attr\/dist\/|\/common\/|\/wallet\/config$/.test(u);
    assert.ok(reqs.every(okReq), `정적 자원 외 요청: ${reqs.filter((u) => !okReq(u)).join(', ')}`);
```
그리고 케이스 제목의 "정적 자원 말고는 아무 요청도 없이" 를 "정적 자원과 스냅 설정(/wallet/config) 말고는 요청 없이" 로 바꾼다.

자동 백업 케이스(약 707행)의 `make` 안 `await p.fill('#salt', USER_SALT);` 를 `await p.click('#saltFromSnapBtn'); await p.waitForFunction(() => document.getElementById('salt').value !== '');` 로 바꾼다.

새 케이스(자동 백업 케이스 뒤):
```js
  await t('속성 도구: MetaMask 가 없으면 salt 를 못 가져오고 사유를 보이며 커밋먼트를 만들지 않는다; 옛 기록의 salt 가 스냅 salt 와 다르면 경고', async () => {
    const p = await context.newPage();
    await p.addInitScript(() => { delete window.ethereum; });
    await p.goto(`${wallet.base}/attr.html`);
    await p.fill('#uid', String(uid)); await p.click('#saltFromSnapBtn');
    await waitText(p, '#formVerdict', 'MetaMask');
    assert.equal(await p.inputValue('#salt'), '', 'salt 는 비어 있다');
    await p.close();
    const q = await context.newPage();
    await q.goto(`${wallet.base}/attr.html`);
    await q.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r)), { ...JSON.parse(await q.evaluate(() => localStorage.getItem('mode3_attr_tool_v1'))), s_u: '987654321' });
    await q.reload(); await q.click('#saltFromSnapBtn');
    await q.waitForSelector('#saltWarn:not([hidden])');
    assert.ok((await q.textContent('#saltWarn')).includes('시드로 복구할 수 없는'));
    await q.close();
  });
```
(이 케이스는 기록을 바꿔 두므로 끝에서 원래 기록을 되돌리거나, 뒤 케이스가 기록에 기대면 그 전에 원래 값을 저장해 두었다가 복원한다 — 실행해 보고 맞춘다. 단, 기록의 `commit` 이 s_u 와 맞지 않아 `load()` 가 거절하지는 않는다: `load()` 는 형식만 본다.)

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_browser.mjs`
Expected: 속성 도구 케이스들 FAIL(`#saltFromSnapBtn` 없음).

- [ ] **Step 3: attr.html 마크업**

43-45행을 다음으로(주석 38-40행의 2026-11-10 문단은 새 주석으로 대체):
```html
      <!-- 2026-11-12(스펙 snap-derived-secrets S2): salt 는 스냅이 MetaMask 시드에서 유도한다 — 직접 넣지 않고 "스냅에서 가져오기" 로 받는다. 같은 시드면 언제나 같은 값이라
           MetaMask 를 시드로 복원하면 같은 PPID 로 돌아온다. -->
      <p class="muted" data-i18n="attr_salt_hint">salt 는 스냅이 MetaMask 시드에서 만듭니다 — "스냅에서 가져오기" 를 누르세요. 시드만 있으면 같은 salt 가 다시 나옵니다.</p>
      <label><span data-i18n="attr_salt">salt (s_u)</span> <input id="salt" inputmode="numeric" pattern="[0-9]+" placeholder="98765…" required readonly /></label>
      <p class="row-actions"><button type="button" id="saltFromSnapBtn" class="btn-ghost" data-i18n="attr_salt_from_snap_btn">스냅에서 가져오기</button> <button type="button" id="copySaltBtn" …(기존 그대로)…</p>
      <p id="saltWarn" class="warn" hidden data-i18n="attr_salt_not_derived">이 기록의 salt 는 스냅이 만든 값과 다릅니다 — 시드로 복구할 수 없는 salt 입니다.</p>
```
(`copySaltBtn` 버튼 마크업은 원래 줄의 것을 그대로 옮긴다. `.warn` 클래스가 공통 CSS 에 없으면 `class="muted"` 로 두고 `style` 은 쓰지 않는다.)

- [ ] **Step 4: attr.html 스크립트**

228행 `$('saltGenBtn').addEventListener(…)` 를 지우고 다음을 넣는다:
```js
  // 2026-11-12(스펙 snap-derived-secrets §3): 스냅의 getSalt — snapId 는 같은 오리진 에이전트의 /wallet/config 에서. 이미 설치·허용된 스냅이면 다시 요청하지 않는다(지갑 화면과 같은 규칙).
  async function snapSalt() {
    const eth = window.ethereum;
    if (!eth?.request) throw Object.assign(new Error('MetaMask(Flask)가 없습니다'), { reason: 'snap_unavailable' });
    const cfg = await (await fetch('/wallet/config')).json();
    if (!cfg?.snapId) throw Object.assign(new Error('스냅 설정(snapId)을 읽지 못했습니다'), { reason: 'snap_unavailable' });
    let installed = false;
    try { const s = (await eth.request({ method: 'wallet_getSnaps' }))?.[cfg.snapId]; installed = Boolean(s) && !s.blocked && s.enabled !== false; } catch { installed = false; }
    if (!installed) await eth.request({ method: 'wallet_requestSnaps', params: { [cfg.snapId]: {} } });
    const r = await eth.request({ method: 'wallet_invokeSnap', params: { snapId: cfg.snapId, request: { method: 'getSalt', params: {} } } });
    if (!isDec(String(r?.s_u ?? ''))) throw Object.assign(new Error('스냅이 salt 를 주지 않았습니다'), { reason: 'snap_unavailable' });
    return String(r.s_u);
  }
  $('saltFromSnapBtn').addEventListener('click', async () => {
    clearVerdict($('formVerdict'));
    $('saltFromSnapBtn').disabled = true;
    try {
      const s = await snapSalt();
      $('salt').value = s;
      const rec = load();
      $('saltWarn').hidden = !(rec && rec.s_u !== s);
    } catch (e) {
      verdict($('formVerdict'), false, 'attr_make_failed', { reason: e.reason ?? 'snap_unavailable', detail: e.message });
    } finally { $('saltFromSnapBtn').disabled = false; }
  });
```
`render()` 의 `$('uid').value = rec.uid; $('salt').value = rec.s_u;` 는 그대로 둔다(기록을 열면 그 salt 를 보인다 — 비교는 가져오기 뒤).

- [ ] **Step 5: 문자열**

`mode3/common/strings.js`: `attr_salt_hint` ko·en 을 Step 3 의 문구로, `attr_salt_gen_btn` 줄을 지우고 `attr_salt_from_snap_btn: { ko: '스냅에서 가져오기', en: 'Get from Snap' }`, `attr_salt_not_derived: { ko: '이 기록의 salt 는 스냅이 만든 값과 다릅니다 — 시드로 복구할 수 없는 salt 입니다.', en: "This record's salt differs from the Snap's — it cannot be recovered from the seed." }` 를 더한다. `attr_auid_hint` 의 "스냅은 이 기록의 salt 로 등록합니다." 는 그대로 맞다(기록의 salt = 스냅 salt).

`grep -n "snap_unavailable:" mode3/common/strings.js` 로 reason 이 있는지 확인 — 있으면 재사용, 없으면 Task 3 Step 7 과 같은 형식으로 추가.

- [ ] **Step 6: 통과 확인**

Run: `bash scripts/run_tests.sh browser`
Expected: 4 파일 PASS.

- [ ] **Step 7: 커밋**

```bash
git add mode3/attr.html mode3/common/strings.js tests/test_mode3_browser.mjs
git commit -m "feat(attr): 속성 도구 salt 는 스냅에서 가져오기(시드 유도, 직접 입력·새로 뽑기 제거), 옛 기록 salt 가 다르면 경고(스펙 snap-derived-secrets S2)"
```

---

### Task 5: 문서·스펙 정정·전체 확인

**Files:**
- Modify: `docs/superpowers/specs/2026-11-12-mode3-snap-derived-secrets-design.md` (Ruling P1·P2·P3 반영)
- Modify: `docs/superpowers/specs/2026-11-06-mode3-attr-commitment-id-token-design.md` (결정 표에 D21 행)
- Modify: `docs/MODE3_DEMO.md` (스냅 0.2.0 갱신·시드 복구 시연·한계)

- [ ] **Step 1: 스펙 정정**

`2026-11-12-…-design.md`:
- §4.1 첫 bullet 의 "`{ slot: acct.slot, restored: true }`" 응답 설명 끝에 "— 상태는 201(새 등록과 같다, 에이전트·헬퍼가 201 만 성공으로 본다. 계획 Ruling P1)" 를 붙이고, §4.1 마지막 bullet 의 "응답 `/cia/register` 201 에 `restored` 를 더한다" 는 그대로 둔다.
- §4.2 첫 bullet 을 "에이전트에 등록이 있을 때: 이미 있는 `POST /wallet/register/resume`(s_u·sk_u → auid·pk_u 대조 → 기존 등록 반환)으로 처리한다. `/wallet/register` 는 바꾸지 않는다(계획 Ruling P2)." 로 바꾼다.
- §4.4 끝에 "범위 밖(계획 Ruling P3): 스냅 등록은 남고 에이전트 상태만 잃은 경우 — 지금처럼 `already_registered`." 한 줄.

- [ ] **Step 2: 속성 커밋먼트 스펙 D21 행**

`2026-11-06-…` 의 결정 표 D20 행 뒤에, 같은 열 형식으로:
`| D21 | salt 는 스냅이 MetaMask 시드에서 유도하고 속성 도구는 "스냅에서 가져오기" 로 받는다 — 11-10 의 직접 입력·새로 뽑기를 대체(스펙 2026-11-12 snap-derived-secrets). | 시드만 있으면 같은 salt·같은 PPID 로 복구된다. 대가: 스냅 ID 가 바뀌면 salt 가 바뀐다. |`
(표의 실제 열 수에 맞춘다.)

- [ ] **Step 3: 런북**

`docs/MODE3_DEMO.md` 의 D20(자동 백업) 노트 근처에 절을 더한다:
- 스냅 0.2.0: `snap_getEntropy` 권한이 늘어 MetaMask 가 스냅 갱신을 승인받는다(지갑 화면 설정 "Snap 다시 설치"). 이미 등록된 스냅은 저장된 옛 비밀을 그대로 쓴다 — 시드 복구를 쓰려면 재시연 세트로 비우고 새로 등록한다. (Flask 가 갱신 때 상태를 유지하는지는 실제 확인 결과를 적는다 — Task 5 Step 5.)
- 시드 복구 시연: 등록·로그인 → MetaMask 에서 스냅 제거(또는 같은 SRP 로 새 프로필에 복원) → RP 로그인 → 같은 PPID·같은 RP 계정. 에이전트 상태까지 지운 경우(`/wallet/reset`)도 같다(인증 창 등록 모드에 속성 도구의 auid).
- 한계: 스냅 ID(`local:http://localhost:8082`)가 바뀌면 유도값이 바뀐다. 속성(attrs·blind)은 시드에서 나오지 않는다 — 속성 도구 기록·백업에서.

- [ ] **Step 4: 전체 테스트**

Run(임시 hardhat :8545 위): `npm test` → `bash scripts/run_tests.sh snap` → `bash scripts/run_tests.sh chain`(백그라운드, 시간 한도 넉넉히) → `bash scripts/run_tests.sh browser`
Expected: 모두 PASS. 실패는 이름·핵심 오류를 그대로 보고한다. 끝나면 자기가 띄운 hardhat 만 내리고 :8545 가 비었는지 확인.

- [ ] **Step 5: Flask 갱신 확인(사용자와 함께)**

자동화할 수 없다 — 사용자에게 순서를 안내하고 결과를 받는다: 스냅 서버(:8082)가 새 `dist/` 를 서빙하는지 확인 → 지갑 화면 설정 "Snap 다시 설치" → 새 권한 승인 → 기존 등록이 남아 있는지(지갑 화면 상태) 보고받아 런북 Step 3 의 해당 줄에 결과를 적는다.

- [ ] **Step 6: 커밋**

```bash
git add docs/superpowers/specs/2026-11-12-mode3-snap-derived-secrets-design.md docs/superpowers/specs/2026-11-06-mode3-attr-commitment-id-token-design.md docs/MODE3_DEMO.md
git commit -m "docs(mode3): 스냅 시드 유도 비밀 — 런북(0.2.0 갱신·시드 복구 시연·한계), 속성 커밋먼트 D21, 스펙 정정(복구 201·resume 재사용·범위)"
```
