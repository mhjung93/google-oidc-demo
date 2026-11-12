# 스냅 계정 번호 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 한 MetaMask 시드로 만든 IdP 계정들이 계정 번호 k 마다 서로 다른 s_u·sk_u 를 갖게 한다(리뷰 I-3).

**Architecture:** 스냅이 `snap_getEntropy` salt 에 번호를 붙여(`…/v2/<k>`) 비밀을 유도하고 `nextIndex` 를 `reset` 너머로 보관한다. 번호는 속성 도구 기록·에이전트 등록 기록에 적혀 흐르고, 없으면 0번(또는 사용자가 정한 다음 가입 번호)을 쓴다. IdP·회로·컨트랙트는 그대로.

**Tech Stack:** MetaMask Snap(`snap-mode3`, mm-snap build), Node/Express 에이전트, 정적 HTML(`mode3/*.html`), Playwright 브라우저 테스트.

**Spec:** `docs/superpowers/specs/2026-11-12-mode3-snap-account-index-design.md` (원 스펙: `2026-11-12-mode3-snap-derived-secrets-design.md`)

## Global Constraints

- 유도 salt: `zkd/mode3/s_u/v2/<k>`·`zkd/mode3/sk_u/v2/<k>`, k 는 10진 정수 `0 ≤ k ≤ 2^31−1`, 범위 밖은 `bad_index`.
- 스냅 버전 `0.2.0 → 0.3.0`(manifest·package.json). `npm run zk:*`·회로 재빌드 금지. 새 의존성 금지.
- IdP(`cia.js`)·PPID 식·회로·컨트랙트는 바꾸지 않는다.
- 모든 화면 문구·주석·커밋 메시지는 한글(기존 문체). 화면 이름은 "zk 스냅 화면(localhost:5100)", "속성 도구(/attr.html)".
- 커밋은 경로 지정 `git add -- <paths>`(`sui-repo/` 주의), 트레일러 두 줄(Co-Authored-By: Claude Opus 5.5 / Claude-Session URL).
- 비밀 파일(`.env`, `*_state.json`, `*_keys.json`, `role.env` 등)은 읽지도 출력하지도 않는다.

## Rulings (스펙과 다르게 정한 것 — 실행 전 사용자 검토 대상)

- **P1** `getSalt({})` 의 기본 번호는 **스냅에 등록(또는 보류 등록)이 있으면 그 번호, 없으면 `nextIndex`**(스펙 §2.3 은 `nextIndex`). 속성 도구는 이미 등록된 계정의 속성 변경에도 쓰이므로(그 계정의 salt 가 나와야 한다). 대가: 없음에 가깝다 — 첫 가입 전엔 같은 값.
- **P2** zk 스냅 화면(snap 모드)에는 계정 탭이 없다(`tests/test_mode3_browser.mjs` "탭은 연결된 서비스뿐") — "계정 번호" 접는 칸을 **"연결된 서비스" 카드 아래**에 둔다(스펙 §3.4 는 "계정 탭 상세").
- **P3** 속성 도구는 화면을 열 때 스냅을 부르지 않는다(MetaMask 창이 저절로 뜨지 않게). 번호 칸은 기록의 번호로 채우고, 비어 있으면 "스냅에서 가져오기" 때 스냅 기본(P1)으로 채운다. 번호 칸을 바꾸면 salt 칸을 비운다.
- **P4** 0.2.0 스냅 판별: `getSalt` 응답에 정수 `index` 가 없으면 `snap_outdated`(0.2.0 은 번호를 모르고 v1 salt 를 준다).
- **P5** `lib/mode3_secret_source.js` `stripSecrets` 가 `index` 를 남긴다(정의돼 있을 때만) — snap 모드 에이전트 상태 파일에 번호를 저장하려면 필요.
- **P6** 상수 이름은 `ENTROPY_SALT_S_U`·`ENTROPY_SALT_SK_U` 를 그대로 쓰고 값만 v2 접두로 바꾼다(스펙의 `_V2` 이름 대신 — `tests/helpers/snap_sim.mjs` 가 이 이름을 import 한다).

## Review Focus

1. 이미 등록된 계정에서 속성 도구 "스냅에서 가져오기" — 등록 번호의 salt 가 나와야 한다(P1; Task 1 테스트·Task 3 브라우저 742 케이스가 잡는다).
2. 0.2.0 스냅이 설치된 채 0.3.0 페이지를 쓰면 — `snap_outdated` 로 멈춰야 하고, v1 비밀로 등록이 만들어지면 안 된다(Task 3 Google 경로 사전 검사).
3. 번호 칸을 바꾼 뒤 salt 를 다시 안 가져오고 커밋먼트를 만들면 — 번호와 salt 가 어긋난 기록이 생기면 안 된다(Task 3 attr: 번호 바꾸면 salt 비움).
4. `nextIndex` 가 2^31−1 에서 등록 저장 — 넘치지 않아야 한다(Task 1: `Math.min`).
5. 에이전트 기록에 `index` 가 없는(이 변경 이전) 상태에서 스냅만 비었을 때 복구 — 0번으로 시도(Task 3 `restoreSnapIfEmpty`).

---

### Task 1: 스냅 — 번호별 유도·nextIndex·RPC (+ 시뮬레이터·브라우저 스텁 동기화, 0.3.0 빌드)

**Files:**
- Modify: `snap-mode3/src/crypto.js` (유도 함수·상수)
- Modify: `snap-mode3/src/index.js` (상태·RPC)
- Modify: `snap-mode3/snap.manifest.json`, `snap-mode3/package.json` (버전 0.3.0; manifest shasum 은 빌드가 갱신)
- Modify: `snap-mode3/dist/bundle.js` (빌드 산출물 — 저장소에 들어 있다)
- Modify: `tests/helpers/snap_sim.mjs` (실제 스냅과 같은 입출력)
- Modify: `tests/helpers/ethereum_stub.js` (스텁 스냅 버전 문자열 `'0.2.0'` → `'0.3.0'`)
- Test: `snap-mode3/test/rpc.test.mjs`

**Interfaces:**
- Produces (crypto.js): `INDEX_MAX = 2 ** 31 - 1`, `isIndex(v): boolean`, `deriveRegistrationSecrets(index: number): Promise<{ s_u: string, sk_u: string }>`(범위 밖 `bad_index` 던짐), `ENTROPY_SALT_S_U = 'zkd/mode3/s_u/v2/'`, `ENTROPY_SALT_SK_U = 'zkd/mode3/sk_u/v2/'`.
- Produces (RPC): `getSalt({index?}) → {s_u, index}`; `register({uid, s_u?, index?}) → {uid, s_u, sk_u, index}`; `prepareRegister({index?}) → {s_u, sk_u, index}`; `setNextIndex({index}) → {ok:true, nextIndex}`; `getPublicInfo()` 에 `index: number|null`, `nextIndex: number`; `storeRegistration` 이 `nextIndex = min(INDEX_MAX, max(nextIndex, index+1))`; `reset` 은 `nextIndex` 를 남긴다(0 이면 상태를 통째로 비운다).
- Produces (snap_sim): `derivedSecrets(srp, index = 0)`, 시뮬레이터 메서드 위와 같은 입출력.

- [ ] **Step 1: 실패하는 테스트 쓰기** — `snap-mode3/test/rpc.test.mjs` 의 마지막 `console.log(failed ? …` 줄 바로 앞에 넣는다:

```js
// 2026-11-12(스펙 snap-account-index, 리뷰 I-3): 계정 번호 k 마다 다른 비밀. 번호는 기록이 들고 다니고, nextIndex 는 reset 을 넘어 남는다.
await t('계정 번호: 번호가 다르면 s_u·sk_u 가 다르고 같은 번호면 같다; getSalt 기본은 등록 번호 → 없으면 nextIndex; storeRegistration 이 nextIndex 를 올리고 reset 뒤에도 남는다', async () => {
  entropy.srp = 'srp-A'; store.state = null;
  const g0 = await call('getSalt', {}); assert.equal(g0.index, 0, '처음엔 0번');
  const g1 = await call('getSalt', { index: 1 }); assert.equal(g1.index, 1);
  assert.notEqual(g1.s_u, g0.s_u, '번호가 다르면 salt 가 다르다');
  assert.equal((await call('getSalt', { index: 1 })).s_u, g1.s_u, '같은 번호면 같은 salt');
  const r = await call('register', { uid: '7', s_u: g1.s_u, index: 1 });
  assert.equal(r.index, 1); assert.equal(r.s_u, g1.s_u); assert.match(r.sk_u, /^[0-9a-f]{64}$/);
  assert.equal((await call('getSalt', {})).index, 1, '등록이 있으면 기본은 그 번호(Ruling P1)');
  await call('storeRegistration', { attrs: ATTRS, slot: 0, auid: '5' });
  const info = await call('getPublicInfo', {}); assert.equal(info.index, 1); assert.equal(info.nextIndex, 2);
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  assert.equal(store.state?.registration ?? null, null, 'reset 은 등록을 지운다');
  assert.equal((await call('getPublicInfo', {})).nextIndex, 2, 'reset 뒤에도 nextIndex 는 남는다');
  const p = await call('prepareRegister', {});
  assert.equal(p.index, 2, '보류 등록은 nextIndex'); assert.notEqual(p.sk_u, r.sk_u, '다른 번호 → 다른 sk_u');
  assert.deepEqual(await call('prepareRegister', { index: 9 }), p, '보류가 있으면 그 비밀·번호 그대로');
  answers.push(true); await call('reset', {});
  store.state = null;
});

await t('계정 번호 검사: bad_index(범위·형식)·setNextIndex·번호와 어긋난 s_u 는 salt_not_derived; nextIndex 는 상한에서 넘치지 않는다', async () => {
  store.state = null;
  for (const bad of [-1, 1.5, '3', 2 ** 31]) {
    await assert.rejects(() => call('getSalt', { index: bad }), /bad_index/);
    await assert.rejects(() => call('setNextIndex', { index: bad }), /bad_index/);
    await assert.rejects(() => call('register', { uid: '7', index: bad }), /bad_index/);
  }
  await assert.rejects(() => call('setNextIndex', {}), /bad_index/);
  assert.deepEqual(await call('setNextIndex', { index: 5 }), { ok: true, nextIndex: 5 });
  assert.equal((await call('getSalt', {})).index, 5, '등록이 없으면 기본은 nextIndex');
  const s0 = (await call('getSalt', { index: 0 })).s_u;
  await assert.rejects(() => call('register', { uid: '7', s_u: s0, index: 4 }), /salt_not_derived/, '0번 salt 를 4번으로 등록할 수 없다');
  assert.equal(store.state?.registration ?? null, null, '거절은 등록을 만들지 않는다');
  await call('setNextIndex', { index: 2 ** 31 - 1 });
  await call('register', { uid: '7' }); await call('storeRegistration', { attrs: ATTRS, slot: 0, auid: '5' });
  assert.equal((await call('getPublicInfo', {})).nextIndex, 2 ** 31 - 1, '상한에서 멈춘다');
  answers.push(true); await call('reset', {});
  store.state = null;
});
```

- [ ] **Step 2: 실패 확인**

Run: `node snap-mode3/test/rpc.test.mjs 2>&1 | tail -20`
Expected: 새 두 케이스 FAIL(`g0.index` 가 undefined, `setNextIndex` 는 `method_not_found`). 기존 케이스는 ok.

- [ ] **Step 3: crypto.js 구현** — 상수와 `deriveRegistrationSecrets` 를 바꾼다(머리 주석에 한 줄 추가: `// 2026-11-12(스펙 snap-account-index): 계정 번호 k 마다 따로 유도한다 — salt 끝에 10진 k(규칙 v2). 같은 시드의 여러 IdP 계정이 서로 다른 비밀을 갖는다.`):

```js
export const ENTROPY_SALT_S_U = 'zkd/mode3/s_u/v2/';    // 끝에 10진 계정 번호를 붙인다(v2, 2026-11-12 스펙 snap-account-index)
export const ENTROPY_SALT_SK_U = 'zkd/mode3/sk_u/v2/';
export const INDEX_MAX = 2 ** 31 - 1;
export const isIndex = (v) => Number.isInteger(v) && v >= 0 && v <= INDEX_MAX;
```
```js
/** 계정 번호 index 의 등록 한 벌 — 같은 SRP·같은 스냅 ID·같은 번호면 언제나 같은 값. salt 의 v2 는 유도 규칙의 버전이다(번호 없는 v1 을 대체). */
export async function deriveRegistrationSecrets(index) {
  if (!isIndex(index)) throw new Error('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수');
  const get = (salt) => snap.request({ method: 'snap_getEntropy', params: { version: 1, salt: `${salt}${index}` } });
  return { s_u: saltFromEntropy(await get(ENTROPY_SALT_S_U)), sk_u: skFromEntropy(await get(ENTROPY_SALT_SK_U)) };
}
```

- [ ] **Step 4: index.js 구현**
  - import 에 `isIndex, INDEX_MAX` 추가: `import { deriveRegistrationSecrets, isIndex, INDEX_MAX, ATTR_MAX, SCALAR_MAX } from './crypto.js';`
  - `fail` 정의 아래에 도우미:
```js
// 계정 번호(2026-11-12 스펙 snap-account-index): nextIndex 는 다음 가입이 쓸 번호 — reset 을 넘어 남는다(비밀이 아니다).
const nextIndexOf = (state) => (isIndex(state.nextIndex) ? state.nextIndex : 0);
const indexParam = (params, dflt) => {
  if (params.index === undefined || params.index === null) return dflt;
  if (!isIndex(params.index)) fail('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수');
  return params.index;
};
```
  - `register`: `const secrets = await deriveRegistrationSecrets();` → `const index = indexParam(params, nextIndexOf(state)); const secrets = await deriveRegistrationSecrets(index);`; 저장 객체에 `index` 추가(`state.registration = { uid, index, s_u: …`); 반환 `{ uid, s_u: secrets.s_u, sk_u: secrets.sk_u, index }`. `salt_not_derived` 문구는 그대로. 순서: `bad_uid` 검사 다음에 `indexParam`(이미 등록 → bad_uid → bad_index).
  - `prepareRegister`: 보류가 있으면 `return { s_u: pend.s_u, sk_u: pend.sk_u, index: isIndex(pend.index) ? pend.index : 0 };`, 없으면 `const index = indexParam(params, nextIndexOf(state));` 로 유도·저장(`{ uid: null, index, s_u: … }`)하고 `{ s_u, sk_u, index }` 반환.
  - `getSalt`:
```js
    case 'getSalt': {
      // 기본 번호(Ruling P1): 등록(보류 포함)이 있으면 그 번호 — 속성 도구는 등록된 계정의 속성 변경에도 쓰인다. 없으면 다음 가입 번호.
      const own = state.registration && isIndex(state.registration.index) ? state.registration.index : null;
      const index = indexParam(params, own ?? nextIndexOf(state));
      const { s_u } = await deriveRegistrationSecrets(index);
      return { s_u, index };
    }
```
  - `storeRegistration`: `reg.auid = String(auid);` 다음 줄에 `state.nextIndex = Math.min(INDEX_MAX, Math.max(nextIndexOf(state), (isIndex(reg.index) ? reg.index : 0) + 1));   // 이 번호는 이제 쓰였다(복구로 채운 등록도)`
  - `getPublicInfo` 반환에 `index: r && isIndex(r.index) ? r.index : null, nextIndex: nextIndexOf(state),` 추가.
  - 새 RPC(`getPublicInfo` 앞):
```js
    // 다음 가입 번호를 사용자가 정한다(2026-11-12 스펙 snap-account-index §2.3) — 새 PC 에서 0번이 아닌 계정을 되살리거나 새로 가입할 때. 확인 창 없음(오리진은 :5100 뿐).
    case 'setNextIndex': {
      if (!isIndex(params.index)) fail('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수');
      state.nextIndex = params.index; await setState(state);
      return { ok: true, nextIndex: state.nextIndex };
    }
```
  - `reset`: `await clearState();` → 
```js
      const keep = nextIndexOf(state);
      await clearState();
      if (keep > 0) await setState({ ...EMPTY_STATE, consents: {}, nextIndex: keep });   // 다음 가입 번호만 남긴다 — 초기화 뒤 다른 계정이 같은 비밀을 받지 않게
```
  - 확인 창 문구 `'이 Snap 의 등록을 지웁니다. 등록 비밀(s_u·sk_u)과 동의 기록이 사라집니다.'` 는 그대로.

- [ ] **Step 5: 테스트 통과 확인**

Run: `node snap-mode3/test/rpc.test.mjs 2>&1 | tail -25`
Expected: `all passed`. 기존 케이스 중 reset 뒤 `assert.equal(store.state, null)`(현재 356행 부근) 이 앞 케이스의 `storeRegistration` 으로 nextIndex 가 1 이 되어 실패하면, 그 줄만 `assert.equal(store.state?.registration ?? null, null);` 로 바꾸고(Ruling 으로 기록 — 상태에 nextIndex 만 남는 것은 의도) 다시 돌린다.

- [ ] **Step 6: snap_sim.mjs 동기화** — 실제 스냅과 같은 입출력:
  - import 에 `isIndex, INDEX_MAX` 추가(`../../snap-mode3/src/crypto.js`).
  - `export const derivedSecrets = (srp, index = 0) => ({ s_u: saltFromEntropy(stubEntropy(srp, `${ENTROPY_SALT_S_U}${index}`)), sk_u: skFromEntropy(stubEntropy(srp, `${ENTROPY_SALT_SK_U}${index}`)) });`
  - `state` 초기값에 `nextIndex: 0`. 도우미 `const indexParam = (v, dflt) => { if (v === undefined || v === null) return dflt; if (!isIndex(v)) fail('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수'); return v; };`
  - `register({ uid, s_u: suIn, index: idxIn } = {})`: bad_uid 검사 뒤 `const index = indexParam(idxIn, state.nextIndex); const reg = derivedSecrets(srp, index);`, 저장에 `index`, 반환에 `index`.
  - `prepareRegister({ index: idxIn } = {})`: 보류면 `{ s_u, sk_u, index: pend.index ?? 0 }`, 아니면 `indexParam(idxIn, state.nextIndex)` 로 유도·저장, 반환에 `index`.
  - `getSalt({ index: idxIn } = {})`: `const own = state.registration && isIndex(state.registration.index) ? state.registration.index : null; const index = indexParam(idxIn, own ?? state.nextIndex); return { s_u: derivedSecrets(srp, index).s_u, index };`
  - `storeRegistration`: `reg.auid = String(auid);` 뒤 `state.nextIndex = Math.min(INDEX_MAX, Math.max(state.nextIndex, (isIndex(reg.index) ? reg.index : 0) + 1));`
  - `setNextIndex({ index } = {}) { if (!isIndex(index)) fail('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수'); state.nextIndex = index; return { ok: true, nextIndex: index }; }`
  - `getPublicInfo` 에 `index: r && isIndex(r.index) ? r.index : null, nextIndex: state.nextIndex`.
  - `reset()` 은 `state.nextIndex` 를 건드리지 않는다(지금 코드 그대로 — registration·userCred·consents 만 비운다).
  - `tests/helpers/ethereum_stub.js`: `version: '0.2.0'` → `version: '0.3.0'`.

- [ ] **Step 7: 버전·빌드**
  - `snap-mode3/snap.manifest.json`·`snap-mode3/package.json` 의 `"version": "0.2.0"` → `"0.3.0"`.
  - Run: `cd snap-mode3 && timeout 300 npm run build > /tmp/claude-1000/-home-node1phi-Desktop-google-oidc-demo/92bb2d9b-b323-4423-a306-f93d036ea1fc/scratchpad/snap_build.log 2>&1; echo exit=$?; tail -5 /tmp/claude-1000/-home-node1phi-Desktop-google-oidc-demo/92bb2d9b-b323-4423-a306-f93d036ea1fc/scratchpad/snap_build.log | cut -c1-200`
  - Expected: `exit=0`, `dist/bundle.js` 와 manifest `shasum` 이 바뀐다(`git diff --stat -- snap-mode3/`).

- [ ] **Step 8: 스냅·유닛 그룹 확인**

Run: `bash scripts/run_tests.sh snap 2>&1 | tail -5; node tests/test_mode3_secret_source.js 2>&1 | tail -3`
Expected: 모두 통과.

- [ ] **Step 9: 커밋**

```bash
git add -- snap-mode3/src/crypto.js snap-mode3/src/index.js snap-mode3/snap.manifest.json snap-mode3/package.json snap-mode3/dist/bundle.js snap-mode3/test/rpc.test.mjs tests/helpers/snap_sim.mjs tests/helpers/ethereum_stub.js
git commit -m "feat(snap): 계정 번호 k 마다 다른 비밀(유도 v2/<k>), nextIndex 는 reset 너머로, getSalt·register·prepareRegister 번호·setNextIndex, 0.3.0(스펙 snap-account-index §2)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

---

### Task 2: 에이전트 — 등록 기록에 번호 저장·status 반환

**Files:**
- Modify: `lib/mode3_secret_source.js` (`stripSecrets` 가 `index` 를 남긴다 — Ruling P5)
- Modify: `mode3_wallet_agent.js` (`/wallet/register` 본문 `index`, `/wallet/status` 의 `index`)
- Test: `tests/test_mode3_secret_source.js`, `tests/test_mode3_wallet_snap.mjs`

**Interfaces:**
- Consumes: Task 1 snap_sim `register()` 반환의 `index`.
- Produces: `POST /wallet/register` 본문 `index?: integer 0..2^31−1`(아니면 400 `{ reason: 'bad_index' }`), 등록 기록 `index`; `GET /wallet/status` 의 `index: number|null`.

- [ ] **Step 1: 실패하는 테스트 쓰기**
  - `tests/test_mode3_secret_source.js` 의 `stripSecrets 는 …` 케이스 안, `assert.equal(stripSecrets(null), null);` 앞에:
```js
  assert.equal(stripSecrets({ ...REG, index: 3 }).index, 3, '계정 번호는 비밀이 아니라 남긴다(2026-11-12 스펙 snap-account-index)');
  assert.equal('index' in stripSecrets(REG), false, '번호가 없으면 키도 없다');
```
  - `tests/test_mode3_wallet_snap.mjs` 의 `register: s_u·sk_u 없으면 400; …` 케이스에서
    `assert.equal((await wallet.post('/wallet/register', { uid: r0.uid, code: code1, s_u: 'zz', sk_u: r0.sk_u })).status, 400);` 다음 줄에:
```js
    for (const bad of [-1, 1.5, '0', 2 ** 31]) {
      const rb = await wallet.post('/wallet/register', { uid: r0.uid, code: code1, s_u: r0.s_u, sk_u: r0.sk_u, index: bad });
      assert.equal(rb.status, 400, `index=${j(bad)}`); assert.equal(rb.body.reason, 'bad_index');
    }
```
    그리고 성공 등록 줄을 `const r = await wallet.post('/wallet/register', { uid: r0.uid, code: code1, s_u: r0.s_u, sk_u: r0.sk_u, index: r0.index });` 로 바꾸고, 같은 케이스 끝(`assert.equal(sim.getPublicInfo().registered, true); …` 앞)에:
```js
    assert.equal(r0.index, 0, '시뮬레이터 첫 등록은 0번'); assert.equal(s.index, 0, '/wallet/status 가 계정 번호를 준다');
    assert.ok(file.includes('"index"'), '번호는 상태 파일에 남는다(비밀이 아니다)');
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_secret_source.js 2>&1 | tail -4`
Expected: `stripSecrets` 케이스 FAIL(index undefined).
Run(:8545 hardhat 필요 — 없으면 scratchpad `min.config.cjs` 로 `npx hardhat node --config <scratchpad>/min.config.cjs` 를 백그라운드로 띄운다): `node tests/test_mode3_wallet_snap.mjs 2>&1 | grep -E "^(ok|FAIL)" | head -5`
Expected: `register: …` 케이스 FAIL(`bad_index` 400 이 아니라 201/409).

- [ ] **Step 3: 구현**
  - `lib/mode3_secret_source.js` `stripSecrets`:
```js
  const { uid, auid, pk_u, slot, attrs, profile = null, provider = 'demo', userCred, index } = registration;
  return { uid, auid, pk_u, slot, attrs, profile, provider, userCred: userCred ? { Cf_u: userCred.Cf_u, issuedAt: userCred.issuedAt } : null, ...(index !== undefined ? { index } : {}) };
```
  - `mode3_wallet_agent.js` `/wallet/register`: 구조분해에 `index` 추가(`… s_u: suIn, sk_u: skIn, index } = req.body ?? {};`), `profileIn` 검사 줄 다음에:
```js
    // 계정 번호(2026-11-12 스펙 snap-account-index §3.3): 스냅이 비밀을 유도한 번호 — 비밀이 아니라 기록에 남긴다(스냅만 비었을 때 같은 번호로 되살린다).
    if (index !== undefined && !(Number.isInteger(index) && index >= 0 && index <= 2 ** 31 - 1)) return res.status(400).json({ reason: 'bad_index', detail: '계정 번호는 0 이상 2^31−1 이하의 정수' });
```
    `const full = { uid, … userCred: null };` 를 `const full = { uid, …, userCred: null, ...(index !== undefined ? { index } : {}) };` 로.
  - `/wallet/status` 응답 객체 첫 줄 `registered: Boolean(reg), uid: reg?.uid ?? null,` 다음에 `index: Number.isInteger(reg?.index) ? reg.index : null,` 추가.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_secret_source.js 2>&1 | tail -2; node tests/test_mode3_wallet_snap.mjs 2>&1 | grep -cE "^FAIL"; node tests/test_mode3_wallet_snap_oidc.mjs 2>&1 | grep -cE "^FAIL"; node tests/test_mode3_wallet_agent.mjs 2>&1 | grep -cE "^FAIL"`
Expected: 모두 통과, FAIL 개수 0.

- [ ] **Step 5: 커밋**

```bash
git add -- lib/mode3_secret_source.js mode3_wallet_agent.js tests/test_mode3_secret_source.js tests/test_mode3_wallet_snap.mjs
git commit -m "feat(mode3): 에이전트가 스냅 계정 번호를 등록 기록에 남기고 /wallet/status 로 준다, 범위 밖은 400 bad_index(스펙 snap-account-index §3.3)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

---

### Task 3: 스냅 창·zk 스냅 화면·속성 도구 — 번호를 흘리고 보여 주기

**Files:**
- Modify: `mode3/wallet.html` (팝업 `snapDerivedSalt`·`restoreSnapIfEmpty`·`codeRegister`·`googleRegister`; zk 스냅 화면 "계정 번호" 접는 칸)
- Modify: `mode3/attr.html` (계정 번호 칸, 기록의 `index`)
- Modify: `mode3/common/strings.js` (새 ui·reason 키, `snap_outdated` 문구 0.3.0)
- Test: `tests/test_mode3_browser.mjs`

**Interfaces:**
- Consumes: Task 1 RPC(`getSalt({index?})→{s_u,index}`, `register({uid,s_u,index})`, `prepareRegister({index?})→{…,index}`, `setNextIndex({index})`, `getPublicInfo().nextIndex`), Task 2 `/wallet/register` 의 `index`·`/wallet/status` 의 `index`, snap_sim `derivedSecrets(srp, index)`.
- Produces: 속성 도구 기록(localStorage `mode3_attr_tool_v1`, version 2)의 `index: number`; DOM `#acctIndex`(속성 도구), `#indexFold`·`#meIndex`·`#meNextIndex`·`#nextIndexInput`·`#nextIndexBtn`·`#indexVerdict`(zk 스냅 화면).

- [ ] **Step 1: 실패하는 브라우저 테스트 쓰기** (`tests/test_mode3_browser.mjs`)
  1. 첫 등록 케이스(`첫 로그인 = 지갑 등록(2026-11-09): …`)의 기록 심기 줄 객체에 `index: 0` 을 더한다: `{ version: 2, uid: String(demoUid), s_u: USER_SALT, index: 0, profile: { birthYear: '1990', country: 'JP' } }`. 같은 케이스의 `assert.equal(snapState.registration?.uid, uid, 'Snap 에도 등록이 저장됐다');` 다음에:
```js
    assert.equal(snapState.registration?.index, 0, '기록의 계정 번호로 등록했다(2026-11-12 스펙 snap-account-index)');
    assert.equal(snapState.nextIndex, 1, '등록을 저장하면 다음 가입 번호가 오른다'); assert.equal(st.index, 0, '에이전트 기록에도 번호');
```
  2. `zk 스냅 화면: 제목 "zk 스냅", …` 케이스 바로 뒤에 새 케이스:
```js
  await t('zk 스냅 화면 계정 번호(2026-11-12 스펙 snap-account-index §3.4): "연결된 서비스" 아래 접는 칸에 이 계정 번호·다음 가입 번호, 바꾸기는 스냅 setNextIndex', async () => {
    await walletPage.click('#indexFold > summary');
    await waitText(walletPage, '#meIndex', '0'); await waitText(walletPage, '#meNextIndex', '1');
    await walletPage.fill('#nextIndexInput', '7'); await walletPage.click('#nextIndexBtn');
    await waitText(walletPage, '#meNextIndex', '7'); assert.equal(snapState.nextIndex, 7);
    await walletPage.fill('#nextIndexInput', '-1'); await walletPage.click('#nextIndexBtn');
    await waitText(walletPage, '#indexVerdict', '계정 번호'); assert.equal(snapState.nextIndex, 7, '잘못된 번호는 바꾸지 않는다');
    await walletPage.fill('#nextIndexInput', '1'); await walletPage.click('#nextIndexBtn');
    await waitText(walletPage, '#meNextIndex', '1'); assert.equal(snapState.nextIndex, 1);
    await walletPage.click('#indexFold > summary');
  });
```
  3. `속성 도구(/attr.html): …` 케이스에서 `assert.equal(await p.inputValue('#salt'), USER_SALT, …);` 다음에 `assert.equal(await p.inputValue('#acctIndex'), '0', '번호 칸이 비어 있으면 스냅 기본 — 등록된 계정의 번호(Ruling P1)');`, `assert.equal(rec.version, 2); …` 줄 다음에 `assert.equal(rec.index, 0, '기록에 계정 번호');`.
  4. 그 케이스 바로 뒤에 새 케이스:
```js
  await t('속성 도구 계정 번호: 번호를 바꾸면 salt 칸이 비고, 1번으로 가져오면 다른 salt(같은 시드라도) — 0번으로 되돌리면 등록 salt', async () => {
    const p = await context.newPage(); await p.goto(`${wallet.base}/attr.html`);
    try {
      await p.fill('#acctIndex', '1');
      assert.equal(await p.inputValue('#salt'), '', '번호를 바꾸면 salt 를 다시 가져와야 한다');
      await p.click('#saltFromSnapBtn'); await p.waitForFunction(() => document.getElementById('salt').value !== '');
      assert.equal(await p.inputValue('#salt'), derivedSecrets(STUB_SRP, 1).s_u); assert.notEqual(await p.inputValue('#salt'), USER_SALT);
      await p.fill('#acctIndex', '0'); await p.click('#saltFromSnapBtn');
      await p.waitForFunction((v) => document.getElementById('salt').value === v, USER_SALT);
    } finally { await p.close(); }
  });
```
  5. `하네스: 준비한 대화상자 응답이 남지 않았다…` 케이스 바로 앞에 새 케이스(뒤에 이 계정을 쓰는 케이스가 없도록 맨 끝에 둔다):
```js
  await t('I-3(2026-11-12 스펙 snap-account-index): 같은 시드의 스냅을 초기화하고 다른 계정을 가입하면 계정 번호가 올라 sk_u·salt 가 다르다 — IdP 는 새 계정으로 받는다', async () => {
    const skA = snapState.registration.sk_u, saltA = snapState.registration.s_u;
    const u = await context.newPage(); await u.goto(`${cia.base}/user`);
    await u.click('#showSignupBtn'); await u.fill('#signupId', 'demo-user-b'); await u.fill('#signupPwd', DEMO_PWD); await u.fill('#signupPwd2', DEMO_PWD); await u.click('#signupBtn');
    await waitText(u, '#profileVerdict', '가입했습니다'); await u.close();
    const uidB = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.id === 'demo-user-b').uid;
    // "스냅 초기화" 의 결과(등록·동의를 지우고 nextIndex 만 남긴다 — 스냅 RPC 테스트가 reset 자체를 본다) + 에이전트 비우기
    snapState = { version: 1, registration: null, userCred: null, consents: {}, nextIndex: snapState.nextIndex };
    assert.equal((await wallet.post('/wallet/reset', { confirm: true })).status, 200);
    const saltB = derivedSecrets(STUB_SRP, 1).s_u;
    const auidB = (await auidOf({ uid: BigInt(uidB), s_u: BigInt(saltB) })).toString();
    await walletPage.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r)), { version: 2, uid: String(uidB), s_u: saltB, index: 1, profile: { birthYear: '1990', country: 'JP' } });
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'demo-user-b'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', auidB); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await awaitPopupClosed(popup);
    assert.equal(snapState.registration?.index, 1); assert.equal(snapState.registration?.uid, String(uidB));
    assert.notEqual(snapState.registration.sk_u, skA, '다른 계정은 다른 서명키 — IdP 가 pk_u 로 묶지 못한다');
    assert.notEqual(snapState.registration.s_u, saltA);
    const st = (await wallet.get('/wallet/status')).body; assert.equal(st.index, 1); assert.equal(String(st.uid), String(uidB));
  });
```
  6. 파일 머리의 `derivedSecrets(STUB_SRP)` 호출(`USER_SALT`)은 기본 번호 0 이라 그대로 둔다.

- [ ] **Step 2: 실패 확인**

Run(:8545 필요, Chrome 필요): `node tests/test_mode3_browser.mjs > /tmp/claude-1000/-home-node1phi-Desktop-google-oidc-demo/92bb2d9b-b323-4423-a306-f93d036ea1fc/scratchpad/br_red.log 2>&1; grep -E "^(ok|FAIL)" /tmp/claude-1000/-home-node1phi-Desktop-google-oidc-demo/92bb2d9b-b323-4423-a306-f93d036ea1fc/scratchpad/br_red.log | grep FAIL | cut -c1-120`
Expected: 새·수정 케이스 FAIL(첫 등록의 `registration.index` 없음 — 팝업이 index 를 안 넘김, `#indexFold`·`#acctIndex` 없음). 다른 케이스는 첫 등록 실패에 연쇄될 수 있다 — FAIL 목록을 기록해 둔다.

- [ ] **Step 3: strings.js** — `ui` 에 (기존 `rp_race_hide_btn` 처럼 `{ ko, en }`):
```js
    wallet_index_summary: { ko: '계정 번호', en: 'Account number' },
    wallet_index_label: { ko: '이 계정 번호', en: 'This account number' },
    wallet_next_index_label: { ko: '다음 가입 번호', en: 'Next sign-up number' },
    wallet_next_index_btn: { ko: '바꾸기', en: 'Change' },
    wallet_index_desc: { ko: '한 MetaMask 로 계정을 여러 개 쓰면 계정마다 번호가 다르고 비밀도 다릅니다. 새 PC 에서 0번이 아닌 계정을 되살리거나 새로 가입할 때 다음 가입 번호를 여기서 정합니다.', en: 'Each account on one MetaMask has its own number and its own secrets. Set the next sign-up number here to restore a non-zero account on a new PC or to sign up a new one.' },
    wallet_next_index_failed: { ko: '다음 가입 번호를 바꾸지 못했습니다', en: 'Could not change the next sign-up number' },
    attr_index: { ko: '계정 번호', en: 'Account number' },
    attr_index_hint: { ko: '비워 두면 스냅이 고릅니다 — 등록된 계정이 있으면 그 번호, 없으면 다음 가입 번호. 번호가 다르면 salt 도 다릅니다.', en: 'Leave empty to let the Snap choose — the registered account\'s number, otherwise the next sign-up number. A different number gives a different salt.' },
```
  `reasons` 에(`demo_race_off` 와 같은 모양):
```js
    bad_index: { where: 'wallet', ko: { title: '계정 번호가 올바르지 않습니다', cause: '계정 번호는 0 이상 2147483647 이하의 정수입니다.', action: '번호를 다시 넣으세요.' }, en: { title: 'Invalid account number', cause: 'The account number must be an integer from 0 to 2147483647.', action: 'Enter the number again.' } },
```
  `snap_outdated` 의 ko·en 문구에서 `0.2.0` 을 `0.3.0` 으로, ko cause 를 `'설치된 스냅이 0.3.0 전 버전이라 계정 번호별 salt 를 만들지 못합니다.'`(en: `'The installed Snap is older than 0.3.0 and cannot derive the per-account salt.'`)로 바꾼다. `attr_salt_hint` 는 그대로.

- [ ] **Step 4: wallet.html 팝업**
  - `snapDerivedSalt` 를 바꾼다:
```js
    /** 스냅의 시드 유도 salt(getSalt). index 를 주면 그 계정 번호, 안 주면 스냅 기본(등록 번호 → 다음 가입 번호). 0.3.0 전 스냅은 { ok:false, reason:'snap_outdated' }
     *  — 0.1.0 은 getSalt 가 없고(method_not_found), 0.2.0 은 번호를 몰라 응답에 index 가 없다(Ruling P4). 그 밖의 오류는 던진다. */
    async function snapDerivedSalt(index) {
      let r;
      try { r = await invokeSnap('getSalt', index === undefined ? {} : { index }); }
      catch (e) { if (/method_not_found/.test(e?.message ?? '')) return { ok: false, reason: 'snap_outdated' }; throw e; }
      if (!Number.isInteger(r?.index)) return { ok: false, reason: 'snap_outdated' };
      return { ok: true, s_u: String(r?.s_u ?? ''), index: r.index };
    }
```
  - `restoreSnapIfEmpty`: `const probe = await snapDerivedSalt();` → 
```js
      const index = Number.isInteger(st.index) ? st.index : 0;   // 에이전트 기록의 계정 번호 — 이 변경 전 기록에는 없어 0번(스펙 snap-account-index §3.2)
      const probe = await snapDerivedSalt(index);
```
    `invokeSnap('prepareRegister', {})` → `invokeSnap('prepareRegister', { index })`.
  - `codeRegister`: `const snapSalt = await snapDerivedSalt();` 앞에:
```js
      // 2026-11-12(스펙 snap-account-index §3.2): 기록에 계정 번호가 없으면 번호 없는 v1 salt(0.2.0 이전) — 시드로 복구할 수 없는 기록이다.
      if (!Number.isInteger(rec.index)) { step('속성 도구 기록에 계정 번호가 없다 — 속성 도구에서 "스냅에서 가져오기" 로 다시 만들어야 한다.'); return { ok: false, reason: 'attr_record_salt_not_derived' }; }
```
    `snapDerivedSalt()` → `snapDerivedSalt(rec.index)`; `invokeSnap('register', { uid, s_u: rec.s_u })` → `invokeSnap('register', { uid, s_u: rec.s_u, index: rec.index })`; `/wallet/register` 본문에 `index: reg.index,` 추가(`{ uid, code, s_u: reg.s_u, sk_u: reg.sk_u, index: reg.index, ...(rec.profile ? … ) }`).
  - `googleRegister`: `step('등록 비밀을 만드는 중…');` 앞에:
```js
      const probe = await snapDerivedSalt();   // 0.3.0 전 스냅이면 보류 등록을 만들기 전에 멈춘다(Ruling P4) — 번호 없는 비밀로 등록하지 않게
      if (!probe.ok) { step('스냅이 옛 버전이다 — 다시 설치해야 한다.'); return { ok: false, reason: probe.reason }; }
```
    `/wallet/register` 본문을 `{ id_token: g.token, s_u: prep.s_u, sk_u: prep.sk_u, ...(Number.isInteger(prep.index) ? { index: prep.index } : {}) }` 로.

- [ ] **Step 5: wallet.html zk 스냅 화면**
  - 마크업: `sessionsCard` 의 `<div id="boundsVerdict"></div>` 다음 줄에:
```html
      <!-- 계정 번호(2026-11-12 스펙 snap-account-index §3.4, Ruling P2): snap 모드 화면에는 계정 탭이 없어 여기 둔다(applySnapMode 가 보인다). -->
      <details class="fold" id="indexFold" hidden>
        <summary data-i18n="wallet_index_summary">계정 번호</summary>
        <dl class="kv">
          <dt data-i18n="wallet_index_label">이 계정 번호</dt><dd><code id="meIndex">-</code></dd>
          <dt data-i18n="wallet_next_index_label">다음 가입 번호</dt><dd><code id="meNextIndex">-</code> <input id="nextIndexInput" inputmode="numeric" style="width:7em" /> <button type="button" id="nextIndexBtn" class="btn-ghost" data-i18n="wallet_next_index_btn">바꾸기</button></dd>
        </dl>
        <p class="muted" data-i18n="wallet_index_desc">한 MetaMask 로 계정을 여러 개 쓰면 계정마다 번호가 다르고 비밀도 다릅니다. 새 PC 에서 0번이 아닌 계정을 되살리거나 새로 가입할 때 다음 가입 번호를 여기서 정합니다.</p>
        <div id="indexVerdict"></div>
      </details>
```
  - `applySnapMode()` 안 첫 줄들 사이에 `$('indexFold').hidden = false;`.
  - 상태를 그리는 함수(지금 `$('meUid').textContent = s?.uid ?? '-';` 가 있는 곳) 에 `$('meIndex').textContent = Number.isInteger(s?.index) ? String(s.index) : '-';`.
  - `showSaltBtn` 핸들러 정의 앞에:
```js
    // 다음 가입 번호(스냅 getPublicInfo.nextIndex) — 접는 칸을 열 때와 바꾼 뒤에만 읽는다(5초 refresh 마다 스냅을 부르지 않게).
    async function loadNextIndex() {
      try { const info = await invokeSnap('getPublicInfo', {}); $('meNextIndex').textContent = Number.isInteger(info?.nextIndex) ? String(info.nextIndex) : '-'; }
      catch { $('meNextIndex').textContent = '-'; }
    }
    $('indexFold').addEventListener('toggle', () => { if ($('indexFold').open) loadNextIndex(); });
    $('nextIndexBtn').addEventListener('click', async () => {
      $('indexVerdict').className = ''; $('indexVerdict').textContent = '';
      const raw = $('nextIndexInput').value.trim();
      try {
        if (!/^[0-9]+$/.test(raw) || Number(raw) > 2 ** 31 - 1) throw Object.assign(new Error(raw), { reason: 'bad_index' });
        await ensureConnected();
        await invokeSnap('setNextIndex', { index: Number(raw) });
        $('nextIndexInput').value = '';
        await loadNextIndex();
      } catch (e) {
        setVerdict($('indexVerdict'), false, 'wallet_next_index_failed', { reason: e.reason ?? (/bad_index/.test(e.message ?? '') ? 'bad_index' : 'snap_unavailable'), detail: e.message });
      }
    });
```
    (`setVerdict` 의 세 번째 인자는 ui 키, `{ reason }` 은 reasons 키 — 같은 파일 319행 정의. 판정 칸에 `bad_index` 의 제목 "계정 번호가 올바르지 않습니다" 가 보인다.)

- [ ] **Step 6: attr.html**
  - 마크업: `attr_salt_hint` 문단 앞에
```html
      <p class="muted" data-i18n="attr_index_hint">비워 두면 스냅이 고릅니다 — 등록된 계정이 있으면 그 번호, 없으면 다음 가입 번호. 번호가 다르면 salt 도 다릅니다.</p>
      <label><span data-i18n="attr_index">계정 번호</span> <input id="acctIndex" inputmode="numeric" pattern="[0-9]*" /></label>
```
  - `snapSalt()` → `snapSalt(index)`: invoke params `index === undefined ? {} : { index }`; `method_not_found` 메시지를 `'설치된 스냅이 0.3.0 전 버전입니다'` 로; 반환 직전에
```js
    if (!Number.isInteger(r?.index)) throw Object.assign(new Error('설치된 스냅이 0.3.0 전 버전입니다(계정 번호를 모른다)'), { reason: 'snap_outdated' });   // Ruling P4
```
    반환값을 `{ s_u: String(r.s_u), index: r.index }` 로.
  - "스냅에서 가져오기" 핸들러 본문:
```js
      const raw = $('acctIndex').value.trim();
      if (raw !== '' && !(/^[0-9]+$/.test(raw) && Number(raw) <= 2 ** 31 - 1)) throw Object.assign(new Error(raw), { reason: 'bad_index' });
      const r = await snapSalt(raw === '' ? undefined : Number(raw));
      $('salt').value = r.s_u; $('acctIndex').value = String(r.index);
      const rec = load();
      // 경고는 "이 기록이 시드로 복구되지 않는다" 일 때만: 번호가 없는 기록, 또는 같은 번호인데 salt 가 다른 기록.
      $('saltWarn').hidden = !(rec && (!Number.isInteger(rec.index) || (rec.index === r.index && rec.s_u !== r.s_u)));
```
  - 번호 칸을 바꾸면 salt 를 비운다(Ruling P3): 핸들러 정의 뒤에 `$('acctIndex').addEventListener('input', () => { $('salt').value = ''; });`
  - submit: `const uid = …, s_u = …;` 다음에
```js
      const idxRaw = $('acctIndex').value.trim();
      if (!(/^[0-9]+$/.test(idxRaw) && Number(idxRaw) <= 2 ** 31 - 1)) throw Object.assign(new Error(tt('attr_bind_required') || '계정 번호와 salt 는 "스냅에서 가져오기" 로 채웁니다'), { reason: 'bad_index' });
      const index = Number(idxRaw);
```
    `save({ version: REC_VERSION, …, uid, s_u, profile, … })` 에 `index,` 추가(`uid, s_u, index, profile, …`).
  - `render()`: `$('uid').value = rec.uid; $('salt').value = rec.s_u;` → `$('uid').value = rec.uid; $('salt').value = rec.s_u; $('acctIndex').value = Number.isInteger(rec.index) ? String(rec.index) : '';`
  - 백업 불러오기 검사에 `if (rec.index !== undefined && !(Number.isInteger(rec.index) && rec.index >= 0 && rec.index <= 2 ** 31 - 1)) throw new Error('백업의 계정 번호가 올바르지 않습니다');` 를 `version === 1` 검사 다음 줄에.

- [ ] **Step 7: 통과 확인**

Run: `node tests/test_mode3_browser.mjs > /tmp/claude-1000/-home-node1phi-Desktop-google-oidc-demo/92bb2d9b-b323-4423-a306-f93d036ea1fc/scratchpad/br_green.log 2>&1; grep -cE "^ok" …/br_green.log; grep -E "^FAIL" …/br_green.log | cut -c1-160`
Expected: FAIL 0. 이어서 `node tests/test_mode3_wallet_snap_oidc_browser.mjs 2>&1 | grep -E "^FAIL" | head` — FAIL 0, `node tests/test_mode3_demo_strings.js 2>&1 | tail -3` — 통과.

- [ ] **Step 8: 커밋**

```bash
git add -- mode3/wallet.html mode3/attr.html mode3/common/strings.js tests/test_mode3_browser.mjs
git commit -m "feat(mode3): 스냅 창이 기록·에이전트의 계정 번호로 등록·복구, zk 스냅 화면에 계정 번호·다음 가입 번호, 속성 도구 계정 번호 칸(스펙 snap-account-index §3)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

---

### Task 4: 문서·전체 확인

**Files:**
- Modify: `docs/MODE3_DEMO.md` (스냅 갱신 절)
- Modify: `docs/superpowers/specs/2026-11-12-mode3-snap-derived-secrets-design.md` (머리 한 줄)

- [ ] **Step 1: 런북** — `docs/MODE3_DEMO.md` 의 스냅 0.2.0 갱신 절("### 스냅 재설치" 부근)에 새 소절:

```markdown
#### 스냅 0.3.0 — 계정 번호 (2026-11-12, 스펙 `2026-11-12-mode3-snap-account-index-design.md`)
- 비밀을 계정 번호 k 마다 따로 유도한다(`zkd/mode3/s_u/v2/<k>`). 한 MetaMask 로 계정을 여러 개 만들어도 s_u·sk_u 가 달라 IdP 가 pk_u 로 묶지 못한다.
- **0.3.0 재설치 필요.** 유도 규칙이 v1 → v2 로 바뀌어 0.2.0 으로 등록한 계정은 시드로 되찾을 수 없다 — 데모 리셋 뒤 새로 등록한다.
- 번호는 속성 도구(`/attr.html`)의 "계정 번호" 칸과 기록, 에이전트 등록 기록에 남는다. 비워 두면 스냅이 고른다(등록된 계정 번호 → 다음 가입 번호).
- zk 스냅 화면(localhost:5100) "연결된 서비스" 아래 "계정 번호" 를 열면 이 계정 번호와 다음 가입 번호가 보이고, 다음 가입 번호를 바꿀 수 있다(Google 가입·새 PC 복구용).
- 한계: 상태를 다 잃은 PC 에서 새 계정을 만들면 번호가 0 부터다 — 이미 쓴 번호면 그 계정과 키가 겹친다. 기록 없이 0번이 아닌 계정을 되살리려면 번호를 기억해 넣어야 한다.
```

- [ ] **Step 2: 원 스펙 머리** — `2026-11-12-mode3-snap-derived-secrets-design.md` 의 `- 상태:` 줄 다음에 `- 갱신(2026-11-12): 유도 규칙은 계정 번호 스펙(`2026-11-12-mode3-snap-account-index-design.md`, v2/<k>)으로 대체됐다 — §2.2 의 v1 문자열은 더 쓰지 않는다.`

- [ ] **Step 3: 전체 그룹**

Run: `bash scripts/run_tests.sh unit 2>&1 | tail -3; bash scripts/run_tests.sh snap 2>&1 | tail -3; bash scripts/run_tests.sh chain > …/chain.log 2>&1; tail -3 …/chain.log; bash scripts/run_tests.sh browser > …/browser.log 2>&1; tail -3 …/browser.log`
Expected: 모두 통과. 실패는 이름과 핵심 오류를 그대로 보고한다(30초 재로그인 타임아웃 같은 부하성 실패는 한 번 다시 돌려 구분한다).

- [ ] **Step 4: 커밋**

```bash
git add -- docs/MODE3_DEMO.md docs/superpowers/specs/2026-11-12-mode3-snap-derived-secrets-design.md
git commit -m "docs(mode3): 스냅 0.3.0 계정 번호 — 런북 갱신·한계, 원 스펙에 v2 대체 표시" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

- [ ] **Step 5: 정리** — 직접 띄운 hardhat 을 명령줄 확인 뒤 종료하고 :8545 가 비었는지 본다. 남은 테스트 서버가 없는지 확인한다. 배포(VM·스냅 재설치)는 하지 않는다 — 사용자 승인 대상.

---

## 최종 리뷰
- 마지막 태스크 뒤 Opus 리뷰어 한 명이 브랜치 전체(이 계획의 커밋 범위)를 본다. Review Focus 다섯 줄을 그대로 넘긴다.
