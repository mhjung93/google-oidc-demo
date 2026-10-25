# Mode 3 Snap 모드 OIDC 래퍼 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Snap 모드 지갑(에이전트 :5100 + MetaMask Snap)에서 Google 계정 등록 → RP 로그인(발급) → 자기 폐기가 동작하게 한다(분리 VM 데모 대상).

**Architecture:** Snap 은 uid 없이 비밀을 먼저 만드는 `prepareRegister`(보류 등록)를 얻고 `storeRegistration` 이 uid·provider 를 채운다. 에이전트는 nonce 3종을 계산하는 `/wallet/oidc/nonce` 와 `/wallet/register`·`/wallet/login`·`/wallet/self_revoke` 의 `id_token` 경로를 얻어 IdP 의 기존 검증 경로로 중계한다. Google 버튼(GSI)은 지갑 페이지·팝업(localhost:5100)에서만 그린다. IdP(`cia.js`)는 바꾸지 않는다.

**Tech Stack:** Node 22 ESM, express, jose(이미 의존성 — `decodeJwt`), @metamask/snaps-sdk 1.4 / snaps-cli(`mm-snap build`), Playwright(Chrome), bash.

**Spec:** `docs/superpowers/specs/2026-10-26-mode3-snap-oidc-wrapper-design.md`(선행: `2026-10-16-mode3-oidc-wrapper-design.md`)

## Global Constraints

- 모든 주석·문구·커밋 메시지는 한국어(기존 문체). 기존 스타일·네이밍 유지, 최소 변경.
- 새 의존성 추가 금지(jose 는 이미 `package.json` 에 있다).
- `cia.js` 는 수정하지 않는다.
- `.env`·`cia_state.json`·`cia_keys.json`·`*_keys.json`·`mode3_wallet_state.json`·`mode3_rp_registration*.json`·`idp_state.json` 은 읽거나 출력하거나 커밋하지 않는다. `scripts/demo_split_start.sh` 를 **실행하지 않는다**(검증은 `bash -n` 과 가짜 env 파일로).
- id_token 은 에이전트 로그·상태 파일에 남기지 않는다(`auth_code` 와 같은 규칙).
- `npm run zk:*`·회로 재빌드 금지. hardhat 노드 로그 출력 금지.
- 사용자 데모 프로세스(:5100/:8082/:8547/:8548, VM)는 건드리지 않는다. 테스트는 격리 스택 헬퍼가 띄우는 포트만 쓴다. :8545 노드가 없으면 `npx hardhat node` 를 백그라운드로 띄워도 되고, 자기가 띄운 것은 끝나고 내린다.
- 커밋: `git add <files>` + `git commit -m … -- <files>`(`git add -A` 금지). 메시지 끝에 두 줄:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`
- 새 테스트 파일은 `scripts/run_tests.sh` 의 해당 그룹 배열에 넣는다.
- Snap 오류 사유 문자열은 `사유: 설명` 모양(`fail('bad_uid: …')`)을 유지하고, `tests/helpers/snap_sim.mjs` 는 `snap-mode3/src/index.js` 와 같은 사유 접두어를 던진다.

## Review Focus

1. 보류 등록(uid 없음) 상태의 Snap 에서 `consentLogin`·`selfRevoke`·`showSalt`·`updateUserCred`·`syncAttrs`·`consentRevokeSession` 은 `not_registered` 로 거절돼야 한다(증인·비밀번호 프롬프트가 uid 없이 나가지 않게) — Task 1 테스트.
2. Google 단계 실패 뒤 다시 시도하면 `prepareRegister` 가 같은 `s_u·sk_u` 를 돌려줘 nonce 가 같아야 한다 — Task 1·Task 2 테스트.
3. `provider` 가 없는 옛 에이전트 상태 파일·데모 등록은 `/wallet/status.provider === 'demo'` 로 보여 로그인이 지금처럼 IdP 인증 창 경로를 타야 한다 — Task 2 테스트(기존 snap 테스트에 단언 추가).
4. id_token 문자열이 에이전트 상태 파일에 남지 않아야 한다 — Task 2 테스트.
5. 보류 등록에 uid 없이 `storeRegistration` 이 오면 `bad_uid` 로 거절되고 상태가 바뀌지 않아야 한다 — Task 1 테스트.

---

### Task 1: Snap — 보류 등록(`prepareRegister`), `storeRegistration` 의 uid·provider, 시뮬레이터, 번들 재빌드

**Files:**
- Modify: `snap-mode3/src/index.js`(`requireRegistered`, `register`, `storeRegistration`, `getPublicInfo`, 새 `prepareRegister`)
- Modify: `tests/helpers/snap_sim.mjs`(같은 입출력)
- Modify: `snap-mode3/test/rpc.test.mjs`
- Rebuild: `snap-mode3/dist/bundle.js`, `snap-mode3/dist/bundle.js.map`, `snap-mode3/snap.manifest.json`(`npm run build` 결과 — shasum 갱신)

**Interfaces:**
- Produces(Snap RPC, 지갑 오리진만):
  - `prepareRegister({})` → 확인 창 → `{ s_u: string(10진), sk_u: string(hex64) }` | `{ denied: true }`. 완성 등록(uid 있음)이면 `already_registered:` 로 throw. 보류 등록이 이미 있으면 확인 창 뒤 **같은** 비밀을 돌려준다.
  - `storeRegistration({ attrs, slot, auid, uid?, provider? })` → `{ ok: true }`. 보류 등록이면 `uid` 필수(10진, 아니면 `bad_uid:`). 완성 등록에 다른 uid 가 오면 `uid_mismatch:`. `provider` 는 `/^[A-Za-z0-9_-]{1,32}$/`(아니면 `bad_provider:`).
  - `getPublicInfo()` → 기존 필드 + `pending: boolean`, `provider: string|null`. `registered` 는 uid 가 있을 때만 true.
  - `register({ uid })` 는 보류 등록을 **덮어쓴다**(완성 등록만 `already_registered`).
- Produces(시뮬레이터): `sim.prepareRegister(decision='allow')`, `sim.storeRegistration({ attrs, slot, auid, uid, provider })`, `sim.getPublicInfo()` 가 위와 같은 입출력.

- [ ] **Step 1: 실패하는 Snap 단위 테스트를 쓴다** — `snap-mode3/test/rpc.test.mjs` 의 `'등록 전에는 비밀이 필요한 RPC 가 거절된다'` 케이스 **앞**(상태가 비어 있는 지점이어야 한다 — 바로 앞의 reset 케이스 뒤)에 넣는다. `answers` 큐·`call`·`stateJson`·`lastDialogText` 는 파일에 이미 있다.

```js
await t('prepareRegister: 거절이면 { denied } 이고 상태가 없다; 승인이면 uid 없는 보류 등록 — registered=false, pending=true', async () => {
  answers.push(false);
  assert.deepEqual(await call('prepareRegister', {}), { denied: true });
  assert.equal(store.state, null, '거절은 상태를 만들지 않는다');
  answers.push(true);
  const p = await call('prepareRegister', {});
  assert.match(p.s_u, /^[0-9]+$/); assert.match(p.sk_u, /^[0-9a-f]{64}$/);
  assert.ok(/Google/.test(lastDialogText()), '확인 창 제목에 Google');
  assert.ok(!lastDialogText().includes(p.sk_u) && !lastDialogText().includes(p.s_u), '확인 창에 비밀 값은 없다');
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, false); assert.equal(info.pending, true); assert.equal(info.uid, null); assert.equal(info.provider, null);
  // 다시 시도(Google 단계 실패 뒤) — 같은 비밀(같은 pk_u → 같은 nonce)
  answers.push(true);
  assert.deepEqual(await call('prepareRegister', {}), p);
});

await t('보류 등록에서는 비밀이 필요한 RPC 가 not_registered 로 거절된다(uid 없는 증인·프롬프트 금지)', async () => {
  for (const m of ['consentLogin', 'updateUserCred', 'syncAttrs', 'selfRevoke', 'consentRevokeSession', 'showSalt']) {
    await assert.rejects(() => call(m, { origin: RP_ORIGIN }), /not_registered/, `${m}`);
  }
});

await t('storeRegistration(보류): uid 가 없으면 bad_uid 이고 상태 그대로; uid·provider 를 주면 완성 등록', async () => {
  const before = stateJson();
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77' }), /bad_uid/);
  assert.equal(stateJson(), before, '거절은 상태를 바꾸지 않는다');
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77', uid: '5', provider: 'bad provider!' }), /bad_provider/);
  assert.equal(stateJson(), before);
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77', uid: '5', provider: 'google' }), { ok: true });
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, true); assert.equal(info.pending, false); assert.equal(info.uid, '5'); assert.equal(info.provider, 'google');
  // 완성 등록: 다른 uid 는 uid_mismatch, 같은 uid·uid 생략은 받는다
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77', uid: '6' }), /uid_mismatch/);
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77' }), { ok: true });
  // 완성 등록이면 prepareRegister 는 already_registered
  await assert.rejects(() => call('prepareRegister', {}), /already_registered/);
});

await t('register 는 보류 등록을 덮어쓴다(완성 등록만 already_registered); reset 은 보류도 지운다', async () => {
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  answers.push(true); const p = await call('prepareRegister', {});
  answers.push(true); const r = await call('register', { uid: '42' });
  assert.equal(r.uid, '42'); assert.notEqual(r.sk_u, p.sk_u, 'register 는 새 비밀을 만든다');
  assert.equal((await call('getPublicInfo', {})).pending, false);
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  answers.push(true); const p2 = await call('prepareRegister', {});
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  assert.ok(!String(stateJson()).includes(p2.sk_u), 'reset 뒤 보류 비밀이 남지 않는다');
  assert.equal(store.state, null);
});
```

  기존 케이스 중 `getPublicInfo` 결과를 `deepEqual` 로 통째 비교하는 곳이 있으면 `pending`·`provider` 를 기대값에 더한다(값은 그 시점 상태 그대로).

- [ ] **Step 2: 실패를 확인한다**

Run: `bash scripts/run_tests.sh snap`
Expected: 새 케이스들이 `method_not_found: prepareRegister` 등으로 FAIL.

- [ ] **Step 3: `snap-mode3/src/index.js` 를 고친다**

`requireRegistered` 를 uid 기준으로 바꾼다(보류 등록은 "등록 없음"으로 본다):

```js
// 보류 등록(prepareRegister, uid 없음 — 2026-10-26 Snap OIDC 래퍼)은 "등록 없음" 으로 본다: uid 없는 증인·프롬프트가 나가면 안 된다.
const requireRegistered = (state) => (state.registration?.uid ? state.registration : fail('not_registered: 이 Snap 에 등록이 없다'));
```

`register` 의 첫 줄을 바꾼다(보류는 덮어쓴다):

```js
      if (state.registration?.uid) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
```

`register` 케이스 바로 뒤에 `prepareRegister` 를 넣는다:

```js
    // Google 등록(2026-10-26 Snap OIDC 래퍼 §2.1): 등록 토큰의 nonce 는 pk_u 에 묶이는데(reg:H(pk_u)), uid 는 토큰을 받은 뒤에야
    // IdP 가 정한다 — 그래서 uid 없이 비밀을 먼저 만들어 "보류 등록" 으로 둔다. uid 는 storeRegistration 이 채운다.
    // 보류가 이미 있으면(Google·IdP 단계 실패 뒤 재시도) 같은 비밀을 돌려준다 — 같은 pk_u 라 nonce 도 같다.
    case 'prepareRegister': {
      if (state.registration?.uid) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      const ok = await confirm('Google 계정 등록', ['등록 비밀(s_u·sk_u)을 만들어 이 Snap 에 보관합니다.', 'uid 는 Google 로그인 뒤 IdP 가 정합니다.', null, '속성은 지갑에만 남고 IdP 에는 커밋먼트와 공개키만 갑니다.']);
      if (!ok) return { denied: true };
      const pend = state.registration;
      if (pend) return { s_u: pend.s_u, sk_u: pend.sk_u };
      const secrets = createRegistrationSecrets();
      state.registration = { uid: null, s_u: secrets.s_u, auid: null, sk_u: secrets.sk_u, slot: null, attrs: null, provider: null, registeredAt: new Date().toISOString() };
      state.userCred = null; await setState(state);
      return { s_u: secrets.s_u, sk_u: secrets.sk_u };
    }
```

`storeRegistration` 을 바꾼다(검사를 모두 끝낸 뒤에만 상태를 바꾼다):

```js
    // 에이전트 POST /wallet/register 응답(slot·attrs·auid)을 저장한다. sk_u·s_u 는 register/prepareRegister 때 이미 저장했으므로 받지 않는다(V9 §7.1).
    // 2026-10-26: 보류 등록(prepareRegister)은 여기서 uid 를 받아 완성된다. provider 는 IdP 응답의 값(데모 등록은 생략 가능).
    case 'storeRegistration': {
      const reg = state.registration ?? fail('not_registered: 이 Snap 에 등록이 없다');
      const { attrs, slot, auid, uid, provider } = params;
      if (!Array.isArray(attrs) || attrs.length !== 6 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 6개');
      if (!attrs.every((a) => BigInt(a) < ATTR_MAX)) fail('bad_attrs: attrs 원소는 2^64 미만');
      if (!Number.isInteger(slot) || slot < 0) fail('bad_slot');
      if (!isDec(String(auid ?? ''))) fail('bad_auid: auid 는 10진 문자열');
      if (reg.uid === null || reg.uid === undefined) { if (!isDec(String(uid ?? ''))) fail('bad_uid: 보류 등록에는 uid(10진 문자열)가 필요하다'); }
      else if (uid !== undefined && String(uid) !== reg.uid) fail('uid_mismatch: 등록된 uid 와 다르다');
      if (provider !== undefined && !(typeof provider === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(provider))) fail('bad_provider: provider 는 영숫자·_·- 1~32자');
      if (reg.uid === null || reg.uid === undefined) reg.uid = String(uid);
      if (provider !== undefined) reg.provider = provider;
      reg.attrs = attrs.map(String);
      reg.slot = slot;
      reg.auid = String(auid);
      await setState(state);
      return { ok: true };
    }
```

`getPublicInfo` 의 반환을 바꾼다:

```js
      return {
        registered: Boolean(r?.uid), pending: Boolean(r && !r.uid), uid: r?.uid ?? null, auid: r?.auid ?? null, attrs: clone(r?.attrs), slot: r?.slot ?? null,
        provider: r?.provider ?? null, hasUserCred: Boolean(state.userCred), consents: clone(state.consents) ?? {},
      };
```

`register` 케이스 위 주석 블록에 한 줄을 더한다: `// 보류 등록(prepareRegister)이 있으면 덮어쓴다 — 완성 등록만 already_registered.`

- [ ] **Step 4: 시뮬레이터를 같은 입출력으로 고친다** — `tests/helpers/snap_sim.mjs`

import 에 `registrationSecretsFromSeed` 를 더한다: `import { createRegistration, registrationSecretsFromSeed } from '../../lib/mode3_wallet.js';` 와 `import { randomBytes } from 'node:crypto';`.

`requireRegistered` 를 바꾼다: `const requireRegistered = () => { if (!state.registration?.uid) throw new Error('not_registered: snap_sim: 등록이 없다'); };`

`register` 첫 줄: `if (state.registration?.uid) throw new Error('already_registered: snap_sim: 이미 등록돼 있다');`

`register` 뒤에 추가:

```js
    /** Google 등록(2026-10-26): 실제 Snap(index.js prepareRegister)과 같은 입출력 — uid 없는 보류 등록, 보류가 있으면 같은 비밀. */
    prepareRegister(decision = 'allow') {
      if (state.registration?.uid) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      if (decision !== 'allow') return { denied: true };
      const pend = state.registration;
      if (pend) return { s_u: pend.s_u, sk_u: pend.sk_u };
      const { s_u, sk_u } = registrationSecretsFromSeed(new Uint8Array(randomBytes(32)));
      state.registration = { uid: null, pwdHash: null, s_u: s_u.toString(), auid: null, sk_u, slot: null, attrs: null, provider: null, registeredAt: new Date().toISOString() };
      state.userCred = null;
      return { s_u: state.registration.s_u, sk_u };
    },
```

`registrationSecretsFromSeed` 의 반환에서 `sk_u` 가 hex 문자열이 아니면(구현을 읽어 확인) `createRegistration` 이 쓰는 것과 같은 변환을 한다 — `createRegistration` 의 `sk_u` 와 같은 모양이어야 한다.

`storeRegistration` 을 index.js 와 같은 검사·순서로 바꾼다(첫 줄은 `if (!state.registration) fail('not_registered: snap_sim: 등록이 없다');`, 이어서 bad_attrs·bad_slot·bad_auid·bad_uid·uid_mismatch·bad_provider, 모두 통과한 뒤에만 uid·provider·attrs·slot·auid 를 쓴다 — Step 3 코드와 같은 문장).

`getPublicInfo` 를 index.js 와 같은 필드로: `{ registered: Boolean(r?.uid), pending: Boolean(r && !r.uid), uid: r?.uid ?? null, auid: r?.auid ?? null, attrs: clone(r?.attrs), slot: r?.slot ?? null, provider: r?.provider ?? null, hasUserCred: Boolean(state.userCred), consents: clone(state.consents) }`.

- [ ] **Step 5: 테스트 통과 확인**

Run: `bash scripts/run_tests.sh snap`
Expected: all passed.
Run: `node tests/test_mode3_wallet_snap.mjs`(chain — :8545 필요)
Expected: 기존 케이스 전부 ok(시뮬레이터 변경 회귀 없음). `tests/test_mode3_wallet_snap.mjs:429` 의 시뮬레이터 케이스가 사유 문자열을 정규식으로 본다면 새 접두어(`not_registered:`/`already_registered:`)에 맞는지 확인하고, 안 맞으면 테스트가 아니라 시뮬레이터 메시지를 기존 문구를 포함하도록 맞춘다(예: `'already_registered: snap_sim: 이미 등록돼 있다'` 는 `이미 등록돼 있다` 를 포함한다).

- [ ] **Step 6: 번들 재빌드**

Run: `cd snap-mode3 && npm run build`
Expected: `dist/bundle.js`·`snap.manifest.json`(source.shasum) 이 바뀐다. `git diff --stat -- snap-mode3` 로 세 파일만 바뀌었는지 본다.
Run: `bash scripts/run_tests.sh snap` 한 번 더(소스 기준이라 같아야 한다).

- [ ] **Step 7: 커밋**

```bash
git add snap-mode3/src/index.js snap-mode3/test/rpc.test.mjs tests/helpers/snap_sim.mjs snap-mode3/dist/bundle.js snap-mode3/dist/bundle.js.map snap-mode3/snap.manifest.json
git commit -m "feat(snap-mode3): Google 등록용 보류 등록(prepareRegister) — storeRegistration 이 uid·provider 를 채움, getPublicInfo 에 pending·provider; 시뮬레이터 동기화, 번들 재빌드" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- snap-mode3/src/index.js snap-mode3/test/rpc.test.mjs tests/helpers/snap_sim.mjs snap-mode3/dist/bundle.js snap-mode3/dist/bundle.js.map snap-mode3/snap.manifest.json
```

---

### Task 2: 에이전트 — `/wallet/oidc/nonce`, `id_token` 경로 3곳, `provider`, `/wallet/config.oidc`

**Files:**
- Modify: `mode3_wallet_agent.js`
- Modify: `lib/mode3_secret_source.js`(`stripSecrets` 가 `provider` 를 남김)
- Create: `tests/test_mode3_wallet_snap_oidc.mjs`
- Modify: `tests/test_mode3_wallet_snap.mjs`(데모 등록의 `provider === 'demo'` 단언 한 줄)
- Modify: `scripts/run_tests.sh`(chain 배열에 새 파일)

**Interfaces:**
- Consumes: Task 1 의 `sim.prepareRegister()`, `sim.storeRegistration({ …, uid, provider })`.
- Produces(HTTP, 지갑 페이지 같은 오리진 — CORS 없음):
  - `GET /wallet/config` → 기존 필드 + `oidc: { enabled, provider, clientId, issuer }`(IdP 를 못 읽으면 `{ enabled:false, provider:null, clientId:null, issuer:null }`, 실패는 캐시하지 않음).
  - `POST /wallet/oidc/nonce`:
    - `{ purpose:'register', sk_u }` → `200 { nonce }`(= `regNonce(eddsaPubOf(sk_u))`), sk_u 형식 오류 400.
    - `{ purpose:'issue', arid, r_rp }` → `200 { nonce }`(= `issueNonce(registration.pk_u, aridSOf({arid, r_rp}))`), 미등록 409 `not_registered`, 형식 오류 400.
    - `{ purpose:'revoke' }` → `200 { nonce }`(= `newRevokeNonce()`).
    - 그 밖 400 `bad_purpose`.
  - `POST /wallet/register { id_token, s_u, sk_u, profile? }` → `201 { uid, slot, auid, attrs, profile, provider }`. `id_token` 과 `uid/pwd/code` 를 함께 주면 400. 토큰을 못 읽으면 400 `bad_id_token`. IdP oidc 꺼짐 503 `oidc_disabled`. IdP 의 uid 가 다르면 502 `uid_mismatch`. 기존 경로의 201 에도 `provider:'demo'`.
  - `GET /wallet/status` → 기존 필드 + `provider`(등록이 있으면 `registration.provider ?? 'demo'`, 없으면 null).
  - `POST /wallet/login` 본문에 `id_token`(선택, 문자열) → `/cia/issue` 에 그대로(재시도 포함).
  - `POST /wallet/self_revoke { id_token }` → 토큰 `sub` 로 계산한 uid 가 등록 uid 와 같을 때만 `/cia/account/self_revoke { id_token }` 중계(다르면 403 `uid_mismatch`, `uid/pwd` 와 함께면 400).

- [ ] **Step 1: 실패하는 chain 테스트를 쓴다** — `tests/test_mode3_wallet_snap_oidc.mjs`

```js
// snap 모드 지갑 에이전트의 OIDC 래퍼 경로(스펙 2026-10-26 Snap OIDC 래퍼 §2·§6). Snap 은 시뮬레이터, Google 은 RS256 발급자 스텁.
// 격리 IdP 는 CIA_ISSUE_AUTH=code — Google 계정은 인증 창 코드 대신 발급마다 id_token 을 낸다. hardhat :8545 필요. (chain 그룹)
//   node tests/test_mode3_wallet_snap_oidc.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { createSnapSim } from './helpers/snap_sim.mjs';
import { VKEY_PATH, eddsaPubOf } from '../lib/mode3_wallet.js';
import { aridSOf } from '../lib/mode3_credential.js';
import { uidOf, regNonce, issueNonce, isRevokeNonce } from '../lib/mode3_oidc_nonce.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, oidc: true });
const { cia, wallet, rp, oidc: stub } = stack;
const sim = createSnapSim();
const SUB = 'g-snap-1';
const UID = uidOf(stub.provider, SUB);

try {
  const stateFile = () => fs.readFileSync(stack.walletStateFile, 'utf8');
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const loginBase = async () => {
    const ch = (await rp.post('/api/mode3/challenge')).body;
    return { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, verifiedOrigin: info.origin };
  };
  const tokens = [];   // 상태 파일에 남지 않는지 마지막에 본다
  const mint = async (o) => { const tok = await stub.mint(o); tokens.push(tok); return tok; };

  await t('config.oidc 는 IdP 의 public_keys.oidc 를 그대로 싣는다', async () => {
    const r = await wallet.get('/wallet/config');
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.oidc, { enabled: true, provider: stub.provider, clientId: stub.clientId, issuer: stub.issuer });
  });

  let prep = null;
  await t('oidc/nonce: register = regNonce(pk_u(sk_u)); revoke 는 revoke:hex64; 등록 전 issue 는 409; 모르는 purpose·잘못된 sk_u 는 400', async () => {
    prep = sim.prepareRegister();
    assert.deepEqual(sim.prepareRegister(), prep, '재시도는 같은 비밀');
    const n = await wallet.post('/wallet/oidc/nonce', { purpose: 'register', sk_u: prep.sk_u });
    assert.equal(n.status, 200, j(n.body)); assert.equal(n.body.nonce, regNonce(await eddsaPubOf(prep.sk_u)));
    const rv = await wallet.post('/wallet/oidc/nonce', { purpose: 'revoke' });
    assert.equal(rv.status, 200); assert.ok(isRevokeNonce(rv.body.nonce), rv.body.nonce);
    assert.equal((await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: '1', r_rp: '2' })).status, 409);
    assert.equal((await wallet.post('/wallet/oidc/nonce', { purpose: 'nope' })).status, 400);
    assert.equal((await wallet.post('/wallet/oidc/nonce', { purpose: 'register', sk_u: 'zz' })).status, 400);
  });

  await t('register(id_token): uid·pwd 와 함께면 400, 못 읽는 토큰 400 bad_id_token, nonce 가 다른 토큰은 IdP 가 거절(502, cia.reason=oidc_nonce_mismatch)', async () => {
    const good = await mint({ sub: SUB, nonce: regNonce(await eddsaPubOf(prep.sk_u)) });
    assert.equal((await wallet.post('/wallet/register', { id_token: good, uid: UID, s_u: prep.s_u, sk_u: prep.sk_u })).status, 400);
    assert.equal((await wallet.post('/wallet/register', { id_token: good, pwd: 'x', s_u: prep.s_u, sk_u: prep.sk_u })).status, 400);
    const bad = await wallet.post('/wallet/register', { id_token: 'not-a-jwt', s_u: prep.s_u, sk_u: prep.sk_u });
    assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'bad_id_token');
    const other = await mint({ sub: SUB, nonce: 'reg:' + '0'.repeat(64) });
    const mm = await wallet.post('/wallet/register', { id_token: other, s_u: prep.s_u, sk_u: prep.sk_u });
    assert.equal(mm.status, 502, j(mm.body)); assert.equal(mm.body.cia?.reason, 'oidc_nonce_mismatch');
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '실패한 등록은 상태를 남기지 않는다');
  });

  await t('register(id_token): 201 { uid=H(provider|sub), provider } → Snap storeRegistration(uid·provider) → status.provider', async () => {
    const tok = await mint({ sub: SUB, nonce: regNonce(await eddsaPubOf(prep.sk_u)) });
    const r = await wallet.post('/wallet/register', { id_token: tok, s_u: prep.s_u, sk_u: prep.sk_u });
    assert.equal(r.status, 201, j(r.body));
    assert.equal(r.body.uid, UID); assert.equal(r.body.provider, stub.provider);
    assert.ok(!('sk_u' in r.body) && !('s_u' in r.body));
    sim.storeRegistration({ attrs: r.body.attrs, slot: r.body.slot, auid: r.body.auid, uid: r.body.uid, provider: r.body.provider });
    assert.equal(sim.getPublicInfo().registered, true); assert.equal(sim.getPublicInfo().provider, stub.provider);
    const s = (await wallet.get('/wallet/status')).body;
    assert.equal(s.registered, true); assert.equal(s.uid, UID); assert.equal(s.provider, stub.provider);
  });

  await t('login: id_token 없으면 IdP 401 oidc_required 를 그대로; 다른 로그인(r_rp)의 nonce 토큰은 502 cia.reason=oidc_nonce_mismatch; 맞는 토큰은 200', async () => {
    const w = () => sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' });
    const b0 = await loginBase();
    const no = await wallet.post('/wallet/login', { ...b0, witness: w() });
    assert.equal(no.status, 401, j(no.body)); assert.equal(no.body.reason, 'oidc_required');
    const b1 = await loginBase();
    const nOther = (await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: b0.arid, r_rp: b0.r_rp })).body.nonce;
    const mm = await wallet.post('/wallet/login', { ...b1, witness: w(), id_token: await mint({ sub: SUB, nonce: nOther }) });
    assert.equal(mm.status, 502, j(mm.body)); assert.equal(mm.body.cia?.reason, 'oidc_nonce_mismatch');
    if (mm.body.userCredIssued !== undefined) sim.updateUserCred(mm.body.userCredIssued);
    const b2 = await loginBase();
    const n = await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: b2.arid, r_rp: b2.r_rp });
    assert.equal(n.status, 200);
    const regPk = JSON.parse(stateFile()).registration.pk_u;
    assert.equal(n.body.nonce, issueNonce(regPk, await aridSOf({ arid: BigInt(b2.arid), r_rp: BigInt(b2.r_rp) })));
    const ok = await stack.withRelay(() => wallet.post('/wallet/login', { ...b2, witness: w(), id_token: await mint({ sub: SUB, nonce: n.body.nonce }) }));
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.issued, true);
    if (ok.body.userCredIssued) sim.updateUserCred(ok.body.userCredIssued);
  });

  await t('self_revoke(id_token): 다른 계정 토큰 403 uid_mismatch, pwd 와 함께면 400, 맞는 토큰 200 → 다음 로그인 403 account_disabled', async () => {
    const nr = async () => (await wallet.post('/wallet/oidc/nonce', { purpose: 'revoke' })).body.nonce;
    const other = await wallet.post('/wallet/self_revoke', { id_token: await mint({ sub: 'someone-else', nonce: await nr() }) });
    assert.equal(other.status, 403, j(other.body)); assert.equal(other.body.reason, 'uid_mismatch');
    assert.equal((await wallet.post('/wallet/self_revoke', { id_token: await mint({ sub: SUB, nonce: await nr() }), pwd: 'x' })).status, 400);
    const ok = await wallet.post('/wallet/self_revoke', { id_token: await mint({ sub: SUB, nonce: await nr() }) });
    assert.equal(ok.status, 200, j(ok.body));
    const b = await loginBase();
    const n = (await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: b.arid, r_rp: b.r_rp })).body.nonce;
    const after = await wallet.post('/wallet/login', { ...b, witness: sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' }), id_token: await mint({ sub: SUB, nonce: n }) });
    assert.equal(after.status, 403, j(after.body)); assert.equal(after.body.reason, 'account_disabled');
  });

  await t('id_token 은 에이전트 상태 파일에 남지 않는다', async () => {
    const file = stateFile();
    for (const tok of tokens) assert.equal(file.includes(tok), false, '토큰이 상태 파일에 있다');
    assert.equal(file.includes('id_token'), false);
  });
} finally {
  await stack.stop();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
```

  `stack.stop`·`stack.withRelay`·`stack.walletStateFile` 이름은 `tests/test_mode3_wallet_snap.mjs` 가 쓰는 것과 같은지 헬퍼(`tests/helpers/isolated_mode3_stack.mjs`)에서 확인하고, 다르면 헬퍼 쪽 이름에 맞춘다. 상태 파일의 등록 위치(`registration.pk_u`)도 실제 모양에 맞춘다.

  `tests/test_mode3_wallet_snap.mjs` 의 첫 등록 케이스(`assert.equal(s.registered, true); assert.equal(s.uid, '12345'); …` 줄 바로 뒤)에 한 줄을 더한다: `assert.equal(s.provider, 'demo', '데모(code) 등록은 provider=demo — 로그인은 지금처럼 IdP 인증 창 경로');` 그리고 그 케이스의 `/wallet/register` 201 응답에 `assert.equal(r.body.provider, 'demo');`.

  `scripts/run_tests.sh` 의 chain 배열에서 `tests/test_mode3_wallet_snap.mjs` 바로 뒤에 `tests/test_mode3_wallet_snap_oidc.mjs` 를 넣는다(주석 한 줄: `# snap 모드 OIDC 래퍼(Google) — 발급자 스텁, CIA_ISSUE_AUTH=code`).

- [ ] **Step 2: 실패를 확인한다**

Run: `node tests/test_mode3_wallet_snap_oidc.mjs`
Expected: config.oidc 없음·`/wallet/oidc/nonce` 404 등으로 FAIL.

- [ ] **Step 3: `mode3_wallet_agent.js` 를 고친다**

import 추가: `import { decodeJwt } from 'jose';`, `import { uidOf, regNonce, issueNonce, newRevokeNonce } from './lib/mode3_oidc_nonce.js';`, 그리고 기존 `./lib/mode3_credential.js` import 에 `aridSOf` 를 더한다.

`pkCia()` 정의 바로 뒤에 둔다:

```js
// OIDC 래퍼(2026-10-26 Snap OIDC 래퍼 §3): IdP 가 공개하는 oidc 설정(enabled·provider·clientId·issuer). 지갑 페이지가 Google 버튼을 그리고(clientId),
// 에이전트가 토큰의 sub 로 uid 를 미리 계산하는 데(provider) 쓴다. 받으면 고정, 실패는 캐시하지 않는다(pkCia() 와 같은 메모이즈).
const OIDC_OFF = { enabled: false, provider: null, clientId: null, issuer: null };
let oidcCfgP = null;
function oidcConfig() {
  return (oidcCfgP ??= (async () => {
    const r = await fetch(`${CIA_URL}/cia/public_keys`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) throw new Error(`IdP 에서 oidc 설정을 받지 못했다 (${r.status})`);
    const o = (await r.json()).oidc;
    return o?.enabled ? { enabled: true, provider: o.provider, clientId: o.clientId, issuer: o.issuer } : OIDC_OFF;
  })().catch((e) => { oidcCfgP = null; throw e; }));
}
/** 토큰의 sub 로 uid 를 계산한다 — 서명은 검증하지 않는다(판정은 IdP 몫, 스펙 §5). 못 읽으면 null. */
function oidcUidOf(provider, idToken) {
  try { const { sub } = decodeJwt(idToken); return typeof sub === 'string' && sub ? uidOf(provider, sub) : null; }
  catch { return null; }
}
```

`/wallet/config` 를 바꾼다:

```js
app.get('/wallet/config', configCors, async (req, res) => {
  try {
    let oidc = OIDC_OFF;
    try { oidc = await oidcConfig(); } catch { /* IdP 를 못 읽으면 꺼진 것으로 보인다 — 다음 요청이 다시 읽는다 */ }
    res.json({ secrets: SECRETS, snapId: SNAP_ID, walletOrigin: WALLET_ORIGIN, rpcUrl: RPC_URL, chainId: (await chainId()).toString(), ciaUrl: CIA_URL, oidc });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

`/wallet/register` 바로 앞에 nonce 라우트를 둔다:

```js
// OIDC 래퍼 nonce(2026-10-26 Snap OIDC 래퍼 §2): 지갑 페이지가 Google 버튼에 넣을 nonce 를 계산한다 — 비밀을 내지 않는다(pk_u·arid_s 의 해시).
// register 는 sk_u 를 받지만 pk_u 계산에만 쓰고 저장·로그하지 않는다(바로 다음 /wallet/register 가 같은 sk_u 를 보낸다). CORS 없음(같은 오리진 전용).
app.post('/wallet/oidc/nonce', async (req, res) => {
  try {
    const { purpose, sk_u, arid, r_rp } = req.body ?? {};
    if (purpose === 'register') {
      if (typeof sk_u !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sk_u)) return res.status(400).json({ error: 'sk_u(hex 64자) 필요' });
      return res.json({ nonce: regNonce(await eddsaPubOf(sk_u)) });
    }
    if (purpose === 'issue') {
      if (!isDec(arid) || !isDec(r_rp)) return res.status(400).json({ error: 'arid, r_rp(10진 문자열) 필요' });
      if (!state.registration?.pk_u) return res.status(409).json({ reason: 'not_registered' });
      return res.json({ nonce: issueNonce(state.registration.pk_u, await aridSOf({ arid: BigInt(arid), r_rp: BigInt(r_rp) })) });
    }
    if (purpose === 'revoke') return res.json({ nonce: newRevokeNonce() });
    res.status(400).json({ reason: 'bad_purpose', detail: 'purpose 는 register·issue·revoke' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

`/wallet/register` 의 머리를 바꾼다(기존 주석 블록 끝에 `// 2026-10-26: id_token(Google 등록) — uid 는 토큰의 sub 로 계산하고 IdP 에는 uid 없이 { id_token, auid, pk_u, sig_reg } 를 낸다.` 한 줄 추가):

```js
app.post('/wallet/register', async (req, res) => {
  try {
    const { uid: uidIn, pwd, code, id_token, profile: profileIn = null, s_u: suIn, sk_u: skIn } = req.body ?? {};
    let uid = uidIn, oidcProvider = null;
    if (id_token !== undefined) {
      if (uidIn !== undefined || pwd !== undefined || code !== undefined) return res.status(400).json({ error: 'id_token 과 uid·pwd·code 는 함께 줄 수 없다' });
      if (typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });
      let oc;
      try { oc = await oidcConfig(); } catch (e) { return res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
      if (!oc.enabled) return res.status(503).json({ reason: 'oidc_disabled' });
      uid = oidcUidOf(oc.provider, id_token);
      if (!uid) return res.status(400).json({ reason: 'bad_id_token', detail: '토큰의 sub 를 읽지 못했다' });
      oidcProvider = oc.provider;
    } else {
      if (!isDec(uid)) return res.status(400).json({ error: 'uid(10진 문자열) 필요' });
      if (typeof pwd !== 'string' && typeof code !== 'string') return res.status(400).json({ error: 'pwd 또는 code 필요' });
    }
    if (BigInt(uid) >= SCALAR_MAX) return res.status(400).json({ error: 'uid 는 2^250 미만' });
```

  이어지는 기존 줄들(snap 모드 s_u·sk_u 검사부터 `normalized` 까지)은 그대로 둔다. IdP 호출부를 바꾼다:

```js
    const idBody = oidcProvider ? { id_token } : typeof code === 'string' ? { code, uid } : { pwd, uid };
    const r = await ciaPost('/cia/register', { ...idBody, auid: reg.auid.toString(), pk_u: pub, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.auid) });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    if (oidcProvider && r.body.uid !== uid) return res.status(502).json({ reason: 'uid_mismatch', detail: 'IdP 가 정한 uid 가 토큰의 sub 로 계산한 값과 다르다' });
    const provider = r.body.provider ?? oidcProvider ?? 'demo';
```

  `full` 에 `provider` 를 더하고(`…, profile: normalized, attrs, provider, userCred: null`), 201 응답에 `provider` 를 더한다(`res.status(201).json({ uid, slot: r.body.slot, auid: reg.auid.toString(), attrs, profile: normalized, provider })`). `stripSecrets`(`lib/mode3_secret_source.js:12`)는 공개 필드만 골라 `provider` 를 버린다 — 공개 정보이므로 남기게 고친다:

```js
export function stripSecrets(registration) {
  if (!registration) return null;
  const { uid, auid, pk_u, slot, attrs, profile = null, provider = 'demo', userCred } = registration;
  return { uid, auid, pk_u, slot, attrs, profile, provider, userCred: userCred ? { Cf_u: userCred.Cf_u, issuedAt: userCred.issuedAt } : null };
}
```

  (`grep -rn stripSecrets tests/` 로 이 함수의 결과를 `deepEqual` 하는 테스트를 찾아 기대값에 `provider` 를 더한다.) 파일 머리 주석의 snap 모드 registration 모양 설명(`mode3_wallet_agent.js:99`)에도 `provider` 를 더한다.

`/wallet/status` 응답 객체에서 `registered: Boolean(reg), uid: …` 뒤에 `provider: reg ? (reg.provider ?? 'demo') : null,` 를 더한다.

`issueSession` 시그니처에 `id_token = null` 을 더하고 `if (auth_code) req.body.auth_code = auth_code;` 다음 줄에 `if (id_token) req.body.id_token = id_token;   // OIDC 래퍼(2026-10-26): Google 계정은 발급마다 토큰 — 로그에 찍지 않는다` 를 넣는다. JSDoc 첫 줄 아래에 `id_token: Google 계정의 발급 토큰(issue:H(pk_u|arid_s) nonce) — 그대로 /cia/issue 본문에 얹는다.` 를 더한다.

`/wallet/login`: 구조 분해에 `id_token = null` 을 더하고, `allowAgent` 검사 다음 줄에 `if (id_token !== null && typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });` 를 넣는다. `issueSession({ … , auth_code })` 두 호출 모두 `auth_code, id_token` 으로 바꾼다(재시도도 같은 토큰 — 같은 arid_s 다).

`/wallet/self_revoke` 를 바꾼다:

```js
app.post('/wallet/self_revoke', async (req, res) => {
  try {
    const { uid, pwd, id_token } = req.body ?? {};
    // Google 계정(2026-10-26 Snap OIDC 래퍼 §2.3): 비밀번호 대신 revoke: nonce 의 id_token. 이 지갑이 든 계정의 토큰만 중계한다
    // (토큰의 sub 로 계산한 uid 를 등록 uid 와 대조 — 서명 검증은 IdP 몫).
    if (id_token !== undefined) {
      if (typeof id_token !== 'string' || uid !== undefined || pwd !== undefined) return res.status(400).json({ error: 'id_token(문자열)만 — uid·pwd 와 함께 줄 수 없다' });
      if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
      let oc;
      try { oc = await oidcConfig(); } catch (e) { return res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
      if (!oc.enabled) return res.status(503).json({ reason: 'oidc_disabled' });
      const tokUid = oidcUidOf(oc.provider, id_token);
      if (!tokUid) return res.status(400).json({ reason: 'bad_id_token' });
      if (tokUid !== state.registration.uid) return res.status(403).json({ reason: 'uid_mismatch' });
      const r = await ciaPost('/cia/account/self_revoke', { id_token });
      return res.status(r.status).json(r.body ?? {});
    }
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
```

  나머지(기존 비밀번호 경로)는 그대로.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_wallet_snap_oidc.mjs` → all passed.
Run: `node tests/test_mode3_wallet_snap.mjs` → all passed(provider=demo 단언 포함).
Run: `node tests/test_mode3_wallet_agent.mjs` → all passed(file 모드 회귀 없음 — `/wallet/register` 머리 재배치 확인).

- [ ] **Step 5: 커밋**

```bash
git add mode3_wallet_agent.js lib/mode3_secret_source.js tests/test_mode3_wallet_snap_oidc.mjs tests/test_mode3_wallet_snap.mjs scripts/run_tests.sh
git commit -m "feat(wallet-agent): OIDC 래퍼 snap 경로 — /wallet/oidc/nonce(register·issue·revoke), register·login·self_revoke 의 id_token, 등록 provider·config.oidc; 체인 테스트" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- mode3_wallet_agent.js lib/mode3_secret_source.js tests/test_mode3_wallet_snap_oidc.mjs tests/test_mode3_wallet_snap.mjs scripts/run_tests.sh
```

---

### Task 3: 페이지 — 지갑 팝업·지갑 페이지의 Google 단계, IdP `/user` 의 "Google 로 등록", 브라우저 테스트

**Files:**
- Modify: `mode3/wallet.html`(GSI 스크립트·자리, `googleToken()`, `handleRegisterMessage` Google 분기, `runAuthorize` Google 단계, `#selfRevokeBtn` Google 분기)
- Modify: `mode3/cia_user.html`(`#registerGoogleBtn`, 팝업 열기 공통화)
- Modify: `mode3/common/strings.js`(문구 키)
- Create: `tests/test_mode3_wallet_snap_oidc_browser.mjs`
- Modify: `scripts/run_tests.sh`(BROWSER 배열)

**Interfaces:**
- Consumes: Task 1 Snap RPC `prepareRegister`·`storeRegistration({…, uid, provider})`; Task 2 HTTP `/wallet/config.oidc`, `/wallet/oidc/nonce`, `/wallet/register {id_token,…}`(201 에 `uid`·`provider`), `/wallet/status.provider`, `/wallet/login {…, id_token}`, `/wallet/self_revoke {id_token}`.
- Consumes(IdP, 변경 없음): `/cia/public_keys` 의 `oidc.enabled`; `mode3-register` 메시지 프로토콜.
- Produces: `mode3-register` 메시지의 새 모양 `{ type:'mode3-register', provider:'google', ciaUrl }`(uid·code 없음). 결과 `mode3-register-result.result` 에 `uid` 추가.

- [ ] **Step 1: 실패하는 브라우저 테스트를 쓴다** — `tests/test_mode3_wallet_snap_oidc_browser.mjs`

  하네스는 `tests/test_mode3_browser.mjs` 의 머리(약 1~100행: import, `launchBrowser`, `exposeFunction('__snapState'|'__snapDialog'|'__sendTx'|'__getReceipt')`, `addInitScript(buildInitScript(...))`, `idpLogin`, `waitText`)를 그대로 옮기고, `tests/test_mode3_user_web_oidc.mjs` 의 `GSI_STUB`(18~24행)을 그대로 옮긴다. 다른 점만 적는다:

```js
// snap 모드 지갑 + Google(OIDC 래퍼) 브라우저 각본(스펙 2026-10-26 Snap OIDC 래퍼 §6). Snap 은 진짜 snap-mode3/src/index.js(ethereum_stub),
// Google 은 GIS 스텁 + 발급자 스텁. 지갑 오리진은 localhost(GSI 는 localhost 에서만 버튼을 그린다). (browser 그룹)
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, autoRelay: true, oidc: true, walletHost: 'localhost' });
const { cia, wallet, rp, oidc: stub } = stack;
const SUB = 'g-browser-1';
// context 를 만든 뒤:
await context.addInitScript(GSI_STUB(`${stub.base}/mint`));
await context.addInitScript(`window.__gsiSub = ${JSON.stringify(SUB)};`);
context.on('page', (p) => p.on('dialog', (d) => d.accept()));   // Demo.confirmDanger(자기 폐기 확인)
```

  케이스(순서대로, `answers` 는 Snap 대화상자 응답 큐):

```js
  const walletPage = await context.newPage();
  await walletPage.goto(`${wallet.base}/`);
  await t('지갑 페이지(localhost): MetaMask·Snap 연결', async () => {
    await walletPage.click('#connectBtn');
    await waitText(walletPage, '#mmStatus', cfg.snapId);
  });

  await t('/user: "Google 로 등록" → 지갑 팝업 → Snap 보류 등록 확인 → 팝업의 Google 버튼 → 등록됨(provider·uid=H(provider|sub)); IdP 로그인 없이', async () => {
    const u = await context.newPage(); await u.goto(`${cia.base}/user`);
    await u.waitForSelector('#registerGoogleBtn:not([hidden])', { timeout: 15_000 });
    answers.push(true);                                                            // prepareRegister 확인 창
    const [popup] = await Promise.all([context.waitForEvent('page'), u.click('#registerGoogleBtn')]);
    await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 30_000 });
    assert.ok(/Google/.test(JSON.stringify(dialogs.at(-1))), 'Snap 확인 창은 Google 등록');
    await popup.click('#gsiBox .gsi-stub');
    await waitText(u, '#userVerdict', uidOf(stub.provider, SUB).slice(0, 8), 60_000);
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.provider, stub.provider); assert.equal(st.uid, uidOf(stub.provider, SUB));
    assert.equal(JSON.parse(JSON.stringify(snapState)).registration.uid, st.uid, 'Snap 보류 등록에 uid 가 채워졌다');
    await u.close();
  });

  await t('RP 로그인: Snap 동의 뒤 IdP 인증 창 대신 팝업의 Google 버튼 → 로그인 성공(CIA_ISSUE_AUTH=code 인데 코드 없음)', async () => {
    const rpPage = await context.newPage(); await rpPage.goto(rp.base);
    answers.push(true);                                                            // consentLogin
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 60_000 });
    assert.equal(await popup.$eval('#idpAuthOpenBtn', (b) => b.hidden), true, 'IdP 인증 창 버튼은 안 보인다');
    await popup.click('#gsiBox .gsi-stub');
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await rpPage.close();
  });

  await t('자기 폐기: 지갑 페이지의 Google 버튼(비밀번호 프롬프트 없음) → IdP 계정 disabled', async () => {
    const before = dialogs.length;
    await walletPage.click('#selfRevokeBtn');
    await walletPage.waitForSelector('#gsiBox .gsi-stub', { timeout: 15_000 });
    await walletPage.click('#gsiBox .gsi-stub');
    await waitText(walletPage, '#snapVerdict', uidOf(stub.provider, SUB).slice(0, 8), 30_000);
    assert.equal(dialogs.length, before, 'Snap 비밀번호 프롬프트를 띄우지 않는다');
    const a = (await cia.adminGet('/cia/accounts')).body.accounts.find((x) => String(x.uid) === uidOf(stub.provider, SUB));
    assert.equal(a?.disabled, true);
  });
```

  `import { uidOf } from '../lib/mode3_oidc_nonce.js';` 를 더한다. `cia.adminGet`·`wallet.base`·`#connectBtn`·`#mmStatus` 이름은 `tests/test_mode3_browser.mjs`·`tests/test_mode3_user_web_oidc.mjs` 에 쓰인 그대로다(다르면 그 파일의 것에 맞춘다). 성공 판정 문구(`#userVerdict`·`#snapVerdict` 에 uid 앞 8자)는 Step 3 문구가 uid 를 싣기 때문이다.

  `scripts/run_tests.sh` 의 BROWSER 배열 끝(`tests/test_mode3_user_web_oidc.mjs` 다음)에 `# snap 모드 + Google(OIDC 래퍼) — 진짜 Snap 코드 + GIS 스텁, 지갑 오리진 localhost` 와 `tests/test_mode3_wallet_snap_oidc_browser.mjs` 를 넣는다.

- [ ] **Step 2: 실패를 확인한다**

Run: `node tests/test_mode3_wallet_snap_oidc_browser.mjs`
Expected: `#registerGoogleBtn` 을 기다리다 FAIL.

- [ ] **Step 3: `mode3/common/strings.js` 에 문구를 더한다** — `idp_register_btn` 근처(idp_ 묶음)와 `wallet_self_revoke_btn` 근처(wallet_ 묶음)에, 같은 `{ ko, en }` 모양으로:

```js
    idp_register_google_btn: { ko: 'Google 로 등록', en: 'Register with Google' },
    idp_register_google_ok: { ko: 'Google 계정 등록됨 — uid {uid}, 슬롯 #{slot}', en: 'Google account registered — uid {uid}, slot #{slot}' },
```
```js
    wallet_gsi_hint: { ko: 'Google 버튼을 눌러 로그인하세요.', en: 'Press the Google button to sign in.' },
    wallet_gsi_origin: { ko: 'Google 로그인은 http://localhost:5100 에서만 됩니다.', en: 'Google sign-in works only at http://localhost:5100.' },
```

  자리표시자 문법(`{uid}`)이 이 파일의 기존 키(예: `wallet_self_revoke_ok`)와 같은지 확인하고 다르면 기존 문법을 따른다.

- [ ] **Step 4: `mode3/wallet.html` 을 고친다**

  `<script src="/common/demo.js"></script>` 다음 줄에 `<script src="/common/gsi.js"></script>`.

  `<header id="demoBar"></header>` 바로 다음(두 `<main>` 바깥 — 팝업·지갑 화면 모두에서 보인다):

```html
  <!-- Google 로그인(OIDC 래퍼, 2026-10-26): 등록·RP 로그인·자기 폐기가 버튼이 필요할 때만 보인다. 버튼은 사용자가 눌러야 한다(GSI 정책). -->
  <section class="card span2" id="gsiWrap" hidden><p id="gsiHint" class="muted"></p><div id="gsiBox"></div></section>
```

  `openIdpAuthOnClick` 함수 바로 뒤에:

```js
    // Google 토큰(OIDC 래퍼, 2026-10-26 Snap OIDC 래퍼 §2): #gsiWrap 에 버튼을 그리고 사용자가 누르기를 기다린다. nonce 는 에이전트
    // /wallet/oidc/nonce 가 계산한 값. 2분 안에 토큰이 없으면 oidc_cancelled. 돌려주는 것은 { token, reason } — token 이 없으면 reason.
    function googleToken(nonce) {
      return new Promise((resolve) => {
        if (!window.Mode3Gsi?.originOk()) return resolve({ token: null, reason: 'gsi_origin' });
        if (!cfg.oidc?.enabled || !cfg.oidc.clientId) return resolve({ token: null, reason: 'oidc_disabled' });
        const wrap = $('gsiWrap'), box = $('gsiBox');
        tte($('gsiHint'), 'wallet_gsi_hint');
        wrap.hidden = false;
        let timer = null;
        const done = (v) => { clearTimeout(timer); wrap.hidden = true; box.replaceChildren(); resolve(v); };
        timer = setTimeout(() => done({ token: null, reason: 'oidc_cancelled' }), 120_000);
        Mode3Gsi.render({ el: box, clientId: cfg.oidc.clientId, nonce, onToken: (tok) => done(tok ? { token: tok, reason: null } : { token: null, reason: 'oidc_cancelled' }) })
          .catch((e) => done({ token: null, reason: e.reason ?? 'gsi_unavailable' }));
      });
    }
    /** googleToken 실패 사유를 사람이 읽는 줄로. */
    const gsiReasonText = (reason) => (reason === 'gsi_origin' ? (tt('wallet_gsi_origin') || 'Google 로그인은 http://localhost:5100 에서만 됩니다.') : `Google 로그인 실패: ${reason}`);
    /** 에이전트의 등록 provider — 못 읽으면 demo 로 본다(지금까지의 경로). */
    async function walletProvider() {
      try { return (await (await fetch('/wallet/status')).json()).provider ?? 'demo'; } catch { return 'demo'; }
    }
```

  `handleRegisterMessage` 에서 `if (already) { … }` 줄 바로 다음, `step('Snap 등록 확인 창을 확인하세요.');` 앞에 Google 분기를 넣는다:

```js
        // Google 등록(2026-10-26 Snap OIDC 래퍼 §2.1): uid·code 없이 온다. Snap 이 비밀을 보류 등록으로 먼저 만들고(pk_u → reg: nonce),
        // 팝업에서 Google 로그인 → 에이전트가 IdP 에 { id_token, auid, pk_u, sig_reg } 로 등록 → Snap 이 uid·provider 를 채운다.
        if (req.provider === 'google') {
          step('Snap 등록 확인 창을 확인하세요.');
          const prep = await invokeSnap('prepareRegister', {});
          if (!prep || prep.denied) { step('등록 거절'); return reply({ ok: false, reason: 'user_denied' }); }
          const n = await postJson('/wallet/oidc/nonce', { purpose: 'register', sk_u: prep.sk_u });
          if (n.status !== 200) { step('nonce 계산 실패'); log(errText(n.status, n.body)); return reply({ ok: false, reason: n.body.reason ?? `HTTP ${n.status}` }); }
          step(tt('wallet_gsi_hint') || 'Google 버튼을 눌러 로그인하세요.');
          const g = await googleToken(n.body.nonce);
          if (!g.token) { step(gsiReasonText(g.reason)); return reply({ ok: false, reason: g.reason }); }
          step('에이전트에 등록하는 중…');
          const { status, body: b } = await postJson('/wallet/register', { id_token: g.token, s_u: prep.s_u, sk_u: prep.sk_u });
          if (status !== 201) { step('등록 실패 — 다시 시도하면 같은 비밀로 이어진다'); log(errText(status, b)); return reply({ ok: false, reason: b.cia?.reason ?? b.reason ?? `HTTP ${status}`, detail: b.detail ?? null }); }
          step('Snap 에 등록 결과 저장 중…');
          try { await invokeSnap('storeRegistration', { attrs: b.attrs, slot: b.slot, auid: b.auid, uid: b.uid, provider: b.provider }); }
          catch (e) { step('등록이 반만 됐다 — Snap 저장 실패'); log(e.message); return reply({ ok: false, reason: 'wallet_error', detail: e.message }); }
          step('등록 완료 — 창을 닫는다.');
          return reply({ ok: true, slot: b.slot, auid: b.auid, uid: b.uid });
        }
```

  `runAuthorize` 에서 IdP 인증 창 블록(`step(tt('idp_auth_open_btn') …` 부터 `const authCode = authRes.code;` 까지)을 다음으로 바꾼다:

```js
          // 발급 인증(2026-10-26 Snap OIDC 래퍼 §2.2): Google 계정은 IdP 인증 창 대신 이 팝업에서 Google 로그인 — nonce 는
          // issue:H(pk_u|arid_s)(에이전트가 이 로그인의 arid·r_rp 로 계산). 데모 계정은 지금처럼 IdP 인증 창(CIA_ISSUE_AUTH=code)의 1회용 코드.
          let authCode = null, idToken = null;
          if ((await walletProvider()) !== 'demo') {
            const n = await postJson('/wallet/oidc/nonce', { purpose: 'issue', arid: req.arid, r_rp: req.r_rp });
            if (n.status !== 200) { step('nonce 계산 실패'); log(errText(n.status, n.body)); return reply({ ok: false, reason: n.body.reason ?? `HTTP ${n.status}` }); }
            step(tt('wallet_gsi_hint') || 'Google 버튼을 눌러 로그인하세요.');
            const g = await googleToken(n.body.nonce);
            if (!g.token) { step(gsiReasonText(g.reason)); return reply({ ok: false, reason: g.reason }); }
            idToken = g.token;
          } else {
            // IdP 인증 창(Task 14, B5) — CIA_ISSUE_AUTH=code 인 IdP 는 로그인마다 이 창이 낸 1회용 코드가 있어야
            // /cia/issue 가 받는다. 재승인(위 reauth 분기)은 /cia/issue 를 타지 않으므로 거치지 않는다.
            // F-13(2026-10-23): window.open 은 버튼의 click 처리기 안에서만 부른다(openIdpAuthOnClick) — 여기서
            // 곧바로 부르면 Snap 동의의 await 들을 지나며 사용자 제스처가 끊겨 일반 팝업 차단기에 막힌다.
            step(tt('idp_auth_open_btn') || 'IdP 인증 창 열기 버튼을 누르세요.');
            const authRes = await openIdpAuthOnClick(step);   // { code, reason } — code 없으면 취소·차단
            if (!authRes.code) { step('IdP 인증 취소'); return reply({ ok: false, reason: authRes.reason ?? 'idp_auth_cancelled' }); }
            authCode = authRes.code;
          }
```

  `/wallet/login` 본문의 `auth_code: authCode,` 다음 줄에 `id_token: idToken ?? undefined,` 를 넣는다(undefined 는 JSON 에서 빠진다).

  `#selfRevokeBtn` 처리기에서 `await ensureConnected();` 다음 줄에 Google 분기를 넣는다:

```js
        // Google 계정(2026-10-26 Snap OIDC 래퍼 §2.3): 비밀번호 대신 revoke: nonce 의 Google 재로그인. Snap 프롬프트는 띄우지 않는다.
        const st = await (await fetch('/wallet/status')).json().catch(() => ({}));
        if (st.provider && st.provider !== 'demo') {
          const n = await postJson('/wallet/oidc/nonce', { purpose: 'revoke' });
          if (n.status !== 200) { setVerdict($('snapVerdict'), false, 'wallet_self_revoke_failed', { reason: n.body.reason ?? `HTTP ${n.status}` }); return; }
          const g = await googleToken(n.body.nonce);
          if (!g.token) { setVerdict($('snapVerdict'), false, 'wallet_self_revoke_failed', { reason: g.reason, detail: gsiReasonText(g.reason) }); return; }
          const uid = st.uid;
          const res = await postJson('/wallet/self_revoke', { id_token: g.token });
          if (res.status === 200) {
            progress.revoked = true;
            setVerdict($('snapVerdict'), true, 'revoked_ok', () => ({ summary: tt('wallet_self_revoke_ok', { uid }) || `uid ${uid} 계정의 폐기를 요청했습니다.`, detail: safeDetail(res.body) }));
          } else setVerdict($('snapVerdict'), false, 'wallet_self_revoke_failed', { reason: res.body.reason ?? `HTTP ${res.status}`, detail: safeDetail(res.body) });
          return;
        }
```

  위 블록의 마지막 `return;` 바로 앞에 `refresh();` 를 넣는다 — 이 `return` 은 `try` 안이라 처리기 끝의 `refresh()` 를 건너뛰기 때문이다(기존 비밀번호 경로는 try 뒤 `refresh()` 를 탄다). 실패 `return` 들은 기존 취소 경로처럼 갱신하지 않는다.

- [ ] **Step 5: `mode3/cia_user.html` 을 고친다**

  `#registerBtn` 줄의 버튼 다음에 `<button id="registerGoogleBtn" hidden data-i18n="idp_register_google_btn">Google 로 등록</button>` 를 넣는다.

  기존 `$('registerBtn').addEventListener('click', …)` 의 팝업 부분을 공통 함수로 뺀다 — 동작은 그대로:

```js
  /** 지갑 등록 팝업을 열고 결과를 userVerdict 에 그린다. buildMsg() 는 mode3-authorize-ready 를 받았을 때 보낼 메시지. btn 은 대기 중 비활성. */
  function openRegisterPopup(btn, buildMsg, okSummary) {
    btn.disabled = true;
    const restore = () => { btn.disabled = false; };
    const walletOrigin0 = walletOrigin;   // 호출 시점에 고정 — 대기 중 Demo.stack 이 다시 바뀌어도 이 요청은 같은 오리진으로 끝낸다
    if (!walletOrigin0) { restore(); return verdict($('userVerdict'), false, 'idp_register_failed', { reason: 'wallet_origin_unknown', summary: tt('wallet_origin_unknown') }); }
    const popup = window.open(`${walletOrigin0}/?authorize=1`, 'mode3-register', 'width=460,height=640');
    if (!popup) { restore(); return verdict($('userVerdict'), false, 'idp_register_failed', { reason: 'popup_blocked' }); }
    // …기존 본문 그대로(Demo.verdict pending, done/finish, onMsg, timer, closedPoll) — 단 두 곳만 바뀐다:
    //   mode3-authorize-ready 에 보내는 메시지: popup.postMessage(buildMsg(), walletOrigin0)
    //   성공 요약: r.ok ? () => ({ summary: okSummary(r) }) : { reason: r.reason, detail: r.detail }
  }
  $('registerBtn').addEventListener('click', async () => {
    if (!me) return verdict($('userVerdict'), false, 'idp_register_failed', { reason: 'login_required' });
    $('registerBtn').disabled = true;
    const c = await post('/cia/user/register_code');
    $('registerBtn').disabled = false;
    if (c.status !== 200) return verdict($('userVerdict'), false, 'idp_register_failed', { reason: c.body?.reason ?? `HTTP ${c.status}` });
    openRegisterPopup($('registerBtn'), () => ({ type: 'mode3-register', uid: me.uid, code: c.body.code, ciaUrl: location.origin }),
      (r) => tt('idp_register_ok', { slot: r.slot }) || `등록됨 — 슬롯 #${r.slot}`);
  });
  // Google 로 등록(2026-10-26 Snap OIDC 래퍼 §2.1): IdP 로그인·등록 코드 없이 지갑 팝업에서 Google 로그인 — uid 는 IdP 가 토큰으로 정한다.
  $('registerGoogleBtn').addEventListener('click', () => openRegisterPopup($('registerGoogleBtn'), () => ({ type: 'mode3-register', provider: 'google', ciaUrl: location.origin }),
    (r) => tt('idp_register_google_ok', { uid: r.uid, slot: r.slot }) || `Google 계정 등록됨 — uid ${r.uid}, 슬롯 #${r.slot}`));
```

  기존 본문(`Demo.verdict(...pending...)` 부터 `closedPoll` 까지)은 **글자 그대로** `openRegisterPopup` 안으로 옮기고, 위 주석의 두 곳만 바꾼다. `finish` 의 `refreshMe()` 호출은 그대로 둔다.

  초기화 블록(`(async () => { Demo.init(…); initStack(); await refreshMe(); })();`)의 `initStack();` 다음 줄에:

```js
    // Google 등록 버튼은 이 IdP 가 OIDC 래퍼를 켰을 때만 보인다(public_keys.oidc.enabled).
    try { $('registerGoogleBtn').hidden = !(await (await fetch('/cia/public_keys')).json()).oidc?.enabled; } catch { /* 숨긴 채 */ }
```

- [ ] **Step 6: 통과 확인**

Run: `node tests/test_mode3_wallet_snap_oidc_browser.mjs` → all passed.
Run: `node tests/test_mode3_browser.mjs` → all passed(데모 등록·IdP 인증 창 회귀 없음, `openRegisterPopup` 리팩터 확인).
Run: `node tests/test_mode3_user_web_oidc.mjs` → all passed(strings·gsi 공용 파일 회귀 없음).

- [ ] **Step 7: 커밋**

```bash
git add mode3/wallet.html mode3/cia_user.html mode3/common/strings.js tests/test_mode3_wallet_snap_oidc_browser.mjs scripts/run_tests.sh
git commit -m "feat(mode3-pages): snap 모드 Google 래퍼 — /user 'Google 로 등록', 지갑 팝업 Google 단계(등록·RP 로그인), 지갑 페이지 Google 자기 폐기; 브라우저 테스트" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- mode3/wallet.html mode3/cia_user.html mode3/common/strings.js tests/test_mode3_wallet_snap_oidc_browser.mjs scripts/run_tests.sh
```

---

### Task 4: 분리 스크립트 클라이언트 ID 전달 + 런북

**Files:**
- Modify: `scripts/demo_split_start.sh`(머리 사용법 주석, IdP role.env 줄)
- Modify: `docs/MODE3_DEMO.md`(분리 데모 절에 Google 소절)

**Interfaces:**
- Consumes: IdP 의 기존 env `MODE3_OIDC_CLIENT_ID`(cia.js:75).
- Produces: 환경변수 `OIDC`(기본 1, `0` 이면 끔), `MODE3_OIDC_CLIENT_ID`(있으면 `.env` 보다 우선).

- [ ] **Step 1: 스크립트를 고친다**

  머리 사용법 주석의 `ISSUE_AUTH=code …` 묶음 다음에 두 줄:

```bash
#        OIDC=0 bash scripts/demo_split_start.sh          # Google(OIDC 래퍼) 끔. 기본은 켬(2026-10-26): IdP 에 MODE3_OIDC_CLIENT_ID 를 넘긴다 — 값은 환경변수 MODE3_OIDC_CLIENT_ID,
#                                                          # 없으면 이 VM .env 의 GOOGLE_CLIENT_ID(Mode 1 공유 ID, 출력하지 않는다). Google 콘솔 승인 오리진에 http://localhost:5100 이 있어야 한다.
```

  `put_env() { … }` 정의 바로 다음, IdP `printf` 줄 앞에:

```bash
# OIDC 래퍼 클라이언트 ID(2026-10-26 Snap OIDC 래퍼 §3) — 값은 어디에도 출력하지 않는다(진행 줄은 on/off 만).
oidc_client_id() { [ -n "${MODE3_OIDC_CLIENT_ID:-}" ] && { printf '%s' "$MODE3_OIDC_CLIENT_ID"; return; }; [ -f "$1" ] && sed -n 's/^GOOGLE_CLIENT_ID=//p' "$1" | head -n1 | tr -d '\r"'"'"; }
OIDC_LINE=""
if [ "${OIDC:-1}" != 0 ]; then OIDC_ID="$(oidc_client_id .env)"; [ -n "$OIDC_ID" ] && OIDC_LINE="MODE3_OIDC_CLIENT_ID=$OIDC_ID"; unset OIDC_ID; fi
echo "  OIDC(Google): $([ -n "$OIDC_LINE" ] && echo on || echo off)"
```

  IdP `printf` 줄 끝의 `| put_env "$IDP"` 앞에 `${OIDC_LINE:+"$OIDC_LINE"}` 를 인자로 더한다(따옴표 그대로).

  스크립트 안에 `set -x` 가 없는지 확인한다(있으면 그 구간에서 끈다).

- [ ] **Step 2: 검증(스크립트는 실행하지 않는다)**

Run: `bash -n scripts/demo_split_start.sh` → 출력 없음.
가짜 env 로 함수만 확인(스크래치 디렉터리 — 실제 `.env` 를 읽지 않는다):

```bash
S=$(mktemp -d); printf 'X=1\nGOOGLE_CLIENT_ID="fake-id.apps"\n' > "$S/env"
eval "$(sed -n '/^oidc_client_id()/p' scripts/demo_split_start.sh)"
[ "$(oidc_client_id "$S/env")" = fake-id.apps ] && echo OK1
[ "$(MODE3_OIDC_CLIENT_ID=over oidc_client_id "$S/env")" = over ] && echo OK2
[ -z "$(oidc_client_id "$S/none")" ] && echo OK3
rm -r "$S"
```
Expected: `OK1` `OK2` `OK3`.

- [ ] **Step 3: 런북** — `docs/MODE3_DEMO.md` 의 분리 VM 데모 절(`demo_split_start.sh` 를 설명하는 절, `grep -n "demo_split" docs/MODE3_DEMO.md` 로 찾는다) 끝에 소절을 더한다:

```markdown
#### Google 로 등록·로그인·자기 폐기(Snap 모드, 2026-10-26)

- 켜짐이 기본이다: 스크립트가 IdP 에 `MODE3_OIDC_CLIENT_ID` 를 넘긴다(환경변수 → 없으면 이 VM `.env` 의 `GOOGLE_CLIENT_ID`, Mode 1 공유 ID — 값은 출력하지 않는다). 끄려면 `OIDC=0`. IdP 는 공유 ID 로 뜨면 기동 때 경고한다(선행 스펙 §5).
- Google 콘솔의 승인된 JavaScript 오리진에 `http://localhost:5100` 이 있어야 한다. Google 버튼은 지갑 페이지·팝업(localhost:5100)에만 뜬다 — IdP(사설 IP)의 `/account` 에서는 안 된다.
- Snap 이 바뀌었다(보류 등록 `prepareRegister`). `cd snap-mode3 && npm run build` 뒤 MetaMask 에서 Snap 을 다시 설치하고 지갑 페이지 "Snap 초기화".
- 수동 확인(실제 Google, 1회):
  1. IdP `/user` → "Google 로 등록" → 팝업의 Snap 확인 → 팝업의 Google 버튼 → `/user` 에 "Google 계정 등록됨 — uid …".
  2. RP 로그인 → Snap 동의 → 팝업의 Google 버튼(IdP 인증 창 없음) → 로그인 성공 → 거래.
  3. 지갑 페이지 "계정 자기 폐기" → Google 버튼 → 폐기 요청됨 → 다음 RP 로그인 거절(account_disabled).
- 등록이 Google 단계에서 끊기면 다시 "Google 로 등록" 하면 된다 — Snap 이 같은 보류 비밀을 다시 쓴다. 버리려면 "Snap 초기화".
```

- [ ] **Step 4: 커밋**

```bash
git add scripts/demo_split_start.sh docs/MODE3_DEMO.md
git commit -m "feat(split-demo): IdP 에 MODE3_OIDC_CLIENT_ID 전달(환경변수 우선, 없으면 .env 의 GOOGLE_CLIENT_ID — 출력 없음, OIDC=0 으로 끔); 런북 Google 소절" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- scripts/demo_split_start.sh docs/MODE3_DEMO.md
```
