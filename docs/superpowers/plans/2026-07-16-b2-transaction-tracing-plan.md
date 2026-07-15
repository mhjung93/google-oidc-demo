# B2 트랜잭션 추적 구현 계획

> **에이전트 작업자용:** 이 계획을 Task 단위로 실행하려면 superpowers:subagent-driven-development(추천) 또는 superpowers:executing-plans를 사용하세요. 각 단계는 체크박스(`- [ ]`) 문법으로 추적됩니다.

**목표:** 분쟁이 된 온체인 PPID 트랜잭션의 공개된 `(pk_i, max_height)`로부터, 인가된 주체가
실제 `uid`를 복원할 수 있게 한다.

**아키텍처:** IdP(`custom_idp.js`)는 발급 시점에 `r_token → uid` 매핑을 메모리에 기록하고
조회 엔드포인트를 제공한다. RP(`server.js`)는 로그인 성공 시점에 세션별 `rp_nonce`/`r_token`을
메모리에 기록하고, 분쟁 트랜잭션의 `(pk_i, max_height)`로 `r_token`을 재계산해 일치하는
세션을 찾은 뒤 IdP에 조회를 위임하는 엔드포인트를 제공한다.

**기술 스택:** Express (기존), circomlibjs의 Poseidon (기존 `server.js`/`custom_idp.js`에
이미 초기화돼 있음), 별도 신규 의존성 없음.

## 전역 제약사항

- 이번 반복(B2 첫 단계)에서는 인가(authority) 승인 절차를 의도적으로 생략한다 —
  `/api/mode2/trace_transaction`, `/idp/lookup_uid_by_r_token` 둘 다 인증/인가 게이트 없이
  바로 조회 가능하다. 이건 스펙에서 명시적으로 정한 범위이지 누락이 아니다.
- 로그(`issuanceLog`, `sessionLog`)는 메모리 전용이다. 파일/DB에 쓰지 않는다. 서버 재시작
  시 기록이 사라지는 게 의도된 동작이다.
- `pk_i`/`max_height`는 프로젝트 전역 컨벤션과 동일하게 10진수 문자열로 주고받는다 (hex
  아님).
- `circuits/pi_pk_i.circom`, `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol`,
  `wallet_agent.js`는 이 계획에서 수정하지 않는다 — B2는 B1이 만든 값을 읽기만 한다.
- `custom_idp.js`의 `/register_rp`(`psSign`)는 절대 건드리지 않는다.

---

## Task 1: IdP 발급 로그 + 조회 엔드포인트 (`custom_idp.js`)

**파일:**
- 수정: `custom_idp.js:163`(전역 상태 선언부), `custom_idp.js:263-352`(`verifyPiIAndIssueToken`),
  `custom_idp.js:382` 부근(라우트 추가)

**인터페이스:**
- 산출물: `POST /idp/lookup_uid_by_r_token` — 요청 `{ r_token: string }`, 응답 성공 시
  `{ uid: number }` (200), 실패 시 `{ error: string }` (404 없음 / 400 필드 누락)
- Task 2가 이 엔드포인트를 호출한다 (`http://localhost:4000/idp/lookup_uid_by_r_token`, 기존
  `custom_idp.js`의 기본 포트 4000 — 실제 파일에서 `PORT` 상수/환경변수를 확인해서 Task 2와
  일치시킬 것)

- [ ] **Step 1: 전역 발급 로그 선언 추가**

Find (`custom_idp.js:163`):

```js
const usedNonces = new Set();
```

Replace with:

```js
const usedNonces = new Set();
// B2 추적용 발급 로그: r_token -> uid. 메모리 전용, 서버 재시작 시 소실됨(의도된 데모 한계).
const issuanceLog = new Map();
```

- [ ] **Step 2: 발급 시점에 로그 기록**

Find (`custom_idp.js` 근처 348-352번 줄, `verifyPiIAndIssueToken` 함수의 반환 직전):

```js
  console.log(`[CustomIdP][Step 11] IdP auth token issued and returned for Wallet delivery. ${ms(start)}`);

  return idpToken;
```

Replace with:

```js
  issuanceLog.set(rToken.toString(), user.uid);
  console.log(`[CustomIdP][Step 11] IdP auth token issued and returned for Wallet delivery. ${ms(start)}`);

  return idpToken;
```

- [ ] **Step 3: 조회 엔드포인트 추가**

Find (`custom_idp.js:382` 부근):

```js
app.get('/ps_public_keys', (req, res) => {
```

Replace with:

```js
app.post('/idp/lookup_uid_by_r_token', (req, res) => {
  const { r_token } = req.body ?? {};
  if (!r_token) {
    return res.status(400).json({ error: 'r_token is required' });
  }
  const uid = issuanceLog.get(String(r_token));
  if (uid === undefined) {
    return res.status(404).json({ error: 'No issuance record found for this r_token' });
  }
  res.json({ uid });
});

app.get('/ps_public_keys', (req, res) => {
```

- [ ] **Step 4: 문법 검사**

Run: `node --check custom_idp.js`
Expected: 에러 없음.

- [ ] **Step 5: 커밋**

```bash
git add custom_idp.js
git commit -m "feat(mode2): add IdP-side issuance log and r_token->uid lookup endpoint (B2)"
```

---

## Task 2: RP 세션 로그 + 추적 엔드포인트 (`server.js`)

**파일:**
- 수정: `server.js`(전역 상태 선언부, `/api/mode2/sso_success` 핸들러, 라우트 추가)

**인터페이스:**
- 소비: Task 1의 `POST http://localhost:4000/idp/lookup_uid_by_r_token`
- 산출물: `POST /api/mode2/trace_transaction` — 요청 `{ pk_i: string, max_height: string }`,
  응답 성공 시 `{ uid: number }` (200), 실패 시 `{ error: string }` (400/404/502)

- [ ] **Step 1: 전역 세션 로그 선언 추가**

Find (`server.js:37`):

```js
let rpRegistration = null;
```

Replace with:

```js
let rpRegistration = null;
// B2 추적용 세션 로그: 로그인 세션마다 { auid_i, r_token, rp_nonce, timestamp }.
// 메모리 전용, 서버 재시작 시 소실됨(의도된 데모 한계).
const sessionLog = [];
```

- [ ] **Step 2: 로그인 성공 시점에 세션 기록**

Find (`server.js` 근처 622-627번 줄, `/api/mode2/sso_success` 핸들러 안):

```js
  // Single-use: spend the rp_nonce only after the full RP-side verification
  // succeeds, so malformed proof/signature attempts do not burn the session.
  delete req.session.rpNonce;

  console.log('[Mode 2] Verification SUCCESS. Session established.');
  res.json({ success: true });
```

Replace with:

```js
  // B2 추적용: rp_nonce를 지우기 전에 나중에 재계산 가능하도록 세션 기록을 남긴다.
  sessionLog.push({
    auid_i: idpToken.auid_i,
    r_token: idpToken.r_token,
    rp_nonce: sessionRpNonce,
    timestamp: Date.now(),
  });

  // Single-use: spend the rp_nonce only after the full RP-side verification
  // succeeds, so malformed proof/signature attempts do not burn the session.
  delete req.session.rpNonce;

  console.log('[Mode 2] Verification SUCCESS. Session established.');
  res.json({ success: true });
```

- [ ] **Step 3: 추적 엔드포인트 추가**

Find (`server.js` 근처 705번 줄):

```js
const server = app.listen(PORT, async () => {
```

Replace with:

```js
app.post('/api/mode2/trace_transaction', async (req, res) => {
  const { pk_i, max_height } = req.body ?? {};
  if (!pk_i) return res.status(400).json({ error: 'pk_i is required' });
  if (!max_height) return res.status(400).json({ error: 'max_height is required' });

  await ensureEdDSA();
  if (!poseidon) return res.status(503).json({ error: 'Poseidon not initialized yet' });

  const pkField = valueToField(pk_i);
  const maxHeightField = valueToField(max_height);

  const match = sessionLog.find((record) => {
    const rpNonceField = valueToField(record.rp_nonce);
    const recomputed = poseidon.F.toObject(poseidon([pkField, maxHeightField, rpNonceField]));
    return String(recomputed) === String(record.r_token);
  });

  if (!match) {
    return res.status(404).json({ error: 'No matching session found for this pk_i/max_height' });
  }

  try {
    const idpResponse = await fetch(`${CUSTOM_IDP_BASE_URL}/idp/lookup_uid_by_r_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ r_token: match.r_token }),
    });
    const idpResult = await idpResponse.json();
    if (!idpResponse.ok) {
      return res.status(idpResponse.status).json(idpResult);
    }
    res.json({ uid: idpResult.uid });
  } catch (err) {
    res.status(502).json({ error: `Failed to reach IdP for uid lookup: ${err.message}` });
  }
});

const server = app.listen(PORT, async () => {
```

`CUSTOM_IDP_BASE_URL`은 `server.js`에 이미 있는 기존 상수(기본값
`http://127.0.0.1:4000`, `server.js:25`)로, `/register_rp`/`/ps_public_keys` 호출에 이미
쓰이고 있다 — 새로 만들지 말고 그대로 재사용한다.

- [ ] **Step 4: 문법 검사**

Run: `node --check server.js`
Expected: 에러 없음.

- [ ] **Step 5: 커밋**

```bash
git add server.js
git commit -m "feat(mode2): add RP-side session log and trace_transaction endpoint (B2)"
```

---

## Task 3: 엔드투엔드 테스트

**파일:** 없음(검증만, 코드 변경 없음)

- [ ] **Step 1: 서버 기동 확인**

포트 3000(`server.js`), 4000(`custom_idp.js`), 5001(`wallet_agent.js`)가 비어있는지 확인
후, 세 프로세스를 기동한다 (사용자가 이미 띄운 프로세스가 있으면 재사용 여부를 먼저 확인).

- [ ] **Step 2: 정상 흐름 확인**

Mode 2 로그인(Step 1~15)을 curl/스크립트로 1회 실행해서 실제 `pk_i`(B1의
`/submitTransaction` 응답 또는 Step 8 응답에서 얻음)와 `max_height`를 확보한다. 이 값으로
`POST /api/mode2/trace_transaction` 호출:

```bash
curl -s -X POST http://localhost:3000/api/mode2/trace_transaction \
  -H 'Content-Type: application/json' \
  -d '{"pk_i":"<실제 pk_i>","max_height":"<실제 max_height>"}'
```

Expected: `{"uid": <로그인에 사용한 계정의 uid>}`, HTTP 200.

- [ ] **Step 3: 존재하지 않는 pk_i 확인**

```bash
curl -s -X POST http://localhost:3000/api/mode2/trace_transaction \
  -H 'Content-Type: application/json' \
  -d '{"pk_i":"999999999999999999","max_height":"1"}'
```

Expected: `{"error":"No matching session found for this pk_i/max_height"}`, HTTP 404.

- [ ] **Step 4: 다중 세션 구분 확인**

같은 계정으로 로그인을 한 번 더 실행해서 두 번째 세션(다른 `pk_i`)을 만든다. 각 세션의
`pk_i`로 각각 `/api/mode2/trace_transaction`을 호출해서, 두 요청 모두 올바르게 같은 `uid`를
반환하지만 서로 다른 세션 레코드가 매칭되는지 확인(예: 로그로 어떤 레코드가 매칭됐는지
확인).

- [ ] **Step 5: 서버 재시작 후 메모리 소실 확인**

`server.js`와 `custom_idp.js`를 재시작한 뒤, Step 2에서 쓴 `pk_i`로 다시
`/api/mode2/trace_transaction`을 호출 → 404 확인 (의도된 데모 한계).

- [ ] **Step 6: 정리**

기동한 프로세스 종료, 포트 3000/4000/5001이 비어있는지 확인.

- [ ] **Step 7: ledger 갱신**

`.superpowers/sdd/progress.md`에 Task 3 결과 기록.
