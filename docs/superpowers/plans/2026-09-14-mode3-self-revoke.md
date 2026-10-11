# Mode 3 사용자 개시 폐기(self_revoke) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 장치를 잃은 사용자가 계정 비밀번호만으로 자기 계정을 폐기(미만료 credential 리프 삽입 + `disabled`)할 수 있는 CIA 엔드포인트와 사용자 페이지를 추가한다.

**Architecture:** `cia.js`의 기존 `/cia/revoke` `scope: 'account'` 분기를 `revokeAccount(uid, head)` 헬퍼로 빼고, 관리자 라우트와 새 `POST /cia/account/self_revoke`(비밀번호 인증, 관리자 시크릿 불필요)가 그 헬퍼를 공유한다. 게시(`/cia/publish`)·복구(`set_disabled`)·컨트랙트·회로·지갑·RP 는 바꾸지 않는다. 화면은 CIA 가 `GET /account`로 직접 제공한다.

**Tech Stack:** Node.js ESM, express, 기존 격리 테스트 하네스(`tests/helpers/isolated_cia.mjs`, `isolated_mode3_stack.mjs`), hardhat 로컬 노드(:8545).

**Spec:** `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` §6.5.1 (2026-09-14 추가). 실행자는 §6.5·§6.5.1·§6.6 을 읽는다.

## Global Constraints

- 응답·주석·문서는 한글. 기존 파일의 문체(짧은 단정문, `—` 대시)를 따른다.
- `cia.js`의 공개 응답 형태는 바꾸지 않는다. `self_revoke`의 응답은 `/cia/revoke`와 같은 `{ inserted, root, pending }`에 `disabled: true`를 더한 것이다.
- 비밀번호 비교는 기존 `secretMatches`(timingSafeEqual)를 쓴다. 비밀번호를 로그·응답에 넣지 않는다.
- 새 의존성 없음. `express.static` 쓰지 않음(관리자 페이지와 같이 `sendFile` 허용 목록 방식).
- 테스트는 `chain` 그룹(`bash scripts/run_tests.sh chain`)에 이미 있는 두 파일에 케이스를 더한다. :8545 hardhat 노드가 필요하며, 없으면 `npx hardhat node`를 백그라운드로 띄우고 끝나면 종료한다.
- 커밋은 사용자 승인 후에만 한다(CLAUDE.md). 각 Task 끝의 커밋 단계는 "제안 후 승인 시 실행"이다.

---

### Task 1: `revokeAccount` 헬퍼 + `POST /cia/account/self_revoke`

**Files:**
- Modify: `cia.js:255-294` (`/cia/revoke` 라우트) — account 분기를 헬퍼로 추출
- Modify: `cia.js:332-338` (`set_disabled` 라우트 아래) — 새 라우트 추가
- Test: `tests/test_cia_register_issue.mjs:173-178` ('복구' 케이스 바로 뒤에 삽입)

**Interfaces:**
- Consumes: `pruneExpired(uid, head)`, `tree.insert(BigInt) → boolean`(중복이면 false), `state.accounts[uid].disabled`, `state.revoked`, `state.pending`, `persist()`, `headHeight()`, `secretMatches(a, b)`, `DEMO_ACCOUNTS`, `isDec`.
- Produces: `async function revokeAccount(uid, head) → { inserted: string[], root: string, pending: number }` — 관리자 라우트와 self_revoke 가 공유. `POST /cia/account/self_revoke` 본문 `{ uid: string, pwd: string }`, 응답 200 `{ inserted, root, pending, disabled: true }`, 400(형식), 401(비밀번호), 404(미등록).

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_cia_register_issue.mjs`에서 `await t('set_disabled false → 다시 발급된다 (복구, §6.6)', ...)` 블록(177행 `});`) 바로 뒤에 아래를 넣는다. 이 위치에서 계정은 활성 상태이고 `user`는 등록돼 있다. 블록 끝에서 계정을 다시 활성화해야 뒤의 케이스(`계정은 앞의 'set_disabled false' 케이스에서 재활성화됨` 전제)가 그대로 돈다.

```js
  await t('self_revoke: 잘못된 비밀번호 401, 등록 안 된 계정 404, 형식 오류 400', async () => {
    // 관리자 시크릿 없이 부른다 — 이 경로의 인증은 계정 비밀번호뿐이다(설계 §6.5.1).
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'wrong' })).status, 401);
    // alice(67890) 는 데모 계정이지만 이 인스턴스에 등록한 적이 없다.
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' })).status, 404);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: 'abc', pwd: 'password123' })).status, 400);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345' })).status, 400);
    // 실패한 요청은 아무것도 바꾸지 않는다
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 200, '계정은 여전히 활성이어야 한다');
  });

  await t('self_revoke: 비밀번호만으로 계정 전체 폐기 — 리프 삽입 + disabled, 이후 발급 403', async () => {
    const { body: ib } = await issueRequest(user);
    const issued = await cia.post('/cia/issue', ib);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const leaf = await credLeaf(BigInt(issued.body.C));
    const before = (await cia.get('/cia/state')).body.pendingCount;

    const r = await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.disabled, true);
    assert.ok(r.body.inserted.map((h) => BigInt(h)).includes(leaf), '방금 발급한 credential 의 리프가 들어가야 한다');
    assert.equal(r.body.pending, before + r.body.inserted.length);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, r.body.pending);

    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 403, 'disabled 계정은 발급 거절');
  });

  await t('self_revoke: 재요청은 멱등 — 새 리프 없이 200, disabled 유지', async () => {
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.inserted, []);
    assert.equal(r.body.disabled, true);
    assert.equal(r.body.pending, pendingBefore);
    // 복구는 관리자만 한다(§6.6). 뒤 케이스들을 위해 여기서 되살린다.
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 200);
  });
```

- [ ] **Step 2: 테스트가 실패하는지 확인**

:8545 가 비어 있으면 먼저 `npx hardhat node`를 백그라운드로 띄운다.

Run: `node tests/test_cia_register_issue.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: `FAIL self_revoke: ...` 3건 (라우트가 없어 404 → `assert.equal(..., 401)`부터 실패). 나머지 케이스는 `ok`.

- [ ] **Step 3: 헬퍼 추출 + 라우트 구현**

`cia.js`의 `/cia/revoke` 라우트를 아래처럼 바꾼다. `scope === 'account'` 분기의 본문이 `revokeAccount`로 옮겨가고 응답 형태는 그대로다.

```js
// §6.5 계정 전체 폐기: 그 uid 의 미만료 리프 전부 삽입 + disabled. 관리자 폐기(/cia/revoke scope=account)와
// 사용자 자기 폐기(/cia/account/self_revoke, §6.5.1)가 같은 처리를 탄다 — 다른 것은 "누가 개시하느냐"뿐이다.
// tree.insert 는 이미 있는 리프에 false 를 돌려주므로 두 번 불러도 새 리프가 들어가지 않는다(멱등).
async function revokeAccount(uid, head) {
  const targets = pruneExpired(uid, head).map((e) => e.leaf);
  state.accounts[uid].disabled = true;
  const inserted = [];
  for (const l of targets) {
    if (await tree.insert(BigInt(l))) { state.revoked.push(l); state.pending.push(l); inserted.push(l); }
  }
  persist();
  return { inserted, root: tree.getRoot().toString(), pending: state.pending.length };
}

// §6.5 폐기. account = 그 uid 의 미만료 리프 전부 + disabled. credential = 리프 하나.
app.post('/cia/revoke', requireAdmin, async (req, res) => {
  try {
    const { uid, scope, leaf, C } = req.body ?? {};
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    const head = await headHeight();
    if (scope === 'account') return res.json(await revokeAccount(uid, head));
    if (scope !== 'credential') return res.status(400).json({ error: "scope must be 'account' or 'credential'" });
    // 그 uid 의 미만료 발급 목록에 있는 리프만 받는다 — 폐기는 append-only 라 잘못 넣은 리프가
    // 영구히 남고, 범위 밖 값은 트리가 throw 한다. leaf 대신 C 를 주면 서버가 리프를 유도한다.
    // 발급 기록은 {leaf, C} 쌍이라 다시 해시하지 않고 기록에서 찾는다. isDec 은 앞자리 0 을 허용하므로
    // BigInt 로 정규화한 뒤 비교한다.
    const issued = pruneExpired(uid, head);
    let entry;
    if (isDec(C)) entry = issued.find((e) => e.C === BigInt(C).toString());
    else if (isDec(leaf)) entry = issued.find((e) => e.leaf === BigInt(leaf).toString());
    else return res.status(400).json({ error: 'leaf or C required' });
    if (!entry) return res.status(404).json({ error: 'leaf not issued to this uid (or expired)' });
    const inserted = [];
    if (await tree.insert(BigInt(entry.leaf))) { state.revoked.push(entry.leaf); state.pending.push(entry.leaf); inserted.push(entry.leaf); }
    persist();
    res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```

그리고 `app.post('/cia/account/set_disabled', ...)` 라우트 바로 아래에 새 라우트를 넣는다.

```js
// §6.5.1 사용자 개시 폐기. 인증은 계정 비밀번호다 — 지갑 키가 아니다. 장치를 잃은 사용자에게 sk_u 는 없고
// 공격자에게는 있으므로, 인증 수단은 장치 밖에 있어야 한다. 처리는 관리자의 계정 폐기와 같다.
// 등록(§6.1)과 같은 순서로 검사한다: 형식 → 비밀번호 → 등록 여부. 비밀번호가 틀리면 등록 여부를 알려주지 않는다.
app.post('/cia/account/self_revoke', async (req, res) => {
  try {
    const { uid, pwd } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid, pwd required' });
    const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
    if (!acct || !secretMatches(pwd, acct.password)) return res.status(401).json({ error: 'invalid credentials' });
    if (!state.accounts[uid]) return res.status(404).json({ error: 'not registered' });
    const head = await headHeight();
    const out = await revokeAccount(uid, head);
    res.json({ ...out, disabled: true });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `node tests/test_cia_register_issue.mjs 2>&1 | grep -E "^(ok|FAIL)|통과|실패"`
Expected: 모든 케이스 `ok`, `FAIL` 0건. 기존 `revoke(account)` 케이스도 그대로 통과해야 한다(헬퍼 추출이 동작을 바꾸지 않았다는 증거).

- [ ] **Step 5: 커밋 (사용자 승인 후)**

```bash
git add cia.js tests/test_cia_register_issue.mjs
git commit -m "feat(mode3): 사용자 개시 폐기 — POST /cia/account/self_revoke, 계정 폐기를 revokeAccount 로 공유 (§6.5.1)"
```

---

### Task 2: 사용자 페이지 `GET /account` + 데모 스택 테스트

**Files:**
- Create: `mode3/cia_account.html`
- Modify: `cia.js:170` (`/admin` 라우트 옆) — `/account` 라우트 추가
- Test: `tests/test_mode3_demo_stack.mjs` — 각본 변형 1케이스 + 페이지 서빙 목록에 `/account` 추가

**Interfaces:**
- Consumes: Task 1 의 `POST /cia/account/self_revoke` (`{ uid, pwd }` → `{ inserted, root, pending, disabled }`), 기존 `/cia/publish`, `/cia/account/set_disabled`, 지갑 `/wallet/login`(disabled 면 403 `account_disabled`).
- Produces: `GET /account` → `text/html`, 본문에 `"CIA 사용자"` 문자열 포함(테스트 마커).

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_mode3_demo_stack.mjs`에서 `await t('8. 로그인: 재발급 + RP ok, PPID 동일', ...)` 블록 바로 뒤에 넣는다.

```js
  await t("4'. 사용자 자기 폐기(비밀번호) → 게시 → 지갑 403 → 관리자 복구 → PPID 동일", async () => {
    // 관리자 시크릿 없이, 계정 비밀번호만으로(설계 §6.5.1). 8 번에서 발급받은 credential 이 살아 있다.
    const r = await cia.post('/cia/account/self_revoke', { uid, pwd: 'password123' });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.disabled, true);
    assert.ok(r.body.inserted.length >= 1, '8 번의 credential 리프가 들어가야 한다');
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const denied = await loginViaRp();
    assert.equal(denied.walletStatus, 403, j(denied));
    assert.equal(denied.wallet.reason, 'account_disabled');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const again = await loginViaRp();
    assert.equal(again.walletStatus, 200, j(again));
    assert.equal(again.wallet.issued, true);
    assert.equal(again.rp.ok, true, j(again.rp));
    assert.equal(again.rp.PPID, PPID1);
  });
```

같은 파일의 `페이지 서빙` 케이스의 배열에 항목 하나를 더한다.

```js
    for (const [c, p, marker] of [[wallet, '/', 'Mode 3 지갑'], [rp, '/', 'Mode 3 로그인'], [cia, '/admin', 'CIA 관리자'], [cia, '/account', 'CIA 사용자']]) {
```

`cia.post`가 `isolated_mode3_stack.mjs`의 `cia` 객체에 있는지 확인한다. `startIsolatedMode3Stack`은 내부에서 `startIsolatedCia`를 쓰고 그 객체는 `post`(시크릿 없음)와 `adminPost`를 둘 다 노출한다(`tests/helpers/isolated_cia.mjs:76-79`). 없다면 같은 형태로 `post`를 추가한다.

- [ ] **Step 2: 테스트가 실패하는지 확인**

Run: `node tests/test_mode3_demo_stack.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: `FAIL 페이지 서빙: ...`( `/account` 가 404 ). `4'.` 케이스는 Task 1 이 끝났으면 `ok`, 아니면 `FAIL`.

- [ ] **Step 3: 페이지와 라우트 작성**

`mode3/cia_account.html` (관리자 페이지와 같은 뼈대, 시크릿 입력 없음):

```html
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="referrer" content="same-origin" />
  <title>Mode 3 CIA 사용자</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 24px auto; padding: 0 16px; }
    fieldset { border: 2px solid #1565c0; margin-bottom: 16px; }
    pre { background: #f6f6f6; padding: 10px; white-space: pre-wrap; font-size: 0.85em; }
    .muted { color: #666; font-size: 0.9em; }
  </style>
</head>
<body>
  <h2>Mode 3 CIA 사용자</h2>
  <p class="muted">장치를 잃었거나 빼앗겼을 때, 계정 비밀번호만으로 내 계정을 폐기한다(설계 §6.5.1). 지갑 키는 필요 없다.
    폐기하면 재발급은 즉시 막히고, 이미 발급된 credential 은 관리자가 게시한 뒤부터 거절된다. 복구는 관리자만 할 수 있다.</p>

  <fieldset>
    <legend>인증</legend>
    <label>uid <input id="uid" value="12345" size="8" /></label>
    <label style="margin-left:12px">비밀번호 <input id="pwd" type="password" size="24" /></label>
  </fieldset>

  <fieldset>
    <legend>조작</legend>
    <button id="revokeBtn">내 계정 폐기</button>
  </fieldset>

  <pre id="out">-</pre>

  <script>
    const $ = (id) => document.getElementById(id);
    $('revokeBtn').addEventListener('click', async () => {
      const r = await fetch('/cia/account/self_revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uid: $('uid').value.trim(), pwd: $('pwd').value }),
      });
      const b = await r.json().catch(() => null);
      $('pwd').value = '';
      $('out').textContent = `POST /cia/account/self_revoke → ${r.status}\n${JSON.stringify(b, null, 2)}`;
    });
  </script>
</body>
</html>
```

`cia.js`의 `/admin` 라우트 바로 아래:

```js
// 사용자 페이지(§6.5.1). 잃어버린 지갑이 아니라 어느 장치에서든 열 수 있어야 하므로 CIA 가 직접 낸다.
app.get('/account', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_account.html')));
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `node tests/test_mode3_demo_stack.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 전부 `ok`. 이어서 chain 그룹 전체:

Run: `bash scripts/run_tests.sh chain 2>&1 | tail -4`
Expected: `== 통과 12 / 실패 0 ==`

- [ ] **Step 5: 커밋 (사용자 승인 후)**

```bash
git add cia.js mode3/cia_account.html tests/test_mode3_demo_stack.mjs
git commit -m "feat(mode3): CIA 사용자 페이지 /account — 비밀번호로 내 계정 폐기, 데모 스택 각본 변형 테스트"
```

---

### Task 3: 데모 문서 갱신

**Files:**
- Modify: `docs/MODE3_DEMO.md:35` (페이지 목록), `:41-49` (시연 각본 표), `:51-55` (하지 말 것 절 앞)

**Interfaces:**
- Consumes: Task 2 의 `GET /account`.
- Produces: 없음(문서).

- [ ] **Step 1: 페이지 목록에 사용자 페이지 추가**

35행을 아래로 바꾼다.

```markdown
페이지: 지갑 `http://127.0.0.1:5100/`, RP `http://127.0.0.1:3100/`, CIA 관리자 `http://127.0.0.1:4100/admin`, CIA 사용자 `http://127.0.0.1:4100/account`.
```

- [ ] **Step 2: 시연 각본에 대안 행 추가**

`| 4 | 관리자 | 계정 폐기 → 게시 | ... |` 행 바로 아래에 넣는다.

```markdown
| 4′ | 사용자 페이지 → 관리자 | (4 대신) `12345` / `password123` 로 내 계정 폐기 → 관리자가 게시 | `disabled:true`, `inserted` 에 리프, 이후 5~8 동일 |
```

표 아래 문장(`같은 각본이 ... 고정돼 있다.`) 뒤에 한 문단을 더한다.

```markdown
4′ 은 관리자 없이 사용자가 스스로 폐기하는 경로다(설계 §6.5.1). 인증은 계정 비밀번호이고 지갑 키가 아니다 —
장치를 잃은 사용자에게 지갑 키는 없고 공격자에게는 있기 때문이다. 처리와 게시는 4 와 같고, 복구는 여전히 관리자만 한다.
```

- [ ] **Step 3: 확인**

Run: `grep -n "account\|4′" docs/MODE3_DEMO.md`
Expected: 페이지 목록 1줄, 표 행 1줄, 설명 문단 1줄이 보인다.

- [ ] **Step 4: 커밋 (사용자 승인 후)**

```bash
git add docs/MODE3_DEMO.md
git commit -m "docs(mode3): 데모 문서에 사용자 페이지 /account 와 자기 폐기 각본 4′ 추가"
```

---

## 자체 점검

- **스펙 대응:** §6.5.1 의 엔드포인트·인증 순서·처리 공유 → Task 1. `GET /account` 화면 → Task 2. 멱등성 → Task 1 테스트 3번째 케이스. 게시·복구 불변 → 어느 Task 도 건드리지 않음. 알려진 한계(무차별 대입)는 스펙에만 적고 코드 변경 없음.
- **이름 일관성:** `revokeAccount(uid, head)`, `/cia/account/self_revoke`, 응답 키 `inserted`·`root`·`pending`·`disabled` 가 Task 1·2·3 에서 동일.
- **기존 테스트 영향:** Task 1 테스트 블록은 계정을 재활성화하고 끝나며, 뒤의 크래시 복구 케이스는 시작 시 `publish` 로 pending 을 비우므로 추가된 대기 리프에 영향받지 않는다.
