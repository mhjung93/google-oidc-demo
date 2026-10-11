# Fresh Per-Login Session Key Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `wallet_agent.js`의 세션 서명키(`pk_i`/`sk_i`)가 로그인마다 새로 생성되게 바꿔서, 논문의 formal protocol(세션마다 다른 `sk_i`)과 일치시키고 IdP/RP/온체인 관찰자의 세션 간 상관관계 추적(cross-service linkability)을 막는다.

**Architecture:** 디스크 영속화(`wallet_state.json`)하던 `getOrCreateSessionKey()`를, Step 8에서 매번 새 키를 만들어 메모리에만 두는 `generateNewSessionKey()`와 `/submitTransaction`에서 그 값을 읽기만 하는 `getCurrentSessionKey()`로 나눈다.

**Tech Stack:** 기존 `@noble/curves`(secp256k1) 그대로 재사용, 새 의존성 없음.

## Global Constraints

- `wallet_state.json`의 `salt`/`agentToken` 필드는 그대로 영속화 유지 — 이번 변경과 무관, 손대지 않는다.
- 기존 `mode2SessionKey` 필드를 지우는 마이그레이션 코드는 추가하지 않는다 — 더 이상 안 읽으므로 죽은 데이터로 남아도 무방.
- `circuits/*.circom`, `contracts/*.sol`, `custom_idp.js`, `client.js`, `server.js`는 이 변경과 무관 — 건드리지 않는다.
- 새 세션키는 반드시 메모리에만 두고 디스크에 쓰지 않는다.

---

### Task 1: 세션키 생성 로직 분리

**Files:**
- Modify: `wallet_agent.js:307-325`(`getOrCreateSessionKey()` 정의부), `wallet_agent.js:396-398`(Step 8 호출부), `wallet_agent.js:568`(`/submitTransaction` 호출부)

**Interfaces:**
- Produces: `generateNewSessionKey()` — 인자 없음, `{ sk_i: Uint8Array, pk_i: BigInt, address: string, publicKeyHex: string }` 반환. `getCurrentSessionKey()` — 인자 없음, 같은 형태 반환, 활성 세션 없으면 throw.

- [ ] **Step 1: `getOrCreateSessionKey()`를 두 함수로 교체**

`wallet_agent.js`에서 다음 블록(307-325행)을 찾는다:

```js
// 세션 서명키(pk_i/sk_i): P-256 대신 secp256k1을 쓴다 — 이유는 PPIDWallet 컨트랙트가
// payload 서명을 회로 밖에서 ecrecover로 직접 검증하기 때문(온체인 ecrecover는
// secp256k1 전용). WebCrypto의 SubtleCrypto는 secp256k1을 지원하지 않으므로
// @noble/curves를 쓴다. 로그인 시점(Step 8)에 한 번 생성해서 state 파일에 저장해두고,
// 이후 트랜잭션 제출 단계(다른 HTTP 요청)에서 같은 키를 재사용한다 — 그전엔 이 키가
// 요청 하나 처리 후 버려졌었는데, payload 서명을 나중에 또 해야 하므로 영속화가
// 필요해졌다.
function getOrCreateSessionKey() {
  const state = readState();
  if (!state.mode2SessionKey) {
    const sk_i = secp256k1.utils.randomPrivateKey();
    state.mode2SessionKey = bytesToHex(sk_i);
    writeState(state);
  }
  const sk_i = Uint8Array.from(Buffer.from(state.mode2SessionKey, 'hex'));
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const address = ethAddressFromSecp256k1Pubkey(pubUncompressed);
  return { sk_i, pk_i: BigInt(address), address, publicKeyHex: `0x${bytesToHex(pubUncompressed)}` };
}
```

다음으로 교체:

```js
// 세션 서명키(pk_i/sk_i): P-256 대신 secp256k1을 쓴다 — 이유는 PPIDWallet 컨트랙트가
// payload 서명을 회로 밖에서 ecrecover로 직접 검증하기 때문(온체인 ecrecover는
// secp256k1 전용). WebCrypto의 SubtleCrypto는 secp256k1을 지원하지 않으므로
// @noble/curves를 쓴다.
//
// 이 키는 로그인(Step 8)마다 새로 생성해서 메모리에만 둔다 — pk_i는 IdP/RP 양쪽
// 증명의 평문 public input이자 온체인 pi_pk_i에도 노출되므로, 고정된 값을 계속
// 재사용하면 IdP가 세션 간 상관관계를 추적하거나 서로 다른 RP/온체인 관찰자가
// pk_i만으로 같은 지갑임을 알아낼 수 있다(논문 Property 5, cross-service
// unlinkability가 막으려는 바로 그 속성). 같은 방문(로그인→트랜잭션 제출) 안에서는
// 이 프로세스가 계속 떠 있는 동안 메모리 값이 유지되므로 일관성 문제는 없다.
let currentSessionKey = null;

function generateNewSessionKey() {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const address = ethAddressFromSecp256k1Pubkey(pubUncompressed);
  currentSessionKey = { sk_i, pk_i: BigInt(address), address, publicKeyHex: `0x${bytesToHex(pubUncompressed)}` };
  return currentSessionKey;
}

function getCurrentSessionKey() {
  if (!currentSessionKey) {
    throw new Error('No active session key — call /generateStep8Proofs (login) first');
  }
  return currentSessionKey;
}
```

- [ ] **Step 2: Step 8 호출부를 `generateNewSessionKey()`로 교체**

`wallet_agent.js`에서 다음 줄(396-398행)을 찾는다:

```js
    // 세션 서명키: secp256k1, wallet_state.json에 영속화됨 (getOrCreateSessionKey 참고).
    // pk_i는 이제 공개키 블롭의 해시가 아니라 그 공개키의 이더리움 주소 자체다.
    const { pk_i: pkField, publicKeyHex } = getOrCreateSessionKey();
```

다음으로 교체:

```js
    // 세션 서명키: secp256k1, 로그인마다 새로 생성됨 (generateNewSessionKey 참고).
    // pk_i는 이제 공개키 블롭의 해시가 아니라 그 공개키의 이더리움 주소 자체다.
    const { pk_i: pkField, publicKeyHex } = generateNewSessionKey();
```

- [ ] **Step 3: `/submitTransaction` 호출부를 `getCurrentSessionKey()`로 교체**

`wallet_agent.js`에서 다음 줄(568행)을 찾는다:

```js
    const { sk_i, pk_i } = getOrCreateSessionKey();
```

다음으로 교체:

```js
    const { sk_i, pk_i } = getCurrentSessionKey();
```

- [ ] **Step 4: 구문 검사**

Run: `node --check wallet_agent.js && echo OK`
Expected: `OK`

- [ ] **Step 5: 커밋**

```bash
git add wallet_agent.js
git commit -m "feat(mode2): generate a fresh session key (pk_i/sk_i) per login

wallet_agent.js's secp256k1 session key was persisted forever in
wallet_state.json and reused across every login/RP - diverging from
the paper's formal protocol (sk_i = KDF(k_user, auid, sid_i, ctx_i),
session-fresh via sid_i) and letting the IdP correlate sessions or
RPs/chain observers link the same wallet across services via the
plaintext pk_i public input, undermining Property 5 (cross-service
unlinkability) at the implementation level.

Splits getOrCreateSessionKey() into generateNewSessionKey() (Step 8,
fresh in-memory key per login) and getCurrentSessionKey() (submitTransaction,
reads the current visit's key, throws if none exists). salt/agentToken
in wallet_state.json are untouched. PPIDWallet.execute() re-verifies
pk_i per call rather than fixing it at deploy time, so this is
compatible with the existing on-chain design."
```

---

### Task 2: 라이브 검증

이 태스크는 컨트롤러가 직접 실행한다(서브에이전트에 위임하지 않음) — 실제 사용자 브라우저를 다루는 작업이라 매 단계 사용자 확인이 필요하다. 회로/zkey는 안 바뀌었으므로 `custom_idp.js` 재시작이나 `PPIDWalletFactory` 재배포는 필요 없다 — `wallet_agent.js`만 재시작하면 된다.

**Files:** 없음.

- [ ] **Step 1: 사용자에게 재시작 확인**

`wallet_agent.js`를 재시작해야 새 코드가 반영된다는 걸 알리고 승인을 받는다.

- [ ] **Step 2: `wallet_agent.js` 재시작**

Run:
```bash
pid=$(lsof -ti :5001 -sTCP:LISTEN); [ -n "$pid" ] && kill $pid
sleep 1
lsof -i :5001 -sTCP:LISTEN | tail -n +2
```
Expected: 빈 출력(포트 비워짐 확인). 그 뒤 기존과 같은 환경변수로 재시작:
```bash
PPID_WALLET_FACTORY_ADDRESS=<현재 배포된 factory 주소> MODE2_ETH_RPC_URL=http://127.0.0.1:8545 node wallet_agent.js &
```
Expected: `[WalletAgent] Local wallet-side Step 8 agent listening on http://127.0.0.1:5001` 출력.

- [ ] **Step 3: 사용자에게 라이브 테스트 요청**

브라우저에서: 로그인(Step 1-15) 완료 후 `ssoMetadata.signingPublicKey`(또는 추적 UI의 `pk_i` 입력 필드에 자동으로 채워진 값)를 기록해둔다. 로그아웃 없이 새로고침 후 다시 로그인해서, 이번엔 **다른** `pk_i`가 나오는지 확인 요청. 그리고 로그인 한 번 한 뒤 바로 "Send PPID Transaction"을 눌러서, 트랜잭션이 문제없이 성공하는지(=로그인 때 쓰인 `pk_i`와 트랜잭션 제출 때 쓰인 `pk_i`가 일치한다는 간접 증거) 확인 요청.

- [ ] **Step 4: 포트 정리 여부 확인**

테스트가 끝나면 포트를 정리할지 사용자에게 확인한다.

## Self-Review

- **스펙 커버리지**: 스펙의 "포함" 목록(`generateNewSessionKey`/`getCurrentSessionKey` 분리, 메모리 전용)이 Task 1에 매핑됨. "범위 밖"(salt/agentToken, 다른 파일들, 마이그레이션)은 어느 태스크에서도 건드리지 않음.
- **플레이스홀더 검사**: 없음.
- **타입/이름 일관성**: `generateNewSessionKey`/`getCurrentSessionKey`/`currentSessionKey` 이름이 Task 1 전체에서 일관되게 쓰임.
