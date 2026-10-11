# Mode 2 후속 작업 2/3: wallet_agent.js의 loopback + 시스템 브라우저 + Snap 승인 연동

## 상태

사용자 승인 완료(2026-07-29), 아직 구현 안 됨. Wallet-IdP 통신 재설계의 3개 서브프로젝트 중 두 번째(Wallet 쪽).

## 배경

서브프로젝트 1(2026-07-24, 커밋 `dd6c3e4`→`76beac1`→`aefc71a`→`6ba7218`→`e15090c`)이 `custom_idp.js`에 표준 OIDC 형태의 `POST /par` + `GET/POST /authorize` + `POST /token`을 완전히 추가·테스트·리뷰 완료했다. 이번 서브프로젝트는 그 반대편, 즉 `wallet_agent.js`가 실제로 이 새 엔드포인트들을 호출하는 클라이언트 역할을 하도록 만드는 것이다.

`custom_idp.js`가 이미 제공하는 계약(서브프로젝트 1 스펙/커밋에서 확정, 재확인 없이 그대로 소비):

- `POST /par`: `client_id`('pairct-wallet' 고정), `redirect_uri`(`^http:\/\/127\.0\.0\.1:\d+\/oidc\/callback$` 형태의 loopback), `response_type`('code'), `state`, `nonce`, `code_challenge`, `code_challenge_method`('S256'만 허용), `zkpProof`, `zkpPublicSignals`(`pi_arid_i`, 7개 십진 문자열, uid 제외), `chain_id`, `requestBinding: {pk_i, signature}`를 받는다. `requestBinding.signature`는 `keccak256(AbiCoder.defaultAbiCoder().encode(['string','string','string'], [state, nonce, code_challenge]))`를 Wallet의 세션키(`sk_i`, secp256k1)로 서명한 것이며, `ethers.recoverAddress`로 복원한 주소가 `requestBinding.pk_i`와 대소문자 무시 일치해야 한다 — `wallet_agent.js`의 `/submitTransaction`이 이미 쓰는 서명 방식(keccak256+AbiCoder+secp256k1 r/s/v)과 정확히 같다. ZKP는 구조적 검사만 하고(전체 Groth16 검증은 로그인 시점으로 미뤄짐), 성공하면 `{request_uri, expires_in: 60}`을 반환한다.
- `GET /authorize?client_id=pairct-wallet&request_uri=...`: 사람이 시스템 브라우저에서 여는 로그인/동의 페이지(`idp/authorize.html`/`.js`로 이미 구현됨). Wallet은 이 URL을 여는 것 외에 할 일이 없다 — 로그인/동의 자체는 사용자가 그 브라우저 탭 안에서 직접 한다.
- 로그인+동의 성공 시 브라우저가 `redirect_uri?code=...&state=...`로(클라이언트 사이드 `window.location.href`를 통해) 이동한다. 거부 시 `redirect_uri?error=access_denied&state=...`.
- `POST /token`: `grant_type`('authorization_code'), `code`, `redirect_uri`, `client_id`, `code_verifier`를 받아 PKCE(S256) 검증 후 "PairCT signed login statement"(`{iss, aud, nonce, arid_i, auid_i, r_token, max_height, chain_id, exp, signature: {R8,S}}`, EdDSA-Poseidon 9-field 서명)를 반환한다. `code`는 1회용.

`wallet_agent.js`가 이미 갖고 있어서 재사용하는 것:
- `pi_arid_i`/`pi_PPID` 증명 생성 로직(`/generateStep8Proofs`의 기존 본문 — RP_REG credential 소유증명까지 포함하도록 오늘 이미 확장됨).
- 세션 서명키(`sk_i`/`pk_i`, `generateNewSessionKey()`, secp256k1) 및 `/submitTransaction`이 쓰는 것과 동일한 `keccak256+AbiCoder` 서명 패턴.
- `verifyRpCredential()`(EdDSA-Poseidon 기반, 이미 완료).
- Express 서버 + `X-Wallet-Agent-Token` 인증 미들웨어(기존 라우트들과 동일하게 신규 라우트에도 적용).

이번에 새로 필요한 것 — MetaMask Snap 승인 다이얼로그 연동 시, 브레인스토밍 도중 발견한 핵심 제약: **`wallet_agent.js`는 Node 프로세스라서 `window.ethereum`에 접근할 수 없다.** `wallet_invokeSnap` 호출은 브라우저 JS(`client.js`)에서만 가능하므로, Snap 승인은 `wallet_agent.js`의 백그라운드 처리 안에서 직접 못 하고, 그 시점에 상태를 노출해서 `client.js`가 대신 호출하고 결과를 보고하는 왕복이 필요하다.

## 아키텍처

### 왜 폴링 구조인가

`client.js`가 `wallet_agent.js`에 단일 blocking HTTP 요청을 보내면, 그 요청은 사용자가 시스템 브라우저에서 로그인+동의를 마칠 때까지(수십 초~수 분) 열려있어야 한다. 사용자가 이미 "여러 단계/폴링 구조"를 선택했다 — RP 페이지가 "브라우저에서 로그인 중..." 같은 진행 상태를 보여줄 수 있고, 오래 열린 단일 커넥션에 기대지 않는다.

### 전체 시퀀스

```
client.js                          wallet_agent.js                     custom_idp.js         시스템 브라우저
    │  POST /startLogin                   │                                   │                     │
    │─────────────────────────────────────▶│ (202 jobId, 백그라운드 시작)      │                     │
    │                                      │ generating_proof                 │                     │
    │  GET /loginStatus?jobId=... (폴링)   │                                   │                     │
    │─────────────────────────────────────▶│ awaiting_wallet_approval         │                     │
    │  (status 확인)                        │                                   │                     │
    │  wallet_invokeSnap(confirmLogin) ────────────────────────────────────────────────────▶ Snap 승인│
    │◀──────────────────────────────────────────────────────────────────────────────────────────────│
    │  POST /confirmLoginResult {approved}│                                   │                     │
    │─────────────────────────────────────▶│ (승인이면 계속)                    │                     │
    │                                      │ loopback 리스너 오픈, /par 호출 ──▶│                     │
    │                                      │◀───────────────────────request_uri│                     │
    │                                      │ awaiting_browser_login            │                     │
    │                                      │ open(authorize URL) ─────────────────────────────────▶ │
    │  GET /loginStatus (계속 폴링)         │                                   │  로그인+동의 (사람이 직접)│
    │─────────────────────────────────────▶│                                   │◀────────────────────│
    │                                      │◀──── GET /oidc/callback?code=...&state=... ─────────────│
    │                                      │ exchanging_token, /token 호출 ────▶│                     │
    │                                      │◀──────────────────signed statement│                     │
    │  GET /loginStatus → done            │ done                              │                     │
    │◀─────────────────────────────────────│                                   │                     │
```

### 상태 머신

`GET /loginStatus?jobId=...`가 반환하는 `status` 값:

1. `generating_proof` — `pi_arid_i`/`pi_PPID` 증명 생성 중.
2. `awaiting_wallet_approval` — `client.js`가 Snap `confirmLogin` 다이얼로그를 띄우고 `POST /confirmLoginResult`로 결과를 보고하길 기다림.
3. `awaiting_browser_login` — `/par` 성공, 시스템 브라우저가 열렸고 loopback 콜백을 기다림.
4. `exchanging_token` — 콜백에서 `code`를 받아 `/token` 교환 중.
5. `done` — 성공. 아래 "최종 결과 필드" 참고.
6. `denied` — Snap에서 거부됐거나(`approved: false`), 브라우저 동의 화면에서 거부됨(`error=access_denied`).
7. `failed` — 어느 단계든 에러 또는 타임아웃. `{status: 'failed', error: '<메시지>'}`.

작업 레코드는 `jobId -> {status, ...}` 형태의 메모리 전용 Map으로 관리한다(이 프로젝트의 다른 임시 저장소들과 동일한 패턴, 서버 재시작 시 소실은 의도된 데모 한계).

### Loopback 리스너

Snap 승인(`approved: true`) 확인 직후:
1. `http.createServer()`로 포트 0(OS가 빈 포트 자동 할당)에 리스너를 연다. `server.address().port`로 실제 할당된 포트를 읽는다.
2. `redirect_uri = http://127.0.0.1:{할당된 포트}/oidc/callback`를 구성.
3. PKCE `code_verifier`(랜덤)/`code_challenge`(`base64url(SHA256(code_verifier))`, Node 내장 `crypto` 사용 — 서브프로젝트 1과 동일 방식), `state`, `nonce`를 생성.
4. `sk_i`로 request binding 서명(`keccak256(AbiCoder.encode(['string','string','string'],[state,nonce,code_challenge]))`)을 만들어 `POST /par`를 서버-투-서버(Node `fetch`, 브라우저 안 거침)로 호출.
5. 성공하면 상태를 `awaiting_browser_login`으로 바꾸고, `open` npm 패키지로 `${IDP_ORIGIN}/authorize?client_id=pairct-wallet&request_uri=...`를 연다.
6. 리스너가 `GET /oidc/callback`을 받으면: 쿼리의 `state`가 3번에서 생성한 값과 일치하는지 확인(불일치 시 CSRF 의심으로 `failed` 처리, 콜백 요청에는 일반 에러 페이지 응답). `error` 파라미터가 있으면 `denied`. `code`가 있으면 `exchanging_token`으로 전환, 브라우저에는 "이 탭을 닫고 원래 페이지로 돌아가세요" 안내 HTML을 응답한 뒤 리스너를 닫는다.
7. `code`를 받으면 `POST /token`을 서버-투-서버로 호출(`code`, `code_verifier`, `redirect_uri`, `client_id`). 성공하면 `done`, 실패하면 `failed`.
8. 타임아웃: 리스너를 연 시점부터 90초(서브프로젝트 1의 `/par` TTL 60초보다 여유를 둔 값 — TTL 자체를 조정할지는 별도 논의로 미룸, 배경 참고) 안에 콜백이 안 오면 리스너를 닫고 `failed`(타임아웃 메시지) 처리.

### Snap 신규 케이스: `confirmLogin`

`snap/src/index.js`의 `onRpcRequest`에 `hello` 케이스와 같은 패턴(`type: 'confirmation'`, boolean 반환)으로 추가:

```js
case 'confirmLogin': {
  const confirmed = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: panel([
        heading('Wallet Login Approval'),
        text(`Origin: **${origin}**`),
        text('A PairCT-compatible identity provider login is about to start in your system browser.'),
        text('Do you want to proceed?'),
      ]),
    },
  });
  return { approved: Boolean(confirmed) };
}
```

**주의**: `snap/`은 별도 패키지로 `snap/dist/bundle.js`에 번들링된다. `snap/src/index.js`를 고치면 `npm run build`(mm-snap build, `snap/` 디렉터리 안에서)로 재빌드해야 하고, 실제 브라우저의 MetaMask가 이 Snap을 다시 연결(재설치/재연결)해야 반영된다 — curl로 검증 불가능하고 사용자가 직접 브라우저에서 확인해야 하는 유일한 구간이다.

## 데이터 구조

### `POST /startLogin`

요청: `{ rpCredential, r_i, rpNonce }` — 지금의 `/generateStep8Proofs`와 동일한 바디.
응답(즉시): `202 { jobId }`.

### `GET /loginStatus?jobId=...`

응답: `{ status, error? }` (진행 중 상태들) 또는 `{ status: 'done', ...최종 결과 }`.

**`done` 상태의 최종 결과 필드**: 오늘 `/generateStep8Proofs` 응답의 RP FE가 실제로 쓰는 필드(`ppid`, `arid_i`, `auid_i`, `pk_i`, `publicKeyHex`, `pi_PPID`)에 서브프로젝트 1의 `/token` 응답(`statement: {iss, aud, nonce, arid_i, auid_i, r_token, max_height, chain_id, exp, signature}`)을 더한 형태로 간다. 정확한 필드명/중복 여부(예: `arid_i`를 최상위와 `statement` 안에 둘 다 둘지)는 구현 계획 단계에서 확정한다 — 이 스펙은 "두 정보가 합쳐져서 나간다"는 계약만 고정한다.

### `POST /confirmLoginResult`

요청: `{ jobId, approved: boolean }`.
응답: `{ success: true }` (또는 `jobId`가 `awaiting_wallet_approval` 상태가 아니면 400).

## 범위

**포함:**
- `wallet_agent.js`: `POST /startLogin`, `GET /loginStatus`, `POST /confirmLoginResult` 3개 엔드포인트, 상태 머신을 관리하는 in-memory job store, loopback HTTP 리스너 생성/타임아웃/정리 로직, `/par`·`/token`을 호출하는 서버-투-서버 클라이언트 코드, PKCE(`code_verifier`/`code_challenge`) 생성, request binding 서명 생성.
- `package.json`: `open` npm 패키지를 새 의존성으로 추가.
- `snap/src/index.js`: `confirmLogin` 케이스 추가 + `npm run build`로 재번들.

**명시적으로 범위 밖 (다른 서브프로젝트/후속 작업):**
- `client.js`가 실제로 `/startLogin`을 호출하고 폴링하고 Snap을 부르고 `/confirmLoginResult`를 보고하도록 고치는 것 — 서브프로젝트 3.
- `idp/login_popup.js`, `wallet/relay.html`/`relay.js`, 그리고 지금의 `/generateStep8Proofs` 기반 팝업 흐름 제거 — 서브프로젝트 3이 끝나 새 경로로 완전히 전환된 뒤.
- `custom_idp.js`의 `/par`/`/authorize`/`/token` 자체 변경 — 서브프로젝트 1에서 이미 완료, 이번엔 순수 소비자로만 붙는다.
- `/par`의 `PAR_REQUEST_TTL_MS`(60초) 조정 — 배경에서 언급한 대로 사용자가 "나중에 조정"으로 미룸.
- `circuits/*.circom` 변경 — 없음, `pi_arid_i`를 그대로 재사용.

## 테스트 및 검증

- `node --check wallet_agent.js` 구문 검사.
- `/startLogin`→`/loginStatus`→`/confirmLoginResult`→(내부적으로 `/par`/`/token` 호출)까지는 Node 스크립트로 curl 스타일 검증 가능 — 다만 `awaiting_browser_login` 단계에서 실제 시스템 브라우저가 열리고 사람이 `idp/authorize.html`에서 로그인/동의를 해야 `code`가 나오므로, **이 구간부터는 자동화 스크립트만으로 끝까지 검증할 수 없다.** 구현 계획에서는 "loopback 리스너가 열리고 올바른 `redirect_uri`로 `/par`가 성공하는 것까지"를 자동 테스트로 확인하고, 그 이후(브라우저에서 실제 로그인 → 콜백 도착 → `/token` 성공 → `done`)는 컨트롤러/사용자가 직접 브라우저로 검증하는 라이브 검증 단계로 둔다.
- Snap `confirmLogin` 변경은 `mm-snap build` 후 사용자가 직접 브라우저에서 MetaMask Snap을 재연결하고 다이얼로그가 뜨는지 확인해야 한다 — 자동화 불가.
- 음성 케이스: 잘못된 `jobId`로 `/loginStatus`/`/confirmLoginResult` 호출 시 404/400, Snap에서 거부(`approved: false`) 시 `denied`로 전이하고 `/par`가 호출되지 않는지, loopback 타임아웃이 실제로 90초 후 `failed`로 전이하는지.

## Self-Review

- **플레이스홀더 검사**: 없음.
- **범위 일관성**: "포함" 목록(3개 엔드포인트, job store, loopback 리스너, `open` 의존성, Snap `confirmLogin`)이 아키텍처·데이터 구조 섹션과 1:1 대응됨.
- **모순 검사**: "client.js 변경은 서브프로젝트 3 범위"를 배경·아키텍처·범위 세 군데에서 일관되게 명시. TTL 조정을 미뤘다는 사용자 결정이 아키텍처(90초 타임아웃 근거)와 범위(범위 밖 항목) 양쪽에 일관되게 반영됨.
- **경계 사례**: Snap 승인 로직이 브라우저에서만 가능하다는 제약을 브레인스토밍 중 발견해서 반영함 — 이게 이 스펙에서 가장 비직관적인 부분이라 아키텍처 섹션 서두에 명시적으로 설명을 남겨둠.
