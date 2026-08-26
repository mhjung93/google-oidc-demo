# Mode 2 후속 작업 1/3: custom_idp.js에 표준 OIDC 형태 /par·/authorize·/token 신설

## 상태

사용자 승인 완료(2026-07-24), 아직 구현 안 됨. Wallet-IdP 통신 재설계의 3개 서브프로젝트 중 첫 번째(IdP 쪽).

## 배경

`docs/OIDC_PAIRCT_SECURITY_COMPARISON.md`(2026-07-21 00:04 작성, relay-iframe 수정보다 먼저 쓰여져 일부 항목은 이미 낡음)가 지적한 gap 중, 오늘 세션에서 이미 닫힌 것과 아직 열려있는 것을 재확인했다.

**이미 닫힌 gap:**
- "IdP-side RP hiding"(JS 레벨) — relay-iframe 작업(2026-07-21 커밋 `b01706d`/`4b87531`/`38358d4`)으로 `idp/login_popup.js`가 보는 opener origin이 RP가 아니라 지갑(wallet) origin이 됨.
- `ppid`가 `/sso_with_credentials`/`/consent_result`로 새던 문제 — 오늘 `idp/login_popup.js`에 `businessForIdP()` 필터를 추가해서 고침. (`arid_i = rid·rp_nonce`, `auid_i = ppid·rp_nonce`인데 IdP가 `ppid`까지 알면 `rid = arid_i·ppid/auid_i`로 완전히 역산 가능했음.)
- "IdP 인증과 토큰 발급의 서버 측 결합" — 문서는 불충족이라 했지만, 실제 코드(`custom_idp.js`의 `req.session.pendingPairCT`)를 보면 이미 서버 세션으로 묶여 있음. 문서가 낡은 것으로 판단, 재작업 안 함.

**아직 열려있는 gap (이번 재설계의 목표):**
- "토큰이 RP FE에 노출되지 않는 backend delivery" — 지금은 IdP 팝업 → 지갑의 relay iframe(브라우저 JS) → `client.js`(RP FE) 순으로 `idpToken` 원본이 전달된다. relay iframe은 지갑 *origin*에서 실행될 뿐 지갑의 실제 신뢰 경계(`wallet_agent.js` Node 프로세스, 개인키/salt 보유)가 아니다. `client.js`가 여전히 원문 토큰을 자기 JS 메모리에 들고 있다.
- "브라우저 요청–응답 session binding" — `r_i`가 IdP 서명이나 `pi_i`에 안 묶여 있음.
- "Replay resistance" — `usedNonces`/세션 저장소가 메모리 전용.

사용자가 명시한 목표: **"통신 흐름만 OIDC와 같으면 된다"** — 즉 PAR/Authorization Code/PKCE/loopback redirect 같은 **프로토콜 메커니즘**은 실제 표준 그대로 따르되, ZKP나 최종 발급물(서명된 statement)의 **내용물**은 PairCT 고유 암호(EdDSA-Poseidon, Groth16)로 유지한다.

## 아키텍처

### 왜 PAR(RFC 9126)인가

표준 OIDC `/authorize`는 브라우저가 GET으로 방문하는 URL이라 쿼리 파라미터가 작아야 하는데, `pi_arid_i` ZKP(proof + public signals)는 쿼리 문자열에 넣기엔 너무 크다. PAR은 정확히 이 문제(큰/민감한 인가 요청 파라미터를 브라우저 URL에 안 실어도 되게)를 풀기 위한 실제 OAuth 표준이라 그대로 채택한다.

### 3단계 흐름

1. **`POST /par`** — Wallet Agent가 시스템 브라우저를 열기 *전에*, 서버-투-서버(Node fetch, 브라우저 안 거침)로 인가 요청 전체를 IdP에 밀어넣는다.
2. **`GET /authorize?client_id=pairct-wallet&request_uri=...`** — 시스템 브라우저가 이 짧은 URL로 이동한다. IdP가 로그인 폼 → 동의 화면을 보여주고, 승인되면 1회용 `code`를 발급해 `redirect_uri`(Wallet Agent의 loopback 리스너, 다른 서브프로젝트에서 구현)로 302 리다이렉트한다.
3. **`POST /token`** — Wallet Agent의 loopback 리스너가 `code`를 받으면, 다시 서버-투-서버로 IdP에 code+PKCE verifier를 제출하고 **PairCT signed login statement**를 받는다.

### 기존 흐름과의 관계: 완전히 추가적(additive)

`/register_rp`, `/sso_with_credentials`, `/consent_result`는 **손대지 않는다.** 오늘 커밋된 relay-iframe 기반 로그인 흐름은 이 서브프로젝트 이후에도 그대로 동작해야 한다. 새 `/par`/`/authorize`/`/token`은 완전히 별도의, 병행 가능한 엔드포인트 집합이다 — 나중에 Wallet/RP 서브프로젝트가 끝나야 실제로 그쪽 스위치가 새 경로로 넘어가고, 그때 가서 예전 엔드포인트를 정리(제거)한다. 이번 서브프로젝트만으로는 curl/테스트 스크립트로 새 엔드포인트 3개를 독립적으로 검증할 수 있을 뿐, 브라우저를 통한 전체 E2E는 Wallet/RP 서브프로젝트가 끝나야 된다.

## 데이터 구조

### `client_id`

`'pairct-wallet'` 고정 상수 — RP별 동적 등록(`rid`) 없이 이 데모의 유일한 신뢰 클라이언트.

### `POST /par` 요청/응답

요청 바디:
```json
{
  "client_id": "pairct-wallet",
  "redirect_uri": "http://127.0.0.1:{port}/oidc/callback",
  "response_type": "code",
  "state": "...",
  "nonce": "...",
  "code_challenge": "...",
  "code_challenge_method": "S256",
  "zkpProof": { ... },
  "zkpPublicSignals": [ ... ],
  "chain_id": "31337",
  "requestBinding": { "pk_i": "...", "signature": "0x..." }
}
```

`requestBinding`은 `pi_arid_i` 재사용 결정에 따라, ZKP 자체와는 별개로 Wallet의 세션키(`sk_i`, secp256k1)로 `(state, nonce, code_challenge)`를 서명한 것 — 회로 변경 없이 "이 ZKP와 이 인가 요청이 같은 세션에서 나왔다"는 걸 묶는다. `chain_id`는 `pi_arid_i`의 public signal이 아니라(오늘의 `business.chain_id`와 같은 자리) 평문 필드로 그대로 받는다 — RP 감사가 아니라 온체인 유효성 창(`max_height`)이 어느 체인 기준인지 구분하는 값이라 감출 이유가 없다.

**중요: `/par`는 ZKP를 완전히 검증하지 않는다.** `pi_arid_i`의 첫 번째 public signal은 `uid`인데, `verifyPiIAndIssueToken`이 하듯 `[user.uid, ...zkpPublicSignals]`로 재구성하려면 *인증된* `uid`가 필요하다. `/par`는 로그인 이전에 호출되므로 이 시점엔 어느 `uid`인지 알 수 없다 — 그래서 오늘 이미 있는 2단계 패턴(`/sso_with_credentials`가 먼저 세션에 보류시키고, `/consent_result`가 로그인 확인 후에야 `verifyPiIAndIssueToken`으로 실제 검증하는 것)을 그대로 따른다.

`/par`가 실제로 하는 것:
- `zkpProof`/`zkpPublicSignals`가 `assertDecimalSignals(zkpPublicSignals, 7, ...)` 형태(길이 7, 십진 문자열)인지 구조적으로만 확인한다. Groth16 `snarkjs.groth16.verify` 호출은 아직 하지 않는다.
- `requestBinding.signature`가 `requestBinding.pk_i`로 `(state, nonce, code_challenge)`에 대해 유효한지 검증한다(secp256k1 ECDSA). 정확히는: `bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string','string','string'], [state, nonce, code_challenge]))`를 만들고, `ethers.recoverAddress(bindingHash, requestBinding.signature)`로 복원한 주소가 `requestBinding.pk_i`(대소문자 무시 비교)와 일치하는지 확인한다 — `/submitTransaction`이 이미 쓰는 서명 방식(keccak256+AbiCoder+secp256k1)과 동일 패턴, `wallet_agent.js`의 `pk_i`가 "공개키의 이더리움 주소"인 것과도 일치.
- 이 두 가지만 통과하면(진짜 ZKP 검증은 아직 안 됐어도) `request_uri`를 발급한다 — "이 요청이 최소한 구조적으로 올바르고 어떤 세션키가 보낸 것인지"만 이 시점에 보장된다.

응답(성공):
```json
{ "request_uri": "urn:pairct:par:<random>", "expires_in": 60 }
```
(`request_uri`의 정확한 문자열 포맷은 예시이며, 구현 계획 단계에서 확정한다.)
실패 시 표준 OAuth 에러 응답 형태(`error`, `error_description`)를 따른다.

`request_uri`로 저장되는 서버 메모리 레코드는 `{ redirect_uri, state, nonce, code_challenge, code_challenge_method, zkpProof, zkpPublicSignals, chain_id, requestBinding, expiresAt }` — ZKP는 아직 미검증 원본 그대로 저장해 둔다(진짜 검증은 `/authorize`의 로그인 성공 시점에 한다). `chain_id`는 평문 그대로 보관. 1회용, TTL 짧게(60초), `custom_idp.js`의 다른 메모리 전용 저장소(`issuanceLog`, `auidILog`, `usedNonces`)와 같은 패턴 — 서버 재시작 시 소실되는 것도 동일한 "의도된 데모 한계"로 취급한다.

### `GET /authorize`

`request_uri`로 저장된 레코드를 찾아 로그인 폼을 보여준다. **IdP는 `rid`/`origin`을 모르므로 "어느 RP에 로그인하는지"를 동의 화면에 구체적으로 못 보여준다** — "PairCT 호환 지갑 앱이 로그인을 요청합니다" 같은 일반 문구만 가능하다. 이건 의도된 동작(IdP-side RP hiding의 직접적 귀결)이지 버그가 아니다.

로그인 폼/동의 화면 자체의 정확한 페이지 전환 방식(오늘의 `idp/login_popup.html` 마크업 재사용 여부 등)은 이 스펙에서 고정하지 않고 구현 계획(writing-plans) 단계에서 정한다 — 이 스펙은 프로토콜 계약만 고정한다.

**로그인 폼 제출(비밀번호 확인) 성공 시, 그제서야 `uid`가 확정되므로 이 시점에 `verifyPiIAndIssueToken`과 동일한 방식으로 저장해둔 ZKP를 완전히 검증한다** — `[user.uid, ...record.zkpPublicSignals]`를 `vkeyAridI`로 `snarkjs.groth16.verify`하고, 오늘 추가한 `pk_IdP_x`/`pk_IdP_y` 대조도 동일하게 수행한다. 이 전체 검증이 실패하면 로그인 자체를 거부한다(`code` 발급 안 함). 검증에 성공하면 `zkpPublicSignals`에서 `arid_i`/`auid_i`/`max_height`/`token_nonce`(=r_token)/`auid` 값을 뽑아 이후 동의/코드 발급 단계에서 쓴다.

승인 시: 1회용 `code`(랜덤 opaque 값, TTL 60초 — `/par`의 `request_uri`와 동일한 기준)를 발급해 `redirect_uri?code=...&state=...`로 302. `code`는 `request_uri` 레코드의 `redirect_uri`/`code_challenge` + ZKP 검증을 통과해서 나온 `arid_i`/`auid_i`/`max_height`/`token_nonce`/`auid` + 평문으로 들고 있던 `chain_id` + 로그인한 `uid`를 참조하는 서버 메모리 레코드에 연결된다.

거부 시: `redirect_uri?error=access_denied&state=...`로 302(표준 OAuth 에러 리다이렉트 관례).

### `POST /token`

요청 바디:
```json
{
  "grant_type": "authorization_code",
  "code": "...",
  "redirect_uri": "http://127.0.0.1:{port}/oidc/callback",
  "client_id": "pairct-wallet",
  "code_verifier": "..."
}
```

IdP 검증: `code` 존재/미만료/미소모, `redirect_uri` 일치, `SHA256(code_verifier)`(base64url) == 저장된 `code_challenge`(PKCE 표준 검증). 통과하면 `code`를 즉시 소모(1회성 재사용 방지) 처리하고 **PairCT signed login statement**를 발급한다.

### PairCT signed login statement

오늘 만든 `idpToken` 구조에 3개 필드를 추가한다:

```json
{
  "iss": "custom-idp",
  "aud": "pairct-wallet",
  "nonce": "<POST /par에 실었던 값>",
  "arid_i": "...",
  "auid_i": "...",
  "r_token": "...",
  "max_height": "...",
  "chain_id": "...",
  "exp": 1234567890,
  "signature": { "R8": ["...", "..."], "S": "..." }
}
```

`iss`/`aud`/`nonce`는 위변조 방지를 위해 **서명 대상 메시지에 포함**되어야 한다. EdDSA-Poseidon 서명 메시지 배열이 오늘의 6개 필드(`[domain, arid_i, auid_i, r_token, max_height, chain_id]`)에서 9개(`[domain, iss, aud, nonce, arid_i, auid_i, r_token, max_height, chain_id]`)로 늘어난다. `iss`/`aud`는 기존 `valueToField()`로 필드 원소화한다(문자열이므로 `DOMAIN_IDP_TOKEN` 만들 때와 동일한 방식).

**이 서명 포맷은 기존 `idpToken`의 6필드 서명 포맷과 별개다** — 기존 `/consent_result`가 발급하는 `idpToken`은 그대로 6필드 포맷을 유지한다(다른 서브프로젝트가 새 포맷으로 전환하기 전까지 `server.js`/`wallet_agent.js`의 기존 검증 로직을 안 건드리기 위함). 새 9필드 포맷을 실제로 검증하는 코드(`server.js`의 `sso_success`, `wallet_agent.js`의 Step 12에 해당하는 로직)를 새로 만드는 건 Wallet/RP 서브프로젝트의 범위다.

## 범위

**포함:**
- `custom_idp.js`: `POST /par`, `GET /authorize`, `POST /token` 3개 엔드포인트 신설.
- 인메모리 저장소 2개(pushed request record by `request_uri`, authorization code record by `code`) — 기존 `issuanceLog`/`auidILog`/`usedNonces`와 같은 패턴(메모리 전용, TTL/1회성).
- PKCE(S256) 검증 로직 — `server.js`의 Mode 1 PKCE 구현(`generators.codeChallenge` 등)과 동치인 SHA256+base64url 비교를 `custom_idp.js`에 직접 구현(Node `crypto` 모듈, 새 의존성 없음).
- EdDSA-Poseidon 서명 메시지를 9필드로 확장하는 로직(새 statement 발급 전용, 기존 `idpToken` 발급 경로와 별개 함수).
- 로그인/동의 화면(정확한 마크업/전환은 구현 계획에서 확정).

**명시적으로 범위 밖 (다른 서브프로젝트):**
- `wallet_agent.js`의 loopback HTTP 리스너, 시스템 브라우저 실행, MetaMask Snap 다이얼로그 연동, `/par`·`/token` 호출 로직, PairCT signed login statement 검증 로직 — 서브프로젝트 2.
- `client.js`의 팝업/relay 중계 제거 및 단순화, `wallet_agent.js`에 "로그인해줘"만 요청하고 결과를 받는 구조로 변경 — 서브프로젝트 3.
- `idp/login_popup.js`, `wallet/relay.html`/`relay.js` 제거 — 서브프로젝트 2·3이 완료되어 새 경로로 완전히 전환된 뒤에 별도 정리.
- `circuits/pi_arid_i.circom` 등 회로 변경 — 오늘 이미 완료된 EdDSA-Poseidon RP_REG credential 소유증명을 그대로 재사용하며, 이번 서브프로젝트에서 회로를 추가로 건드리지 않는다.
- `/register_rp`, `/sso_with_credentials`, `/consent_result` — 변경 없음.
- TLS, IdP 키 영속성/rotation, `DEMO_BOUND_UID` 하드코딩(Wallet-IdP account binding) — 별도의, 더 큰 인프라 이슈로 이번 재설계 범위 밖.

## 테스트 및 검증

- `node --check custom_idp.js` 구문 검사.
- curl 기반 스크립트로 `/par` → `/authorize`(로그인 폼 GET, 로그인 POST, 동의 POST) → `/token` 전체 흐름을 직접 시뮬레이션(오늘 세션에서 `/register_rp`·`/generateStep8Proofs`·`/sso_with_credentials`·`/consent_result`를 curl로 엮어 검증한 것과 동일한 방식) — 브라우저나 Wallet Agent 없이도 프로토콜 계약이 맞는지 확인 가능.
- 음성 케이스: 잘못된 `code_verifier`로 `/token` 호출 시 거부되는지, 이미 소모된 `code` 재사용 시 거부되는지, 만료된 `request_uri`로 `/authorize` 접근 시 거부되는지, ZKP 검증 실패 시 `/par`이 거부되는지.
- 기존 흐름(`/register_rp`·`/sso_with_credentials`·`/consent_result`) 회귀 확인 — 이번 변경이 addtive이므로 기존 curl 테스트가 여전히 통과해야 함.

## Self-Review

- **플레이스홀더 검사**: 없음.
- **범위 일관성**: "포함" 목록이 아키텍처 3단계(`/par`/`/authorize`/`/token`)와 데이터 구조 섹션에 1:1로 대응됨.
- **모순 검사**: "기존 흐름 안 건드림"을 배경·아키텍처·범위 세 군데에서 일관되게 명시함. PairCT signed login statement가 기존 `idpToken`과 별개 포맷임을 데이터 구조·범위 양쪽에서 일치시킴.
- **미확정 사항**: 로그인/동의 화면의 정확한 페이지 마크업/전환 방식은 의도적으로 미확정 — 구현 계획 단계에서 확정하기로 배경에 명시함.
