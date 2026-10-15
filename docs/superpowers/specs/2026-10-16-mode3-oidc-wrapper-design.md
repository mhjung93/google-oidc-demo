# Mode 3 — OIDC 래퍼: Google 로그인으로 등록·자기 폐기

작성 2026-10-16. 상태: **초안(사용자 검토 대기)**. 브랜치 `feat/mode3-v11`(web 모드 `2026-10-15-mode3-browser-user-page-design.md` 위). 근거: 2026-10-15 논의 "OIDC wrapper 로 Google OIDC 를 세션 토큰 서명으로 감쌀 수 있나 → 래퍼는 신뢰해야 한다", 2026-10-16 질문 네 개의 답(진입점 둘 다 · 브라우저 직접 + 로컬 가짜 발급자 · 자기 폐기도 Google 재로그인 · 미등록이면 안내 후 사용자 페이지로).

## 0. 한 줄 요약

Google ID 토큰(RS256)은 회로에 들어가지 않는다. **IdP 가 래퍼**다 — 체인 밖에서 Google 토큰을 검증해 계정(uid)을 만들고, 그 뒤 세션 토큰은 지금처럼 EdDSA-Poseidon 으로 재서명한다. 회로·토큰·컨트랙트·RP 검증기·사용자 코어의 증명 경로는 바뀌지 않는다. 사용자가 믿는 것은 지금과 같이 IdP 하나이고, IdP 가 더 믿는 것은 Google 의 JWKS 다. 데모 계정(testuser·alice, uid·비밀번호)은 그대로 남는다. web 모드(브라우저 사용자 페이지) 전용이다.

## 1. 결정

- **D1 진입점 둘.** 등록은 사용자 페이지의 "Google 로 등록"(유일한 등록 위치). RP 로그인 모달의 Google 버튼은 같은 승인 팝업을 `provider:'google'` 표시와 함께 여는 진입점이다 — 미등록이면 팝업이 안내와 사용자 페이지 링크를 보이고 `not_registered` 로 회신한다(팝업 안 등록 없음).
- **D2 토큰은 브라우저가 직접 받는다**(Google Identity Services, 공개 클라이언트 ID 만, 시크릿·리다이렉트 없음). IdP 쪽 인가 코드 흐름(Mode 1 방식)은 쓰지 않는다.
- **D3 uid 유도.** `uid = SHA-256(provider ‖ "|" ‖ sub) mod 2^250`(10진 문자열, `provider` 는 IdP 설정값 `MODE3_OIDC_PROVIDER`, 기본 `google`). 토큰의 `iss` 가 아니라 설정값을 쓰는 이유: Google 은 `iss` 를 `https://accounts.google.com` 과 `accounts.google.com` 두 형태로 내므로 `iss` 를 섞으면 같은 계정이 두 uid 가 된다 — 검증은 두 형태를 모두 허용하고, 유도에는 쓰지 않는다. IdP 는 `sub`·이메일을 저장하지 않고 `accounts[uid].provider` 만 둔다(`'google'` | `'demo'`). 같은 Google 계정의 두 번째 등록은 지금처럼 409.
- **D4 토큰 결속(nonce).** 등록 토큰의 `nonce` 는 `"reg:" + SHA-256(auid|pk_u.x|pk_u.y)`(소문자 hex) — IdP 가 요청의 auid·pk_u 로 다시 계산해 대조한다. 가로챈 토큰을 다른 키 재료로 등록하는 재사용을 막는다. 자기 폐기 토큰의 `nonce` 는 `"revoke:" + 32바이트 임의 hex` — 접두어가 달라 등록 토큰으로 폐기하거나 폐기 토큰으로 등록할 수 없다(폐기 토큰 재사용은 같은 계정 재폐기 = 멱등, 무해).
- **D5 자기 폐기도 Google 재로그인.** 계정 페이지(`:4100/account`)와 사용자 페이지의 "계정 자기 폐기" 에 Google 버튼. `POST /cia/account/self_revoke { id_token }` → IdP 가 토큰의 `sub` 로 uid 를 다시 계산해 그 계정을 폐기. 데모 계정은 비밀번호 그대로.
- **D6 오리진.** Google 은 승인된 JavaScript 원본으로 `http://localhost:포트` 는 받고 `http://127.0.0.1:포트` 는 받지 않는다. IndexedDB 는 오리진별이라 등록과 로그인은 같은 주소여야 한다. 그래서 **Google 을 켠 데모는 사용자 오리진을 `http://localhost:5100` 으로 통일한다**(설정만: 정적 서버 `MODE3_WALLET_PUBLIC_ORIGIN`, IdP·RP 의 `MODE3_WALLET_AGENT_ORIGIN`). Google 콘솔에는 `http://localhost:5100`(사용자 페이지)과 `http://localhost:4100`(계정 페이지)을 추가한다. 코드는 오리진에 무관하다.
- **D7 테스트는 로컬 가짜 발급자.** IdP 는 발급자·JWKS·클라이언트 ID 를 env 로 받고(기본 Google), 테스트는 RS256 발급자 스텁으로 같은 코드 경로를 돈다. 실제 Google 확인은 런북의 수동 체크리스트 1회.

## 2. 구성요소

| 구성요소 | 위치 | 역할 |
|---|---|---|
| OIDC 검증 모듈 | `lib/mode3_oidc.js`(신규, Node 전용) | `createOidcVerifier({ issuer, jwksUrl, clientId })` → `verify(idToken, { expectedNoncePrefix })` : `jose` `createRemoteJWKSet`+`jwtVerify`(alg RS256, `iss`·`aud`·`exp`) → `{ sub, nonce, iss }`; `uidOf(provider, sub)`; `regNonce(auid, pk_u)`; 실패는 `Error{ reason }`. |
| IdP | `cia.js` | `/cia/register` 가 `{ uid, pwd }` 또는 `{ id_token }` 을 받는다; `/cia/account/self_revoke` 가 `{ uid, pwd }` 또는 `{ id_token }` 을 받는다; `/cia/public_keys` 에 `oidc: { enabled, provider, clientId, issuer }` 추가(공개값). env `MODE3_OIDC_ISSUER`(기본 `https://accounts.google.com`), `MODE3_OIDC_JWKS_URL`(기본 `https://www.googleapis.com/oauth2/v3/certs`), `MODE3_OIDC_CLIENT_ID`(기본 `GOOGLE_CLIENT_ID`), `MODE3_OIDC_PROVIDER`(기본 `google`). 클라이언트 ID 가 없으면 `enabled:false` 이고 `id_token` 요청은 503 `oidc_disabled`. |
| 사용자 코어 | `mode3/user/core/user_core.js` | `prepareRegistration()`(메모리 보류 재료 `{ s_u, sk_u, auid, pk_u }` + `nonce`), `completeRegistration({ idToken, profile, vaultPassword })`(기존 `register` 의 금고·저장 규칙 공유), `selfRevokeWithIdToken({ idToken })`. 기존 `register({ uid, pwd, … })`·`selfRevoke({ uid, pwd })` 는 그대로. |
| 사용자 페이지 | `mode3/user/index.html`·`ui.js`(+ `mode3/user/gsi.js` 신규: GIS 스크립트 로드·버튼 렌더·토큰 콜백) | 등록 카드에 Google 버튼(조건: `config.oidc.enabled && location.hostname === 'localhost'`; 아니면 안내 문구), 보관 카드의 자기 폐기에 Google 버튼. 금고 비밀번호 칸은 공유. |
| 승인 팝업 | `mode3/user/popup.js` | 요청의 `provider` 표시, 요약에 "신원: Google 계정 / 데모 계정"(`registration.provider`), 미등록이면 안내 + 사용자 페이지 링크 + `not_registered` 회신. |
| RP 페이지 | `mode3/rp.html` | 모달의 Google 버튼 → `startIdpLogin({ provider:'google' })` → 팝업 요청에 `provider` 를 싣는다. 버튼은 `rp_info.oidc.enabled` 일 때만 활성(IdP `public_keys` 를 RP 가 중계). |
| 계정 페이지 | `mode3/cia_account.html` | Google 버튼(IdP 의 `public_keys.oidc.clientId` 로 GIS 초기화) → `self_revoke { id_token }`. |
| 정적 서버 | `mode3_user_static.js` | **변경 없음.** 사용자 페이지는 `oidc` 설정을 IdP 의 `/cia/public_keys` 에서 직접 읽는다(이미 사용자 오리진에 CORS 가 열려 있고, 코어 `idp.publicKeys()` 가 있다) — 정적 서버가 중계하면 IdP 가 늦게 뜰 때 `enabled:false` 로 굳는다. |
| 테스트 헬퍼 | `tests/helpers/oidc_issuer_stub.mjs` | RS256 키 생성, `GET /jwks`, `POST /mint { sub, nonce, aud?, iss?, expSeconds? }` → ID 토큰. `startIsolatedCia({ oidc: true })` 가 스텁을 띄워 env 를 넣는다. |

## 3. 흐름

### 3.1 등록(사용자 페이지, localhost:5100)
1. 페이지 로드 → `core.prepareRegistration()` → `nonce`. GIS 를 `{ client_id, nonce, callback }` 로 초기화하고 버튼을 그린다. 다시 시도할 때마다 재료·nonce 를 새로 만든다.
2. 사용자가 금고 비밀번호를 적고 Google 버튼 → Google 이 ID 토큰을 콜백으로 준다.
3. `core.completeRegistration({ idToken, profile, vaultPassword })` → 금고 규칙(없으면 생성, 있으면 비밀번호 검증)은 `register` 와 같다 → `POST /cia/register { id_token, auid, pk_u, sig_reg }`.
4. IdP: `oidc.verify(id_token, { expectedNoncePrefix:'reg:' })` → `nonce === regNonce(auid, pk_u)` 대조 → `uid = uidOf(provider, sub)` → 이후 기존 등록 코드(`already registered` 409, auid·pk_u·sig_reg 검사, 슬롯 배정) → `provider:'google'` 기록 → 201 `{ slot, schemaHash, uid, provider }`(uid 는 지갑이 저장해야 하므로 응답에 싣는다 — 데모 계정은 요청에 있던 값을 그대로 돌려준다).
5. 코어는 응답의 `uid` 로 `registration` 을 저장한다(`provider` 포함). 그 뒤 로그인·증명·트랜잭션은 변경 없음.

### 3.2 RP 모달 Google 버튼
`startIdpLogin({ provider:'google' })` → 팝업 요청 `mode3-authorize` 에 `provider` → 팝업: 등록 없음이면 `user_register_hint_google` 문구 + `${location.origin}/` 링크, 회신 `{ ok:false, reason:'not_registered' }`; 있으면 요약에 신원 줄을 더하고 기존 흐름.

### 3.3 자기 폐기
사용자 페이지·계정 페이지의 Google 버튼은 `nonce = "revoke:" + 임의 hex` 로 GIS 를 초기화한다. 토큰 → `POST /cia/account/self_revoke { id_token }` → IdP: `verify(…, { expectedNoncePrefix:'revoke:' })` → `uid = uidOf(provider, sub)` → 계정 없음 404 → 기존 `revokeAccount(uid)`. 사용자 페이지는 폐기 뒤 지금처럼 세션을 비운다.

## 4. 오류·사유

새 사유(`strings.js` reasons, ko/en, where): `oidc_disabled`(503, IdP 설정 없음), `oidc_invalid`(401, 서명·iss·aud·exp 실패 — detail 에 `jose` 의 코드명만), `oidc_nonce_mismatch`(400), `oidc_unavailable`(502, Google JWKS 를 못 받음 — 등록만 막힘). 페이지 전용: `gsi_unavailable`(GIS 스크립트 로드 실패 — 오프라인), `gsi_origin`(hostname 이 localhost 가 아님 — 안내). 기존 `already_registered`·`register_failed` 는 그대로 쓴다.

## 5. 보안·프라이버시 메모

- 래퍼 신뢰: IdP 가 Google 토큰을 올바로 검증한다는 것을 사용자가 믿는다 — IdP 는 이미 자격증명 발급자이므로 신뢰 경계는 넓어지지 않는다. Google 은 등록·폐기 시점에만 관여하고 세션·RP·PPID 를 보지 못한다.
- 결속: 등록 토큰은 nonce 로 (auid, pk_u) 에 묶인다. 토큰이 새어도 그 키 재료 없이는 쓸 수 없고, 같은 재료로 다시 쓰면 409 다. 폐기 토큰 재사용은 멱등.
- IdP 는 `sub`·이메일을 저장하지 않는다(uid 는 단방향 유도). 단 IdP 는 토큰을 받는 순간 Google 신원을 안다 — 데모 계정의 uid·비밀번호와 같은 위치의 지식이다.
- `aud` 는 반드시 이 데모의 클라이언트 ID 와 같아야 한다(다른 앱에 발급된 Google 토큰 재사용 차단). JWKS 는 `jose` 의 원격 집합(캐시·키 회전 처리)으로 받는다.
- 오리진: localhost 통일(D6)은 Google 제약 때문이다. 127.0.0.1 로 연 사용자 페이지에서는 Google 버튼이 숨고 안내만 나온다.

## 6. 런북·운영

- Google 콘솔: Mode 1 의 OAuth 클라이언트에 승인된 JavaScript 원본 `http://localhost:5100`·`http://localhost:4100` 추가. 리다이렉트 URI 는 필요 없다.
- env: IdP `MODE3_OIDC_CLIENT_ID`(또는 기존 `GOOGLE_CLIENT_ID`), 사용자 오리진 셋을 `http://localhost:5100` 으로. Google 없이 띄우면 버튼이 숨고 데모 계정만 된다.
- 재시연 세트는 그대로 + Google 로 등록한 브라우저의 "모두 지우기".
- 수동 체크리스트: Google 로 등록 → zkONE 로그인 → zkTWO 로그인 → 계정 페이지에서 Google 로 자기 폐기 → 재검증이 `revoked`.

## 7. 테스트

- unit: `tests/test_mode3_oidc.js` — `uidOf` 결정성·범위(< 2^250), `regNonce` 형식, `verify` 가 스텁 JWKS(메모리 키)로 서명·iss·aud·exp·nonce 접두어를 거르는지(`jose` 로 직접 만든 토큰).
- chain: `tests/test_cia_oidc_register.mjs` — 격리 IdP + 발급자 스텁: 정상 등록(응답 uid = 유도값, provider google) → 같은 sub 재등록 409 → nonce 불일치 400 → 다른 aud 401 → 만료 401 → revoke 토큰으로 등록 400 → 자기 폐기 200 → 등록 토큰으로 폐기 400 → `oidc_disabled`(env 없는 IdP). 데모 계정 등록은 그대로 되는지 회귀 1건.
- browser: `tests/test_mode3_user_web_oidc.mjs` — Playwright 가 `google.accounts.id` 를 스텁(발급자 스텁에서 토큰을 받아 콜백 호출)으로 대체해 localhost 오리진의 사용자 페이지에서 Google 등록 → zkONE 로그인(RP 모달 Google 버튼) → 자기 폐기 → 다음 로그인 실패(`account_disabled`). 미등록 상태의 RP Google 버튼이 팝업 안내를 보이는지도 본다.
- 기존 그룹 전부 통과 유지(데모 계정 경로·에이전트 불변).

## 8. 범위 밖

Google 외 발급자의 검증(같은 env 로 OIDC 호환 발급자는 동작하지만 확인하지 않음), 이메일·이름 표시, Snap·에이전트(file) 모드의 Google 등록, IdP 쪽 인가 코드 흐름, 회로·토큰 변경, 계정 연결(한 uid 에 여러 발급자).
