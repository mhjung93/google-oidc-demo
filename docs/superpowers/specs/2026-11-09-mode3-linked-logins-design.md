# Mode 3 — zkID 계정에 Google·네이버 로그인 연결 (설계, 2026-11-09)

- 상태: **대체됨(2026-11-10)** → `2026-11-10-mode3-rp-social-logins-design.md` — 사용자 지적 "연결된 로그인은 RP 에서 지원해야 하는 기능" 으로 연결을 RP 로 옮기고 이 설계의 IdP 쪽 연결은 걷어낸다. (원래 상태: 사용자 승인 2026-11-09, 대화 중 섹션별 승인 → "추천대로 다 해줘".)
- 배경: 같은 날 "IdP 여러 개" 설계를 검토하다 사용자가 취소하고 이 방향으로 바꿨다 — IdP 는 zkID 하나, 로그인 수단을 셋(아이디·Google·네이버)으로 하고
  zkID 계정 하나에 외부 계정 여럿을 연결한다.
- 비범위: 다중 IdP, 등록부·폐기 게시의 IdP 밖 분리(ZDS), Google 래퍼 계정(`provider:'google'`)의 가입·로그인 경로(그대로 둔다), Snap.

## 1. 결정

| # | 결정 | 이유 |
|---|---|---|
| L1 | 계정의 중심은 zkID(아이디) 계정이다. `/user` 에 아이디로 로그인한 사용자가 Google·네이버 계정을 **공급자별로 하나씩** 연결·해제한다. | 사용자 선택 "zkID 계정에 Google·네이버 연결". |
| L2 | RP 의 "Google/네이버로 로그인" 은 **IdP 인증 창이 중개**한다(구조 A). 지갑 팝업이 인증 창을 `method=google\|naver` 로 열고, IdP 가 공급자 인증을 받아 연결된 계정의 1회용 코드(발급·등록)를 지갑에 돌려준다. 지갑은 공급자를 모른다. | 세 수단이 한 경로(코드 → 발급)로 모이고, 네이버의 인가 코드 교환·client secret·콘솔 등록이 IdP 한 곳에 있다. 대가: 외부 토큰이 발급에 암호학적으로 묶이지 않는다 — 묶음은 아이디 경로와 같은 IdP 1회용 코드다. |
| L3 | 한 외부 계정 `(provider, sub)` 은 zkID 계정 하나에만 연결된다. Google 래퍼 계정의 `sub` 은 연결할 수 없다(409 `oidc_has_own_account`). | 어느 버튼이든 계정이 하나로 정해져야 한다. |
| L4 | 연결은 계정에 속한다 — 지갑 연결 해제(`unlink_wallet`)가 외부 연결을 풀지 않는다(지금은 푼다). | 연결은 아이디·비밀번호 로그인으로 만든 것이라 지갑과 무관하다. |
| L5 | 341702f 의 "아이디 지갑 + Google 토큰 → `/cia/issue` 에서 첫 번에 자동 연결" 은 지운다. 아이디 계정이 `/cia/issue` 에 `id_token` 을 내면 400 `use_auth_window`. 에이전트의 "아이디 지갑이 다른 uid 토큰을 통과" 도 되돌린다. | 연결 경로를 /user 하나로. |
| L6 | 미등록 지갑 + Google·네이버 버튼 → 인증 창 **등록 모드**(`purpose=register&method=…`). 연결된 zkID 계정의 등록 코드로 지금 등록 흐름(b16d639)을 탄다. Google 래퍼 가입(`googleRegister`)으로 가지 않는다. 래퍼 가입은 `/user?google=1`(테스트·수동 확인)에만 남는다. | 연결된 계정이 있는데 별개 계정이 생기지 않게. |
| L7 | Google 래퍼 지갑(`provider:'google'`)은 지금처럼 지갑 안에서 Google 토큰으로 발급한다. 래퍼 지갑으로 네이버 버튼 → `provider_mismatch`. | 래퍼 경로는 비범위. |
| L8 | 분리 데모: 브라우저는 IdP 를 `http://localhost:4100`(호스트의 SSH 터널 → .10:4100)으로 연다. 지갑 에이전트의 `MODE3_CIA_URL` 이 이 주소다. RP 서버는 지금처럼 .10 주소로 부른다. | Google 은 `http://` 원본으로 `localhost` 만 받는다(2026-10-16 래퍼 스펙 D6). ID 토큰 iss 는 discovery 에서 읽으므로 주소 형태가 달라도 된다(Phase 1). |

## 2. IdP 서버 (`cia.js`)

### 2.1 공급자 표
- `PROVIDERS = { google, naver }`. 각 항목 `{ enabled, provider, issuer, jwksUrl, clientId, verifier, … }`.
- google: 지금 env(`MODE3_OIDC_CLIENT_ID`·`MODE3_OIDC_ISSUER`·`MODE3_OIDC_JWKS_URL`·`MODE3_OIDC_PROVIDER`, `GOOGLE_CLIENT_ID` 폴백) 그대로. 래퍼 경로(`/cia/register` id_token·`/cia/issue` 래퍼 계정·`/cia/account/self_revoke`)는 이 항목을 쓴다.
- naver: `MODE3_NAVER_CLIENT_ID`·`MODE3_NAVER_CLIENT_SECRET`(둘 다 있어야 켜진다). 기본 `issuer=https://nid.naver.com`, `jwksUrl=…/oauth2/jwks`, `authorizeUrl=…/oauth2/authorize`, `tokenUrl=…/oauth2/token` — 테스트용으로 `MODE3_NAVER_ISSUER`·`MODE3_NAVER_JWKS_URL`·`MODE3_NAVER_AUTHORIZE_URL`·`MODE3_NAVER_TOKEN_URL` 로 덮는다. `redirect_uri` = `MODE3_NAVER_REDIRECT_URI` 또는 `${CIA_PUBLIC_URL}/cia/oidc/naver/callback`.
- 검증기는 `createOidcVerifier`(RS256) 그대로, 공급자별 하나.
- `/cia/public_keys.oidc`: `{ enabled, provider, clientId, issuer }`(래퍼용 Google, 지금 모양 유지) **에 더해** `providers: { google: { enabled, clientId }, naver: { enabled } }`.

### 2.2 계정 레코드
- `linked: { google?: { sub, linkedAt }, naver?: { sub, linkedAt } }`. 옛 `linkedOidc:{provider,sub,linkedAt}` 는 기동 때 `linked[provider]` 로 옮기고 지운다(`persist`).
- 색인 `(provider, sub) → uid` 는 메모리(기동·연결·해제 때 갱신).
- `/cia/user/me`: `linked: { google: { linkedAt } | null, naver: … }` — `sub` 은 내지 않는다. `linkedOidc` 필드는 없앤다.

### 2.3 nonce·ticket (메모리, 5분, 1회용)
- `POST /cia/oidc/nonce { purpose:'link'|'auth' }` → `{ nonce }`(`link:<64hex>` 또는 `auth:<64hex>`). `link` 는 로그인 세션 필요, 세션 uid 에 묶는다. Google 버튼(GIS)이 쓴다.
- 네이버: `start` 가 `{ state, nonce, code_verifier, purpose, uid?(link), ctx?(auth) }` 를 state 키로 저장. 콜백이 검증을 끝내면 `auth` 는 `ticket` → `{ provider:'naver', sub, at }` 을 만든다.

### 2.4 엔드포인트
| 경로 | 동작 |
|---|---|
| `POST /cia/oidc/nonce` | 위. |
| `GET /cia/oidc/naver/start?purpose=link` | 로그인 세션 필요. 네이버 인가로 302(`response_type=code&scope=openid&state&nonce&code_challenge(S256)`). |
| `GET /cia/oidc/naver/start?purpose=auth&ctx=<쿼리>` | 인증 창의 쿼리(`nonce`·`wallet`·`return`·`purpose`·`method`)를 그대로 보관해 두고 302. |
| `GET /cia/oidc/naver/callback?code&state` | state 소비 → 토큰 교환(client secret·code_verifier) → id_token 검증(aud=client_id, nonce 일치) → `link`: 연결 후 `/user?linked=naver`(실패면 `/user?link_error=<reason>`), `auth`: `/login?<보관한 쿼리>&ticket=…`(실패면 `&auth_error=<reason>`). |
| `POST /cia/user/link { provider:'google', id_token }` | nonce `link:` + 세션 uid 일치 확인 → 연결. |
| `POST /cia/user/unlink { provider }` | 연결 해제(비밀번호 묻지 않음 — 로그인 세션으로 충분, 데모 범위). |
| `POST /cia/auth/code` | `method:'password'`(기본, 지금 그대로) \| `method:'google', id_token` \| `method:'naver', ticket`. 외부 수단은 확인된 sub 의 연결 계정을 찾는다(없으면 404 `oidc_not_linked`). 이후 `purpose` 별 처리(등록 409·발급 `auid` 확인)는 지금과 같다. |

연결 규칙: 이미 이 계정에 같은 공급자의 다른 sub 가 있으면 409 `oidc_already_linked`(먼저 해제), 이 sub 가 다른 계정에 있으면 409 `oidc_linked_elsewhere`, 래퍼 계정 sub 이면 409 `oidc_has_own_account`, 꺼진 공급자는 503 `provider_disabled`.

## 3. 화면

### 3.1 인증 창 (`cia_login.html`)
- `method` 쿼리(기본 `password`). `google` 은 아이디·비밀번호 칸 대신 GIS 버튼(`/common/gsi.js`, nonce `auth:`), `naver` 는 "네이버로 인증" 버튼(`/cia/oidc/naver/start?purpose=auth&ctx=…`). 발급 모드의 `auid` 칸은 그대로 받는다.
- 네이버에서 돌아오면(`ticket`) 버튼이 "계속"이 되고, 누르면 `auid` 와 함께 `/cia/auth/code` 를 부른다. `auth_error` 면 사유를 보인다.
- 결과 반환(`idp_code`·`idp_purpose`·`idp_uid`)은 지금 그대로.

### 3.2 /user
- "연결된 로그인" 카드: 공급자별 한 줄(연결됨·날짜 + [연결 해제] / [연결]). 꺼진 공급자는 비활성 + "이 데모에서 설정되지 않음". 기존 `meLinked` 줄은 지운다.
- `?linked=naver`·`?link_error=` 를 읽어 결과를 보이고 주소를 정리한다.

### 3.3 RP 페이지 (`rp.html`, `mode3_rp.js`)
- `rp_info.oidc` 에 IdP 의 `providers` 를 함께 싣는다. Google 버튼 = `providers.google.enabled`(없으면 옛 `oidc.enabled`), 네이버 버튼 = `providers.naver.enabled` 이면 `startIdpLogin({provider:'naver'})`, 아니면 지금 안내.
- 문구: "zkID 계정에 연결한 Google·네이버로도 로그인합니다".

### 3.4 지갑 (`wallet.html`, 에이전트)
- `goIdpAuth(req, origin, { purpose, method })` — `method` 를 인증 창 쿼리에 싣는다.
- `processAuthorize`: 래퍼 지갑이 아니고(`provider!=='google'`) `req.provider ∈ {google, naver}` → 인증 창 `method=req.provider`(미등록이면 `purpose=register`). 래퍼 지갑 + naver → `provider_mismatch`. 래퍼 지갑 + google 은 지금 경로.
- 에이전트: `/wallet/login` 의 `id_token` 은 래퍼 지갑에서만 받는다(아이디 지갑이면 400 `use_auth_window`).

## 4. 데모·문서
- `demo_split_start.sh`: 호스트에 `ssh -N -L 4100:127.0.0.1:4100 zkd@$IDP` 를 띄운다(`SPLIT_IDP_TUNNEL=0` 으로 끔, :4100 이 이미 쓰이면 중단). 지갑 에이전트 `MODE3_CIA_URL=http://localhost:4100`. 호스트 셸에 `MODE3_NAVER_CLIENT_ID`·`MODE3_NAVER_CLIENT_SECRET` 이 있으면 IdP role.env 에 넣는다(`MODE3_NAVER_REDIRECT_URI=http://localhost:4100/cia/oidc/naver/callback`). stop 이 터널도 내린다.
- 네이버 개발자센터 등록(사용자): 서비스 URL `http://localhost:4100`, Callback `http://localhost:4100/cia/oidc/naver/callback`. Google 콘솔: 승인된 JavaScript 원본 `http://localhost:4100`.
- `docs/MODE3_DEMO.md` 에 연결 시연 순서와 위 설정.
- 미확인(실제 네이버로 확인할 것): 콜백에 `http://localhost` 허용 여부, 토큰 교환의 `code_verifier`·`client_secret` 동시 사용.

## 4.1 리뷰 반영(2026-11-09, Opus 리뷰)
- 래퍼 계정 생성(`/cia/register` id_token, `/cia/issue` 첫 로그인 자동 등록)도 L3 을 지킨다 — 이미 아이디 계정에 연결된 Google 이면 409 `oidc_linked_elsewhere`.
- RP 는 브라우저용 IdP 주소를 따로 받는다: `MODE3_CIA_BROWSER_URL`(기본 `MODE3_CIA_URL`) — `rp_info.ciaUrl`(가입·관리자 링크)·health CORS 에 쓰고, 서버 간 호출은 `MODE3_CIA_URL`(VM 주소). 분리 데모는 `$IDP_UI` 를 넣는다.
- 연결 로그인은 **snap 모드 전용**이다. web 모드 사용자 페이지(`mode3/user/popup.js`, 개발 일시 중지)는 인증 창 `method` 를 모른다 — 네이버 버튼 요청은 `snap_mode_only` 로 거절, Google 은 예전 래퍼 경로 그대로. 터널은 기본으로 snap 모드에서만 켠다(`SPLIT_IDP_TUNNEL` 로 바꾼다).
- 1회용 저장소를 둘로: 인증 없이 채울 수 있는 것(auth nonce·auth 쪽 네이버 state, 상한 2000)과 로그인 세션이 필요한 것·ticket. ticket 은 인증 창의 용도(issue|register)에 묶는다. 네이버 state 앞에 용도(`auth-`·`link-`)를 붙여 만료된 state 로 돌아와도 인증 창 쪽은 `/login?auth_error=naver_state_invalid` 로.
- 상태 이행: 옛 기록에서 같은 외부 계정이 둘에 연결돼 있으면 앞 계정만 남기고 notes 에 남긴다. `MODE3_NAVER_REDIRECT_URI` 가 없으면 기동 경고.
- 남는 위험: RP 팝업 제한 시간(120초) 안에 네이버 왕복·auid 입력·MetaMask·증명이 모두 끝나야 한다.

## 5. 테스트
- `tests/helpers/oidc_issuer_stub.mjs` 에 네이버 흉내(`/oauth2/authorize` 가 바로 redirect_uri 로 code 를 돌려주고, `/oauth2/token` 이 client_secret·code_verifier 를 확인해 nonce 를 담은 id_token 을 준다)를 붙인다.
- 새 `tests/test_cia_linked_logins.mjs`(chain): Google 연결(nonce 세션 묶임·재사용 거절·다른 계정 409·래퍼 sub 409)·해제, 네이버 start→callback→연결, `auth/code` method google·naver(발급·등록·미연결 404·auid 불일치 403), ticket 재사용 거절, `unlink_wallet` 이 연결을 남기는지, 옛 `linkedOidc` 마이그레이션, `/cia/issue` 아이디 계정 + id_token → 400.
- 기존 `test_cia_oidc_register`(341702f 연결 케이스는 새 규칙으로 바꾼다), 에이전트·브라우저 테스트의 Google 연결 케이스를 새 흐름으로 고친다. 브라우저: /user 연결 카드(GIS 스텁), RP 네이버 버튼 → 인증 창 `method=naver`.
