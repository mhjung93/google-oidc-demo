# Mode 3 — OIDC 와 zk-Delegation 비교: 각자가 본 식별자를 화면에 (설계, 2026-11-19)

- 상태: **구현됨(2026-11-19, 사용자 승인 뒤).** 구현하며 정한 것과 같은 날 받은 데모 시나리오에 맞춘 것은 §9. 방향은 사용자 결정(2026-11-19 대화): "OIDC 쓸 때와 zk-Delegation 쓸 때를 비교해, IdP 가 본 서비스 식별자(rid ↔ arid)와
  서비스가 본 사용자 식별자(uid ↔ auid_s)를 표시" → OIDC 쪽은 **실제 OIDC 로그인을 추가**, 표시는 **각 화면에 따로**.
- 한 줄: zkIdP 가 비교용으로 **일반 OIDC 공급자**(sub = uid, aud = rid)도 되고, 서비스는 그 로그인을 받는다. 같은 사용자가 두 방식으로 로그인해 보면
  zkIdP 관리자 화면과 서비스 화면에 각자가 **실제로 받은 값**이 나란히 찍힌다.

  | | 일반 OIDC | zk-Delegation |
  |---|---|---|
  | zkIdP 가 본 서비스 | `rid`(= 그 서비스의 arid) — 어느 서비스인지 안다 | `arid_s` — 로그인마다 다른 가려진 값, 어느 서비스인지 모른다 |
  | 서비스가 본 사용자 | `uid` — 모든 서비스에서 같은 값 | `auid_s` — 로그인마다 다른 값(+ 이 서비스에서만 같은 PPID) |

- 용어 주의: 요청은 "zk-Delegation 쓸 시 arid" 였지만 zkIdP 가 실제로 받는 값은 `arid` 가 아니라 **`arid_s`** = Poseidon(T, arid, r_rp) 다(arid 자체는 받지 않는다) — 화면에는 `arid_s` 로 적는다.
- 근거 조사(2026-11-19, 코드): zkIdP 는 이미 OIDC discovery·JWKS 를 내고(`/.well-known/*`), 발급 때 `sub = auid_s`·`aud = arid_s` 인 ID 토큰을 서명한다(`cia.js` `signIdToken`).
  서비스는 그 토큰을 π 의 공개 신호와 대조하고(`mode3_rp.js` `verifyIdToken`) 세션·로그인 기록에 `auid_s` 를 둔다. 서비스에는 리디렉션식 소셜 로그인의 틀이 있다
  (`lib/mode3_rp_social.js` 네이버: state·nonce·PKCE·콜백, `lib/mode3_oidc.js` 검증기, `lib/mode3_rp_accounts.js` 계정의 로그인 수단 칸). zkIdP 는 등록된 서비스를 `arid → { name, origin, status }` 로 안다.
- 비범위: 회로·zkey·컨트랙트, zk-Delegation 의 등록·발급·폐기 규칙, 스냅·에이전트 모드의 흐름, Google·네이버 로그인(그대로), 실제 운영용 OIDC 공급자 기능(클라이언트 시크릿·동의 기억·refresh·userinfo).

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| C1 | zkIdP 에 **일반 OIDC 인가 코드 흐름**(PKCE 필수, 공개 클라이언트)을 더한다. 켜는 값 `CIA_PLAIN_OIDC=1`(기본 꺼짐). 분리 데모 스크립트는 passkey-web 에서 기본으로 켠다(`PLAIN_OIDC=0` 으로 끔), 그 밖의 모드는 기본 끔. | 비교의 OIDC 쪽이 진짜여야 화면의 값이 참이다. 꺼 두면 지금과 같다. |
| C2 | 클라이언트는 **승인된 서비스**다 — `client_id` = 그 서비스의 `arid`(이 문서의 `rid`), `redirect_uri` 는 `<등록된 origin>/api/rp/zkoidc/callback` 과 **글자 그대로** 같아야 한다. 따로 클라이언트를 등록하지 않는다. | zkIdP 가 이미 아는 값만 쓴다. 시크릿이 없으므로 PKCE(S256)와 리디렉션 주소 일치가 방어다. |
| C3 | `GET /oidc/authorize` 는 zkIdP 의 동의 화면(`mode3/cia_oidc.html`)을 낸다. 로그인돼 있지 않으면 그 화면에서 로그인한다(아이디·비밀번호, 그리고 증명 로그인이 켜진 구성이면 "패스키로 로그인"). 로그인 뒤 **"zkIdP 가 〈서비스 이름〉(rid …)에 내 uid 〈값〉 을 알려 줍니다"** 를 보이고 "계속"·"취소". 동의는 기억하지 않는다. | 무엇이 넘어가는지 그 자리에서 보인다 — 비교의 요점. 매번 묻는 것은 시연용(운영이면 기억한다). |
| C4 | `POST /oidc/token`(서비스 서버가 부른다): 코드(1회용·60초, `client_id`·`redirect_uri`·`code_challenge`·uid·nonce 에 묶임) + `code_verifier` → `{ id_token }`. 토큰은 지금 서명 키(ES256)로 `iss` = zkIdP, **`sub` = uid, `aud` = client_id(arid)**, `nonce`. discovery 문서에 두 엔드포인트와 `subject_types_supported: ['pairwise','public']` 을 더한다. | zk-Delegation 토큰(`sub` = auid_s·`aud` = arid_s)과 같은 발급자·같은 키라 서비스의 검증기를 그대로 쓴다. |
| C5 | zkIdP 는 계정마다 **가장 최신 값 하나씩** 남긴다: 일반 OIDC 는 `lastOidc = { rid, name, at }`, zk-Delegation 은 `lastAridS = { value, at }`. 기록(이력)은 두지 않는다. | 표시에 필요한 최소. `arid_s` 는 지금 "저장하지 않는다"(D1) — `lastAuidS`(2026-11-12)와 같은 모양의 예외다(사용자 결정). 가려진 값 하나라 새로 드러나는 것은 없다. |
| C6 | **zkIdP 관리자 화면**(`/admin` "uid ↔ auid 대응" 표)에 열 둘: "일반 OIDC 에서 본 서비스" = 서비스 이름 + `rid`, "zk-Delegation 에서 본 서비스" = `arid_s`(+ "어느 서비스인지 모름"). 각각 시각과 함께, 없으면 "-". | 요청의 "IdP 가 rid 확인". 지금 표에 이미 `auid`·최신 `auid_s` 가 있어 한 줄에서 견줄 수 있다. |
| C7 | 서비스에 로그인 수단 **`zkoidc`** 를 더한다(계정 저장소의 네 번째 칸 — 네이버와 같은 모양: 로그인·연결·해제, 색인 `byZkOidc`). 경로 `GET /api/rp/zkoidc/start`·`/api/rp/zkoidc/callback`(네이버와 같은 state·nonce·PKCE·세션 묶기). 켜는 값 `MODE3_RP_ZKOIDC=1`(스크립트가 C1 과 함께 켠다). 로그인 창에 **"zkIdP 로 로그인 (일반 OIDC · 비교용)"** 버튼. | 로그인이 돼야 "서비스가 본 값" 이 생긴다. 계정 틀을 그대로 써서 잔고·화면이 다른 수단과 같다. `uid` 로 만든 계정과 PPID 로 만든 계정은 서로 다른 서비스 계정이다(연결하지 않는 한) — 그것도 비교의 일부다. |
| C8 | **서비스 화면**(로그인 뒤 "내 계정" 위)에 "zkIdP 가 이 서비스에 알려 준 사용자 식별자" 한 칸: 일반 OIDC 로그인이면 `uid`("모든 서비스에서 같은 값"), zk-Delegation 로그인이면 `auid_s`("로그인마다 다른 값")와 `PPID`("이 서비스에서만 같은 값"). `/api/rp/me` 에 `seen: { protocol, uid \| auid_s, PPID }` 를 더한다. | 요청의 "RP 가 uid 확인". 지금 `/api/rp/me` 는 sub 를 싣지 않는다 — `zkoidc` 에 한해 싣는 예외다(화면에 보이는 것이 목적). Google·네이버는 그대로 싣지 않는다. |
| C9 | 이름·문구: 버튼과 화면에 **"비교용"** 을 적는다. 일반 OIDC 로그인은 zk-Delegation 을 거치지 않는다(증명·세션 키·온체인 지갑 없음 — 출금 같은 zk 기능은 그 로그인에서 쓸 수 없다, 지금 Google·네이버 로그인과 같다). | 두 길이 같은 것으로 보이지 않게. |

## 2. 흐름

1. 서비스 "로그인" → "zkIdP 로 로그인 (일반 OIDC · 비교용)" → 서비스가 state·nonce·PKCE 를 만들고 `…/oidc/authorize?response_type=code&client_id=<arid>&redirect_uri=…&scope=openid&state=…&nonce=…&code_challenge=…&code_challenge_method=S256` 으로 보낸다.
2. zkIdP 동의 화면: (로그인) → "〈서비스〉 에 내 uid 를 알려 줍니다" → "계속" → zkIdP 가 `lastOidc` 를 적고 코드를 붙여 서비스 콜백으로 돌려보낸다. "취소" 는 `error=access_denied`.
3. 서비스 콜백: state 확인 → `/oidc/token` → 토큰 검증(`iss`·`aud` = 자기 arid·`nonce`) → `zkoidc` 수단으로 로그인 → 첫 화면. "알려 준 식별자" 칸에 `uid`.
4. 견줄 때: 로그아웃 → "zkIdP 로 로그인"(zk-Delegation) → 같은 칸에 `auid_s`·`PPID`. zkIdP 관리자 화면의 그 계정 줄에는 `rid`(서비스 이름)와 `arid_s` 가 나란히 있다.
   zkTWO 에서도 두 방식으로 해 보면: 일반 OIDC 는 두 서비스가 **같은 `uid`** 를 받고 zkIdP 는 **두 `rid`** 를 구별해 안다. zk-Delegation 은 두 서비스의 `auid_s`·`PPID` 가 다르고 zkIdP 는 `arid_s` 둘을 서비스에 잇지 못한다.

## 3. 오류(사유 사전)

- zkIdP(동의 화면에 그대로 보인다 — 서비스로 돌려보내지 않는다): `oidc_client_unknown`(승인된 서비스가 아니다), `oidc_redirect_mismatch`, `oidc_request_invalid`(response_type·PKCE·scope), `plain_oidc_disabled`.
- 서비스(지금 네이버와 같은 길 — `/?social_error=…`): `zkoidc_state_invalid`, `zkoidc_denied`, `bad_nonce`·`oidc_*`(검증기의 기존 사유), `provider_disabled`.
- 토큰 엔드포인트: `invalid_grant`(코드 없음·만료·재사용·verifier 불일치·client/redirect 불일치) — OAuth 의 이름 그대로.

## 4. 바뀌는 곳(예상)

- `cia.js`: `/oidc/authorize`(화면)·`POST /oidc/authorize/decision`(같은 오리진, 로그인 세션)·`POST /oidc/token`·discovery, `lastOidc`·`lastAridS` 기록과 `/cia/accounts` 응답. 상태 파일 버전은 그대로(계정 레코드에 없는 칸은 null 로 읽는다).
- `mode3/cia_oidc.html`(새 화면), `mode3/cia_admin.html`(열 둘).
- `lib/mode3_rp_accounts.js`(`zkoidc` 칸·색인 — 옛 파일은 빈 색인으로 읽는다), `lib/mode3_rp_social.js`(start·callback·`seen`), `lib/mode3_oidc_link.js`(인가 주소·코드 교환을 공급자 설정으로 — 네이버 함수는 그대로 두고 같은 모양을 하나 더), `mode3_rp.js`(설정·zk 로그인의 `seen`).
- `mode3/rp.html`(버튼·"알려 준 식별자" 칸·계정 패널의 줄), `mode3/common/strings.js`.
- `scripts/demo_split_start.sh`(`PLAIN_OIDC`), `lib/mode3_health.js`(켜짐 여부 — 화면이 버튼을 보일지), 문서 `docs/MODE3_DEMO.md`·`docs/MODE3_DEMO_SCRIPT.md`.

## 5. 보안 메모

- **이 로그인은 일부러 드러낸다**: 서비스는 uid 를, zkIdP 는 어느 서비스인지를 안다 — 견줄 기준선이다. 기본은 꺼져 있고 화면에 "비교용" 이라 적는다.
- 인가 요청: `redirect_uri` 글자 일치·승인된 서비스만·PKCE S256 필수·`state` 는 그대로 돌려준다. 코드는 1회용·60초이고 요청의 `client_id`·`redirect_uri`·`code_challenge`·`nonce`·로그인한 uid 에 묶인다.
- 동의 결정은 같은 오리진의 JSON POST + 로그인 세션으로만 받는다(다른 사이트가 대신 "계속" 하지 못한다). 화면은 프레임에 못 넣는다(지금 헤더 그대로).
- 서비스 쪽은 네이버와 같은 방어를 쓴다: state 를 쿠키 세션에도 두어 콜백을 같은 브라우저에서만 받고(로그인 CSRF), nonce 를 토큰과 대조한다.
- 같은 발급자·같은 키로 두 종류의 토큰이 나온다(일반: `aud` = arid, zk: `aud` = arid_s). 서비스는 일반 토큰의 `aud` 를 **자기 arid 와 정확히** 대조하고, zk 토큰은 지금처럼 증명의 `arid_s` 와 대조한다 — 한쪽 토큰을 다른 쪽에 못 쓴다(`arid_s` 가 arid 와 같을 수 없다는 데 기대지 않고, 일반 토큰에만 `nonce` 와 `zkid_plain: true` 클레임을 싣고 그것을 확인한다).
- `lastAridS` 는 zkIdP 가 원래 받는 값을 하나 남길 뿐이다. 그래도 "남기지 않는다" 에서 물러난 것이므로 D1 의 주석에 적는다.

## 6. 테스트

- 단위: 계정 저장소의 `zkoidc` 칸(로그인·연결·해제·옛 파일 읽기), 인가 주소·PKCE 도우미, 사유 사전, 스크립트 기본값.
- zkIdP(chain 그룹, 격리 IdP): 꺼져 있으면 404/`plain_oidc_disabled`; 모르는 client·다른 redirect·PKCE 없음은 화면 오류이고 돌려보내지 않는다; 로그인 → 결정 → 코드 → 토큰의 `sub`·`aud`·`nonce`;
  코드 재사용·만료·틀린 verifier 는 `invalid_grant`; 로그인 세션 없이 결정 불가; `lastOidc`·`lastAridS` 가 `/cia/accounts` 에 보인다.
- 서비스(격리 스택): start → (zkIdP 를 직접 거쳐) callback → `zkoidc` 계정·`/api/rp/me` 의 `seen.uid`; 남의 state·바뀐 nonce·다른 `aud` 의 토큰 거절; zk 로그인의 `seen.auid_s`·`PPID`.
- 브라우저(passkey-web 스택): 한 사용자가 일반 OIDC → zk-Delegation 순으로 로그인해 서비스 칸이 `uid` → `auid_s` 로 바뀌고, zkIdP 관리자 표에 `rid`(서비스 이름)와 `arid_s` 가 보인다. 꺼진 스택에서는 버튼이 없다.
- 회귀: 지금 브라우저·체인 테스트(꺼진 기본값에서 동작이 같아야 한다).

## 7. 미검증 위험

- 리디렉션 왕복이 HTTPS 이름(`*.zkd.test`)·쿠키(SameSite=Lax) 조합에서 도는지는 실제 분리 데모에서 처음 본다(네이버 콜백과 같은 조건이긴 하다).
- 서비스 계정이 수단마다 따로 생겨 "같은 사람인데 잔고가 다르다" 로 보일 수 있다 — 화면 문구로 설명해야 한다.

## 8. 후속(이 스펙 밖)

- 두 방식을 한 장에 견주는 비교 화면(이번에는 "각 화면에 따로" 로 정했다).
- 서비스 관리자 화면의 로그인 기록에 일반 OIDC 줄.

## 9. 구현하며 정한 것(2026-11-19)

- **데모 시나리오(같은 날 사용자 제시)에 맞춰 "받은 JWT" 를 보인다**: 서비스의 칸은 "zkIdP 가 이 서비스에 알려 준 것(ID 토큰의 sub·aud)" 이고, 일반 OIDC 는 `sub = uid`·`aud = rid`,
  zk-Delegation 은 `sub = auid_s`·`aud = arid_s`·`PPID` 를 보인다. 토큰 본문(JSON)을 펼쳐 볼 수 있다(서명은 싣지 않는다). `/api/rp/me` 의 `seen` 은
  `{ protocol: 'oidc', uid, rid, jwt }` / `{ protocol: 'zk', auid_s, arid_s, PPID, jwt }`. zk 쪽 토큰을 보이려고 **웹 코어가 발급 응답의 zkIdP ID 토큰을 로그인 결과에 싣는다**
  (에이전트는 원래 넘겼다 — 공개값뿐이다. 서비스는 받은 토큰을 지금처럼 증명의 공개 신호와 대조한다).
- **C7 의 "연결·해제" 화면은 없다**: 서비스의 "내 계정" 패널이 2026-11-16 부터 화면에서 빠져 있다 — 계정 저장소는 `zkoidc` 칸의 연결·해제를 지원하지만 경로는 로그인만 둔다.
- 동의 화면의 정보는 `GET /oidc/authorize/info`(같은 오리진)로 읽는다 — 화면은 주소창의 값을 믿지 않고 zkIdP 의 답만 그린다. 켜짐 여부는 `rp_info.social.zkoidc.enabled`
  (`lib/mode3_health.js` 는 건드리지 않았다).
- 동의 화면의 "패스키로 로그인" 은 `/user` 페이지와 같은 길(챌린지 → 지갑 창 → 증명 로그인)이고, 코드는 그 화면에 따로 짧게 있다.
- zk 토큰과 일반 토큰의 구분: 일반 토큰에만 `nonce`·`zkid_plain: true`. 서비스는 일반 토큰의 `aud` 를 자기 arid 와, `nonce` 를 그 로그인의 것과 대조하고 그 클레임을 요구한다.
- 테스트: `tests/test_mode3_plain_oidc.mjs`(chain — 요청과 쿠키만으로 전체 흐름·거절), `tests/test_mode3_user_passkey_web_proof.mjs` 의 비교 케이스 넷(browser), 꺼진 스택의 버튼 없음
  (`tests/test_mode3_user_passkey_web.mjs`), 스크립트 기본값(`tests/test_demo_split_passkey_web.mjs`).

### 실제 Google(2026-11-19 사용자 결정: "실제 구글을 꼭 써야 한다")

- 시나리오 3·4 의 OIDC 는 **실제 Google** 이다. Google 은 승인 오리진·돌아올 주소로 공개 최상위 도메인이나 localhost 만 받는다 — 서비스의 데모 이름(`*.zkd.test`)은 등록할 수 없다.
  그래서 서비스는 Google 에 **리디렉션식**(암묵 흐름, `response_type=id_token` — 클라이언트 시크릿이 필요 없다)으로 다녀오고, 돌아올 주소는 **지갑 정적 서버의 `https://127.0.0.1:<포트>/google-relay`**
  (그 서버 인증서의 SAN 에 127.0.0.1 이 있다)다. 그 화면(`mode3/user/google_relay.html`·`.js`)은 조각(#)에 실려 온 `id_token`·`state` 를 그 로그인을 시작한 서비스의 첫 화면으로 조각째 넘긴다 —
  넘길 곳은 정적 서버가 아는 서비스 오리진(`/user/config` 의 `rpOrigins`)뿐이고, 토큰을 읽거나 저장하지 않는다.
- 서비스 페이지는 로그인 전에 `state`("이 오리진(base64url).난수")를 그 브라우저의 `sessionStorage` 에 남기고, 돌아온 조각(`#google_back=1`)의 `state` 가 같을 때만 토큰을 서버(`POST /api/rp/google` — 지금 검증 그대로:
  서명·iss·aud = 이 서비스의 클라이언트 ID·1회용 nonce)에 낸다. 남이 만든 링크로는 로그인되지 않는다(`google_state_invalid`). 토큰은 주소창·히스토리에 남기지 않는다.
- 설정: 서비스 `MODE3_RP_GOOGLE_REDIRECT_URI`(있으면 리디렉션식 — passkey-web 에서 Google 버튼이 다시 보인다)·`MODE3_RP_GOOGLE_AUTHORIZE_URL`(기본 Google). 스크립트는 passkey-web 에서 중계 주소를 자동으로 넘기고,
  `RP1_GOOGLE_CLIENT_ID`·`RP2_GOOGLE_CLIENT_ID` 로 서비스마다 다른 클라이언트 ID 를 줄 수 있다(토큰의 `aud` = rid 가 서비스마다 달라진다 — 없으면 공유 ID). **Google 콘솔의 그 클라이언트에
  "승인된 리디렉션 URI" 로 `https://127.0.0.1:5100/google-relay` 를 넣어야 한다(사용자가 한다).**
- 서비스의 칸은 Google 로그인이면 "Google 이 이 서비스에 알려 준 것": `sub = uid`(Google 의 사용자 식별자 — 같은 Google 프로젝트의 클라이언트면 서비스가 달라도 같다)·`aud = rid`(클라이언트 ID)와 토큰 본문.
  `/api/rp/me` 의 `seen` 에 `issuer: 'google' | 'zkidp'` 가 붙는다. **지금까지 `/api/rp/me` 는 Google sub 를 싣지 않았다 — 이 표시를 위해 로그인한 본인에게만 싣는 것으로 바꿨다**(계정 보기 `methods` 에는 여전히 없다).
- zkIdP 일반 OIDC(위 C1~C9)는 그대로 있다 — Google 을 쓸 수 없을 때(인터넷·콘솔 설정)의 대역이다.
- 미검증: 실제 Google 이 `https://127.0.0.1:5100/google-relay` 를 받아 주는지와 암묵 흐름이 그 클라이언트에서 켜져 있는지는 **실제 콘솔·실제 계정으로 확인하지 못했다**(자동 테스트는 대역 발급자). 시나리오의
  "Google 이 rid 를 안다" 는 Google 의 계정 선택 화면("〈앱 이름〉(으)로 이동")과 토큰의 `aud` 로 보인다 — Google 쪽 화면을 우리가 그릴 수는 없다.

### "받은 것·검증한 것" 그림(시나리오 6·7 — 2026-11-19 사용자 결정: "각자 화면에 다")

- 공용 모듈 `mode3/common/flow_figure.js`(상자 둘·화살표 둘·목록: 검증한 것 ✓ / 알 수 없는 것 ✗ / 알게 되는 것 !)와 `demo.css` 의 `.flow-*`. 문구는 사전의 `flow_*` 키.
- zkIdP: `/cia/issue` 가 계정마다 `lastIssue = { at, auid_s, arid_s, Cf_u, Cf_s, max_height, chainid, allowAgent }` 를 덮어쓴다(연결 해제 때 지운다). `/cia/accounts`(관리자)가 싣고,
  관리자 화면의 "uid ↔ auid 대응" 표 줄마다 "그림" 버튼이 표 아래(`#issueFigure`)에 그린다.
- 서비스: `/api/rp/me` 의 `seen.received`(zk 로그인: arid·pk_i·만료 높이·두 root·챌린지 앞자리·토큰 유무) 로 "알려 준 것" 칸 아래(`#seenFigure`)에 그린다. 기존 OIDC 로그인은 받은 토큰과 "알게 되는 것".
- 검증 항목의 문장은 코드가 실제로 하는 검사를 사람 말로 옮긴 것이다 — 요청마다 통과 여부를 따로 기록해 보이는 것은 아니다(로그인이 성공했다는 것이 곧 그 검사들을 모두 통과했다는 뜻이다).

### 시나리오의 나머지

- 시나리오 9·10(trace tag 없는 개봉: 서비스가 그 PPID 의 최신 `auid_s` 를 내면 zkIdP 가 uid 를 돌려준다 — 회로·컨트랙트에서 tag 제거)은 이 스펙 밖이다.
