# Mode 3 — passkey-web: 패스키(π_IdP)로 zkIdP 에 로그인 (설계, 2026-11-19)

- 상태: **구현됨(2026-11-19, 사용자 승인 뒤).** 구현하며 정한 것은 §9. 방향은 사용자 승인(2026-11-19 대화): "패스키를 도입한다면 zkIdP 로그인도 패스키로" → 세 안(A: zkIdP 전용 패스키·서버 검증,
  B: 패스키 → s_u → π_IdP 를 로그인으로 인정, C: 그대로) 중 **B**.
- 한 줄: passkey-web 에서 zkIdP 의 본인 확인을 "아이디·비밀번호" 에서 "이 계정 auid 의 s_u 를 안다는 증명(π_IdP)" 으로 바꾼다. 패스키는 지금 것 하나 그대로다.
- 근거 조사(2026-11-19, 코드): IdP 는 이미 등록·슬롯·발급·세션 폐기에서 π_IdP 를 검증한다(`cia.js` `checkIdpAuth`). 발급 정책 `CIA_ISSUE_AUTH=key`(증명만으로 발급)가
  이미 있고 web 모드가 쓴다 — passkey-web 만 `code`(로그인마다 인증 창)로 띄우고 있다(passkey-web 스펙 W5). π_IdP 의 `ctx` 는 공개 입력일 뿐 내용은 회로 밖이다
  (`circuits/pi_idp.circom` ⑤) — 새 용도의 ctx 를 더해도 회로·zkey 는 그대로다.
- 관련: passkey-web 스펙 `2026-11-17-mode3-passkey-web-design.md`(W5 를 이 스펙이 바꾼다), pk_u 제거 스펙 2026-11-12(ctx·tag), IdP 페이지 스펙 2026-10-22(1회용 코드·세션).
- 비범위: 회로·zkey·컨트랙트, 스냅 모드·에이전트 패스키 모드·web 모드의 동작(그대로), 가입(아이디·비밀번호 그대로), 계정 복구(인증 창 그대로), Google·네이버, §8 의 후속.

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| L1 | passkey-web 의 발급 정책 기본값을 **`key`** 로 바꾼다(`scripts/demo_split_start.sh` — 지금은 에이전트 모드(snap·passkey)와 passkey-web 이 `code`, web 이 `key`). `ISSUE_AUTH=code` 로 띄우면 지금 동작(로그인마다 인증 창)이다. | IdP 코드는 그대로 — `key` 정책은 이미 있다. 대가: 발급의 본인 확인이 "비밀번호 + s_u" 에서 "s_u" 하나가 된다(§5). |
| L2 | IdP 가 자기 정책을 알린다 — `/cia/public_keys` 에 `issueAuth: 'key' \| 'code'`. 승인 창(`popup.js`)은 **등록된 지갑 + `key`** 일 때만 인증 창을 건너뛴다. 못 읽으면 `code` 로 본다. | 지갑 설정과 IdP 설정이 어긋날 자리를 없앤다(정본은 IdP 하나). 못 읽었을 때 인증 창으로 가는 쪽이 안전하다(코드가 필요 없으면 남을 뿐이다). |
| L3 | **가입·첫 등록·계정 복구는 그대로** 아이디·비밀번호(인증 창 등록 모드)다. 비밀번호를 없애지 않는다. | 첫 등록 전에는 계정에 auid 가 없어 증명으로 본인을 가릴 수 없다. 패스키를 잃었을 때 zkIdP 에 들어가 연결 해제·계정 삭제를 할 수단이 남아야 한다. |
| L4 | **로그인은 패스키를 한 번 묻는다**(정책이 `key` 일 때 — §9) — 새 세션 발급(서비스 로그인)과 zkIdP 페이지 로그인은 10분 보관분·이전 메모로 건너뛰지 않는다(`core.withSalt(fn, { fresh: true })` — 범위의 첫 salt 를 패스키에서 새로 얻고, 얻은 값으로 보관을 갱신한다). 출금·재검증·속성 맞추기는 지금처럼 보관분을 쓴다. | 승인 단계가 없고(`MODE3_POPUP_CONSENT=0`, 11-18) 비밀번호 창도 빠지면, 보관 10분 안의 로그인에는 사람 손이 한 번도 닿지 않는다. "패스키로 로그인" 이 화면에서 보이는 것도 이 한 번이다. 대가: 10분 안에 두 서비스에 로그인하면 패스키를 두 번 묻는다. **(제안 — 빼도 나머지는 그대로 선다.)** |
| L5 | zkIdP 페이지(`mode3/cia_user.html` 로그인 카드)에 **"패스키로 로그인"** 버튼. passkey-web 이고 정책이 `key` 일 때만 보인다. 아이디·비밀번호 폼은 그대로 둔다. | 사용자 질문의 본래 자리. 이 페이지는 패스키를 직접 부를 수 없어(RP ID 가 지갑 오리진) 지갑 창을 연다(§2.3). |
| L6 | 로그인 증명의 ctx: `loginCtx({ nonce }) = Poseidon(D_CTX_LOGIN, nonce)`, `DOMAIN_MODE3_CTX_LOGIN` = ASCII "MODE3CTXLOGIN"(다른 ctx 도메인과 같은 인코딩). | 다른 용도의 증명(등록·슬롯·발급·폐기)을 로그인에 돌려쓸 수 없게 도메인을 가른다. |
| L7 | 로그인 챌린지: IdP 가 뽑은 난수(필드 원소)를 **로그인 전 세션**에 둔다(`POST /cia/user/login_challenge` → `{ nonce, expiresAt }`). 수명 180초(zkIdP 페이지가 지갑 창을 기다리는 120초보다 길게), 세션당 하나, **검증을 시도하면 지운다**(성공·실패 모두). | 증명이 그 브라우저 세션에만 쓰인다 — 가로챈 증명을 다른 세션에 못 낸다. |
| L8 | 지갑 창의 새 요청 `mode3-idp-login { origin, nonce }` 은 **IdP 오리진(설정 `ciaUrl` 의 오리진)이 연 창에만** 답한다 — 그 밖은 `origin_mismatch`. RP 인증서 검사는 없다(IdP 는 RP 가 아니다). 미등록이면 `not_registered`, 패스키 연결이 없으면 `passkey_setup_required`. 승인 단계는 `popupConsent` 설정을 따른다. | 이 검사가 피싱 방어의 전부다 — 다른 사이트가 지갑 창을 열어 자기 nonce 로 로그인 증명을 받아 가면 그 사이트가 피해자로 zkIdP 에 들어간다. |
| L9 | `POST /cia/user/login_proof { uid, nonce, auid_s, C_u_pt, C_s_pt, max_height, tag, proof_idp }` — 같은 오리진 전용(CORS 없음). 세션의 챌린지 대조 → 계정·auid 있음 → `checkIdpAuth({ uid, auid: 계정의 auid, ctx: loginCtx(nonce) })` → 비밀번호 로그인과 같은 세션 수립(`loginKeepingOtherRole`). 정책이 `code` 면 403 `proof_login_disabled`. | `code` 정책(스냅 데모)에서는 비밀번호가 계정 관리의 관문으로 남아야 한다 — s_u 만으로 zkIdP 에 들어가지 못하게 한다. 계정 상태 규칙(폐기된 계정 등)은 비밀번호 로그인과 같게 둔다. |
| L10 | 응답·오류는 지금 사전 방식 — 새 사유 `login_challenge_expired`·`proof_login_disabled`. 모르는 계정·auid 없는 계정·틀린 증명은 구분하지 않고 401 `invalid_credentials`. | 비밀번호 로그인과 같은 원칙(계정 존재를 알려 주지 않는다). |

## 2. 흐름

### 2.1 서비스 로그인 — 등록된 지갑 (바뀜)

zkONE "zkIdP 로 로그인" → 승인 창(`https://wallet.zkd.test:5100/?authorize=1`) → RP 인증서 검사 → (승인 단계는 설정대로) → **패스키 한 번(L4)** →
속성 도구 기록이 있으면 속성 맞추기(지금과 같다) → `/cia/issue`(π_IdP, `auth_code` 없음) → π_cred → 창 닫힘. **zkIdP 인증 창으로 가지 않는다.**

### 2.2 서비스 로그인 — 미등록 지갑 (그대로)

승인 창 → zkIdP 인증 창(등록 모드: 아이디·비밀번호·auid) → 돌아와 등록 → 이어서 발급. 패스키는 돌아온 뒤 한 번(등록·발급이 한 `withSalt` 범위).
`key` 정책의 IdP 는 등록 응답에 발급 코드를 주지 않는다 — 코드 없이 발급한다(지금 코드 그대로).

### 2.3 zkIdP 페이지 로그인 (새로)

1. `https://idp.zkd.test:4100/user` 로그인 카드의 "패스키로 로그인" → `POST /cia/user/login_challenge` → `{ nonce }`.
2. 페이지가 지갑 창을 연다(`<지갑 오리진>/?authorize=1` — IdP 는 지갑 오리진을 `MODE3_WALLET_AGENT_ORIGIN` 으로 안다) → `mode3-authorize-ready` 를 기다려
   `mode3-idp-login { origin, nonce }` 를 그 오리진에만 보낸다.
3. 지갑 창: 오리진 대조(L8) → 등록·패스키 연결 확인 → 패스키 한 번 → `core.idpLoginProof({ nonce })` = `{ uid, nonce, …π_IdP 필드 }` → 연 창에 돌려주고 닫힌다.
4. 페이지가 `POST /cia/user/login_proof` → 세션 수립 → 지금 비밀번호 로그인 뒤와 같은 화면.

### 2.4 `code` 정책의 IdP (그대로)

`ISSUE_AUTH=code` 로 띄우면 승인 창은 지금처럼 인증 창을 다녀오고, "패스키로 로그인" 버튼은 보이지 않는다.

## 3. 오류(사유 사전)

- `login_challenge_expired`(aa): 챌린지가 없거나 지났거나 nonce 가 다르다 — "다시 '패스키로 로그인' 을 누르세요".
- `proof_login_disabled`(aa): 이 IdP 설정(`CIA_ISSUE_AUTH=code`)은 증명 로그인을 받지 않는다 — "아이디·비밀번호로 로그인하세요".
- 지갑 창의 `origin_mismatch`·`not_registered`·`passkey_setup_required`·`passkey_mismatch` 는 지금 사유 그대로(문구에 zkIdP 페이지에서 본 경우를 덧붙일지는 구현 때 화면을 보고 정한다).

## 4. 바뀌는 곳(예상)

- `lib/mode3_credential.js`: `DOMAIN_MODE3_CTX_LOGIN`, `loginCtx`.
- `cia.js`: `/cia/public_keys` 의 `issueAuth`, `/cia/user/login_challenge`, `/cia/user/login_proof`. 발급·등록 경로는 손대지 않는다.
- `mode3/cia_user.html`: 버튼·지갑 창 왕복(여는 쪽). `/mode3/health` 의 `walletKind` 와 `public_keys.issueAuth` 로 버튼을 보인다.
- `mode3/user/core/user_core.js`: `withSalt` 의 `fresh`, `idpLoginProof`, IdP 정책 읽기. 증명 기록(영지식 증명 카드)의 purpose 에 `idp_login` 추가.
- `mode3/user/popup.js`: 등록됨 + `key` 면 인증 창 생략, `mode3-idp-login` 처리.
- `mode3/common/strings.js`: 버튼·창 제목·안내·새 사유 둘·증명 카드의 purpose 이름.
- `scripts/demo_split_start.sh`: passkey-web 의 `ISSUE_AUTH` 기본값. (`scripts/demo_web_reset.sh` 는 split 이 아니라 손대지 않는다.)
- 사용자 페이지 번들(`mode3/user/dist/`)은 기존 절차로 다시 만든다(생성물 — 커밋하지 않는다).
- 문서: `docs/MODE3_DEMO.md`, `docs/MODE3_DEMO_SCRIPT.md`(passkey-web 의 로그인 단계), passkey-web 스펙 W5 에 "2026-11-19 스펙이 바꿨다" 한 줄.

## 5. 보안 메모

- **인증 요소가 준다**: 발급과 zkIdP 로그인이 "비밀번호 + s_u" 에서 "s_u(패스키 소지 + 사용자 확인)" 로. 패스키 자체가 소지·확인 두 요소이고 지갑 오리진에 묶여 피싱에 강하지만,
  비밀번호가 따로 막아 주던 경우(s_u 만 새어 나간 경우)는 이제 막지 못한다.
- **지갑 사이트를 믿는 범위가 넓어진다**: 지갑 오리진의 코드는 지금도 s_u 를 만진다(그래서 IdP 와 운영자를 나눈다 — W2). 지금까지는 그것으로 세션 발급·폐기까지였고,
  이제 zkIdP `/user` 의 로그인 세션에도 닿는다 — 내 정보 조회와 프로필 변경(바뀌면 자격증명·세션이 은퇴한다)까지다. **연결 해제·계정 폐기는 세션과 따로 비밀번호를 다시 요구하므로
  (`/cia/user/unlink_wallet`·`self_revoke` 의 `pwOk`) 증명 로그인만으로는 못 한다**(2026-11-19 리뷰 M10 — 초안의 "연결 해제·계정 삭제에도 닿는다" 를 바로잡음).
- **IdP 오리진을 믿는 범위도 넓어진다**(리뷰 M11): 지갑 창이 증명을 주는 조건은 "연 창이 IdP 오리진" 하나다 — 그 오리진의 어느 페이지(`/admin`·`/rp`·`/login` 포함)에 스크립트 주입이 있으면
  사용자 로그인 증명까지 이어진다(패스키 창 한 번은 남는다). 알려진 주입은 없다.
- **IdP 가 새로 아는 것은 없다**: 로그인 증명은 발급 증명과 같은 공개 입력 모양이고, C_u·C_s·auid_s 는 버리는 값이다(다른 비발급 요청과 같다). IdP 는 패스키도 PRF 도 보지 않는다.
- **A 안을 택하지 않은 이유**: 같은 패스키를 IdP 오리진과 나누면(RP ID 를 넓히면) IdP 가 같은 PRF 입력으로 s_u 를 계산한다. 전용 패스키를 따로 두면 패스키가 둘이 되고
  서버 쪽 WebAuthn 검증이 새로 필요하다.
- **재사용 방지**: tag = Poseidon(T_TAG, s_u, ctx), ctx 에 IdP 가 뽑은 1회용 nonce — 한 번 낸 증명은 그 세션의 그 챌린지에만 맞는다.
- **패스키를 잃으면**: 비밀번호로 zkIdP 에 들어가 연결 해제 또는 계정 삭제(L3). 같은 패스키가 동기화돼 있으면 "이미 있는 패스키 쓰기" 로 복구(그대로).
- `key` 정책에서는 인증 창의 발급 코드가 본인 확인에 쓰이지 않는다(받아도 무시된다 — 지금 web 모드와 같다).

## 6. 테스트

- 단위: `loginCtx`(도메인·범위·다른 ctx 와 겹치지 않음), 사유 사전(새 사유 둘), `demo_split_start.sh` 의 passkey-web 기본 정책(`tests/test_demo_split_passkey_web.mjs`).
- IdP(`tests/test_cia_accounts.mjs`, chain 그룹): `public_keys.issueAuth`; 챌린지 → 증명 → 세션 성공; 다른 세션의 nonce·재사용·만료·다른 계정의 uid·auid 없는 계정은 거절;
  발급용 ctx 로 만든 증명은 거절; `code` 정책이면 403.
- 웹 코어(`tests/test_mode3_user_core_passkey.mjs`): `key` 스택에서 코드 없이 발급; 보관분이 있어도 로그인은 패스키 한 번(`fresh`), 출금은 보관분; `idpLoginProof`.
- 브라우저(`tests/test_mode3_user_passkey_web.mjs`): 등록된 뒤의 서비스 로그인이 인증 창을 거치지 않는다; zkIdP 페이지 "패스키로 로그인"; **IdP 가 아닌 오리진의
  `mode3-idp-login` 은 `origin_mismatch`**; `code` 스택에서는 버튼이 없고 인증 창을 거친다.
- 회귀: 스냅·web·에이전트 패스키 브라우저 테스트와 단위 그룹(동작이 바뀌지 않아야 한다).

## 7. 미검증 위험

- 실제 Chrome·Google 비밀번호 관리자에서 로그인마다 뜨는 패스키 창의 체감(L4) — 자동 테스트는 패스키 대역을 쓴다.
- zkIdP 페이지가 여는 지갑 창이 팝업 차단에 걸리는지(클릭 직후에 열므로 서비스 페이지와 같은 조건일 것으로 본다).
- 시연 순서(S0~S18)가 passkey-web 에서만 달라진다 — W5 가 지키려던 "모드와 상관없이 같은 순서" 를 이 모드에서 포기한다.

## 8. 후속(이 스펙 밖)

- 비밀번호 없는 가입(가입 = 패스키 만들기 + 등록 한 번에).
- 증명으로 계정 찾기(새 브라우저에서 패스키만으로 복구 — 지갑이 uid 를 모르는 상태에서의 조회 요청이 필요하다).
- 에이전트 패스키 모드(`http://localhost:5100`)에 같은 로그인.

## 9. 구현하며 정한 것(2026-11-19)

- **L4 는 `key` 정책에서만 건다.** `code` 정책은 로그인마다 비밀번호 창이 있어 사람 손이 이미 닿는다 — §2.4("그대로")와 맞춰 보관분을 그대로 쓴다. 승인 창이 요청을 처리하기 전에
  IdP 의 정책을 한 번 읽어 정한다(`popup.js` `run`).
- **챌린지 응답에 지갑 오리진을 싣지 않는다.** zkIdP 페이지는 이미 자기 `/mode3/health` 의 `walletOrigin` 으로 지갑 오리진을 안다(Google 등록 창과 같은 길) — 그 창 여는 함수(`openRegisterPopup`)를
  결과 종류·실패 제목·성공 처리만 바꿔 다시 쓴다.
- **챌린지를 받은 뒤 창을 연다**(스펙 §2.3 순서 그대로). 같은 오리진의 짧은 요청이라 클릭의 활성 시간 안이다 — 늦으면 `popup_blocked` 로 보이고 다시 누르면 된다.
- **증명 로그인 엔드포인트는 형식 오류도 `invalid_credentials` 로 답한다**(계정이 있으면 400, 없으면 401 로 갈리지 않게). vkey 를 못 읽은 경우만 503 을 그대로 낸다.
- **브라우저 테스트는 파일을 나눴다**: 기존 `tests/test_mode3_user_passkey_web.mjs` 는 `code` 정책 스택 그대로(§2.4 의 회귀 — 버튼 숨김 한 건 추가), `key` 정책은
  `tests/test_mode3_user_passkey_web_proof.mjs`. 피싱 케이스(L8)는 오리진 대조를 끈 변형에서 실패하는 것을 확인했다(증명이 서비스 오리진으로 나갔다).
- ~~`mode3-idp-login` 은 모드를 가르지 않는다~~ → **passkey-web 에서만 답한다**(리뷰 M10): web 모드의 승인 창·코어는 `not_passkey_mode` 로 거절한다 — 비범위("web 모드의 동작은 그대로")와 맞춘다.

### 리뷰(2026-11-19, Opus — Critical·Important 0, Minor 11) 뒤 바꾼 것

- **L7 의 챌린지는 로그인 세션이 아니라 전용 쿠키(`cia.lc`, HttpOnly·SameSite=Lax·경로 `/cia/user`·수명 = 챌린지 수명) + 서버의 표에 둔다**(M1·M2·M3). 로그인 전 요청이 세션(`cia.sid`)을 만들면
  인증 없는 요청이 만료 없는 세션을 쌓고, 남의 사이트의 폼 POST 가 새 세션 쿠키로 로그인을 풀 수 있고, 세션 저장이 응답 때라 같은 챌린지의 동시 제출이 둘 다 통했다.
  표는 2000개 상한(넘치면 오래된 것부터 버린다)이고 검증 전에 동기적으로 지운다. 두 엔드포인트는 JSON 본문만 받는다(415 `json_only`). "그 브라우저에 묶인다" 는 성질은 그대로다.
- **zkIdP 로그인은 정책과 상관없이 언제나 패스키를 묻는다**(M4) — 지갑 창이 정책을 못 읽어 `code` 로 보게 돼도 보관분으로 증명을 내지 않는다. 서비스 로그인의 L4 는 그대로 `key` 정책에서만.
- 지갑 창은 IdP 오리진 대조를 통과한 뒤에만 "zkIdP 로그인" 제목과 주소 줄을 그린다(M5). zkIdP 페이지의 지갑 창 이름을 흐름마다 다르게 하고, 로그인 처리가 끝날 때까지 버튼을 잠근다(M8).
- §5 의 "연결 해제·계정 삭제에도 닿는다" 를 바로잡았다(M10), IdP 오리진 신뢰 범위를 적었다(M11).
- **고치지 않은 것**: 응답 시간으로 등록된 uid 를 가릴 수 있다(M6 — 비밀번호 로그인과 같은 데모 범위), 탭 둘이 서로의 챌린지를 지운다(M7 — 브라우저당 하나), 승인 창이 오리진 대조 전에 IdP 정책을 읽는다(M9 —
  서비스 로그인에만 남았다, 느린 IdP 에서 최대 3초). IdP 에서 연결이 풀린 계정의 지갑은 `key` 정책에서 인증 창의 안내 없이 발급 거절로 끝난다(화면 미확인).
