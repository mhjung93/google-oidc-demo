# Mode 3 — "패스키로 로그인" 이 계정을 스스로 만든다(Google 이메일) 설계

2026-11-20. 상태: 구현 중. 대상 모드: `passkey-web`(zkIdP 발급 정책 `key`).

## 0. 사용자 결정(2026-11-20)

- zkIdP `/user` 의 "패스키로 로그인" 을 누르면, 이 브라우저가 아직 zkIdP 계정에 연결돼 있지 않을 때 **새 계정을 바로 만든다**.
- 계정의 아이디는 **Google 로그인으로 확인한 이메일**이다("패스키 관리자가 구글이니까"). 패스키에는 이메일이 들어 있지 않고, 웹 페이지는 패스키가 어느 Google 계정에 저장됐는지 알 수 없다 — 그래서 가입할 때 Google 로그인을 한 번 거친다.
- 그 뒤의 로그인은 Google 을 다시 묻지 않는다(패스키 한 번 — 2026-11-19 증명 로그인 그대로).

## 1. 정한 것

| # | 내용 |
|---|---|
| G1 | uid 는 지금처럼 zkIdP 가 배정하는 순번(100001…)이다. Google 계정에서 계산하지 않는다(기존 래퍼 계정 `uid = H(google\|sub)` 와 다른 길 — 그쪽은 발급마다 Google 토큰을 요구한다). |
| G2 | 계정의 아이디(`loginId`)는 Google ID 토큰의 `email`(반드시 `email_verified: true`)이다. 비밀번호는 없다 — 이 계정은 패스키(증명 로그인)로만 들어간다. |
| G3 | 같은 Google 계정(`sub`)으로는 계정을 하나만 만든다. 같은 Google 계정 + **같은 패스키**(같은 auid)면 기존 계정으로 들어간다(복구). 같은 Google 계정 + 다른 패스키면 거절(`signup_other_passkey`). zkIdP 는 `sub` 의 해시와 이메일만 계정에 둔다. |
| G4 | Google 토큰은 "이 패스키의 이 등록 요청" 에만 쓸 수 있다 — 토큰의 nonce = `regNonce(tag)`, `tag = Poseidon(T_TAG, s_u, registerCtx(n))`(기존 Google 등록의 결속 그대로). 가로챈 토큰으로 다른 패스키를 등록하지 못한다. |
| G5 | 속성은 기본값(`DEFAULT_PROFILE` — 1990·KR)으로 등록한다. 속성 도구를 거치지 않는다(나중에 지갑 페이지에서 바꿀 수 있다). |
| G6 | 새 가입은 **패스키 한 번**이다. π_IdP 의 공개 입력에 uid 가 들어가므로, 지갑 창은 Google 로 가기 전에 uid 를 예약받아(`POST /cia/signup/reserve`) 등록 증명과 zkIdP 로그인 증명을 미리 만들어 둔다. Google 을 다녀오는 동안 창에 남는 것은 **공개값뿐**(uid·auid·n·tag·증명)이고 sessionStorage 에 둔다 — salt 는 어디에도 두지 않는다. |
| G7 | 복구(G3 의 같은 패스키)는 기존 uid 로 증명을 다시 만들어야 하므로 패스키를 한 번 더 묻는다. |
| G8 | Google 은 `*.zkd.test` 를 돌아올 주소로 받지 않는다 — 서비스의 Google 로그인과 같은 중계 주소(`https://127.0.0.1:<지갑 포트>/google-relay`)를 쓴다. 중계 화면은 지갑 오리진이 시작한 요청이면 지갑 창(`/?authorize=1`)으로 돌려보낸다. |
| G9 | 이 길은 zkIdP 가 `key` 정책이고 OIDC(Google) 클라이언트 ID 와 돌아올 주소(`MODE3_OIDC_REDIRECT_URI`)가 모두 있을 때만 열린다. 아니면 지금처럼 "등록 없음" 안내다. |

## 2. 흐름

1. `/user` "패스키로 로그인" → 로그인 챌린지 → 지갑 창(`mode3-idp-login`, nonce).
2. 지갑 창: 등록이 있으면 기존 증명 로그인. 없으면 —
   1. 연결된 패스키가 없으면 "패스키 만들기" 버튼(한 번 누른다).
   2. 패스키 → s_u → `POST /cia/signup/reserve` → uid.
   3. 난수 n, 등록 증명(`registerCtx(n)`), 로그인 증명(`loginCtx(nonce)`)을 만든다. Google nonce = `regNonce(tag)`.
   4. 공개값을 sessionStorage 에 두고 Google 로 이동(`response_type=id_token`, `scope=openid email`, `prompt=select_account`).
3. Google → 중계 → 지갑 창(`#google_back=1&state=…&id_token=…`).
4. 지갑 창: state 대조 → `POST /cia/register { signup: true, id_token, uid, auid, n, …증명 }`.
   - 201: 로컬 등록 저장 → 미리 만든 로그인 증명을 `/user` 페이지로 돌려준다 → `/cia/user/login_proof` → 로그인.
   - 409 `signup_exists { uid }`: 패스키를 한 번 더 → 그 uid 로 등록(복구) → 로그인 증명 → 로그인.
5. `/user` 페이지와의 연결(opener)이 끊겼거나 로그인 챌린지(360초 — zkIdP 페이지는 지갑 창을 300초 기다린다)가 지났으면 가입만 끝내고 "다시 눌러 주세요" 를 보인다(그때는 2 의 기존 증명 로그인이다).

## 3. zkIdP(cia.js)

- `GET /cia/public_keys` 의 `oidc.signup`: `{ authorizeUrl, redirectUri }` 또는 `null`(G9).
- `POST /cia/signup/reserve`(지갑 오리진 CORS): `{ uid }`. 예약은 메모리에만(10분, 최대 500개 — 넘으면 오래된 것부터 버린다). 인증이 없다 — 지금의 `/cia/signup`(아이디·비밀번호 가입)도 인증이 없다. 버려진 예약만큼 uid 번호가 건너뛴다.
- `POST /cia/register` 의 세 번째 길 `signup: true`: 토큰 검증(`reg:` nonce) → `email_verified` → 같은 `sub` 의 계정 찾기(G3) → 예약 확인 → `registerAccount`(π_IdP 검증 뒤 토큰 nonce 를 tag 에 대조 — G4) → 계정에 `loginId = email`, `signup = { provider, sub: sha256(provider|sub), email }`.
- 계정의 `provider` 는 `demo` 로 둔다 — 발급(`/cia/issue`)이 Google 토큰을 요구하지 않는 길이다. Google 로 확인했다는 사실은 `signup` 에 있다.
- 사유: `signup_disabled` 403 · `signup_email_unverified` 403 · `signup_exists` 409(본문에 uid) · `signup_other_passkey` 409 · `signup_reservation_invalid` 409 · 기존 `oidc_*`.

## 4. 범위 밖 · 남는 위험

- 가입에 쓴 Google 계정과 패스키가 저장된 Google 계정이 같은지는 확인하지 못한다(§0).
- 이 계정에는 비밀번호가 없어 `/user` 의 "연결 해제 · 계정 폐기"(비밀번호 확인)는 쓸 수 없다. 패스키를 잃으면 들어갈 길이 없다.
- 실제 Google 로는 확인하지 못했다(Google 콘솔의 승인된 리디렉션 URI 필요) — 테스트는 대역 발급자다. 지갑 창이 Google 을 다녀온 뒤에도 `/user` 페이지와 연결돼 있는지는 실제 Google 에서만 확인된다(끊기면 §2-5).
- 서비스 첫 로그인의 인증 창(아이디·비밀번호·auid)은 그대로 둔다 — `/user` 에서 먼저 가입하면 서비스 로그인은 패스키 한 번이다.
