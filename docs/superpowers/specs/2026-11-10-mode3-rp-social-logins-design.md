# Mode 3 — RP 계정에 zkID·Google·네이버 로그인 연결 (설계, 2026-11-10)

- 상태: 사용자 승인(2026-11-10, 대화 중 결정 R1~R5 → 섹션 1·2·3 각각 "그래").
- 대체: `2026-11-09-mode3-linked-logins-design.md`(zkID 계정에 Google·네이버 연결, 45f3602). 사용자 지적 — "연결된 로그인은 RP 에서 지원해야 하는 기능" — 으로
  연결의 자리를 IdP 에서 RP 로 옮긴다. 11-09 의 IdP 쪽 연결은 걷어낸다(§5).
- 비범위: 다중 IdP, ZDS, Google 래퍼 계정(`provider:'google'`, `/user?google=1`·`/account`) 경로(그대로 둔다), 회로·컨트랙트(바꾸지 않는다), RP 간 계정 병합.

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| R1 | 연결된 로그인은 **RP 에 직접** 둔다 — RP 가 Google·네이버의 OIDC 클라이언트가 되고, RP 계정에 로그인 수단을 연결한다. | 사용자 선택("RP 에 직접 연결"). 그 로그인은 zk-Delegation 을 거치지 않는다(§6). |
| R2 | 11-09 의 zkID 쪽 연결(`/user` 연결 카드, 인증 창 `method=google\|naver`, 지갑 분기)은 **제거**한다. | 사용자 선택. 개념을 한 곳(RP)에만 둔다. |
| R3 | RP 도 **localhost 터널**로 연다 — 브라우저는 zkONE 을 `http://localhost:3100`, zkTWO 를 `http://localhost:3101` 로 연다. | Google 은 평문 http 원본으로 `localhost` 만 받는다(GIS·리다이렉트 둘 다). |
| R4 | 연결되지 않은 Google·네이버로 로그인하면 **새 RP 계정**을 만든다. 계정 하나에 로그인 수단 세 칸(zkID=PPID·Google·네이버)이 **대칭**이다 — 어느 것으로든 가입, 나머지는 "내 계정"에서 연결. 이미 다른 계정에 붙은 수단은 거부(병합 없음). | 사용자 선택("새 RP 계정 만들기", "세 칸 대칭"). |
| R5 | Google·네이버 세션도 **모든 기능**(입금·구매·출금)을 쓴다. 단 출금은 **거래소 보관 잔고**에서 — 소셜 세션에서 산 ETH 는 RP 장부에 쌓이고, 출금은 RP 릴레이어가 자기 돈으로 보내며 장부를 깎는다. PPID 스마트 계정의 출금은 지금처럼 zkID 세션(지갑 증명)만. | 사용자 선택("전부 허용" → "거래소 보관 잔고"). PPID 계정은 지갑의 zk 증명 없이 돈을 내보낼 수 없다(`Mode3Wallet`). 컨트랙트·회로는 바꾸지 않는다. |

## 2. 계정 모델과 저장 (RP 마다 — zkONE·zkTWO 각자)

- **RP 계정** `acct_<16 hex>`(RP 가 정한다):
  `{ id, createdAt, zkid: { PPID, linkedAt } | null, google: { sub, linkedAt } | null, naver: { sub, linkedAt } | null, attrCommit, attrSince, attrUpdatedAt, attrHistory }`.
- **색인**: `byPPID[PPID] → id`, `byGoogle[sub] → id`, `byNaver[sub] → id`. 수단 하나는 계정 하나에만(409 `method_linked_elsewhere`).
- **가입**: 처음 보는 수단으로 로그인하면 그 칸만 채운 계정을 만든다. zkID 로그인(기존 `/api/mode3/login` 성공)이면 `zkid` 칸.
- **연결**: 로그인한 계정의 빈 칸에만(이미 채워진 칸이면 409 `method_already_linked` — 먼저 해제). **해제**: 수단이 하나 이상 남을 때만(409 `last_method`).
- **장부(계정 번호 기준으로 바꾼다)**: `krw[id]`(bigint, 지금은 PPID 기준·메모리) · `custodyEth[id]`(wei, 새). 어느 수단으로 로그인해도 같은 KRW 가 보인다.
  ETH 는 둘: **내 계정(PPID 스마트 계정)** — 체인 잔액, zkID 세션에서만 출금 · **거래소 보관** — 장부 값.
- **속성 커밋먼트**: 지금처럼 zkID 로그인 때 ID 토큰 `name` 으로 받은 값을 고정한다 — 키만 PPID → 계정 번호.
- **파일**: `mode3_rp_accounts.json` version 2 `{ version:2, accounts, byPPID, byGoogle, byNaver, krw, custodyEth }`(값은 10진 문자열, 원자적 쓰기, 0600).
  version 1(`byPPID[PPID] = { attrCommit, since, updatedAt, history }`)은 기동 때 PPID 계정으로 옮긴다. 지금 메모리뿐인 KRW 장부는 이번에 파일로 옮긴다(재기동해도 남는다).

## 3. RP 서버 (`mode3_rp.js`)

### 3.1 설정
- `MODE3_RP_GOOGLE_CLIENT_ID` — 있으면 Google 버튼. 검증은 기존 `createOidcVerifier`(RS256, `MODE3_RP_GOOGLE_ISSUER`·`MODE3_RP_GOOGLE_JWKS_URL` 로 테스트 대체).
- `MODE3_RP_NAVER_CLIENT_ID`·`MODE3_RP_NAVER_CLIENT_SECRET`·`MODE3_RP_NAVER_REDIRECT_URI` — 셋 다 있어야 네이버 버튼. 테스트 대체 `MODE3_RP_NAVER_ISSUER`·`_JWKS_URL`·`_AUTHORIZE_URL`·`_TOKEN_URL`.
  PKCE·코드 교환·`state` 는 `lib/mode3_oidc_link.js`(`createOnceStore`·`pkcePair`·`naverAuthorizeUrl`·`exchangeNaverCode`) 를 그대로 쓴다. 비밀은 응답·로그에 싣지 않는다.
- 쿠키 세션: `express-session`(이미 의존성), **쿠키 이름은 RP 마다 다르게** `<RP 이름 소문자>.sid`(예 `zkone.sid`) — localhost 에서는 포트가 달라도 쿠키를 함께 쓰므로 같은 이름이면
  zkONE·zkTWO·IdP(:4100, `cia.sid`) 세션이 서로 덮어쓴다. `httpOnly`, `sameSite:'lax'`. `MODE3_RP_SESSION_SECRET`(없으면 기동마다 무작위).

### 3.2 엔드포인트 (모두 같은 오리진, JSON 본문은 `Content-Type: application/json` 만 받는다)
- `GET /api/rp/me` → `{ account: id, via: 'zkid'|'google'|'naver', methods: { zkid: { PPID, address, linkedAt }|null, google: { linkedAt }|null, naver: { linkedAt }|null }, attrCommit }` 또는 401.
  sub 은 싣지 않는다.
- `POST /api/rp/oidc/nonce { purpose: 'login'|'link' }` → `{ nonce }`(1회용, 5분; `link` 는 로그인 세션 필요).
- `POST /api/rp/google { id_token, purpose }` — nonce 를 꺼내 검증(`aud`=클라이언트 ID). `login`: 연결된 계정이면 그 계정, 아니면 새 계정 → 세션. `link`: 현재 계정에 붙인다.
- `GET /api/rp/naver/start?purpose=login|link` → 네이버(PKCE S256, `state`·`nonce`) → `GET /api/rp/naver/callback` → `/?social=ok&via=naver` 또는 `/?social_error=<사유>`
  (`link` 면 `/#account` 로). `link` 는 시작 때의 세션 계정과 콜백 때의 세션 계정이 같아야 한다.
- `POST /api/rp/unlink { method: 'zkid'|'google'|'naver' }`, `POST /api/rp/logout`(쿠키 세션을 끝낸다; zkID r_s 세션은 기존 `/api/mode3/logout`).
- `POST /api/rp/ledger { body }` — 쿠키 세션의 계정으로. 본문 문법은 세션키 서명 요청(`/api/mode3/request`)과 같다: `balance` · `deposit:<ms>` · `buy:<eth>:<ms>`, 그리고 쿠키 세션에만
  `withdraw:<0x주소>:<wei>:<ms>`. `buy` 는 KRW 를 깎고 `custodyEth` 에 더한다(체인 거래 없음). `withdraw` 는 `custodyEth` 에서 먼저 깎고 RP 릴레이어가 `to` 로 실제 ETH 를 보낸다
  (전송이 실패하면 되돌린다). 재생 방지는 지금처럼 `(계정, 본문)` 1회 + 시각 ±5분. 두 경로는 같은 장부 함수(`ledgerOp`)를 쓴다.
- **기존 `/api/mode3/login`**: 성공하면 쿠키 세션도 만든다(`via:'zkid'`). 본문 `link: true` 이고 쿠키 세션 계정의 `zkid` 칸이 비었으면 그 PPID 를 붙인다(PPID 가 이미 다른 계정이면 409
  `method_linked_elsewhere`, 로그인 세션도 만들지 않는다). 아니면 PPID 로 계정을 찾고 없으면 만든다.
- **기존 `/api/mode3/request`**(세션키 서명): 지금처럼. 장부 키만 PPID → 그 PPID 의 계정 번호. `buy` 는 지금처럼 PPID 계정으로 실제 ETH.
- 로그인 기록(`mode3_rp_logins.jsonl`)에 `via` 를 남긴다 — RP 관리자 페이지가 보인다.

## 4. RP 화면 (`rp.html`, `rp_admin.html`)

- 로그인 창: "zkID 로 로그인" 그대로(지갑 팝업). **Google**: 그 자리에 GIS 버튼(`/common/gsi.js` `Mode3Gsi.render`, nonce 는 `/api/rp/oidc/nonce`) → `POST /api/rp/google`.
  **네이버**: `/api/rp/naver/start?purpose=login` 으로 이동. 소셜 버튼은 지갑 팝업을 열지 않는다. 설정이 없으면 버튼에 "이 서비스에 설정되지 않음".
- 상단 바: 로그인 수단 배지(zkID·Google·네이버) + PPID 가 있으면 주소.
- 새 **"내 계정"** 패널(상단 메뉴 탭 — 거래소·내 자산 옆, 로그인했을 때만): 수단 세 줄 — 상태(연결됨·날짜 / 연결 안 됨) + 연결·해제. Google 연결은 GIS 버튼, 네이버 연결은 다녀오기, zkID 연결은 평소 zkID 로그인을 `link:true` 로.
  **RP 마다 따로다** — zkONE 에서 연결한 것은 zkTWO 에 아무 영향이 없다(zkTWO 에서 처음 쓰는 수단이면 zkTWO 에 새 계정). 각 RP 에서 로그인한 뒤 각자의 "내 계정" 에서 연결한다.
- 내 자산: KRW · ETH(내 계정 — PPID 가 있을 때) · ETH(거래소 보관). 입금·구매: zkID 세션이면 세션키 서명 요청(지금), 소셜 세션이면 `/api/rp/ledger`.
  출금에 **출금 출처** 선택 — "내 계정"(zkID 세션일 때만, 지금의 온체인 출금) · "거래소 보관"(늘). "로그인 상태(폐기 재확인)" 칸은 zkID 세션에서만.
- 로그인 상태 복원: 새로고침하면 `/api/rp/me` 로 쿠키 세션을 되살린다(zkID r_s 세션의 localStorage 복원은 지금처럼).
- `rp_admin.html`: 로그인 기록에 수단 열.

## 5. zkID 쪽 연결 제거 (45f3602 되돌리기)

- `cia.js`: 네이버 설정·`linkOnce`/`authOnce`·`/cia/oidc/nonce`·`/cia/user/link`·`/cia/user/unlink`·`/cia/oidc/naver/start|callback`·`/cia/auth/code` 의 `method=google|naver`
  (아이디·비밀번호만)·`public_keys.oidc.providers`·`/cia/user/me` 의 `linked`·래퍼 등록의 `oidc_linked_elsewhere` 검사를 지운다. 341702f 자동 연결 제거(아이디 계정 + `id_token` → 400
  `use_auth_window`)와 에이전트의 같은 검사는 **유지**한다.
- `lib/mode3_cia_state.js`: 계정의 `linked`(·옛 `linkedOidc`)는 기동 때 조용히 지운다(노트 하나).
- `lib/mode3_oidc_link.js`: RP 가 쓰는 공용 부분(`createOnceStore`·`pkcePair`·`naverAuthorizeUrl`·`exchangeNaverCode`·`NAVER_DEFAULTS`·`randomHex`)만 남기고 IdP 전용(`LINK_SLOTS`·`sanitizeAuthCtx`·접두사)은 지운다.
- 화면: `cia_login.html` 의 외부 인증 칸(`authExtRow`)·`method` 처리, `cia_user.html` 의 연결 카드, `wallet.html` 의 `method` 분기(RP 소셜 버튼은 더 이상 지갑을 거치지 않는다),
  `mode3/user/popup.js` 의 네이버 응답, `strings.js` 의 해당 키.
- 테스트: `tests/test_cia_linked_logins.mjs` 삭제(`run_tests.sh` 에서도), `test_mode3_oidc_link.mjs` 는 남는 함수만, `test_mode3_wallet_snap_oidc_browser.mjs` 의 11-09 세 케이스 삭제,
  `isolated_cia.mjs`·`isolated_mode3_stack.mjs` 의 `naver`·`uiHost`·`ciaHost` 옵션 정리(RP 쪽으로 옮김).
- IdP VM `role.env` 의 `MODE3_NAVER_*` 3줄을 지운다(키는 RP 로).

## 6. zk 보장을 우회하는 지점 (R1·R5 의 대가 — 데모에서 보일 대비)

- zkID 자격증명을 폐기해도 Google·네이버 로그인은 된다(같은 계정의 거래소 보관 잔고 출금 포함). PPID 계정 출금만 막힌다.
- zkTWO 의 국가·나이 요구(`MODE3_REQUIRE_DISCLOSURE`)는 Google·네이버 로그인에 적용되지 않는다.
- 두 RP 가 같은 Google 클라이언트·네이버 앱을 쓰면 `sub` 이 같다 → 두 RP 가 같은 사람임을 안다(zkID 로그인은 RP 마다 다른 PPID). Google·네이버는 사용자가 어느 RP 를 쓰는지 안다.
- 거래소 보관 잔고는 RP 를 믿어야 한다(수탁). PPID 계정은 자기 수탁 그대로.
- localhost 에서 쿠키는 포트로 격리되지 않는다 — 이름만 다르다. 한 RP 서버가 다른 RP·IdP 의 쿠키 값을 받을 수 있다(데모 한정).

## 7. 데모 (`scripts/demo_split_start.sh`, 런북)

- snap 모드 기본 `SPLIT_RP_TUNNEL=1`: 이 머신에 `-L 127.0.0.1:3100:127.0.0.1:3100 zkd@.11`, `-L 127.0.0.1:3101:127.0.0.1:3101 zkd@.12`(IdP 터널과 같은 방식·같은 정리).
  RP `MODE3_RP_PUBLIC_ORIGIN=http://localhost:3100|3101`, 지갑 에이전트 `MODE3_RP_ORIGIN` 도 그 주소. 0 이면 지금처럼 VM 주소(소셜 버튼 없음).
- RP 공개 주소가 바뀌면 RP 가 스스로 새로 등록한다(`mode3_rp.js` — origin 이 다르면 재등록) → IdP 에 새 승인 대기 항목이 생긴다. 옛 등록 파일은 `.bak-시각`.
- 키: Google 은 지금 IdP 에 넘기는 클라이언트 ID 를 RP 에도(`MODE3_RP_GOOGLE_CLIENT_ID`). 네이버 ID·Secret 은 환경변수 또는 이 머신 `.env` 의 `MODE3_NAVER_CLIENT_ID`·`_SECRET` 을 **RP `role.env` 에만**,
  콜백 `http://localhost:<port>/api/rp/naver/callback`. 진행 줄은 on/off 만.
- 사용자 설정: Google 콘솔 승인된 원본 `http://localhost:3100`·`http://localhost:3101` 추가. 네이버 앱 Callback URL `http://localhost:3100/api/rp/naver/callback`·`http://localhost:3101/api/rp/naver/callback` 추가.
- `docs/MODE3_DEMO.md`: 11-09 "zkID 계정에 Google·네이버 로그인 연결" 절을 이 설계로 바꾼다.

## 8. 테스트

- 새 chain 테스트 `tests/test_rp_social_logins.mjs`(격리 IdP·RP + 가짜 Google 발급자(`/mint`)·가짜 네이버(`oidc_issuer_stub.mjs`)): 소셜 첫 로그인 → 새 계정; zkID 로그인 계정에
  Google·네이버 연결; 소셜 계정에 zkID 연결(`link:true`); 다른 계정에 붙은 수단 409; 마지막 수단 해제 409; nonce 재사용·다른 aud 거절; 네이버 state 위조·세션 바뀜 거절;
  거래소 보관 구매·출금(실제 ETH 가 `to` 로, 부족하면 400); 장부 파일 재기동 뒤 유지; v1 계정 파일 이전; 쿠키 이름이 RP 마다 다름; `/api/rp/me` 에 sub 없음.
- 브라우저(`tests/test_mode3_wallet_snap_oidc_browser.mjs` 의 RP 케이스 교체): RP 로그인 창 Google(GIS 흉내) 로그인 → 내 계정에서 네이버 연결 → 자산에 거래소 보관 ETH·출금 출처 선택.
- 기존: IdP 쪽 연결 테스트 정리(§5), `test_cia_oidc_register`·`test_mode3_cia_state`(linked 제거 이전)·`test_mode3_demo_stack`(장부 키) 갱신. 새 테스트는 `run_tests.sh` 의 해당 그룹에 넣는다.

## 9. 남는 위험

- 실제 네이버가 `http://localhost` 콜백과 `client_secret`+`code_verifier` 동시 사용을 받는지 아직 확인하지 못했다(가짜 네이버로만 시험).
- 네이버 앱 하나에 콜백 주소 여러 개(3100·3101)를 등록할 수 있는지 미확인 — 안 되면 RP 마다 앱을 따로 만든다(그러면 §6 의 네이버 sub 연결성은 사라진다).
- 거래소 보관 출금은 RP 릴레이어 잔액에 달렸다(데모 체인의 기본 계정이라 충분하다).
