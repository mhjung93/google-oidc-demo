# Mode 3 IdP 페이지 — 가입·커밋먼트 등록·RP 등록·인증 창 (설계)

작성 2026-10-22. 브랜치 `feat/mode3-v11` e03729c 이후(미커밋 작업 포함). Snap 모드 기준이며 web 모드(브라우저 전용 사용자 페이지)는 손대지 않는다(2026-10-22 사용자 결정: web 모드 개발 일시 중지).

## 0. 한 줄 요약

사용자가 찾아가는 입구를 "사용자 페이지"(지갑)에서 **IdP 페이지**로 옮긴다. 사용자는 IdP 사용자 페이지에서 계정을 만들고 지갑을 불러 커밋먼트를 등록하며, RP 운영자는 IdP RP 페이지에서 RP 계정을 만들고 RP를 등록한다. 로그인(delegated authentication) 때는 지갑 팝업이 **IdP 인증 창**을 열어 사용자가 uid·비밀번호·auid 를 넣고, IdP 가 낸 1회용 인증 코드를 발급 요청에 싣는다. 프로토콜·회로·컨트랙트·Snap 의 비밀 생성은 바뀌지 않고, IdP 가 받는 것은 지금처럼 auid·공개키·커밋먼트·증명뿐이다.

## 1. 결정 (2026-10-22 대화)

| # | 결정 | 근거 |
|---|---|---|
| D1 | 속성은 지갑 안에만 둔다. IdP 에는 커밋먼트만 간다 | 사용자 요구. 지금 흐름(등록: auid·pk_u·sig_reg, 발급: C_u·π_IdP)과 같다 |
| D2 | 한 브라우저에서 사용자를 바꿀 때는 "Snap 초기화" | Snap 다중 계정은 Snap·동의 창까지 바뀌는 큰 작업 |
| D3 | 새 RP 서버는 **명령 한 줄**로 사람이 띄운다(실행기 없음) | IdP 가 RP 서버를 띄우는 그림이 어색하다 |
| D4 | IdP 인증 창은 **지갑 팝업이** 연다(RP 가 아니라) | RP 가 IdP 로 리디렉션하면 IdP 가 RP 를 알게 된다(RP-hiding 전제) |
| D5 | 인증 창은 uid·비밀번호·**auid(사용자가 붙여 넣음)** 세 칸 | 사용자 요구. 지갑 페이지가 auid·salt 를 복사 버튼과 함께 보인다 |
| D6 | 사용자·RP 는 요청받으면 얼마든지 새로 만들 수 있어야 한다 | 하드코딩 데모 계정(12345/67890)과 고정 RP 둘(zkONE/zkTWO)에서 벗어난다 |

## 2. 역할·페이지 지도

| 누가 | 어디서 | 무엇을 |
|---|---|---|
| 사용자 | IdP `/user` (새) | 가입(uid 는 IdP 가 배정), 로그인, **커밋먼트 등록**(지갑 팝업), 내 등록 상태(auid·슬롯·등록부), 계정 폐기(지금 `/account` 기능) |
| 사용자 | 지갑 `http://localhost:5100` (제목 "지갑") | 속성(내 신원)·세션·트랜잭션 관리, **auid·salt 확인·복사**, Snap 초기화. 사용자가 직접 찾아가는 입구가 아니라 팝업·관리 창 |
| 사용자 | IdP `/login` (새, 인증 창) | RP 로그인(발급) 때 지갑 팝업이 연다. uid·비밀번호·auid 입력 → 1회용 코드 |
| RP 운영자 | IdP `/rp` (새) | 운영자 가입·로그인, **새 RP 만들기**(이름 → RP 키 + 실행 명령), 내 RP 목록·상태 |
| RP 운영자 | 터미널 | `scripts/new_rp.sh` 로 RP 서버 기동(이 VM 또는 RP VM 에 ssh) |
| IdP 관리자 | IdP `/admin` (기존) | RP 승인, 폐기, 개봉 승인 — 그대로 |
| RP 운영자 | RP `/admin` (기존) | 로그인 기록·거래 기록·개봉 — 그대로 |

## 3. IdP 서버 (`cia.js`)

### 3.1 계정

- `state.accounts[uid]` 에 `pwSalt`(16B hex)·`pwHash`(= SHA-256(pwSalt ‖ pwd) hex)·`createdAt` 을 더한다. 가입만 하고 등록 전인 계정은 `pk_u: null, auid: null, slot: null`(등록은 `registerAccount` 가 채운다 — 지금은 계정 생성과 등록이 한 번에 일어나므로 "등록 전 계정"이 새로 생기는 상태다).
- uid 배정: `POST /cia/signup` 이 `nextUid`(상태에 저장, 시작 100001)를 준다. 사용자가 고르지 않는다.
- 데모 시드(`DEMO_ACCOUNTS` testuser/12345·alice/67890)는 `CIA_DEMO_ACCOUNTS=1` 일 때만 기동 때 상태에 넣는다(비밀번호는 해시로). 테스트 도우미(`tests/helpers/isolated_cia.mjs`)는 `'1'` 로 고정하고, 데모 리셋 스크립트 네 개는 넣지 않는다 → 데모에서는 가입으로만 계정이 생긴다.
- `/cia/register` 의 데모 경로는 `{uid, pwd}` 또는 `{uid, code}`(§3.3 의 purpose `register` 코드)를 받는다. pwd 경로는 API·테스트 호환으로 남긴다. 상태의 `pwHash` 로 검사한다(시드도 같은 경로).

### 3.2 세션

- `express-session`(이미 의존성) 메모리 저장소. 쿠키 `cia.sid`, `httpOnly`, `sameSite: lax`, 비밀은 `CIA_SESSION_SECRET` 또는 기동 때 난수(재기동하면 로그인이 풀린다 — 데모 수용).
- 세션 종류 둘: 사용자(`req.session.uid`)와 RP 운영자(`req.session.opId`). 같은 브라우저에서 둘 다 가질 수 있다(시연 때 한 브라우저로 두 역할을 오간다).

### 3.3 엔드포인트 (모두 같은 오리진, CORS 없음. 인증 창의 postMessage 만 지갑 오리진으로 나간다)

| 경로 | 본문 → 응답 | 비고 |
|---|---|---|
| `POST /cia/signup` | `{pwd}` → 201 `{uid}` | pwd 8자 이상. uid 는 `nextUid++` |
| `POST /cia/user/login` | `{uid, pwd}` → 200 `{uid}`; 401 `invalid credentials` | 세션 설정 |
| `POST /cia/user/logout` | → 200 | |
| `GET /cia/user/me` | → `{uid, registered, auid, slot, provider, disabled, registryLeaf, activeCf_u}` | 세션 필요(401). 등록 전이면 `registered:false, auid:null` |
| `POST /cia/user/register_code` | → 200 `{code, expiresAt}` | 세션 필요. 계정이 등록 전이어야 한다(409 `already_registered`). purpose `register` 코드 |
| `POST /cia/auth/code` | `{uid, pwd, auid}` → 200 `{code, expiresAt}` | 인증 창이 부른다. pwd 검사 + 계정이 등록돼 있고 `auid` 가 계정의 auid 와 같아야 한다(아니면 403 `auid_mismatch`). purpose `issue` 코드. 세션 없이도 된다(지갑이 연 새 창) |
| (코드 저장소) | | 코드는 32B hex, 5분, 1회용, `{uid, purpose, auid}` 에 묶임. 쓰면 소진 |
| `POST /cia/register` | 기존 + `{uid, code, auid, pk_u, sig_reg}` | `code` 는 purpose `register`·같은 uid 여야 한다(401 `bad_code`). 성공 시 코드 소진 |
| `POST /cia/issue` | 기존 + `auth_code` | **정책 `CIA_ISSUE_AUTH`**: `key`(기본, 지금처럼 sig_u 만) 또는 `code`(데모 스크립트). `code` 면 provider `demo` 계정은 `auth_code` 가 purpose `issue`·같은 uid·같은 auid 여야 한다(401 `auth_code_required` / `bad_code`). 래퍼(Google) 계정은 지금처럼 `id_token` |
| `POST /cia/rp/signup` | `{id, pwd}` → 201 `{id}` | 운영자 계정 `state.operators[id]`(pwSalt·pwHash·createdAt). id 는 `[a-z0-9_-]{3,32}` |
| `POST /cia/rp/login`·`/logout` | `{id, pwd}` | 세션 `opId` |
| `GET /cia/rp/me` | → `{id, rps:[{name, key, status, origin, arid, requestedAt}]}` | 세션 필요. `key` 는 아직 등록 요청이 오지 않은 RP 에만 보인다 |
| `POST /cia/rp/create` | `{name}` → 201 `{name, key, command}` | `state.rpSlots[key] = {opId, name, status:'created', createdAt}`. name 은 `^zk[A-Za-z0-9]{1,15}$`(페이지 브랜드 규칙), 운영자 안에서 유일. `command` 는 §6 의 한 줄(IdP 는 호스트·포트를 모르므로 자리표시 `<port>` `<host>` 를 둔 문자열) |
| `POST /cia/register_rp` | 기존 + `rp_key?` | 키가 있으면 `rpSlots[key]` 가 `created` 이고 `name` 이 같아야 한다(400 `bad_rp_key`); 등록을 `state.rps[arid].operator = opId`, slot → `status:'pending', arid`. 키 없는 등록(zkONE·zkTWO 의 기동 자동 등록)은 지금처럼 허용하고 운영자 없음으로 둔다 |
| `GET /cia/rp_origins` | → `{origins:[...]}` | **공개**. 승인된(active) RP 의 origin 목록 — 지갑 에이전트의 동적 허용 목록(§5.4). IdP 가 어차피 아는 공개 정보 |

관리자 승인(`/cia/rps/:arid/approve`)은 그대로. 관리자 페이지의 RP 표에 `operator` 열을 더한다.

### 3.4 페이지

- `/user` → `mode3/cia_user.html`(새). `/account` 는 `/user` 로 302(기존 링크·테스트는 `/user` 로 바꾼다).
- `/rp` → `mode3/cia_rp.html`(새).
- `/login` → `mode3/cia_login.html`(새, 인증 창). 쿼리 `nonce=<hex>&wallet=<origin>`(발급 전용).
- 셋 다 `/common` 레이어(문구·데모 바)를 쓴다. `/login` 은 데모 바 없이 좁은 창.

## 4. 인증 창 프로토콜 (지갑 팝업 ↔ IdP `/login`)

```
RP 페이지 ──mode3-authorize──▶ 지갑 팝업(localhost:5100/?authorize=1)
                                │ 승인 버튼 → window.open(`${ciaUrl}/login?nonce=N&wallet=${location.origin}`)
                                │                      사용자: uid·비밀번호·auid 입력 → POST /cia/auth/code
                                ◀── postMessage({type:'mode3-idp-auth', nonce:N, code}) ── IdP 창(닫힘)
                                │ POST /wallet/login { …, auth_code: code }  → 에이전트 → POST /cia/issue { …, auth_code }
                                ▼ 증명·서명 → mode3-authorize-result ──▶ RP
```

- IdP 창은 `targetOrigin` 을 **설정값 `MODE3_WALLET_AGENT_ORIGIN` 하나**로만 보낸다(쿼리의 `wallet` 과 같아야 열린다 — 다른 오리진이 열면 "지갑 오리진이 아니다" 로 멈춘다). 코드는 등록 비밀(sk_u 서명·π_IdP)이 없으면 쓸모없으므로 유출 영향은 발급 1회 시도에 그친다.
- `nonce` 는 팝업이 만들고 응답에서 대조한다(다른 창의 응답 무시).
- 창을 닫거나 60초 안에 응답이 없으면 팝업은 `idp_auth_cancelled` 로 RP 에 실패를 돌려준다.
- Google(래퍼) 계정: `/login` 이 IdP 의 `public_keys.oidc` 가 켜져 있으면 Google 버튼을 함께 보인다. nonce 는 지금처럼 `issue:`/`reg:` 규칙(팝업이 쿼리로 넘긴 `gnonce`)이고, 응답은 `{id_token}` — 팝업은 지금과 같이 `id_token` 으로 발급한다. 지금 팝업 안의 GIS 슬롯은 제거한다. Google 은 `localhost` 오리진만 받으므로 분리 구성(IdP 가 192.168.226.10)에서는 Google 버튼이 뜨지 않는다(한계, 런북).
- IdP 세션 단축("이 계정으로 계속")은 **넣지 않는다**(사용자가 입력 장면을 원한다). 뒤에 옵션으로 더할 수 있다.

## 5. 지갑 (에이전트 `mode3_wallet_agent.js`, `mode3/wallet.html`, Snap)

### 5.1 이름
- `wallet.html` 제목·헤더: "사용자 페이지" → "지갑". 체험 모드·안내 바에서 지갑을 가리키는 문구는 "지갑 페이지".

### 5.2 auid·salt 확인
- 내 신원 카드에 `auid`·`salt(s_u)` 를 전체 값·복사 버튼(⧉)과 함께 보인다. salt 는 "비밀 — 시연용 표시, 어디에도 보내지 마세요" 라벨. Snap 모드에서는 Snap 의 등록 조회(`mode3_get_registration`, 이미 uid·s_u 를 돌려준다)로 읽는다.

### 5.3 커밋먼트 등록 (IdP 페이지 → 지갑 팝업)
- IdP 사용자 페이지가 세션으로 `POST /cia/user/register_code` 를 받아 지갑 팝업을 연다(지갑 오리진은 IdP `/mode3/health` 의 `walletOrigin`). 팝업 요청 종류 `mode3-register { uid, code, ciaUrl }` 추가(허용 발신 오리진: **IdP 오리진**(`MODE3_CIA_URL`) — RP 오리진이 아니다).
- 팝업: 요약(IdP 주소·uid) → 승인 버튼 → Snap `mode3_register({ uid })`: **대화상자는 확인 하나**("IdP X 에 uid N 으로 등록합니다. 속성은 지갑에만 남습니다." + 기본 속성 표시). uid·비밀번호 프롬프트는 없앤다 → 에이전트 `POST /wallet/register { uid, code, s_u, sk_u, profile? }` → IdP `/cia/register { uid, code, auid, pk_u, sig_reg }` → 결과를 IdP 페이지에 `mode3-register-result` 로 돌려준다.
- 속성: 등록 때는 기본값(KR·1990), 바꾸려면 지갑 페이지 "내 신원"(지금과 같다 — 다음 로그인이 새 C_u). IdP 는 속성을 받지 않는다(D1).
- Snap 번들 재빌드 필요(`mode3_register` 의 프롬프트 제거·uid 인자). 체크섬이 바뀌므로 MetaMask Flask 에서 Snap 재설치.

### 5.4 RP 허용 목록(동적)
- 에이전트의 RP 오리진 목록 = 기동 env `MODE3_RP_ORIGIN` ∪ IdP `GET /cia/rp_origins`(10초마다, 실패하면 마지막 값 유지). CORS(`loginCors`·health)·`isRpOrigin` 이 이 합집합을 본다. 새 RP 가 승인되면 **재기동 없이** 로그인된다.

### 5.5 로그인(발급)에 인증 코드
- 팝업 `mode3-authorize` 처리: 승인 뒤 §4 의 IdP 창을 열고 `auth_code` 를 받아 `POST /wallet/login { …, auth_code }`. 에이전트는 `/cia/issue` 본문에 `auth_code` 를 그대로 싣는다. 재검증(캐시 π)·세션 요청·트랜잭션은 발급이 없으므로 창을 열지 않는다.

## 6. RP 서버·기동 명령

- `mode3_rp.js`: env `MODE3_RP_KEY` 가 있으면 `/cia/register_rp` 본문에 `rp_key` 를 싣는다. 그 밖은 그대로.
- `scripts/new_rp.sh NAME PORT KEY [--host IP] [--relayer N] [--countries 410,392] [--min-age 19] [--require-disclosure]`:
  - 로컬(한 머신 데모): `$LOGS/demo_env.txt`(demo_web_reset.sh 가 쓴 로그·거울 주소)와 같은 공통 env 로 `node mode3_rp.js` 를 띄운다. 등록 파일·로그인 로그는 `mode3_rp_<name>_registration.json` / `mode3_rp_<name>_logins.jsonl`(`.gitignore` 에 `mode3_rp_*` 추가).
  - `--host` 가 있으면(분리 데모) 그 VM 의 `~/zkd-demo/role.env`(rp1 의 것) 위에 이름·포트·공개 오리진·릴레이어 인덱스·키를 덮어 `~/zkd-demo/rp_<name>.env` 로 쓰고 ssh 로 띄운다(기동·중지는 지금 분리 스크립트와 같은 `{ … & }` 형식).
  - 릴레이어 인덱스는 기본 `3 + 기존 RP 수`(0·1 은 zkONE·zkTWO, 2 는 Snap 모드 에이전트). 겹치면 nonce 충돌로 배포가 실패하므로 사람이 지정할 수도 있다.
  - IdP RP 페이지가 보여 주는 `command` 는 이 스크립트 한 줄이다(호스트·포트는 자리표시).

## 7. 체험 모드·문구

- 단계(`strings.js` steps): `rp_create`(IdP RP 페이지 "새 RP 만들기", 새) → `approve`(관리자) → `register`(**IdP 사용자 페이지** 가입·커밋먼트 등록, where `idp_user`) → `login` → `login2` → `use` → `disclose` → `revoke`(지갑·`idp_user`·관리자) → `open`. 페이지 id `idp_user`·`idp_rp` 를 `demo.js` 의 페이지 집합과 `tests/test_mode3_demo_strings.js` 의 `TOUR_PAGES` 에 더한다. `account` 페이지 id 는 `idp_user` 로 바뀐다.
- 사유 사전(새): `bad_code`, `auth_code_required`, `auid_mismatch`, `idp_auth_cancelled`, `bad_rp_key`, `signup_failed`, `operator_login_failed`.
- 상태 패널(`Demo.stack`): IdP 페이지들은 `self:'aa'`.

## 8. 리셋 스크립트·런북

- 네 스크립트: `CIA_ISSUE_AUTH=code`, `CIA_DEMO_ACCOUNTS` 미설정(시드 없음). zkONE·zkTWO 는 지금처럼 자동 등록(키 없음, 운영자 없음) — 시연에서 "요청받아 만드는 RP" 는 zkTHREE 를 RP 페이지에서 만든다.
- 시연 순서(런북): ① RP 페이지에서 운영자 가입·"새 RP 만들기(zkTHREE)" → 명령 복사 → 터미널에서 `new_rp.sh` ② 관리자 승인 ③ 사용자 페이지에서 가입 → "커밋먼트 등록"(지갑 팝업·Snap 확인) ④ 지갑 페이지에서 auid 복사 ⑤ zkONE 로그인 → 지갑 팝업 → IdP 인증 창(uid·비밀번호·auid) → 승인 → 성공 ⑥ 이후 단계는 지금과 같다.
- Snap 초기화: 사용자 전환·리셋 뒤.

## 9. 테스트

| 묶음 | 파일 | 내용 |
|---|---|---|
| chain | `tests/test_cia_accounts.mjs`(새) | signup(uid 배정·pwd 길이), user login/me/logout, register_code(세션·등록 뒤 409), auth/code(auid 불일치 403, 재사용 401, 만료), register with code, issue 정책 `code`(코드 없음 401·맞는 코드 200·다른 auid 401), rp signup/login/create(키·이름 규칙), register_rp with key(운영자 연결·bad_rp_key), rp_origins(승인 전 비어 있음·승인 뒤 포함), 시드 플래그 |
| chain | `tests/test_mode3_wallet_agent.mjs` | 동적 RP 허용 목록(IdP 에 승인된 새 오리진 → 10초 안에 CORS 허용), `/wallet/login` 의 `auth_code` 전달, `/wallet/register` 의 `code` 경로 |
| browser | `tests/test_mode3_browser.mjs` | IdP 사용자 페이지 가입 → 커밋먼트 등록(팝업 → Snap 시뮬 확인 → 등록됨) → 지갑 페이지 auid·salt 표시·복사 → RP 로그인 때 IdP 인증 창(uid·pwd·auid 입력) → 성공; auid 틀리면 `auid_mismatch`; RP 페이지에서 운영자 가입·RP 만들기 → 명령 문자열에 키 포함 |
| browser | `tests/test_mode3_tour.mjs`, `tests/test_mode3_demo_strings.js` | 새 단계·페이지 id |
| snap | `snap-mode3/test/rpc.test.mjs` | `mode3_register({uid})` 가 프롬프트 없이 확인 하나로 등록하고 비밀을 저장 |
| chain | `tests/test_mode3_rp.mjs` | `MODE3_RP_KEY` 전달 |

기존 테스트의 데모 계정(12345·67890)은 도우미가 시드를 켜므로 그대로 돈다. 발급 정책은 테스트 기본 `key` 라 기존 발급 테스트는 바뀌지 않는다.

## 10. 비목표·한계

- web 모드(`mode3/user`, `mode3_user_static.js`)는 손대지 않는다 — web 모드로 돌아갈 때 §4·§5.3 을 옮겨야 한다(사용자 코어에 `auth_code`·`mode3-register`).
- Snap 다중 계정 없음(D2). IdP 세션 단축 없음(§4). 비밀번호 해시는 데모 수준(SHA-256+salt, KDF 아님).
- 인증 창은 지갑이 열지만, 악의적 페이지가 같은 URL 을 열어 사용자가 비밀번호를 넣게 할 수는 있다(피싱) — 코드만으로는 발급이 안 되므로 영향은 제한적이며 런북에 적는다.
- Google 인증은 IdP 가 `localhost` 로 열릴 때만(분리 구성에서는 비활성).
- RP 서버 기동은 사람이 한다(D3). IdP 는 RP 의 호스트·포트를 모른다 — 등록 요청이 와야 origin 을 안다.

## 11. 수용 기준

1. 리셋 직후 IdP 에 계정이 없고, `/user` 가입만으로 계정이 생기며 uid 가 배정된다.
2. 커밋먼트 등록이 IdP 페이지에서 시작돼 지갑 팝업·Snap 확인을 거쳐 끝나고, IdP 는 auid·pk_u·sig_reg 외에 아무것도 받지 않는다(요청 본문 검사 테스트).
3. zkONE 로그인 때 IdP 인증 창이 뜨고, uid·비밀번호·auid 가 맞을 때만 발급된다. auid 가 틀리면 RP 페이지에 `auid_mismatch` 가 보인다.
4. RP 페이지에서 만든 zkTHREE 를 `new_rp.sh` 로 띄우고 관리자가 승인하면, 지갑 에이전트를 다시 띄우지 않고 zkTHREE 에 로그인된다.
5. 지갑 페이지에서 auid·salt 를 복사할 수 있고, 제목이 "지갑"이다.
6. 분리 Snap 데모(`demo_split_snap_reset.sh`)와 한 머신 Snap 데모(`demo_snap_reset.sh`)가 위 순서로 끝까지 돈다. 기존 테스트 묶음(unit·chain·browser·snap)이 통과한다.
