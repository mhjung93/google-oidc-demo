# Mode 3 — 설치 없는 패스키 모드: 웹 모드(브라우저 증명) + 패스키 PRF salt, 네 서비스 HTTPS (설계, 2026-11-17)

- 상태: **초안 — 사용자 검토 대기.** 방향은 사용자 승인(2026-11-17 대화): 최종 목적은 "패스키 모드에서 스냅·에이전트를 완전히 빼고 아무 설치 없이 브라우저만으로",
  도메인 방식 **(가) HTTPS 도메인**, 이름은 **(a) `/etc/hosts`**(처음 한 번 sudo), **`libnss3-tools` 처음 한 번 설치 허용**, 사용자 페이지는 **호스트 PC 정적 서버**,
  salt 는 **금고에 10분 보관**, 등록·로그인 흐름은 **지금 스냅 데모에 맞춘다**, 구현은 **X(웹 모드 화면에 옮긴다)** — 설계 1부(구조) 승인, 범위(뺄 것 포함) 승인.
- 근거 조사(2026-11-17): 웹 모드는 지금 프로토콜에서 그대로 돈다 — `tests/test_mode3_user_core.mjs` 22/22, `tests/test_mode3_user_web.mjs` 17/17.
  zk 스냅 화면을 그대로 내주는 방안(Y)은 웹 코어에 증인 모드 라우트·외부 salt 등록·서버 릴레이어 대체 등이 없어 규모가 커서 택하지 않았다(조사 보고 요지는 §9).
- 관련: 에이전트 패스키 모드 스펙 `2026-11-17-mode3-passkey-mode-design.md`(유도식 P2·계정 복구 §10·10분 보관 §11), 웹 모드 스펙 2026-10-15(브라우저 전용 사용자 페이지).
- 비범위: 회로·zkey·컨트랙트, IdP 의 등록·발급·폐기 규칙(바꾸지 않는다 — HTTPS 기동과 허용 오리진 설정만), 스냅 모드·에이전트 패스키 모드(그대로), §8 의 후속.

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| W1 | 새 모드 이름은 **`passkey-web`** — 리셋 스크립트 `WALLET_MODE=passkey-web`, 정적 서버 설정 `secrets: 'passkey-web'`. `web`(금고 salt)·`passkey`(에이전트)·`snap` 은 그대로 둔다. | 기존 모드를 깨지 않는다. 서비스 페이지는 `passkey-web` 을 `web` 과 같은 팝업 프로토콜로 본다. |
| W2 | 사용자 페이지는 기존 웹 모드 앱(`mode3/user/` — `index.html`·`ui.js`·`popup.js`·`core/`)이다. 호스트 PC 의 **비밀 없는 정적 서버**(`mode3_user_static.js`)가 `https://wallet.zkd.test` 로 낸다. 에이전트·MetaMask 는 없다. | 실제 배포의 "지갑 사이트" 자리. IdP·서비스와 다른 운영자라는 신뢰 분리를 유지한다(IdP 가 사용자 페이지 코드를 내면 salt 를 빼낼 수 있다 — 기각). |
| W3 | **salt = 패스키 PRF**(에이전트 패스키 모드 P2 와 같은 식·같은 상수, `mode3/common/passkey_store.js` 의 `saltFromPrf`·`createPasskey`·`derivePrf` 재사용). RP ID 는 **`wallet.zkd.test`**. | 같은 패스키면 같은 salt·auid·PPID 다. 다만 RP ID 가 `localhost` 와 달라 **에이전트 패스키 모드의 패스키는 여기서 쓸 수 없다**(새로 만든다). |
| W4 | 금고(IndexedDB, 추출 불가 AES 키 — `vault.js` 자동 금고)에는 `blind_u`·세션 개인키를 지금처럼 둔다. **salt 는 10분 만료로만** 금고에 둔다(`passkeyHold: { s_u, until }` 암호문). 같은 오리진의 탭·팝업이 함께 쓴다. 지금의 영구 salt·시드(`seed`)·복구 코드(`zkd1.`)는 이 모드에서 쓰지 않는다. | 사용자 결정(금고 10분). 웹 모드는 재검증·세션 요청·출금도 팝업이 증명을 만들어 salt 가 자주 필요하다. 대가: 10분 동안 암호문이지만 브라우저 저장소에 salt 가 있다 — 에이전트 패스키 모드 P3("어디에도 저장 안 함")의 예외(오리진 격리·추출 불가 키가 경계). |
| W5 | 등록·로그인은 **지금 스냅 데모와 같다**: 발급 정책 `CIA_ISSUE_AUTH=code`(로그인마다 IdP 인증 창 — 아이디·비밀번호·auid), **첫 로그인 = 등록**(인증 창 등록 모드 → 속성 도구 기록의 salt 가 패스키 salt 와 같은지 auid 로 대조 → `/cia/register { code, … }`), 속성 변경은 속성 도구 기록에서. 웹 코어가 인증 코드(`auth_code`)를 발급·등록 요청에 싣게 바꾼다. | 사용자 결정 — 시연 순서(S0~S18)가 모드와 상관없이 같게. 지금 웹 코어는 `key` 정책 전제(코드를 보내지 않는다). |
| W6 | **계정 복구**(에이전트 패스키 모드 §10 P11~P15 와 같은 흐름)를 웹 화면에 옮긴다 — 패스키 연결 → 복구 카드(속성 → auid 보기 → IdP 인증 창 → 돌아와 등록 `restored`). 브라우저 저장소를 잃었거나 다른 PC 일 때. | IdP 는 같은 계정·같은 auid 재등록에 기존 슬롯을 돌려준다(바꾸지 않는다). |
| W7 | **세션 복구 카드는 두지 않는다.** | 웹 모드는 세션 키를 금고에 둬 "재시작으로 증인이 사라지는" 문제가 없다. 서비스의 "현재 세션이 만료됐습니다" 상단 바(`eeea513`)는 공통이라 그대로 동작한다. |
| W8 | 네 서비스를 **HTTPS** 로 띄운다 — `wallet.zkd.test`(호스트 PC), `idp.zkd.test`(.10), `zkone.zkd.test`(.11), `zktwo.zkd.test`(.12). 세 서버(`cia.js`·`mode3_rp.js`·`mode3_user_static.js`)는 `MODE3_TLS_CERT`·`MODE3_TLS_KEY`(PEM 경로)가 있으면 Node 내장 `https` 로 뜬다(없으면 지금처럼 http). | HTTPS 페이지(사용자 페이지)가 부르는 API 는 HTTPS 여야 한다(mixed content). 새 의존성 없음. |
| W9 | **체인 RPC 프록시**: 정적 서버가 같은 오리진에 읽기·쓰기 JSON-RPC 통로 `/rpc/app`(→ 응용 체인)·`/rpc/rev`(→ 폐기 체인)를 둔다. `/user/config` 의 `rpcUrl`·`revRpcUrl` 은 이 상대 경로. 허용 메서드는 웹 코어가 쓰는 `eth_*` 읽기·`eth_call`·`eth_chainId`·`net_version` 으로 한정하고 그 밖(`eth_sendTransaction`·`hardhat_*`·`evm_*`·`personal_*`)은 거절한다. | 웹 코어는 체인을 브라우저에서 직접 읽는데 hardhat 은 `http://` 라 HTTPS 페이지에서 막힌다. 거래는 서비스 릴레이가 보내므로 쓰기 메서드는 필요 없다. |
| W10 | **처음 한 번 준비 스크립트** `scripts/zkd_tls_setup.sh`(사용자가 직접 실행, sudo): `libnss3-tools` 설치 → `/etc/hosts` 에 네 이름 추가(이미 있으면 건너뜀, 표시 주석으로 묶음) → 데모 CA 생성(`.local/zkd-ca/`, openssl, 이미 있으면 재사용) → Chrome 저장소(`~/.pki/nssdb`)에 CA 등록(이미 있으면 건너뜀) → "Chrome 을 다시 시작하세요". | 사용자 결정. CA 를 재사용해 신뢰 등록은 한 번이다. CA 개인키는 `.local/` 에만(이미 ignore) — 저장소·응답에 출력하지 않는다. |
| W11 | **리셋마다**(`demo_split_start.sh` 의 `WALLET_MODE=passkey-web`): 그 CA 로 네 서버 인증서를 발급(SAN = 이름 + 그 머신 IP, 유효 30일)하고 VM 세 곳에 CA 공개 인증서와 함께 복사 → 각 서버를 `MODE3_TLS_*`·HTTPS 오리진으로 띄운다. 포트는 지금과 같다(4100·3100·3101·5100). **서버 간 호출**(서비스 → IdP 등)은 지금처럼 IP 로 가되 `https://<IP>:<port>` 이고, 모든 Node 프로세스에 `NODE_EXTRA_CA_CERTS=<CA 공개 인증서>` 를 준다(VM 의 `/etc/hosts` 는 건드리지 않는다 — IP SAN 이 있어서). CA 가 없으면 `BLOCKED: 먼저 bash scripts/zkd_tls_setup.sh` 로 멈춘다. | 사용자 결정(자동 발급). VM 의 IdP·RP 터널(127.0.0.1)은 이 모드에서 쓰지 않는다 — 브라우저가 이름으로 바로 간다. |
| W12 | 서비스 페이지(`mode3/rp.html`): `walletCfg.secrets === 'passkey-web'` 을 `web` 과 같게 본다(로그인·재검증·세션 요청·출금 모두 사용자 오리진의 팝업). | 웹 모드 프로토콜이 이미 있다. |

## 2. 흐름

1. **준비(처음 한 번)**: 사용자가 `bash scripts/zkd_tls_setup.sh` → Chrome 재시작.
2. **리셋**: `WALLET_MODE=passkey-web bash scripts/demo_split_start.sh` → 체인·Blockscout·IdP(https)·zkONE·zkTWO(https)·사용자 정적 서버(https) 기동. 끝에 주소 넷을 알린다.
3. **패스키 설정**(사용자 페이지 `https://wallet.zkd.test/`): 금고가 없으면 자동 금고를 만들고, 설정 카드에서 "패스키 만들기"(PRF 확인까지) 또는 "이미 있는 패스키 쓰기". credential ID 는 kv 에 공개값으로 둔다.
4. **속성 도구**: `https://wallet.zkd.test/attr.html`(같은 오리진 — 기록을 첫 등록이 읽는다). salt 는 사용자 페이지 "salt 보기"(패스키 또는 10분 보관분)에서 복사.
5. **첫 서비스 로그인 = 등록**: 서비스에서 "zkID 로 로그인" → 사용자 페이지 팝업 → (미등록) IdP 인증 창 등록 모드(아이디·비밀번호·auid) → 돌아와 패스키(또는 보관분)로 salt → 속성 도구 기록의 salt·auid 대조 → 코어가 등록·발급·로그인. 팝업 하나에 패스키 최대 한 번.
6. **이후 로그인·재검증·세션 요청·출금**: 팝업이 보관분 salt 를 쓰고, 10분이 지났으면 패스키를 한 번 묻고 다시 10분 보관.
7. **계정 복구**: 저장소를 잃으면 "이미 있는 패스키 쓰기" → 복구 카드(§1 W6).
8. **데모 리셋 신호**: 지금 웹 모드의 데모 세대(`MODE3_DEMO_GENERATION`) 규칙 그대로 — 사용자 페이지가 옛 등록·세션을 지운다. 패스키 연결(credential ID)은 남긴다.

## 3. 오류(사유 사전)
에이전트 패스키 모드의 `passkey_*` 사유를 그대로 쓴다(`passkey_wrong_origin` 의 안내 문구는 모드에 맞게 — 주소가 `https://wallet.zkd.test`). 새 사유:
`tls_setup_required`(스크립트 전용 안내 — 사전에는 넣지 않는다), `rpc_method_blocked`(프록시가 막은 메서드, 정적 서버 403).
나머지(인증 코드·등록·복구의 사유)는 스냅 데모에서 이미 쓰는 것을 쓴다(`register_auid_mismatch`·`already_registered`·`attr_record_missing`·`attr_record_salt_mismatch`·`bad_code` 등).

## 4. 바뀌는 곳(예상)
- `mode3/user/core/user_core.js`·`vault.js`: salt 공급원(패스키 콜백 + 10분 보관), 인증 코드 발급·등록 경로, 외부 salt 로 등록, 계정 복구, 영구 salt·시드·복구 코드 경로를 이 모드에서 끈다.
- `mode3/user/ui.js`·`popup.js`·`index.html`: 패스키 설정 카드, salt 보기, 첫 로그인 등록(IdP 인증 창 왕복 — 지금 zk 스냅 화면의 `goIdpAuth`·`takeIdpReturn` 방식), 계정 복구 카드.
- `mode3/common/passkey_store.js`: RP ID 를 하드코딩 `localhost` 에서 "페이지 호스트" 로(에이전트 패스키 모드는 여전히 localhost — 오리진 검사로 지킨다).
- `mode3_user_static.js`: `secrets` 설정값, HTTPS 기동, `/rpc/*` 프록시, `/attr.html`·`/attr/*` 서빙(지금 없으면).
- `cia.js`·`mode3_rp.js`: HTTPS 기동(env), 허용 오리진에 https 이름.
- `mode3/rp.html`: `passkey-web` = `web`.
- `scripts/zkd_tls_setup.sh`(새), `scripts/demo_split_start.sh`(새 모드), `scripts/build_user_app.mjs`(필요 시).
- `docs/MODE3_DEMO.md`·`docs/MODE3_DEMO_SCRIPT.md`.

## 5. 보안 메모
- 패스키 RP ID 는 `wallet.zkd.test` — 다른 이름(idp·zkone·zktwo)의 페이지는 이 패스키를 부를 수 없다(호스트가 다르고 서로의 상위 도메인이 아니다). `zkd.test` 를 RP ID 로 쓰지 않는다(그러면 모든 하위 이름이 부를 수 있다).
- 10분 보관분은 같은 오리진(`wallet.zkd.test`)의 페이지만 읽는다(IndexedDB 오리진 격리 + 추출 불가 키).
- 데모 CA 개인키(`.local/zkd-ca/`)가 새면 그 CA 를 신뢰하는 Chrome 에서 어떤 사이트도 위조할 수 있다 — 준비 스크립트가 이름 제약(Name Constraints: `zkd.test`)을 CA 에 넣어 `*.zkd.test` 밖에는 쓸 수 없게 한다.
- RPC 프록시는 허용 목록 밖 메서드를 막는다(W9) — 체인 계정 잠금 해제·블록 조작을 사용자 페이지가 부를 수 없다.

## 6. 테스트
- 단위: 금고 10분 보관(만료·다른 탭 공유·지움), RPC 프록시 허용 목록, 인증서 발급 스크립트의 SAN·이름 제약(openssl 로 확인).
- 코어(`tests/test_mode3_user_core.mjs` 확장 또는 새 파일, chain 그룹): 패스키 salt 공급원(콜백 대역)으로 첫 로그인 = 등록(코드 경로), 재로그인, 계정 복구 `restored`, 보관분 사용·만료.
- 브라우저(새 파일, browser 그룹): 정적 서버 + 결정적 WebAuthn 스텁(기존 `tests/helpers/webauthn_stub.js`) — 설정 → 첫 로그인 등록(IdP 인증 창) → 재검증·세션 요청이 보관분으로 패스키 없이 → 저장소 비우고 계정 복구 → 같은 PPID. 테스트는 HTTPS 대신 `localhost` 오리진으로 돈다(`wallet.zkd.test` 대역 — RP ID 가 페이지 호스트를 따르므로 코드 경로는 같다).
- 회귀: 기존 `web` 모드 테스트(코어 22, 브라우저 17), 스냅·에이전트 패스키 모드 브라우저 테스트.
- 수동(사용자): 준비 스크립트·HTTPS·hosts·VM 배포는 자동 테스트가 못 덮는다 — 첫 데모에서 확인.

## 7. 미검증 위험
- VM 세 곳에서 Node `https` 기동·인증서 복사·오리진 설정이 처음 한 번에 맞을지(분리 데모는 실제 VM 으로만 확인된다).
- 준비 스크립트의 `apt`·`/etc/hosts`·`certutil` 단계는 이 머신(Ubuntu 20.04)에서만 확인한다.
- 증명이 브라우저에서 돌아 느리다(웹 모드 2026-10 측정치 기준 — 로그인 수 초). zkey 내려받기(수백 MB)는 첫 접속 때 한 번.

## 8. 후속(이 스펙 밖)
- Race (2) 시연·거울 상한(`evm_mine`·에이전트 릴레이어 필요), 사용자 페이지의 "보내기"(에이전트 릴레이어), Google·네이버 로그인(승인 오리진), 한 머신 스크립트(`demo_web_reset.sh`)의 `passkey-web`.
- 공인 인증서·실제 도메인(데모 CA 대신).

## 9. 조사 요지(Y 를 택하지 않은 이유)
zk 스냅 화면이 passkey 모드에서 부르는 에이전트 라우트 중 웹 코어에 없거나 의미가 다른 것: `/wallet/register {uid, code, s_u, profile}`(코드·외부 salt 없음), `/wallet/session/witness`(증인 개념 없음), `/wallet/passkey/*` 전부,
`/wallet/session/revoke` 의 상한·대기분, 서버 릴레이어를 쓰는 `/wallet/tx`·`/wallet/bounds/apply`, Race 의 `/wallet/demo/mine`. 화면의 `/wallet/*` 요청을 가로채는 층(400~700줄)과 코어 수정(300~500줄)이 함께 필요해 규모가 크다.
웹 화면(X)은 이미 코어를 직접 부르고 서비스 페이지의 웹 팝업 프로토콜(재검증·세션 요청·출금 릴레이)이 있어 중간 규모다.
