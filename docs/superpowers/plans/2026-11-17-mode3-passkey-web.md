# Mode 3 설치 없는 패스키 모드(passkey-web) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 스냅·에이전트·MetaMask 없이 브라우저만으로 도는 네 번째 지갑 모드 `passkey-web` 을 더한다 — 웹 모드 사용자 페이지(`mode3/user/`)가 salt 를 패스키 PRF 로 만들어 금고에 10분만 두고, 등록·로그인은 스냅 데모와 같은 IdP 인증 창(`CIA_ISSUE_AUTH=code`)을 거치며, 분리 데모는 네 서비스를 데모 CA 의 HTTPS 이름(`*.zkd.test`)으로 띄운다.

**Architecture:** 웹 코어(`user_core.js`)에 "salt 공급원" 하나를 끼운다 — `passkey-web` 이면 금고의 영구 `s_u` 대신 `vault` 의 10분 보관분 → 없으면 주입된 `passkey.derive()` 를 쓰고, 인증 코드 등록(`registerWithCode`)·발급 코드(`auth_code`)를 싣는다. 팝업은 스냅 데모의 `goIdpAuth`/`takeIdpReturn` 왕복을 새 모듈(`mode3/user/idp_return.js`)로 옮겨 쓰고, 정적 서버는 같은 오리진의 허용 목록 JSON-RPC 프록시(`/rpc/app`·`/rpc/rev`)와 속성 도구를 낸다. 세 서버는 `MODE3_TLS_CERT`·`MODE3_TLS_KEY` 가 있으면 Node 내장 `https` 로 뜬다.

**Tech Stack:** Node 22 · Express · esbuild 번들(`mode3/user/dist`) · 전역 스크립트(`mode3/common/passkey_store.js`) · WebAuthn PRF · IndexedDB(추출 불가 AES-GCM 키) · Playwright(설치된 Chrome) · hardhat :8545 · openssl·certutil(bash 스크립트)

**Spec:** `docs/superpowers/specs/2026-11-17-mode3-passkey-web-design.md` (W1–W12). 패턴 원본: `docs/superpowers/plans/2026-11-17-mode3-passkey-mode.md`, `docs/superpowers/plans/2026-11-17-mode3-passkey-recovery.md`.

## Global Constraints

- 커밋·브랜치 작업은 **사용자 승인 뒤**(CLAUDE.md). 각 Task 의 Commit 단계는 승인을 받고 한다. `git add` 는 경로 지정만(`sui-repo/` 금지).
- 새 의존성 금지(TLS 는 `node:https`, 인증서는 시스템 `openssl`·`certutil`). 회로·zkey·wasm·컨트랙트 재빌드 금지(`npm run zk:*` 금지). IdP 의 등록·발급·폐기 규칙은 바꾸지 않는다 — `cia.js` 는 TLS 기동만.
- 기존 모드 불변: `snap`, 에이전트 `passkey`, `web` 의 기존 테스트가 그대로 통과해야 한다 — 특히 `tests/test_mode3_user_core.mjs`(22), `tests/test_mode3_user_web.mjs`(17), `tests/test_mode3_passkey_browser.mjs`, `tests/test_mode3_browser.mjs`, `tests/test_mode3_wallet_passkey.mjs`.
- 모드 이름은 철자 그대로 `passkey-web`(W1). 정적 서버 env 는 `MODE3_WALLET_SECRETS=passkey-web`(기본 `web`), 리셋 스크립트는 `WALLET_MODE=passkey-web`.
- salt 유도식은 에이전트 패스키 모드와 같다(`saltFromPrf`, PRF 입력 `zkd-s_u-v1`, 도메인 `zkd-passkey-s_u-v1`) — 바꾸지 않는다(W3).
- **salt(`s_u`)는 영구 저장소에 쓰지 않는다**: 금고 `secrets.s_u`·`seed` 는 `passkey-web` 에서 늘 `null`. 예외는 금고의 10분 보관분 `passkeyHold` 하나(암호문, W4). `localStorage`·`sessionStorage`·IdP 대기 저장분(`mode3.authorize.pending`)·복구 결과 키(`mode3_recover_result`)·로그·postMessage 어디에도 없다. (속성 도구 기록 `mode3_attr_tool_v1` 의 salt 는 사용자가 넣는 기존 동작 — 이 계획이 만들지 않는다.)
- 보관 시간: env `MODE3_PASSKEY_HOLD_SECONDS`(기본 600, 0 = 끔, 에이전트와 같은 이름) → `/user/config.passkeyHoldSeconds`. 보관은 맡긴 때부터 센다(읽어도 늘리지 않는다 — 에이전트 P16 과 같다).
- TLS env: `MODE3_TLS_CERT`·`MODE3_TLS_KEY`(PEM 경로, 둘 다 있거나 둘 다 없어야 한다), 서버 간 신뢰는 `NODE_EXTRA_CA_CERTS=<CA 공개 인증서>`. 포트는 지금과 같다 — IdP 4100, zkONE 3100, zkTWO 3101, 사용자 페이지 5100.
- 이름(W8): `wallet.zkd.test`(호스트 PC, `/etc/hosts` 에서 127.0.0.1), `idp.zkd.test`(.10), `zkone.zkd.test`(.11), `zktwo.zkd.test`(.12). 데모 CA 디렉터리 `${ZKD_CA_DIR:-.local/zkd-ca}`.
- 스크립트는 CA·서버 개인키를 출력하지 않는다(내용·`cat`·`echo` 금지, 지문만). 개인키 파일은 600, 디렉터리 700.
- 새 사유(spec §3, 철자 그대로): `rpc_method_blocked`(정적 서버 403), `passkey_mode`(이 모드에서 꺼진 기능 — Ruling R-6). `tls_setup_required` 는 사전에 넣지 않는다(스크립트 안내 문구만, `BLOCKED: 먼저 bash scripts/zkd_tls_setup.sh`).
- 테스트는 localhost·http 로 돈다(spec §6) — TLS 는 테스트 임시 디렉터리의 openssl 일회용 인증서로만. 테스트는 사용자의 :4100/:5100/:3100/:3101/:8547/:8548, VM, `/etc/hosts`, `~/.pki/nssdb`, `.local/zkd-ca` 를 건드리지 않는다.
- 체인 테스트는 동시에 돌리지 않는다. :8545 가 비어 있으면 `ETHERNAL_WORKSPACE= ETHERNAL_API_TOKEN= npx hardhat node` 를 직접 띄우고 끝나면 내린 뒤 비었는지 확인한다(CLAUDE.md 2026-09-11). 새 테스트는 `scripts/run_tests.sh` 의 해당 그룹에 넣는다.
- 응답·문서는 한국어, 기존 문체. 시각은 `date` 실행값만.

## Rulings (스펙이 정하지 않은 곳 — 틀렸을 때 대가)

- **R-1 URL 에 포트:** W2·§2 는 `https://wallet.zkd.test/` 처럼 포트 없이 쓰지만 W11 은 포트를 지금처럼 둔다. 포트를 둔다 — 실제 주소는 `https://wallet.zkd.test:5100` 등. 대가: 문서·안내 문구의 주소가 길어진다(443 로 옮기려면 sudo 바인딩이 필요해 범위 밖).
- **R-2 RP ID:** `rpId = new URL(config.walletOrigin).hostname` 을 `passkey_store` 에 넘기고, 페이지 `location.hostname` 이 그 값과 다르거나 IP 면 WebAuthn 을 부르기 전에 `passkey_wrong_origin`. 인자를 안 주면 지금처럼 `'localhost'`(에이전트 모드 불변). 대가: 설정 오리진과 다른 이름(예: IP 로 연 페이지)에서는 패스키를 아예 못 쓴다 — 의도다.
- **R-3 Name Constraints 에 IP 도:** DNS 제약(`zkd.test`)만 두면 IP 이름은 제약 밖이라 CA 가 새면 임의 IP 사이트를 위조할 수 있다. `permitted;DNS:zkd.test`, `permitted;IP:127.0.0.0/255.0.0.0`, `permitted;IP:<데모망>/255.255.255.0`(기본 `192.168.226.0`, env `ZKD_DEMO_NET`). 대가: 데모망을 바꾸면 CA 를 새로 만들고 Chrome 에 다시 등록해야 한다(스크립트가 망 불일치를 감지하면 `BLOCKED` 로 알린다).
- **R-4 `/etc/hosts`:** `wallet.zkd.test → 127.0.0.1`(정적 서버는 127.0.0.1 에만 listen), 나머지 셋은 `SPLIT_IDP_IP`·`SPLIT_RP1_IP`·`SPLIT_RP2_IP`(기본 .10/.11/.12). 지갑 인증서 SAN 은 `DNS:wallet.zkd.test, IP:127.0.0.1`. 대가: 다른 PC 의 브라우저는 이 데모 지갑을 열 수 없다(spec 도 호스트 PC 정적 서버).
- **R-5 프록시 경로는 passkey-web 에서만 설정에 싣는다:** `/rpc/*` 라우트는 늘 있지만 `/user/config.rpcUrl·revRpcUrl` 이 `/rpc/app`·`/rpc/rev` 가 되는 것은 `passkey-web` 일 때만(웹 모드 회귀 0). `user.js` 는 상대 경로를 `new URL(x, location.origin).href` 로 풀어 provider 를 만든다(ethers FetchRequest 의 상대 URL 의존을 피함). 허용 목록: `eth_chainId, net_version, eth_blockNumber, eth_call, eth_getLogs, eth_getCode, eth_getBalance, eth_getBlockByNumber, eth_getBlockByHash, eth_getTransactionByHash, eth_getTransactionReceipt, eth_getTransactionCount`. 배치는 원소 하나라도 막히면 전체 403. `/rpc/*` 는 전역 `express.json({limit:'16kb'})` **앞에** 자기 파서(`1mb`)로 둔다(ethers 배치가 16kb 를 넘는다). 대가: 목록 밖 읽기 메서드를 코어가 새로 쓰면 그 기능이 403 으로 깨진다 — 브라우저 테스트가 잡는다.
- **R-6 passkey-web 에서 끄는 경로(409 `passkey_mode`):** `register`(무작위 salt 등록), `completeRegistration`·`loginPrepare`·`login({idToken})`(Google 래퍼 — spec §8 후속), `recoveryCode`·`recover`(zkd1 코드), `prepareRegistration`(던짐). 사용자 페이지의 uid·비밀번호 등록 폼·복구 코드 버튼·속성 저장 버튼은 숨긴다(속성은 속성 도구 기록에서, W5). 대가: 이 모드의 첫 등록은 서비스 로그인 하나뿐이다(스냅 데모와 같은 순서 — W5 의 의도).
- **R-7 salt 는 `source()` 에서 미리 받는다:** 지금 코드는 `src.registration().s_u` 를 동기로 읽으므로 `passkey-web` 의 `source()` 가 보관분/패스키로 salt 를 먼저 받아 넣는다. 그래서 캐시 히트 재검증도 보관이 끝났으면 패스키를 한 번 묻는다. 세션 요청(`request`)은 `source()` 를 부르지 않아 salt 가 필요 없다. 대가: 10분 뒤의 캐시 히트 재검증이 패스키 한 번을 더 묻는다.
- **R-8 한 동작 = 패스키 최대 한 번:** `core.withSalt(fn)` 범위 안에서는 처음 얻은 salt 를 메모리로 재사용한다(보관 0초이거나 범위 도중 보관이 끝나도). 팝업은 요청 하나 전체를 감싼다. 대가: 없음(메모리만, 범위가 끝나면 버린다).
- **R-9 보관 조건:** 패스키로 얻은 salt 는 (a) 돌려받은 credential ID 가 kv `passkey.credentialId` 와 같고 (b) 등록이 있으면 `auidOf(s_u) === registration.auid` 일 때만 보관·사용한다 — 아니면 409 `passkey_mismatch`. 등록 전에도 보관한다(속성 도구에 넣을 salt 를 "salt 보기" 로 꺼내야 한다 — §2 4단계). 대가: 등록 전 10분 동안 아직 쓰이지 않은 salt 가 암호문으로 남는다.
- **R-10 승인 → IdP:** 팝업은 승인 버튼을 받은 **뒤** IdP 인증 창으로 가고, 돌아와서는 다시 묻지 않는다. 등록·로그인 모두 매번 인증 창을 거친다(W5 `CIA_ISSUE_AUTH=code`). 미등록이면 **IdP 로 가기 전에** 패스키 연결(`passkey_setup_required`)과 속성 도구 기록(`attr_record_missing`)을 먼저 본다. 대가: 없음(스냅 데모의 `snapSetupReady` 사전 검사와 같은 자리).
- **R-11 계정 복구의 귀로:** IdP 는 늘 `${walletOrigin}/?authorize=1&idp_…` 로 돌려보내므로 `user.js` 는 팝업 화면으로 뜬다. `runPopup` 이 `window.opener` 검사보다 먼저 `takeIdpReturn` 을 보고 `type === 'mode3-recover'` 면 복구를 끝내고 `location.replace('/')` 한다(에이전트 `finishRecover` 와 같다). 대가: 그 순간 팝업 화면이 잠깐 보인다.
- **R-12 `wipe()` 는 credential 을 남긴다:** 데모 세대 리셋(§2 8단계)과 수동 "모두 지우기" 모두 kv `passkey` 를 되돌려 쓴다(보관분·금고·등록·세션은 지운다). 연결을 끊는 것은 별도 `passkeyDisconnect()`(등록이 있으면 409 `registered`). 대가: 다른 패스키로 바꾸려면 "연결 끊기" 를 한 번 더 눌러야 한다.
- **R-13 IdP 401 사유 보존:** 발급이 401 `auth_code_required`·`bad_code` 면 코어가 `issue_failed` 로 뭉개지 않고 그 사유·상태 그대로 돌려준다(oidc 사유와 같은 처리). 웹(key) 모드에서는 나오지 않는 응답이라 회귀 없음.
- **R-14 분리 스크립트가 번들을 만든다:** `WALLET_MODE=passkey-web` 은 기동 전에 `node scripts/build_user_app.mjs`·`node scripts/build_attr_tool.mjs` 를 돌린다(옛 번들로 뜨는 것이 가장 흔한 실패). 터널은 이 모드에서 강제로 끈다(브라우저가 이름으로 바로 간다, W11). 대가: 리셋이 몇 초 길어진다.
- **R-15 서버 간 주소:** `CIA_PUBLIC_URL=https://$IDP:4100`, RP 의 `MODE3_CIA_URL=https://$IDP:4100`(IP SAN 으로 검증), 정적 서버의 `MODE3_CIA_URL=https://idp.zkd.test:4100`(호스트 PC 는 hosts 가 있다), `MODE3_CIA_BROWSER_URL=https://idp.zkd.test:4100`. 체인 RPC 는 http 그대로(서버만 읽는다). 대가: 원격 VM 의 `NODE_EXTRA_CA_CERTS` 경로가 틀리면 RP 가 IdP 에 붙지 못한다 — 기동 단계의 RP 등록 대기가 0건으로 드러난다.

## Review Focus

1. **보관이 팝업 도중 끝남:** 등록 직후 보관 시각이 지나도 같은 팝업의 로그인이 패스키를 다시 묻지 않는다 — Task 5 `withSalt 범위 안에서 보관이 끝나도 derive 1회`.
2. **IdP 에서 돌아왔는데 대기 저장분이 없거나 어긋남**(다른 탭·10분 초과·주소 직접 입력): 이어받지 않고 안내만, ready 를 다시 보내지 않아 서비스가 요청을 두 번 보내지 않으며 등록되지 않는다 — Task 6 단위 `takeIdpReturn` 3건 + 브라우저 `돌아온 길 nonce 불일치`.
3. **큰 배치·막힌 메서드가 섞인 배치:** ethers 배치가 16kb 를 넘어도 200, `evm_mine` 이 하나라도 섞이면 전체 403 이고 블록이 오르지 않는다 — Task 2 `배치 300건`·`막힌 원소가 섞인 배치`.
4. **속성 도구 기록 없음·salt 다름:** 기록이 없으면 IdP 로 보내지 않고, salt 가 다르면 IdP 를 부르지 않아 등록 코드가 타지 않는다 — Task 5 `기록 salt·auid 불일치는 IdP 를 부르지 않는다`, Task 6 `기록 없으면 IdP 로 가지 않는다`.
5. **다른 이름·IP 로 연 페이지:** `http://127.0.0.1:<port>`(분리 데모에선 `https://192.168.226.128:5100`)로 연 사용자 페이지가 WebAuthn 을 부르지 않고 `passkey_wrong_origin` 만 보이며, 정적 서버는 IP·비보안 오리진으로 `passkey-web` 기동을 거부한다 — Task 3 단위, Task 2 `기동 거부`, Task 7 `127.0.0.1 로 열면`.

---

## File Structure

| 파일 | 책임 | Task |
|---|---|---|
| `lib/mode3_tls.js` (새) | `tlsOptionsFromEnv`, `listenMaybeTls` | 1 |
| `cia.js`, `mode3_rp.js`, `mode3_user_static.js` | `app.listen` → `listenMaybeTls` | 1 |
| `tests/helpers/isolated_cia.mjs`, `tests/helpers/isolated_mode3_stack.mjs` | `scheme` 옵션, `PINNED_ENV`·`spawnServer`·`stopChild` export | 1 |
| `lib/mode3_rpc_proxy.js` (새) | `RPC_ALLOW`, `checkRpcBody` | 2 |
| `mode3_user_static.js` | `passkey-web` 설정·기동 규칙, `/rpc/*`, `/attr*` | 2 |
| `mode3/common/passkey_store.js`, `tests/helpers/webauthn_stub.js` | `rpId`·`rpName` 인자, 스텁이 rpId 를 알림 | 3 |
| `mode3/user/core/vault.js` | `holdSalt`·`heldSalt`·`heldUntil`·`clearHold` | 4 |
| `mode3/user/core/user_core.js` | salt 공급원, `withSalt`, 패스키 동작, `registerWithCode`, `auth_code`, `syncProfileFromRecord` | 5 |
| `mode3/user/idp_return.js` (새) | 인증 창 왕복·속성 도구 기록 읽기(DOM 전역 주입) | 6 |
| `mode3/user/popup.js`, `mode3/user/user.js`, `mode3/rp.html` | passkey-web 승인 흐름·복구 귀로, 어댑터 주입, `WEB()` | 6 |
| `mode3/user/ui.js`, `mode3/user/index.html`, `mode3/common/strings.js` | 설정 카드·salt 보기·연결 끊기·복구 카드·숨김 | 7 (사유는 2·5·6) |
| `scripts/zkd_tls_lib.sh` (새), `scripts/zkd_tls_setup.sh` (새) | CA·인증서·hosts 블록 함수, 처음 한 번 준비 | 8 |
| `scripts/demo_split_start.sh` | `WALLET_MODE=passkey-web` | 9 |
| `docs/MODE3_DEMO.md`, `docs/MODE3_DEMO_SCRIPT.md` | 런북 | 9 |
| 새 테스트 | unit: `test_mode3_tls.mjs`, `test_mode3_rpc_proxy.mjs`, `test_mode3_passkey_rpid.mjs`, `test_mode3_vault_hold.mjs`, `test_mode3_user_idp_return.mjs`, `test_zkd_tls_certs.mjs`, `test_demo_split_passkey_web.mjs` · chain: `test_mode3_tls_stack.mjs`, `test_mode3_user_static_passkey_web.mjs`, `test_mode3_user_core_passkey.mjs` · browser: `test_mode3_user_passkey_web.mjs` | 각 Task |

의존: 1 → 2 → 6 → 7, 4 → 5 → 6, 3 → 6, 8 → 9, 1·2 → 9. 3·4·8 은 서로 독립(병렬 가능 — 공유 체인 테스트는 돌리지 않는 것만).

---

### Task 1: 세 서버의 TLS 기동

**Files:**
- Create: `lib/mode3_tls.js`, `tests/test_mode3_tls.mjs`(unit), `tests/test_mode3_tls_stack.mjs`(chain)
- Modify: `cia.js:2049`, `mode3_rp.js:892`, `mode3_user_static.js:370`(각 `app.listen`), `tests/helpers/isolated_cia.mjs:98`(`scheme`), `tests/helpers/isolated_mode3_stack.mjs`(export 추가만), `scripts/run_tests.sh`(UNIT·CHAIN)

**Interfaces:**
- Produces:
  - `tlsOptionsFromEnv(env = process.env): { cert: Buffer, key: Buffer } | null` — 둘 다 비면 `null`, 하나만 있으면 `throw Error` 메시지에 `MODE3_TLS_CERT·MODE3_TLS_KEY 는 함께`, 못 읽으면 경로만 담은 `Error`(파일 내용 금지).
  - `listenMaybeTls(app, { port: number, host: string, env = process.env, onListening?: (scheme: 'http'|'https') => void }): { server, scheme }` — TLS 면 `https.createServer({cert,key}, app)`, 아니면 `http.createServer(app)`.
  - 세 서버의 기동 로그 첫 줄이 `${scheme}://${host}:${port}`.
  - `startIsolatedCia({ …, scheme = 'http' })` → `base = \`${scheme}://127.0.0.1:${port}\``. `isolated_mode3_stack.mjs` 가 `PINNED_ENV`, `spawnServer`, `stopChild` 를 export(동작 불변).

- [ ] **Step 1: 실패하는 테스트**
  - `tests/test_mode3_tls.mjs`: `mkdtemp` 안에서 `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1` 로 `c.pem`·`k.pem`. openssl 이 없으면 `BLOCKED:` 로 실패. 케이스:
    - `env 없음 → http` — `scheme === 'http'`, `GET /x` 200.
    - `cert·key → https` — `https.get({ host:'127.0.0.1', port, path:'/x', ca: c.pem })` 200, 같은 포트에 `http.get` 은 오류 또는 응답 없음(reject).
    - `하나만 주면 거부` — `assert.throws(() => tlsOptionsFromEnv({ MODE3_TLS_CERT: c }), /함께/)`.
    - `없는 파일 → 경로만` — 메시지에 경로가 있고 `BEGIN` 이 없다.
  - `tests/test_mode3_tls_stack.mjs`: `NODE_EXTRA_CA_CERTS` 가 없으면 인증서를 만들고 같은 파일을 그 env 로 다시 실행(`spawnSync(process.execPath, [file], { env, stdio:'inherit' })`, 종료 코드 전달). 안쪽에서:
    - `IdP https` — `startIsolatedCia({ scheme:'https', env:{ MODE3_TLS_CERT, MODE3_TLS_KEY } })`, `cia.base` 가 `https://` 로 시작, `GET /mode3/health` 200.
    - `RP https → IdP https 서버 간 호출` — `spawnServer('mode3_rp.js', …)`(env 는 `rpSpawnFor` 와 같은 키 + TLS, `MODE3_CIA_URL=cia.base`, `MODE3_RP_PUBLIC_ORIGIN=https://127.0.0.1:<port>`, readyUrl `https://…/api/mode3/rp_info`) → 30초 안에 `cia.adminGet('/cia/rps')` 에 그 origin 이 보인다.
- [ ] **Step 2:** `node tests/test_mode3_tls.mjs` → FAIL(모듈 없음). `node tests/test_mode3_tls_stack.mjs` → FAIL(`scheme` 무시로 readiness 실패).
- [ ] **Step 3: 구현** — `lib/mode3_tls.js` 위 시그니처. 세 서버의 `app.listen(PORT, HOST, cb)` 를 `listenMaybeTls(app, { port: PORT, host: HOST, onListening: (scheme) => console.log(…) })` 로(로그 문구의 `http://` 만 `${scheme}://`). `isolated_cia.mjs` 에 `scheme`.
- [ ] **Step 4:** 두 테스트 PASS. 회귀 `node tests/test_cia_startup.mjs`, `node tests/test_mode3_rp.mjs`, `node tests/test_mode3_user_core.mjs`. `run_tests.sh` UNIT 에 `tests/test_mode3_tls.mjs`, CHAIN 에 `tests/test_mode3_tls_stack.mjs`.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 1 — 세 서버 TLS 기동(MODE3_TLS_CERT·KEY)`

---

### Task 2: 정적 서버 — passkey-web 설정, RPC 프록시, 속성 도구

**Files:**
- Create: `lib/mode3_rpc_proxy.js`, `tests/test_mode3_rpc_proxy.mjs`(unit), `tests/test_mode3_user_static_passkey_web.mjs`(chain)
- Modify: `mode3_user_static.js`, `mode3/common/strings.js`(사유 `rpc_method_blocked`), `tests/test_mode3_demo_strings.js`(`REASONS`), `scripts/run_tests.sh`

**Interfaces:**
- Consumes: Task 1 `listenMaybeTls`.
- Produces:
  - `RPC_ALLOW: readonly string[]`(R-5 의 12개), `checkRpcBody(body): { ok: true } | { ok: false, status: 400|403, reason: 'malformed'|'rpc_method_blocked', method?: string }` — 객체 하나 또는 1~500개 배열, 각 원소는 `jsonrpc:'2.0'`·문자열 `method`.
  - env `MODE3_WALLET_SECRETS` ∈ `web`(기본)·`passkey-web`, 그 밖이면 종료 1. `passkey-web` 이면 `MODE3_WALLET_PUBLIC_ORIGIN` 의 호스트가 IP 이거나, `https:` 가 아니면서 호스트가 `localhost` 가 아니면 종료 1(stderr 에 `passkey-web`). `MODE3_PASSKEY_HOLD_SECONDS` 가 0 이상 숫자가 아니면 종료 1.
  - `GET /user/config` 에 `secrets`, `passkeyHoldSeconds`(number); passkey-web 이면 `rpcUrl: '/rpc/app'`, `revRpcUrl: '/rpc/rev'`. `GET /wallet/config`·`/mode3/health` 의 `secrets` 도 그 값.
  - `POST /rpc/app` → `CIA_RPC_URL`, `POST /rpc/rev` → `MODE3_REV_CHAIN_RPC`(없으면 앱): 통과면 상류 상태·본문 그대로, 상류 실패 502 `{ reason: 'chain_unavailable' }`, 막힘 403 `{ reason: 'rpc_method_blocked', method }`, 형식 400 `{ reason: 'malformed' }`, 다른 메서드 405. CORS 헤더 없음.
  - `GET /attr.html`, `/attr/*`(`express.static(mode3/attr, { index:false })`) — 에이전트 `mode3_wallet_agent.js:505-506` 과 같다.

- [ ] **Step 1: 실패하는 테스트**
  - `test_mode3_rpc_proxy.mjs`: `checkRpcBody({jsonrpc:'2.0',id:1,method:'eth_call',params:[]}).ok === true`; `eth_sendTransaction`·`hardhat_mine`·`evm_mine`·`personal_unlockAccount`·`eth_accounts`·`eth_sign` 각각 `{ok:false,status:403,reason:'rpc_method_blocked',method}`; `[허용, evm_mine]` → 403 `method:'evm_mine'`; `[]`·501개·`{}`·`method:5` → 400 `malformed`; `RPC_ALLOW.length === 12`.
  - `test_mode3_user_static_passkey_web.mjs`(`spawnServer` 로 정적 서버만, `CIA_RPC_URL=MODE3_REV_CHAIN_RPC=http://127.0.0.1:8545`, `node scripts/build_user_app.mjs`·`build_attr_tool.mjs` 선행):
    - `config` — `secrets==='passkey-web'`, `rpcUrl==='/rpc/app'`, `revRpcUrl==='/rpc/rev'`, `passkeyHoldSeconds===600`; `/wallet/config.secrets==='passkey-web'`.
    - `프록시 eth_chainId = 직접 호출` — 두 응답의 `result` 같다.
    - `배치 300건` — `eth_blockNumber` 300개 배열(본문 16kb 초과) → 200, 결과 300개.
    - `막힌 메서드` — `eth_sendTransaction` 403 `rpc_method_blocked`; `[eth_blockNumber, evm_mine]` 403 이고 앞뒤 `eth_blockNumber` 가 같다.
    - `형식·메서드` — `GET /rpc/app` 405, `POST {}` 400 `malformed`.
    - `속성 도구` — `/attr.html` 200 `text/html`, `/attr/dist/attr.js` 200.
    - `기동 거부` — 오리진 `https://127.0.0.1:<p>`, `http://wallet.zkd.test:<p>`, `MODE3_WALLET_SECRETS=bogus`, `MODE3_PASSKEY_HOLD_SECONDS=-1` 각각 종료 코드 ≠ 0(직접 `spawn`, 10초 안).
    - `web 회귀` — 기본 env 로 띄우면 `secrets==='web'`, `rpcUrl` 이 `http://` 로 시작.
- [ ] **Step 2:** 두 테스트 FAIL(모듈 없음 / `secrets` 가 `web`).
- [ ] **Step 3: 구현** — `/rpc/*` 두 라우트는 전역 `app.use(express.json({limit:'16kb'}))` **앞에** `express.json({ limit: '1mb' })` 와 함께(R-5). 상류 호출은 `fetch(target, { method:'POST', headers:{'Content-Type':'application/json'}, body })`, 3초 타임아웃. 사전 항목 `rpc_method_blocked`(`where: 'wallet'`, ko/en `title·cause·action` — "사용자 페이지가 체인에 보낼 수 없는 요청입니다").
- [ ] **Step 4:** 두 테스트 PASS, `node tests/test_mode3_demo_strings.js` all ok, 회귀 `node tests/test_mode3_user_core.mjs`. UNIT 에 `test_mode3_rpc_proxy.mjs`, CHAIN 에 `test_mode3_user_static_passkey_web.mjs`.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 2 — 정적 서버 설정·허용 목록 RPC 프록시·속성 도구`

---

### Task 3: passkey_store 의 RP ID 인자

**Files:**
- Modify: `mode3/common/passkey_store.js:28-83`, `tests/helpers/webauthn_stub.js:188`
- Create: `tests/test_mode3_passkey_rpid.mjs`(unit)
- Modify: `scripts/run_tests.sh`(UNIT)

**Interfaces:**
- Produces:
  - `derivePrf({ credentialId?, rpId = 'localhost' } = {}): Promise<{ credentialId, s_u }>` — `navigator.credentials.get` 의 `publicKey.rpId = rpId`.
  - `createPasskey({ rpId = 'localhost', rpName = 'zk 스냅' } = {}): Promise<{ credentialId, s_u }>` — `rp: { id: rpId, name: rpName }`, 안쪽 `derivePrf` 도 같은 `rpId`.
  - 사전 검사 `precheck(rpId)`: `rpId` 가 IPv4(`/^\d+(\.\d+){3}$/`)거나 `:` 를 담거나, `location.hostname !== rpId` 면 `passkey_wrong_origin`(WebAuthn 호출 전). 나머지 검사·오류 매핑은 그대로. `createPasskeyStore` 는 바꾸지 않는다(에이전트는 인자 없이 → `'localhost'`).
  - 스텁: `hit(kind, rpId)` — `window.__webauthnHit(kind, publicKey?.rp?.id ?? publicKey?.rpId ?? null)`(두 번째 인자 추가, 기존 하네스는 무시해도 된다).

- [ ] **Step 1: 실패하는 테스트** — `test_mode3_passkey_rpid.mjs`(`test_mode3_passkey_salt.mjs` 처럼 `vm.runInThisContext`; 전역 `window`·`location={hostname}`·`isSecureContext=true`·`PublicKeyCredential=function(){}`·`navigator.credentials={get,create}` 를 케이스마다 갈아 끼우고 호출 인자를 기록):
  - `기본은 localhost` — hostname `localhost`, `derivePrf({credentialId:'AA'})` → `get` 의 `publicKey.rpId === 'localhost'`.
  - `rpId 를 따른다` — hostname `wallet.zkd.test`, `derivePrf({credentialId:'AA', rpId:'wallet.zkd.test'})` → `rpId === 'wallet.zkd.test'`.
  - `다른 이름 페이지는 거절` — hostname `idp.zkd.test`, 같은 호출 → reject `reason === 'passkey_wrong_origin'`, `get` 호출 0.
  - `에이전트 경로 불변` — hostname `wallet.zkd.test`, `rpId` 없이 → `passkey_wrong_origin`.
  - `IP 거절` — hostname·rpId 모두 `192.168.226.128` → `passkey_wrong_origin`, 호출 0.
  - `만들기` — `createPasskey({ rpId:'wallet.zkd.test', rpName:'zk 지갑' })` → `create` 의 `rp` 가 `{ id:'wallet.zkd.test', name:'zk 지갑' }`, 이어진 `get` 의 `rpId` 같다(스텁 PRF 는 고정 32바이트).
- [ ] **Step 2:** `node tests/test_mode3_passkey_rpid.mjs` → FAIL(`rpId` 무시).
- [ ] **Step 3: 구현** — 위 Produces. 파일 머리 주석의 "RP ID 는 'localhost' 고정(P6)" 을 "기본 localhost(에이전트 P6), passkey-web 은 호출자가 rpId 를 준다(2026-11-17 passkey-web R-2)" 로.
- [ ] **Step 4:** PASS. 회귀 `node tests/test_mode3_passkey_salt.mjs`, `node tests/test_mode3_passkey_browser.mjs`(에이전트 패스키 화면 — 스텁 인자 추가 영향 없음). UNIT 에 추가.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 3 — 패스키 RP ID 인자(에이전트는 localhost 그대로)`

---

### Task 4: 금고의 10분 salt 보관

**Files:**
- Modify: `mode3/user/core/vault.js`
- Create: `tests/test_mode3_vault_hold.mjs`(unit)
- Modify: `scripts/run_tests.sh`(UNIT)

**Interfaces:**
- Produces(`createVault(kv, { now, ttlMs, holdMs = PASSKEY_HOLD_MS })`, `export const PASSKEY_HOLD_MS = 10 * 60_000`):
  - kv 키 `passkeyHold = { until: number, box: <encryptJson(key, { s_u, until })> }` — `until` 은 공개값, salt 는 암호문 안에만.
  - `holdSalt(s_u: string): Promise<boolean>` — `holdMs <= 0` 이면 저장 없이 `false`; 10진 문자열·`(0, 2^250)` 아니면 `throw`; 키 없음 → `throw` `reason:'locked'`; 이미 있으면 덮어쓴다(새 `until = now() + holdMs`).
  - `heldSalt(): Promise<string|null>` — 없음·키 없음 → `null`; `until <= now()`·복호 실패·안쪽 `until` ≠ 바깥 `until` → `kv.del('passkeyHold')` 후 `null`. 읽기는 `until` 을 늘리지 않는다.
  - `heldUntil(): Promise<number|null>` — 유효할 때만 바깥 `until`.
  - `clearHold(): Promise<void>`.
  - `EMPTY_SECRETS` 와 그 밖의 동작은 그대로.

- [ ] **Step 1: 실패하는 테스트** — `test_mode3_vault_hold.mjs`(`createMemKv`, `let t = 1_000_000; now = () => t`, `vault.setup(null)`):
  - `보관·읽기` — `holdSalt(S)` true → `heldSalt() === S`; `JSON.stringify(전체 kv)` 에 `S` 가 없다.
  - `만료` — `t += PASSKEY_HOLD_MS + 1` → `null`, `kv.get('passkeyHold') === undefined`.
  - `늘리지 않음` — 보관 → `t += 9분` 읽기 S → `t += 1분 + 1` → `null`.
  - `다른 탭` — 같은 kv 의 두 번째 `createVault` 가 `heldSalt() === S`.
  - `끔` — `holdMs: 0` 금고는 `holdSalt` false, kv 에 키 없음.
  - `지우기` — `clearHold()` 뒤 `null`.
  - `바깥 until 조작` — kv 의 `until` 만 늘리면 `heldSalt()` null(안쪽과 다름).
  - `잠김` — 금고 없는 vault: `holdSalt` reject `reason==='locked'`, `heldSalt()` null.
  - `형식` — `holdSalt('0')`·`holdSalt('abc')` reject.
- [ ] **Step 2:** FAIL(`holdSalt` 없음).
- [ ] **Step 3:** 구현(`encryptJson`·`decryptJson` 재사용).
- [ ] **Step 4:** PASS, 회귀 `node tests/test_secret_box.mjs`. UNIT 에 추가.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 4 — 금고 10분 salt 보관(탭 공유, 연장 없음)`

---

### Task 5: 웹 코어 — 패스키 salt 공급원·코드 등록·계정 복구

**Files:**
- Modify: `mode3/user/core/user_core.js`, `mode3/common/strings.js`(사유 `passkey_mode`), `tests/test_mode3_demo_strings.js`
- Create: `tests/test_mode3_user_core_passkey.mjs`(chain)
- Modify: `scripts/run_tests.sh`(CHAIN — `test_mode3_user_core.mjs` 옆)

**Interfaces:**
- Consumes: Task 4 `holdSalt`·`heldSalt`·`heldUntil`·`clearHold`, `createVault(kv, { now, holdMs })`; Task 2 `/user/config.secrets`·`passkeyHoldSeconds`.
- Produces(`createUserCore({ …, passkey = null })`; `const PK = config.secrets === 'passkey-web'`; `PK && !passkey?.derive` 면 생성자에서 `throw`; `holdMs = (config.passkeyHoldSeconds ?? 600) * 1000`):
  - `passkey.derive({ credentialId }): Promise<{ credentialId: string, s_u: string }>` — 주입(브라우저는 `Mode3Passkey.derivePrf`, 테스트는 대역).
  - kv `passkey = { credentialId, createdAt }`(공개).
  - 내부 `saltNow(): Promise<string>` — `withSalt` 메모 → `vault.heldSalt()` → `passkey.derive` 순(R-8·R-9). 금고가 없으면 `vault.setup(null)`. credential 없음 → `tag('passkey_setup_required')`, 불일치 → `tag('passkey_mismatch')`. PK 가 아니면 지금처럼 금고 `secrets.s_u`.
  - `source()`·`loginPrepare`(PK 아님 경로)·`revokeSession`·`registerWith` 의 `s_u` 읽기를 `saltNow()` 로(R-7). PK 에서 `vault.writeSecrets` 는 늘 `s_u: null, seed: null`.
  - `core.withSalt(fn): Promise<any>` — 중첩 가능, 바깥 범위가 끝나면 메모를 버린다(던져도).
  - `core.passkeyState()` → `R(200, { credentialId: string|null, createdAt: number|null, heldUntil: number|null })`.
  - `core.passkeyConnect({ credentialId, s_u })` → `R(200, { ok:true, held: boolean })`; 다른 credential 이 있으면 409 `passkey_already_set`; base64url 아님 400 `bad_credential_id`; 등록이 있고 auid 다르면 409 `passkey_mismatch`(저장 안 함). 자동 금고를 만든다.
  - `core.passkeyDisconnect()` → 200 `{ ok:true }`(credential·보관분 삭제) | 409 `registered`.
  - `core.showSalt()` → `R(200, { s_u })` | 409 `passkey_setup_required`·`passkey_mismatch`.
  - `core.passkeyAuid()` → `R(200, { auid })`(salt 는 응답에 없다).
  - `core.registerWithCode({ uid, code, auid = null, profile = null, recordSalt = null })` → `registerWith({ uid, auth: { uid, code }, makeReg: async () => ({ s_u: BigInt(s), auid: await auidOf({ s_u: BigInt(s) }), seed: null }), … })`. IdP 를 부르기 **전에**: `recordSalt !== null && recordSalt !== s` → 409 `attr_record_salt_mismatch`; `auid !== null && auid !== auidOf(s)` → 409 `register_auid_mismatch`. 201 본문에 `issue_code: string|null`, IdP 가 주면 `restored: true`. PK 가 아니면(웹 모드) 409 `not_passkey_mode`(기존 사전 항목).
  - `core.syncProfileFromRecord({ recordSalt, profile })` → `auidOf(recordSalt) !== reg.auid` 면 409 `attr_record_salt_mismatch`; 같으면 `saveProfile(profile)` 결과 그대로(`changed`). 미등록 409 `not_registered`.
  - `login(body, { …, authCode = null })` → `issueSession` 이 `authCode` 를 `req.body.auth_code` 로 싣는다(cred_revoked 재시도도 같은 코드). IdP 401 `auth_code_required`·`bad_code` 는 `R(401, { reason, cia })`(R-13).
  - PK 에서 409 `passkey_mode`: `register`, `completeRegistration`, `loginPrepare`, `login` 에 `idToken`, `recoveryCode`, `recover`; `prepareRegistration` 은 `tag('passkey_mode')` 로 던진다(R-6).
  - `wipe()`: PK 면 kv `passkey` 를 읽어 두고 `kv.clear()` 뒤 다시 쓴다(R-12).

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_user_core_passkey.mjs`(구성은 `test_mode3_user_core.mjs` 를 따른다: `startIsolatedMode3Stack({ userMode:'web', walletEnv:{ MODE3_WALLET_SECRETS:'passkey-web' }, ciaEnv:{ CIA_ISSUE_AUTH:'code' }, autoRelay:true })`; `const SALT = randomScalar().toString(), CID = 'Y2lkLWE'`; `let calls = 0; const derive = async () => (calls++, { credentialId: CID, s_u: SALT })`; `let skew = 0; now = () => Date.now() + skew`; 같은 `kv` 를 쓰는 `coreA`·`coreB`(두 탭); 코드는 `cia.post('/cia/auth/code', { uid:'12345', pwd:'password123', auid: AUID, purpose:'register'|'issue' })`). 케이스 이름 그대로:
  - `설정 전: showSalt 409 passkey_setup_required, register·recoveryCode·loginPrepare 409 passkey_mode`
  - `passkeyConnect: 자동 금고·credential 저장·보관; 다른 credential 409 passkey_already_set` — `heldUntil > now()`.
  - `showSalt·passkeyAuid 는 보관분 — derive 0회` — `s_u === SALT`, `auid === AUID`.
  - `기록 salt·auid 불일치는 IdP 를 부르지 않는다` — 같은 등록 코드로 `recordSalt: '7'` → 409 `attr_record_salt_mismatch`, `auid: '1'+AUID` → 409 `register_auid_mismatch`, 이어서 같은 코드로 정상 → 201(코드가 타지 않았다).
  - `코드 등록 201: issue_code·secrets.s_u null·seed null·평문 salt 없음` — `(await coreA.vault.readSecrets()).s_u === null`, 전체 kv JSON 에 `SALT` 없음.
  - `로그인: issue_code 로 200 → RP ok; 코드 없이 401 auth_code_required; 쓴 코드 재사용 401 bad_code`
  - `다른 탭은 보관분으로 재검증 — derive 0회` — `coreB.revalidate(...)` 200, `calls` 그대로.
  - `보관 만료 뒤 재검증은 derive 1회, 다시 보관` — `skew += 11분`.
  - `withSalt: 보관 0초 코어에서 범위 안 두 동작 derive 1회, 범위 밖 2회` — `{ ...config, passkeyHoldSeconds: 0 }` 코어.
  - `withSalt 범위 안에서 보관이 끝나도 derive 1회`(Review Focus 1) — 범위 안 첫 동작 뒤 `skew += 11분`, 두 번째 동작.
  - `다른 패스키: credential 다르면 409 passkey_mismatch, 같은 credential 다른 salt 도 passkey_mismatch, 보관하지 않는다` — `clearHold` 뒤 대역 교체.
  - `syncProfileFromRecord: 다른 salt 409, 같은 salt·다른 속성 changed:true → 다음 로그인 userCredMs > 0`
  - `wipe 는 credential 만 남긴다` — `kv.get('passkey').credentialId === CID`, `passkeyHold`·`registration` 없음.
  - `계정 복구: wipe 뒤 같은 auid 등록 코드로 registerWithCode(recordSalt 없이) 201 restored:true, 같은 slot, 로그인 PPID 같음`
- [ ] **Step 2:** `node tests/test_mode3_user_core_passkey.mjs` → FAIL(`passkeyConnect` 없음).
- [ ] **Step 3:** 구현(위 Produces). 사전 `passkey_mode`(`where: 'wallet'` — "설치 없는 패스키 모드에서는 쓰지 않는 기능입니다", 조치 "서비스의 'zkID 로 로그인' 으로 등록·로그인하세요"). 사용자 표시 문자열에 salt 가 실리지 않게 `safeDetail` 이 이미 `s_u` 를 거른다 — 그대로.
- [ ] **Step 4:** PASS. 회귀 `node tests/test_mode3_user_core.mjs` 22/22, `node tests/test_mode3_demo_strings.js`. CHAIN 에 추가.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 5 — 웹 코어 패스키 salt 공급원·코드 등록·auth_code·계정 복구`

---

### Task 6: 인증 창 왕복·승인 팝업·서비스 페이지

**Files:**
- Create: `mode3/user/idp_return.js`, `tests/test_mode3_user_idp_return.mjs`(unit), `tests/test_mode3_user_passkey_web.mjs`(browser)
- Modify: `mode3/user/popup.js`, `mode3/user/user.js`, `mode3/user/index.html`(`<script src="/common/passkey_store.js">` 를 `gsi.js` 다음에), `mode3/rp.html:247,350-356`, `mode3/common/strings.js`, `scripts/run_tests.sh`(UNIT·BROWSER)

**Interfaces:**
- Consumes: Task 2 설정·`/attr`; Task 3 `derivePrf({rpId})`; Task 5 `withSalt`·`passkeyState`·`registerWithCode`·`syncProfileFromRecord`·`login(…,{authCode})`.
- Produces(`idp_return.js`, DOM 전역은 인자로 — Node 에서 돈다):
  - `PENDING_KEY = 'mode3.authorize.pending'`, `PENDING_MAX_AGE_MS = 600_000`, `RECOVER_RESULT_KEY = 'mode3_recover_result'`.
  - `idpAuthUrl({ ciaUrl, walletOrigin, nonce, purpose = 'issue' }): string` — `${ciaUrl}/login?nonce&wallet&return=1`(+ `purpose=register`).
  - `savePending(storage, { req, origin, nonce, at }): void`.
  - `takeIdpReturn({ search, storage, now }): null | { req: null } | { req, origin, code, purpose: 'issue'|'register', uid: string|null, auid: string|null }` — `wallet.html:723-735` 와 같은 규칙(저장분은 늘 지운다). 주소 정리(`history.replaceState(…'/?authorize=1')`)는 호출자.
  - `readAttrRecord({ fetch, localStorage }): Promise<{ s_u, profile }|null>` — `wallet.html:855-865` 와 같은 규칙(`reset.json` epoch, version 4|5, `0 < s_u < 2^250`).
  - `user.js`: `const rpId = new URL(config.walletOrigin).hostname`; PK 면 `passkey = { derive: (o) => Mode3Passkey.derivePrf({ ...o, rpId }), create: () => Mode3Passkey.createPasskey({ rpId, rpName: 'zk 지갑' }) }` 를 `createUserCore` 와 `mountUi`·`runPopup` 에 넘긴다. `rpcUrl`·`revRpcUrl` 은 `new URL(x, location.origin).href` 로 푼다(R-5).
  - `popup.js`(PK 일 때만, 그 밖은 지금 그대로): `runPopup` 첫머리에 `takeIdpReturn` → `mode3-recover` 면 `finishRecover`(R-11, `registerWithCode({ uid, code, auid, profile: req.profile, recordSalt: null })` → `sessionStorage[RECOVER_RESULT_KEY] = { ok, restored, reason, detail }` → `location.replace('/')`); `req:null` 이면 `wallet_auth_resume_failed` 문구만, ready 를 보내지 않는다; 유효하면 ready 없이 그 요청을 이어 처리하고 결과는 `back.origin` 으로. `mode3-authorize`: 승인 → (`provider==='google'` 이면 `passkey_mode`) → credential 없음 `passkey_setup_required` → 미등록이면 `readAttrRecord` 없을 때 `attr_record_missing`(IdP 로 안 감) → `savePending` + `location.assign(idpAuthUrl(purpose))`(R-10). 돌아온 뒤 `core.withSalt` 안에서: register 면 `registerWithCode(…recordSalt: rec.s_u, profile: rec.profile)` → `authCode = issue_code`; issue 면 `syncProfileFromRecord`(기록에 profile 이 있을 때) → `login(body, { verifiedOrigin: back.origin, authCode, serviceName, policy })`. `mode3-revalidate`·`mode3-tx` 도 `core.withSalt`. `mode3-config` 회신의 `secrets` 는 `config.secrets`.
  - `rp.html`: `WEB = () => walletCfg.secrets === 'web' || walletCfg.secrets === 'passkey-web'`; 배지 키 `rp_wallet_passkey_web`(ko `사용자 비밀=브라우저(패스키)`)·`rp_wallet_passkey_web_note`.

- [ ] **Step 1: 실패하는 테스트**
  - `test_mode3_user_idp_return.mjs`(가짜 `storage` = Map 래퍼): `idpAuthUrl` 쿼리 4개·`purpose`; 쿼리 없음 → `null`; nonce 불일치 → `{req:null}` 이고 저장분 지워짐; `at` 이 10분 1ms 전 → `{req:null}`; register 인데 uid 비숫자 → `{req:null}`; 정상 register → `uid`·`auid`, auid 비숫자면 `auid:null`; 저장분 JSON 에 `s_u` 키 없음. `readAttrRecord`: epoch 바뀌면 기록 지우고 `null`; version 3 → `null`; `s_u:'0'`·`2^250` → `null`; v5 → `{ s_u, profile }`.
  - `test_mode3_user_passkey_web.mjs`(구성은 `test_mode3_passkey_browser.mjs` 를 따른다 — `stubContext`·`hits`·`stubSalt`·`atIdpLogin`·`backAtWallet`; 스택 `startIsolatedMode3Stack({ userMode:'web', walletHost:'localhost', walletEnv:{ MODE3_WALLET_SECRETS:'passkey-web' }, ciaEnv:{ CIA_ISSUE_AUTH:'code' }, autoRelay:true })`; 번들 셋(`build_user_app`·`build_attr_tool`) 선행; 이 Task 의 케이스는 사용자 페이지에서 IndexedDB `mode3-user` 의 `kv` 에 `passkey = { credentialId: <스텁 credId>, createdAt }` 를 직접 써 둔다; zkID 가입은 `/user` 화면):
    - `rp 배지: passkey-web 은 브라우저(패스키)` — `#walletMode` 에 `패스키`.
    - `속성 도구 기록이 없으면 IdP 로 가지 않는다`(Review Focus 4) — 로그인 → 승인 → 팝업이 `attr_record_missing` 으로 닫히고, 팝업 URL 이 한 번도 `cia.base` 가 아니었다(`page.on('framenavigated')` 기록).
    - `첫 로그인 = 등록: 승인 → 인증 창(등록) → 등록·로그인 성공, 패스키 한 번, rpId localhost` — `hits.get` 증가 1, `__webauthnHit` 의 rpId `'localhost'`; IndexedDB 덤프·localStorage(속성 도구 기록 키 제외)·sessionStorage 에 `SALT_A` 없음.
    - `두 번째 로그인: 인증 창(발급) → 패스키 0번(보관분) → 성공`
    - `재검증·잔액 확인·출금: 보관분으로 패스키 없이 성공` — 출금 `txHash` 있음.
    - `돌아온 길 nonce 불일치: 이어받지 않고 ready 를 다시 보내지 않는다`(Review Focus 2) — RP 페이지에 `mode3-authorize-ready` 수신 카운터를 `evaluate` 로 심고, 인증 창에 도착한 팝업을 `${wallet}/?authorize=1&idp_nonce=bad&idp_code=bad&idp_purpose=register&idp_uid=1` 로 `goto` → `#authStep` 에 "이어받지 못했습니다", 카운터 1 그대로, IndexedDB `registration` 그대로(이 케이스는 새 컨텍스트·미등록으로).
    - `데모 세대가 바뀌면 등록은 지우고 패스키 연결은 남긴다` — `stack.restartWallet({ MODE3_DEMO_GENERATION:'g1' })` → 페이지 열기 → `'g2'` → 열기 → kv `registration` 없음, `passkey.credentialId` 그대로.
- [ ] **Step 2:** 단위 FAIL(모듈 없음), 브라우저 FAIL(배지가 `file`·팝업이 `not_registered`).
- [ ] **Step 3:** 구현(위 Produces). 승인 창 진행 문구는 기존 키(`wallet_auth_to_idp_register`, `wallet_auth_to_idp`, `wallet_auth_resume_failed`)를 쓴다. `attr_record_missing` 안내의 링크는 `${location.origin}/attr.html`.
- [ ] **Step 4:** 두 테스트 PASS. 회귀 `node tests/test_mode3_user_web.mjs` 17, `node tests/test_mode3_browser.mjs`(rp.html 공통). UNIT·BROWSER 에 추가.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 6 — 승인 팝업의 IdP 인증 창 왕복·보관분 salt, 서비스 페이지 passkey-web = web`

---

### Task 7: 사용자 페이지 화면 — 설정·salt 보기·연결 끊기·계정 복구

**Files:**
- Modify: `mode3/user/ui.js`, `mode3/user/index.html`, `mode3/common/strings.js`
- Test: `tests/test_mode3_user_passkey_web.mjs`(케이스 추가)

**Interfaces:**
- Consumes: Task 5 `passkeyState`·`passkeyConnect`·`passkeyDisconnect`·`showSalt`·`passkeyAuid`·`registerWithCode`; Task 6 `passkey.create`·`passkey.derive`, `idp_return.js`, `RECOVER_RESULT_KEY`.
- Produces(테스트가 잡는 id — `cfg.secrets === 'passkey-web'` 일 때만 보인다; `ui.js:80` 의 `secrets: 'web'` 고정은 `config.secrets ?? 'web'` 으로):
  - 설정 카드 `#pkSetupCard`(credential 없을 때): `#pkNewBtn`(→ `passkey.create()` → `passkeyConnect`), `#pkExistingBtn`(→ `passkey.derive({})` → `passkeyConnect`), `#pkSetupVerdict`. 오리진이 맞지 않으면(`location.hostname !== rpId`) 두 버튼 비활성 + `passkey_wrong_origin` 사유와 `config.walletOrigin` 링크(WebAuthn 호출 없음).
  - 저장소 패널: `#pkInfo`(credential ID 앞 12자·보관 남은 분), `#pkShowSaltBtn` → `#pkSaltModal`·`#pkSaltText`·`#pkSaltCopy`·`#pkSaltClose`(닫으면 텍스트 비움), `#pkDisconnectBtn`(등록 있으면 `disabled`).
  - 복구 카드 `#pkRecoverCard`(credential 있음 ∧ 미등록): `#pkRecoverAttrs`(입력 `data-slot` = 스키마 슬롯 이름, `unused`·예비 슬롯 제외, 기본 1990·KR), `#pkRecoverAuidBtn` → `#pkRecoverAuid`, `#pkRecoverGoBtn`(→ `savePending({ req:{ type:'mode3-recover', profile }, origin: location.origin, … })` + `location.assign(idpAuthUrl({ purpose:'register' }))`), `#pkRecoverVerdict`(시작 때 `RECOVER_RESULT_KEY` 를 읽어 보이고 지운다 — `restored` 면 `user_pk_recover_done_restored` "계정을 되찾았습니다(같은 슬롯)").
  - 숨김: `#fileRegFields`, `#registerBtn`, `#profileSaveBtn`, `#recoveryCodeBtn`, `#recoverBtn`, Google 관련 행. 속성 안내에 `/attr.html` 링크.
  - 문구 키(ko·en): `user_pk_setup_title`, `user_pk_setup_desc`, `user_pk_new_btn`, `user_pk_existing_btn`, `user_pk_connected`("패스키를 연결했습니다"), `user_pk_show_salt_btn`, `user_pk_disconnect_btn`, `user_pk_held`, `user_pk_recover_title`, `user_pk_recover_desc`, `user_pk_recover_auid_btn`, `user_pk_recover_go_btn`, `user_pk_recover_done_restored`, `user_pk_recover_done_new`, `user_pk_recover_failed`. `passkey_wrong_origin` 사전 항목의 `cause`·`action` 을 두 모드에 맞게 일반화("패스키는 정해진 주소에서만 — zk 스냅 화면은 http://localhost:5100, 설치 없는 지갑은 https://wallet.zkd.test:5100").

- [ ] **Step 1: 실패하는 테스트**(같은 파일, 각 케이스는 새 스텁 컨텍스트):
  - `설정 카드: 패스키 만들기 → 연결, 카드 숨김, 보관 중 표시` — `#pkNewBtn` → `#pkSetupVerdict` 에 "패스키를 연결했습니다", `hits.create === 1`, kv `passkey.credentialId` 있음, `#pkInfo` 보임.
  - `127.0.0.1 로 열면 WebAuthn 을 부르지 않는다`(Review Focus 5) — `http://127.0.0.1:<port>/` → `passkey_wrong_origin` 문구, `#pkNewBtn` disabled, `hits.create === 0 && hits.get === 0`.
  - `PRF 없는 인증기는 연결하지 않는다` — `prf:false` 스텁 → `passkey_prf_unsupported`, kv `passkey` 없음.
  - `salt 보기: 보관분이면 패스키 0번, 닫으면 지워진다, 저장소에 평문 없음` — `#pkSaltText === SALT`, 닫은 뒤 `''`, IndexedDB 덤프·storage 에 SALT 없음.
  - `등록 폼·복구 코드 버튼이 없다` — 다섯 요소 hidden.
  - `연결 끊기는 미등록일 때만` — 등록 뒤 `#pkDisconnectBtn` disabled.
  - `계정 복구: 저장소를 비운 브라우저에서 같은 패스키로 같은 등록·같은 PPID` — 새 컨텍스트(같은 `SECRET_A`) → `#pkExistingBtn` → `#pkRecoverCard` 보임 → `#pkRecoverAuidBtn` → `#pkRecoverAuid === AUID_A` → `#pkRecoverGoBtn` → 인증 창(아이디·비밀번호·`AUID_A`) → `/` 로 돌아와 `#pkRecoverVerdict` 에 "계정을 되찾았습니다" → 서비스 로그인 → PPID 가 처음과 같다; `sessionStorage` 에 `mode3_recover_result` 없음.
  - `복구에서 다른 auid 를 넣으면 등록되지 않는다` — 인증 창에 끝자리 바꾼 auid → 인증 창 409 또는 `register_auid_mismatch`, kv `registration` 없음.
- [ ] **Step 2:** 새 케이스 FAIL(`#pkSetupCard` 없음).
- [ ] **Step 3:** 구현(위 Produces). 5초→2초 주기 `refresh()` 가 `passkeyState` 도 읽어 카드 표시를 맞춘다.
- [ ] **Step 4:** `node tests/test_mode3_user_passkey_web.mjs` 전부 ok, 회귀 `node tests/test_mode3_user_web.mjs`, `node tests/test_mode3_demo_strings.js`.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 7 — 사용자 페이지 패스키 설정·salt 보기·연결 끊기·계정 복구`

---

### Task 8: 데모 CA·인증서·hosts 준비 스크립트

**Files:**
- Create: `scripts/zkd_tls_lib.sh`, `scripts/zkd_tls_setup.sh`, `tests/test_zkd_tls_certs.mjs`(unit)
- Modify: `scripts/run_tests.sh`(UNIT)

**Interfaces:**
- Produces(`source scripts/zkd_tls_lib.sh`, 모두 `umask 077`, 개인키 내용을 stdout/stderr 에 쓰지 않는다):
  - `zkd_ca_create <ca_dir> <demo_net>` — 이미 `ca.crt`·`ca.key` 가 있으면 아무것도 안 하고 0(재사용). 없으면 EC P-256 `ca.key`(600), `ca.crt`(3650일, `basicConstraints=critical,CA:TRUE,pathlen:0`, `keyUsage=critical,keyCertSign,cRLSign`, `nameConstraints=critical,permitted;DNS:zkd.test,permitted;IP:127.0.0.0/255.0.0.0,permitted;IP:<demo_net>/255.255.255.0`, CN `zkd demo CA`). 있는데 이름 제약의 망이 `<demo_net>` 과 다르면 종료 2(R-3).
  - `zkd_issue_cert <ca_dir> <out_dir> <short> <dns> <ip>...` — `<out_dir>/<short>.key`(600)·`<short>.crt`(30일, SAN `DNS:<dns>` + 각 `IP:`, `extendedKeyUsage=serverAuth`, `basicConstraints=CA:FALSE`). `ca.srl` 은 `<ca_dir>` 안.
  - `zkd_ca_fingerprint <ca_dir>` — SHA-256 지문 한 줄.
  - `zkd_hosts_render <hosts_file> <ip>=<name>...` — 표시 블록(`# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>` … `# <<< zkd-demo <<<`)을 하나로 바꾼(없으면 끝에 더한) 전체 내용을 stdout 으로. 블록 밖 줄은 그대로.
  - `zkd_tls_setup.sh`(`set -euo pipefail`, 사용자가 직접 실행): `certutil` 없으면 `sudo apt-get install -y libnss3-tools` → `zkd_hosts_render /etc/hosts 127.0.0.1=wallet.zkd.test $SPLIT_IDP_IP=idp.zkd.test $SPLIT_RP1_IP=zkone.zkd.test $SPLIT_RP2_IP=zktwo.zkd.test`(IP 기본은 `demo_split_start.sh` 와 같은 .10/.11/.12) 결과가 다르면 임시 파일 → `sudo install -m 644` → `zkd_ca_create "${ZKD_CA_DIR:-.local/zkd-ca}" "${ZKD_DEMO_NET:-192.168.226.0}"` → `~/.pki/nssdb` 없으면 `certutil -N --empty-password -d sql:$HOME/.pki/nssdb` → `certutil -L -n zkd-demo-ca` 가 없으면 `certutil -A -t 'C,,' -n zkd-demo-ca -i ca.crt` → 지문 출력 → "Chrome 을 완전히 종료했다가 다시 여세요". 각 단계는 "건너뜀/했음" 한 줄.

- [ ] **Step 1: 실패하는 테스트** — `test_zkd_tls_certs.mjs`(임시 디렉터리, `bash -c 'source scripts/zkd_tls_lib.sh; …'`, openssl·bash 없으면 `BLOCKED:`):
  - `CA: 이름 제약·CA 표시·키 600` — `openssl x509 -noout -text` 에 `CA:TRUE`, `X509v3 Name Constraints: critical`, `DNS:zkd.test`, `IP:127.0.0.0/255.0.0.0`, `IP:192.168.226.0/255.255.255.0`; `ca.key` mode `0o600`.
  - `서버 인증서: SAN·EKU·30일·검증` — `wallet.crt` 에 `DNS:wallet.zkd.test`, `IP Address:127.0.0.1`, `TLS Web Server Authentication`; `notAfter - notBefore ≤ 31일`; `openssl verify -CAfile ca.crt wallet.crt` → `OK`.
  - `이름 제약이 막는다` — `zkd_issue_cert … evil evil.example.com 10.0.0.1` 은 발급되지만 `openssl verify` 실패(`permitted subtree violation` 또는 `name constraints`).
  - `재사용` — `zkd_ca_create` 두 번째 호출 뒤 `ca.crt` 바이트 같음; 망을 `10.1.2.0` 으로 부르면 종료 2.
  - `개인키를 출력하지 않는다` — 모든 호출의 stdout+stderr 에 `PRIVATE KEY` 없음.
  - `hosts 블록` — 두 번 렌더해도 블록 하나, 블록 밖 줄 보존, IP 를 바꾸면 블록 안만 바뀜.
  - `bash -n scripts/zkd_tls_setup.sh` 성공.
- [ ] **Step 2:** FAIL(파일 없음).
- [ ] **Step 3:** 구현(openssl 설정은 `mktemp` 파일로 — `-addext` 대신 `-extfile`/`-config` 섹션, Ubuntu 20.04 의 OpenSSL 1.1.1 기준).
- [ ] **Step 4:** PASS. UNIT 에 추가. (`zkd_tls_setup.sh` 자체는 실행하지 않는다 — sudo·사용자 Chrome 저장소. 사용자 수동 확인 항목으로 보고.)
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 8 — 데모 CA(이름 제약)·서버 인증서·hosts 준비 스크립트`

---

### Task 9: 분리 데모 `WALLET_MODE=passkey-web` 과 문서

**Files:**
- Modify: `scripts/demo_split_start.sh`, `docs/MODE3_DEMO.md`(":972 패스키 경로" 절 뒤에 새 절, ":1574 테스트" 절), `docs/MODE3_DEMO_SCRIPT.md`
- Create: `tests/test_demo_split_passkey_web.mjs`(unit)
- Modify: `scripts/run_tests.sh`(UNIT)

**Interfaces:**
- Consumes: Task 1 env, Task 2 `MODE3_WALLET_SECRETS=passkey-web`, Task 8 `zkd_tls_lib.sh` 함수.
- Produces(`demo_split_start.sh`):
  - `case` 허용값 `web|snap|passkey|passkey-web`(오류 문구에 넷 다); `passkey-web` → `USER_PORT=5100`, `AGENT_MODE=0`, `SPLIT_IDP_TUNNEL=0`·`SPLIT_RP_TUNNEL=0` 강제(R-14), `SCHEME=https`, 이름 `WALLET_ORIGIN=https://wallet.zkd.test:5100`, `IDP_UI=https://idp.zkd.test:4100`, `RP1_UI=https://zkone.zkd.test:3100`, `RP2_UI=https://zktwo.zkd.test:3101`.
  - **사전 검사(0. 내림 앞, 원격·포트를 건드리기 전)**: `$ZKD_CA_DIR/ca.crt`·`ca.key` 가 없거나 `getent hosts wallet.zkd.test` 가 비면 `BLOCKED: 먼저 bash scripts/zkd_tls_setup.sh` 출력 후 종료 1.
  - 번들: `node scripts/build_user_app.mjs && node scripts/build_attr_tool.mjs`.
  - 인증서: `TLS_OUT="$LOGS/tls"` 에 `zkd_issue_cert` 넷 — wallet(`wallet.zkd.test`, `127.0.0.1`, `$HOST`), idp(`$IDP`), zkone(`$RP1`), zktwo(`$RP2`). 각 VM 에 `on "$h" 'mkdir -p -m 700 ~/zkd-demo/tls'` → `scp -q` 로 `<short>.crt`·`<short>.key`·`ca.crt` → `chmod 600` 키. 원격 홈은 `RHOME=$(on "$h" 'printf %s "$HOME"')`.
  - role.env 추가 줄(VM 마다): `MODE3_TLS_CERT=$RHOME/zkd-demo/tls/<short>.crt`, `MODE3_TLS_KEY=…/<short>.key`, `NODE_EXTRA_CA_CERTS=…/ca.crt`. `COMMON` 의 `MODE3_WALLET_AGENT_ORIGIN`·`MODE3_CIA_BROWSER_URL` 이 위 https 이름. IdP `CIA_PUBLIC_URL=https://$IDP:4100`, `CIA_ISSUE_AUTH=${ISSUE_AUTH:-code}`; RP `MODE3_RP_PUBLIC_ORIGIN=$RP1_UI`, `MODE3_CIA_URL=https://$IDP:4100`(R-15).
  - 정적 서버 기동(호스트 PC): 웹 분기와 같은 env + `MODE3_WALLET_SECRETS=passkey-web MODE3_TLS_CERT=$TLS_OUT/wallet.crt MODE3_TLS_KEY=$TLS_OUT/wallet.key NODE_EXTRA_CA_CERTS=$ZKD_CA_DIR/ca.crt MODE3_CIA_URL=$IDP_UI MODE3_WALLET_PUBLIC_ORIGIN=$WALLET_ORIGIN MODE3_RP_ORIGIN=$RP1_UI,$RP2_UI`.
  - 상태 확인·RP 승인·요약의 `curl` 은 `$SCHEME://` + `--cacert "$ZKD_CA_DIR/ca.crt"`(IP 로 부른다 — IP SAN). `stop_local` 목록에 `5100:mode3_user_static.js`. 속성 도구 리셋 표시(`reset.json`)는 `snap|passkey|passkey-web` 에서.
  - 끝 안내: 주소 넷(https 이름), "처음이면 bash scripts/zkd_tls_setup.sh 뒤 Chrome 재시작", "지갑 페이지에서 패스키 만들기 → 속성 도구(https://wallet.zkd.test:5100/attr.html) → 서비스에서 zkID 로 로그인".

- [ ] **Step 1: 실패하는 테스트** — `test_demo_split_passkey_web.mjs`:
  - `bash -n` 성공.
  - `허용값` — `case` 줄에 `passkey-web`.
  - `사전 검사가 먼저`(실행 안전 조건) — 스크립트 줄 번호로 `zkd_tls_setup.sh` 를 담은 BLOCKED 줄 < 첫 `stop_remote; stop_local` 호출 줄 < 첫 `on "` 호출 줄(함수 정의 줄 제외).
  - `개인키를 출력하지 않는다` — `/(cat|echo|printf)[^\n]*\.key\b/` 없음(scp·chmod·env 대입 줄 제외 규칙은 정규식으로 명시).
  - 위 순서 단언이 통과했을 때만 실행: `WALLET_MODE=bogus bash scripts/demo_split_start.sh` → 종료 1, 출력에 `passkey-web`; `WALLET_MODE=passkey-web ZKD_CA_DIR=<빈 임시 디렉터리> bash scripts/demo_split_start.sh` → 종료 1, 출력에 `BLOCKED` 와 `zkd_tls_setup.sh`, `SPLIT_START` 이후 줄 없음(내림·ssh 전).
- [ ] **Step 2:** FAIL(`passkey-web` 없음).
- [ ] **Step 3: 구현**(위 Produces). 사용법 주석에 `WALLET_MODE=passkey-web` 두 줄.
- [ ] **Step 4:** PASS. UNIT 에 추가. 문서: `docs/MODE3_DEMO.md` 에 "설치 없는 패스키 경로(`passkey-web`, 2026-11-17)" 절 — 준비 스크립트(처음 한 번·sudo·Chrome 재시작), 리셋, 주소 넷(포트 포함, R-1), 흐름(§2 1~8), 10분 보관(`MODE3_PASSKEY_HOLD_SECONDS`), RPC 허용 목록(R-5), 사유 `rpc_method_blocked`·`passkey_mode`, 에이전트 패스키와 패스키가 다르다(RP ID), 미검증(§7 + R-3 의 Chrome 이름 제약 적용, VM https 첫 기동). 테스트 절에 새 테스트 11개와 그룹. `docs/MODE3_DEMO_SCRIPT.md` 에 모드 차이 한 단락(시연 순서 S0~S18 그대로, 지갑 연결 대신 패스키 설정). `node tests/test_mode3_demo_strings.js` all ok(문서 사유 코드 검사).
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): passkey-web 9 — 분리 데모 WALLET_MODE=passkey-web(HTTPS 이름·인증서 배포)·런북`

---

## 마지막 검증(전 Task 뒤)

- `bash scripts/run_tests.sh unit` → 새 7개 포함 전부 ok.
- 체인 그룹은 하나씩: `node tests/test_mode3_tls_stack.mjs`, `node tests/test_mode3_user_static_passkey_web.mjs`, `node tests/test_mode3_user_core_passkey.mjs`, 회귀 `node tests/test_mode3_user_core.mjs`, `node tests/test_mode3_wallet_passkey.mjs`.
- 브라우저: `node tests/test_mode3_user_passkey_web.mjs`, 회귀 `node tests/test_mode3_user_web.mjs`, `node tests/test_mode3_passkey_browser.mjs`, `node tests/test_mode3_browser.mjs`.
- 띄운 hardhat 노드·서버를 내리고 포트가 비었는지 확인. 결과는 성공/실패와 핵심 오류만.
- 자동 테스트가 못 덮는 것(사용자 수동, spec §6·§7): `zkd_tls_setup.sh`(apt·hosts·certutil), Chrome 이 이름 제약 CA 를 받아들이는지, VM 세 곳 https 기동과 서버 간 IP 검증, 실제 Chrome 비밀번호 관리자 PRF.
- 전체 리뷰는 Opus 리뷰어(메모리 규칙).
