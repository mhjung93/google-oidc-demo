# google-oidc-demo

Google OIDC + zk-SNARK 기반 SSO 데모. Mode 1(Google ID Token을 지갑 키에 바인딩)과 Mode 2(Custom IdP + PS 서명 + zk 증명 기반 SSO, `docs/MODE2_FLOW.md` 참고) 두 흐름으로 구성되어 있습니다.

저장소: https://github.com/mhjung93/google-oidc-demo

## 실행 준비 파일

루트 디렉토리에 아래 파일과 산출물이 필요합니다.

- `.env`: RP 서버 설정. 최소한 `APP_MODE`, `BASE_URL`, `SESSION_SECRET`이 필요합니다. Mode 1을 쓰는 경우 `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`도 필요합니다.
- `build/mode2/pi_arid_i_*`, `build/mode2/pi_ppid_*`: Mode 2 ZKP 검증/증명에 필요한 wasm, zkey, verification key 산출물입니다.
- `pot14_final.ptau`: Mode 2 회로를 다시 빌드할 때 `scripts/build_mode2_circuits.sh`가 사용합니다. 이미 `build/mode2` 산출물이 있으면 일반 실행에는 필요하지 않습니다.
- `pot21_final.ptau`: Mode 1 회로 키를 다시 생성할 때 사용합니다. 일반 Mode 2 실행에는 필요하지 않습니다.
- `auditor_keys.json`: Mode 1 암호화 데모에서 필요합니다. 없으면 `node scripts/generate_auditor_keys.js`로 생성합니다.
- `.id_token.txt`: Mode 1 Google 로그인 플로우 중 서버가 생성하는 임시 토큰 파일입니다. 직접 준비하지 않습니다.

민감 파일에는 실제 secret, token, private key가 들어갈 수 있으므로 저장소에 커밋하지 않습니다.

## 설치

```bash
npm install
```

Snap 의존성까지 명시적으로 설치하려면 아래 명령을 사용할 수 있습니다.

```bash
npm install --workspace=google-oidc-demo-snap
```

## Mode 2 실행

Mode 2는 Custom IdP, RP 서버, Snap 서버를 각각 실행합니다. 현재 데모는 최초 1회 wallet-IdP account binding이 이미 완료된 상태를 가정하며, Mode 2 문서의 `uid = 12345`는 그 사전 binding 결과를 하드코딩한 데모 값입니다.

`.env` 예시:

```bash
APP_MODE=2
BASE_URL=http://localhost:3000
CUSTOM_IDP_BASE_URL=http://127.0.0.1:4000
MODE2_ETH_RPC_URL=http://127.0.0.1:8545
SESSION_SECRET=change-me
```

터미널 1: Snap 빌드 및 서빙

```bash
npm run snap:build
npm run snap:serve
```

터미널 2: Custom IdP

```bash
node custom_idp.js
```

터미널 3: Wallet Agent

```bash
node wallet_agent.js
```

터미널 4: RP 서버

```bash
npm run dev
```

브라우저에서 아래 주소로 접속합니다.

```text
http://localhost:3000
```

Mode 2 회로 산출물을 다시 만들 때는 아래 명령을 사용합니다.

```bash
./scripts/build_mode2_circuits.sh
```

### 크레덴셜 폐기(Revocation) 관련 환경변수

크레덴셜 폐기 기능(`docs/superpowers/specs/2026-08-23-baar-revocation-design.md` 참고)을 쓰려면 아래 환경변수가 추가로 필요합니다. 아래 값은 예시일 뿐이며 실제 시크릿·주소로 채워야 합니다.

```bash
IDP_ADMIN_SECRET=change-me
IDP_AUDITOR_SECRET=change-me-too
REVOCATION_IDP_ADDRESS=0x...
REVOCATION_REGISTRY_ADDRESS=0x...
```

- `IDP_ADMIN_SECRET`: `custom_idp.js`의 `POST /idp/revoke`, `POST /idp/publish/*` 관리자 인증에 씁니다. 미설정 시 이 엔드포인트들은 503을 반환합니다.
- `IDP_AUDITOR_SECRET`: `custom_idp.js`의 B2 추적 엔드포인트(`POST /idp/lookup_uid_by_r_token`, `POST /idp/lookup_uid_by_auid_i`) 인증에 씁니다. `server.js`도 같은 값을 읽어 `POST /api/mode2/trace_transaction`에서 IdP를 호출할 때 `X-IdP-Auditor-Secret` 헤더로 실어 보냅니다. 미설정 시 IdP 쪽 엔드포인트는 503을, `server.js`의 트레이스 엔드포인트는 500을 반환합니다.
  - `IDP_ADMIN_SECRET`과 값을 공유하지 않는 별도 변수입니다. 신원 역추적(추적/감사 권한)과 크레덴셜 폐기(관리자 권한)는 서로 다른 권한이어야 하므로, 관리자 시크릿으로는 추적 엔드포인트를 통과할 수 없고 감사자 시크릿으로는 `/idp/revoke`를 통과할 수 없습니다.
  - 이 데모 구성에서는 `server.js`(RP)가 감사자 시크릿을 직접 들고 있어, RP가 자기 사용자를 역추적할 수 있습니다. 데모 편의를 위한 선택이며, 실제 배포에서는 감사자가 RP와 독립된 별도 주체여야 합니다.
- `REVOCATION_IDP_ADDRESS`: 배포/게시 스크립트(`scripts/redeploy_ppid_factory.cjs`, `scripts/push_revocation_root.cjs`)가 `RevocationRegistry`의 `onlyIdP` 주소로 씁니다. 미설정 시 배포·게시가 에러로 중단됩니다.
- `REVOCATION_REGISTRY_ADDRESS`: `wallet_agent.js`가 배포된 `RevocationRegistry`를 조회할 때 씁니다. 미설정 시 `wallet_agent.js`는 기동 시점에 에러를 내고 종료합니다.

### 계정 층(사람 차단) 관리자 엔드포인트

크레덴셜 폐기 트리(`/idp/revoke`, `/idp/publish/*`)는 **이미 발급된 크레덴셜의 회수**만 합니다 — 가역이고, 트리 수명 관리에 따라 결국 만료되어 풀립니다. "이 사람의 앞으로의 로그인 자체를 막는다"는 트리가 할 수 없는 일이라 계정 층에서 처리합니다(`docs/REVOCATION_FOLLOWUPS.md` 0절). 두 엔드포인트 모두 `IDP_ADMIN_SECRET`으로 인증합니다(`IDP_AUDITOR_SECRET`으로는 통과하지 않습니다) — 조회가 아니라 폐기와 같은 등급의 관리 조작이기 때문입니다.

- `POST /idp/account/set_disabled` — body `{ "username": "...", "disabled": true|false }`. 계정을 비활성화/재활성화합니다. 비활성화된 계정은 `/authorize/login`, `verifyPiIAndIssueToken`(`/sso_with_credentials` → `/consent_result` 경로) 양쪽 모두에서 비밀번호 확인 직후, zk 증명 검증 전에 거부됩니다(`/authorize/login`은 403, 레거시 경로는 `/consent_result`에서 400). `disabled` 값은 `idp_state.json`에 영속화됩니다.
- `POST /idp/account/unpin_auid` — body `{ "username": "..." }`. `pinAuidToAccount`가 첫 로그인에서 고정한 `lastAuid`를 해제해, 다음 로그인이 다시 "첫 로그인"처럼 어떤 salt든 받아들이게 합니다. `pinAuidToAccount` 자체(같은 salt만 계속 허용하는 저지선)는 그대로 둡니다 — 지갑이 일방적으로 새 salt를 들이미는 것은 여전히 거부되고, 이 엔드포인트를 통해 IdP(운영자)가 승인한 경우에만 풀립니다. 부정 사용으로 의심되는 계정에는 먼저 `set_disabled`로 차단하세요 — **비활성화된 계정은 이 엔드포인트가 409로 거부합니다**(그렇지 않으면 부정 사용으로 차단한 계정이 이 복구 흐름으로 되살아납니다). 해제 대상 계정이 옛 `auid`에 대한 계정 폐기 리프를 트리에 갖고 있으면(published 또는 pending), 응답의 `staleRevocationLeaf` 필드로 알려줍니다 — 해제 자체는 허용됩니다(새 salt → 새 auid → 새 PPID라 옛 리프가 새 로그인을 막지 못합니다).

### 크레덴셜 폐기 게시 주기 자동화 (`scripts/revocation_sweep.cjs`)

`RevocationRegistry.isRecentRoot(root)`는 root가 **가장 최근 게시로부터 `GRACE_BLOCKS`(200블록) 이내**일 때만 true입니다. 즉 주기적으로 root를 재게시(heartbeat)하지 않으면 게시된 root가 만료되고, **폐기와 무관한 정상 사용자 전원의 `/submitTransaction`이 막힙니다.** 이 스크립트를 데몬으로 계속 띄워 두지 않으면 서비스가 죽습니다.

1회만 실행(기존 동작, 운영자가 수동으로 반복 실행해야 함):

```bash
IDP_ADMIN_SECRET=... REVOCATION_IDP_ADDRESS=0x... REVOCATION_REGISTRY_ADDRESS=0x... \
  npx hardhat run scripts/revocation_sweep.cjs --network localhost
```

`REVOCATION_SWEEP_INTERVAL_SECONDS`를 설정하면 그 간격(초)으로 `prepare → push → commit` 사이클을 무기한 반복하는 데몬 모드로 동작합니다:

```bash
IDP_ADMIN_SECRET=... REVOCATION_IDP_ADDRESS=0x... REVOCATION_REGISTRY_ADDRESS=0x... \
  REVOCATION_SWEEP_INTERVAL_SECONDS=60 \
  npx hardhat run scripts/revocation_sweep.cjs --network localhost
```

관련 환경변수:

- `REVOCATION_SWEEP_INTERVAL_SECONDS`: 설정하면 데몬 모드로 전환되고, 이 초 간격으로 사이클을 반복합니다. 미설정 시 1회 실행 후 종료(기존 동작).
- `REVOCATION_SWEEP_SAFETY_FACTOR`: 안전 가드 배수(기본 4). 온체인 `GRACE_BLOCKS`를 12초/블록 가정으로 환산한 상한을 이 값으로 나눈 것이 허용 간격 상한입니다. `interval × factor`가 그 상한을 넘으면 위험하다고 보고 기동을 거부합니다(연속 몇 번의 사이클 실패까지 grace window 안에서 흡수할 여유를 남기기 위함). `GRACE_BLOCKS` 자체는 하드코딩하지 않고 매번 배포된 registry에서 읽습니다.
- `REVOCATION_SWEEP_FAILURE_ALERT_THRESHOLD`: 연속 실패 횟수가 이 값(기본 3) 이상이면 눈에 띄는 경고 배너를 반복 출력합니다. 사이클 하나가 실패해도 데몬은 죽지 않고 다음 주기에 재시도하지만, 실패가 이어지면 운영자가 놓치지 않게 하기 위함입니다.

데몬은 `SIGINT`/`SIGTERM`을 받으면 진행 중인 사이클을 마치고 정상 종료합니다(강제 중단이 아니라, 다음 사이클을 새로 시작하지 않는 방식). `prepare` 이후 `push` 이전에 멈추면 아무 변화 없이 끝나고, `push` 이후 `commit` 이전에 멈추면 온체인 root는 이미 최신으로 확정된 상태라 지갑은 계속 유효한 root로 동작합니다 — 어느 지점에서 중단돼도 안전합니다.

로컬 데모 체인(hardhat node)은 트랜잭션이 있을 때만 블록을 찍으므로, 벽시계 기준 주기 실행은 안전한 방향의 오차를 냅니다(체인이 벽시계보다 느리게 늙어 실제 grace window가 계산보다 더 넉넉합니다).

### IdP 키·상태 영속화

`custom_idp.js`는 장기 키와 폐기·발급 상태를 프로젝트 루트의 두 파일에 보관합니다. 둘 다 권한 `0600`이고 `.gitignore`에 등록돼 있습니다.

- `idp_keys.json`: EdDSA-Poseidon 개인키와 PS 비밀값(`x`, `y[0..5]`). 공개키는 기동할 때마다 이 비밀값에서 다시 유도하므로 저장하지 않습니다. 파일이 없으면 새로 생성하고, 있으면 로드합니다.
- `idp_state.json`: 게시된 폐기 리프와 그 root, 리프별 만료 블록, 대기 중인 폐기, 발급 로그(`r_token`/`auid_i` → uid), 계정별 `lastAuid`와 `disabled`. 상태가 바뀔 때마다 저장합니다. 스키마 버전은 3입니다 — v1/v2 파일도 손실 없이 마이그레이션해서 불러옵니다(v1: `auidILog` 값 모양 변경, v2: `disabled` 필드 추가 — 둘 다 누락분은 마이그레이션 시점에 안전한 기본값으로 채워집니다).

키가 파일에 남기 때문에 **`custom_idp.js`를 재시작해도 `server.js` 재시작·factory 재배포·`wallet_agent.js` 재시작이 필요하지 않습니다.**

키를 의도적으로 새로 뽑으려면 `IDP_ROTATE_KEYS`를 설정해 실행합니다.

```bash
IDP_ROTATE_KEYS=1 node custom_idp.js
```

이 경우 기존 `idp_keys.json`을 무시하고 새 키를 만들어 덮어씁니다. 새 키는 `server.js`가 캐싱한 PS 공개키, `wallet_agent.js`가 캐싱한 `pk_IdP`, 그리고 `PPIDWalletFactory`에 불변으로 새겨진 신뢰 IdP 키를 모두 무효화하므로, 회전 후에는 `server.js` 재시작 → `scripts/redeploy_ppid_factory.cjs`로 factory 재배포 → 새 factory 주소로 `wallet_agent.js` 재시작까지 이어지는 복구 체인을 함께 돌아야 합니다.

`idp_keys.json`이 손상되었거나 형식이 맞지 않으면 `custom_idp.js`는 **조용히 새 키를 만들지 않고** 명확한 에러로 기동을 중단합니다. 운영자가 모르는 채로 스택 전체가 깨지는 것을 막기 위해서입니다. `idp_state.json`도 마찬가지로, 저장된 리프로 재구성한 root가 저장된 root와 다르면 기동을 중단합니다.

## Mode 1 실행

`.env`에 Google OIDC 클라이언트 설정을 포함해야 합니다.

```bash
APP_MODE=1
BASE_URL=http://localhost:3000
SESSION_SECRET=change-me
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

Google Cloud Console의 OAuth redirect URI에는 아래 값을 등록합니다.

```text
http://localhost:3000/oidc/callback
```

실행:

```bash
npm run snap:build
npm run snap:serve
npm run dev
```

브라우저에서 아래 주소로 접속합니다.

```text
http://localhost:3000
```

## 주요 포트

- RP 서버: `http://localhost:3000`
- Custom IdP: `http://localhost:4000`
- Snap local server: `http://localhost:8081`

## 주요 경로

- RP 서버: `server.js`
- Custom IdP 서버: `custom_idp.js`
- 브라우저 클라이언트: `client.js`, `index.html`
- Snap: `snap/`
- 회로: `circuits/`
- Mode 2 문서: `docs/MODE2_FLOW.md`
- 보조 스크립트: `scripts/`
- 테스트/점검 스크립트: `tests/`
