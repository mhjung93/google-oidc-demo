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

### IdP 키·상태 영속화

`custom_idp.js`는 장기 키와 폐기·발급 상태를 프로젝트 루트의 두 파일에 보관합니다. 둘 다 권한 `0600`이고 `.gitignore`에 등록돼 있습니다.

- `idp_keys.json`: EdDSA-Poseidon 개인키와 PS 비밀값(`x`, `y[0..5]`). 공개키는 기동할 때마다 이 비밀값에서 다시 유도하므로 저장하지 않습니다. 파일이 없으면 새로 생성하고, 있으면 로드합니다.
- `idp_state.json`: 게시된 폐기 리프와 그 root, 리프별 만료 블록, 대기 중인 폐기, 발급 로그(`r_token`/`auid_i` → uid), 계정별 `lastAuid`. 상태가 바뀔 때마다 저장합니다.

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
