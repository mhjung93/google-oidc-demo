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
