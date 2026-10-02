# snap-mode3 — Mode 3 MetaMask Snap

Mode 3 의 등록 비밀(`s_u`·`r_u`·`sk_u`)을 MetaMask 의 암호화 저장소에 보관하고, 로그인·속성 공개·자기 폐기 동의 대화상자를 띄우는
Snap 이다. 정본은 스펙 `docs/superpowers/specs/2026-09-22-mode3-metamask-snap-design.md` §3.1(RPC 표·상태 모양)이고, 같은 입출력의
Node 시뮬레이터가 `tests/helpers/snap_sim.mjs` 다. Mode 2 의 `snap/` 과는 별개 패키지이며 서로 건드리지 않는다.

## 설치·빌드·serve·지갑 페이지 연결

`cd snap-mode3 && npm install` 로 이 디렉터리 안에만 의존성을 깔고(루트 `package.json`·`node_modules` 는 건드리지 않는다),
`npm run build`(= `mm-snap build`)로 `dist/bundle.js` 를 만든다 — 빌드가 `snap.manifest.json` 의 `shasum` 을 갱신하고 번들을 SES 에서
한 번 평가한다. `npm run serve`(= `mm-snap serve`)는 포트 **8082** 로 `snap.manifest.json` 과 `dist/bundle.js` 를 띄우며, 이때 snap id 는
`local:http://localhost:8082` 다. MetaMask **Flask** 에서 지갑 페이지의 "MetaMask 연결" 버튼이 `wallet_requestSnaps({ 'local:http://localhost:8082': {} })`
로 설치·연결한다. 지갑 페이지(Flask 로 띄우는 :5100)는 에이전트 `GET /wallet/config` 가 주는 `snapId` 를 그대로 쓰므로, 다른 포트로
서빙한다면 에이전트의 `MODE3_SNAP_ID` 환경변수도 같이 바꾼다. 이 Snap 은 **지갑 페이지 오리진(`http://127.0.0.1:5100`·`http://localhost:5100`)
의 호출만** 받는다(`src/index.js` 위쪽 `WALLET_ORIGINS` 상수가 정본 — 다른 포트로 지갑 페이지를 띄우면 여기에 더해야 한다).

## 테스트

```
node snap-mode3/test/rpc.test.mjs        # = cd snap-mode3 && npm test
```
전역 `snap` 객체(`snap_manageState`·`snap_dialog`)를 스텁으로 대신해 RPC 9종을 검사한다. 루트 `run_tests.sh` 에서는
`bash scripts/run_tests.sh snap` 으로 같은 파일을 돌린다(2026-09-22 Ruling 9 — 이 패키지의 `node_modules` 를 전제하므로 `unit` 이
아니라 별도 그룹이다). 루트 `lib/` 를 상대 경로로 import 하므로 저장소 안에서 실행해야 한다.

## 메모: 왜 circomlibjs 를 안 쓰는가

`cm_u = s_u·G₃ + r_u·H` 계산은 `src/crypto.js` 에 Baby Jubjub 덧셈·스칼라곱을 BigInt 로 직접 적었다. `circomlibjs` 의 `buildBabyjub` 은
WASM 곡선을 올리는데(WebAssembly 없이 부르면 `Cannot read properties of undefined (reading 'Memory')` 로 죽는다, 2026-09-22 실측)
이 Snap 의 manifest 에는 `endowment:webassembly` 가 없기 때문이다. 결과가 루트 `lib/mode3_issuance.js` 의 `registrationCommit` 과 같은
점인지는 `test/rpc.test.mjs` 가 대조한다. 따라서 스펙 §9(c) 의 대안(페이지가 cm_u 를 계산)은 쓰지 않았다.
