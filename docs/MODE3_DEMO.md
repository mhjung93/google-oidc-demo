# Mode 3 데모 — 기동과 시연

설계: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md`
UI 스펙: `docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md`
온체인 실행: `docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md`

Mode 2 데모(:3000/:4000/:5001)와 **공존**한다. 포트·상태 파일이 다르고 코드를 공유하지 않는다.

## 프로세스와 포트

| 프로세스 | 포트 | 명령 | 상태 파일 |
|---|---|---|---|
| hardhat 노드 | :8545 | `npx hardhat node` | — |
| 폐기 체인 노드 (선택, V10) | :8546 | `HARDHAT_CHAIN_ID=31338 npx hardhat node --port 8546` | — — 아래 "폐기 체인을 별도 노드로" 절. 기본 데모는 :8545 하나에 로그와 거울을 함께 둔다 |
| CIA | :4100 | `node cia.js` | `cia_state.json`, `cia_keys.json` |
| 지갑 에이전트 | :5100 | `node mode3_wallet_agent.js` | `mode3_wallet_state.json` |
| RP | :3100 | `node mode3_rp.js` | `mode3_rp_registration.json`, `mode3_rp_logins.jsonl` |
| RP #2 (선택) | :3101 | `bash scripts/run_mode3_rp2.sh` | `mode3_rp2_registration.json`, `mode3_rp2_logins.jsonl` — 아래 "두 번째 서비스" 절 |
| Snap serve (`snap` 모드에만) | :8082 | `cd snap-mode3 && npm run serve` | — (비밀은 MetaMask 안에) |
| (상태 확인) | 세 서버 공통 | `curl -s http://127.0.0.1:4100/mode3/health` (`:3100`·`:5100` 도 같다) | — |

`GET /mode3/health` 는 2026-09-25 에 붙은 상태 엔드포인트다 — 페이지 위쪽의 상태 점 4개가 이것을 읽는다(아래 "상태 패널" 절).

로그 컨트랙트는 `Mode3Log`(V9, 2026-10-01) 하나다 — 폐기 root(`revRoot`)와 등록부 root(`regRoot`) 둘을 들고 있다.

**V10(2026-10-02, 설계 `docs/superpowers/specs/2026-10-02-mode3-revocation-chain-design.md`)**: 그 `Mode3Log` 는 **폐기 체인의
캐노니컬(정본)** 이 되고, 응용 체인마다 **거울(`Mode3Mirror`)** 이 그 두 root 를 받아 적는다. 서비스(RP)·PPID 계정은 **자기 체인의
거울만** 읽고, CIA 가 캐노니컬 게시를 거울로 중계(릴레이)한다. 회로·증명은 바뀌지 않았다. 기본 데모는 :8545 하나에 로그와 거울을
함께 둔다(같은 체인이어도 서비스는 거울만 읽으므로 "게시 → 릴레이 → 서비스가 본다" 순서는 그대로 보인다).

## 두 번째 서비스 — 같은 사용자, 다른 주소 (2026-09-30)

같은 지갑으로 서비스 둘에 로그인하면 **서비스마다 다른 PPID 계정**을 받고, AA 는 어느 쪽인지 모른다는 것을 눈으로 보이는 구성이다.
서비스 서버는 포트·이름·오리진·등록 파일이 전부 환경 변수라 인스턴스를 하나 더 띄우면 되고, AA 는 오리진별로 서비스를 여럿 등록한다.
막고 있던 것은 지갑의 CORS 허용 오리진이 하나뿐이던 점이었고, 이제 `MODE3_RP_ORIGIN` 이 쉼표 목록을 받는다.

1. 지갑을 두 오리진으로 띄운다(이미 떠 있으면 재시작):
   `MODE3_RP_ORIGIN=http://127.0.0.1:3100,http://127.0.0.1:3101 node mode3_wallet_agent.js`
2. 두 번째 서비스를 띄운다: `bash scripts/run_mode3_rp2.sh` — `:3101`, 이름 `demo-rp2`, 등록 파일 `mode3_rp2_registration.json`, 릴레이어 계정 인덱스 1
   (첫 서비스와 같은 계정을 쓰면 팩토리 배포 nonce 가 겹칠 수 있다). 허용 국가·최소 나이도 바꿔 두면 정책이 서비스마다 다르다는 것까지 보인다.
3. 관리자 페이지(`:4100`)에서 두 번째 서비스 등록을 승인한다 — 승인되면 서비스가 자기 팩토리·검증자를 배포한다(`:3101` 로그).
4. `http://127.0.0.1:3101` 을 열어 같은 사용자로 로그인한다. 세션 카드의 PPID 와 계정 주소가 `:3100` 의 것과 다르다.
   지갑 페이지의 세션 목록에는 두 서비스가 나란히 보이고, 각 세션을 따로 폐기할 수 있다.

`GET /mode3/health` 의 지갑 응답에는 허용 목록이 `rpOrigins` 로 실린다(`rpOrigin` 은 첫 항목).
지갑의 세션 라우트는 요청 오리진과 세션의 서비스 오리진을 대조하므로(9/25 리뷰 D-4·F-1) 한 서비스 페이지가 다른 서비스의 세션을 쓸 수 없다.

## 처음 한 번: 배포와 `.env`

0. `bash scripts/build_mode3_circuit.sh pot21_final.ptau` — `build/mode3/` 의 zkey·vkey·wasm 을 한 세트로 만든다(수 분).
   회로를 바꾼 뒤에는 반드시 다시 돌린다. 다른 기계에 `build/` 를 복사해 뒀다면 그것도 다시 옮긴다.
   2026-09-16 회로 변경(트레이스 태그)으로 build/mode3 를 다시 만들었다 — 노트북 등 다른 기계의 build/mode3 도 다시 복사해야 한다.
   회로 V4(2026-09-18)로 build/mode3 를 다시 만들었다 — 다른 기계의 build/mode3 도 다시 복사. 이 스크립트가
   `contracts/PiCredVerifier.sol` 도 만든다.
   회로 V5(2026-09-21, 자격증명 이중 구조)로 build/mode3 를 또 다시 만들었다. **운영 주의 — 회로가 바뀐 뒤의 순서**(하나라도 빠지면
   새 π 가 온체인에서 `InvalidProof` 나 root 불일치로 막힌다):
   (1) `bash scripts/build_mode3_circuit.sh …` — zkey·vkey·wasm 과 `contracts/PiCredVerifier.sol` 재생성.
   (2) `npx hardhat compile` — `artifacts/` 의 `PiCredVerifier` 를 다시 만든다(옛 아티팩트로 배포한 검증기는 새 π 를 `InvalidProof` 로 거절한다).
   (3) CIA: `RevocationLog` 재배포는 필수가 아니다 — 옛 TAG 3 리프는 Poseidon(4, Cf_u) 와 겹치지 않으므로 옛 로그를 그대로 써도 된다.
       새로 배포한다면(아래 3, `.env` 의 `CIA_LOG_ADDRESS` 갱신) `cia_state.json` 도 함께 지워야 한다 — v5→v6 이행은 폐기·pending·epoch 를
       그대로 두므로, 남아 있으면 기동 시 빈 로그와의 root 대조 실패로 종료한다(아래 "재시연 세트" 와 같은 이유).
   (4) 서비스: `mode3_rp_registration.json` 에서 **`verifierAddress` 와 `factoryAddress` 를 둘 다 지운 뒤** 재시작한다. `factoryAddress` 만 지우면
       RP 가 옛 `verifierAddress`(V4 검증기)를 그대로 다시 써 새 팩토리가 옛 검증기를 가리키고 π 는 여전히 `InvalidProof` 다(`mode3_rp.js` `ensureFactory`).
       env 에 `MODE3_VERIFIER_ADDRESS` 가 있으면 새로 배포한 V5 검증기 주소로 바꾸거나 지운다.
   (5) 상태 파일: 옛 로그를 그대로 쓰면 `cia_state.json` 은 기동 시 v6 로 자동 이행되고(발급 기록만 비움, 폐기 트리 유지) 지갑의
       `mode3_wallet_state.json` 도 v6 로 자동 이행된다(세션·userCred 비움, 등록 유지 — 다음 로그인이 새 C_u 를 받는다). 로그를 새로
       배포했다면 (3) 대로 `cia_state.json` 을 지운다 — 그러면 계정 등록도 사라지므로 지갑 상태 파일도 같이 지우는 편이 맞다.
   로그를 새로 배포하는 쪽을 택하면 아래 "재시연 세트" 를 통째로 한 번 하는 것과 같다.
   회로 V6(2026-09-22, 선택 공개)로 build/mode3 를 또 다시 만들었다 — 순서: (1) `bash scripts/build_mode3_circuit.sh …` (2)
   `npx hardhat compile` (3) 서비스 등록 파일(`mode3_rp_registration.json`)에서 `verifierAddress`·`factoryAddress`·`attrGateAddress`
   를 **셋 다** 지운 뒤 재시작 — `attrGateAddress` 를 안 지워도 RP 가 알아서 다시 배포하지만(팩토리 주소가 바뀌면 자동으로
   재배포한다, `ensureAttrGate`), 옛 `verifierAddress`·`factoryAddress` 를 남기면 V5 와 같은 문제(새 π 가 옛 검증기에서
   `InvalidProof`)가 난다. (4) CIA 상태는 v7 로 **자동 마이그레이션**된다(코드 변경 불필요) — 계정마다 활성 C_u 를 물려(pending
   에 리프로 넣어) 다음 게시에 나가게 한다. **CIA 기동이 이 v7 이행 리프를 자동 게시한다** — 옛 C_u 로 여전히 증명 가능한
   창이 다음 하트비트까지 열려 있지 않게 한다(2026-09-22 최종 리뷰 Important, Ruling 8). 체인 RPC 가 아직 없으면 게시를
   건너뛰고 경고만 남기므로, 그때는 체인이 뜬 뒤 `/cia/publish` 를 수동으로 호출한다. (5) 지갑 상태도 v7 로 **자동 이행**된다(옛 C_u·세션을 비운다, 등록 자체는 유지) —
   다음 로그인에서 지갑이 새 사용자 자격증명을 자동으로 다시 받는다(`userCredMs > 0`). `RevocationLog` 재배포는 V5 와 같은 이유로
   필수가 아니다.
   회로 V7(2026-09-23, 집합 소속)로 build/mode3 를 다시 만들었다 — 다른 기계의 build/mode3 도 다시 복사. 팩토리·AttrGate 재배포
   필요(V6 증명과 호환 없음).
   회로 V8(2026-09-24, 세션 폐기 — 비멤버십 2개)로 build/mode3 를 또 다시 만들었다(설계
   `docs/superpowers/specs/2026-09-24-mode3-session-revocation-design.md`). **공개 입력은 25개 그대로**라 서비스·컨트랙트
   인터페이스는 안 바뀌지만 `contracts/PiCredVerifier.sol` 이 다시 생성되므로 **검증기·팩토리·AttrGate 재배포가 필요하다**
   (V7 검증기는 V8 π 를 `InvalidProof` 로 거절한다). 순서는 V6·V7 과 같다: (1) `bash scripts/build_mode3_circuit.sh …`
   (2) `npx hardhat compile` (3) `mode3_rp_registration.json` 의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 를
   셋 다 지운 뒤 RP 재시작(**팩토리가 바뀌면 PPID 계정 주소도 바뀐다** — 아래 6 의 경고와 같다). (4) CIA 상태는 v8 로 자동
   이행된다(`accounts[uid].sessions = []` — 아래 "세션 폐기(V8)" 절의 주의). 다른 기계의 build/mode3 도 다시 복사한다.
   회로 V9(2026-10-01, 등록부·속성 6슬롯·공개 입력 30)로 build/mode3 를 또 다시 만들었다(설계
   `docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md`). 사용자 자격증명의 활성 여부가 폐기 트리에서
   **등록부(슬롯 트리)** 로 옮겨갔다 — 폐기 트리에는 이제 세션 리프(`Poseidon(5, Cf_s)`)만 남는다(아래 "세션 폐기(V8)"
   절 끝 참고). 순서: (1) `bash scripts/build_mode3_circuit.sh …` (2) `npx hardhat compile` (3) **로그 재배포가 필수다**
   (V5~V8 과 달리 선택이 아니다 — 등록부 root 를 실을 새 컨트랙트가 필요하다): `CIA_ETH_ADDRESS=<ethAddress> npx hardhat
   run scripts/deploy_mode3_log.cjs --network localhost` 가 (로그 이름이 바뀌어) `Mode3Log`(폐기 root·등록부 root 둘을
   들고 있다)를 배포한다 → 출력의 `CIA_LOG_ADDRESS=0x…` 를 `.env` 에 반영한다. (4) `cia_state.json` 은 지우지 않는다 —
   기동 시 v9 로 자동 이행된다(계정마다 슬롯을 배정하고 활성 자격증명의 리프를 계산해 채운 뒤 게시한다). **단** 로그를
   새로 배포했으므로 폐기 트리 쪽(`revoked`)이 빈 새 로그와 어긋나면 CIA 가 기동을 거부한다 — 이때는 "옛 폐기 리프는
   유지한 채 로그 주소만 바꾼 상태 파일"을 쓸 방법이 없으므로(등록부는 새로 시작해도 폐기 트리 쪽은 옛 리프 그대로라
   마찬가지로 어긋난다) 아래 "재시연 세트"(상태 파일을 백업해 두고 새로 시작)를 탄다. (5) `mode3_rp_registration.json`
   의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 셋을 지운 뒤 RP 재시작(**팩토리가 바뀌므로 PPID 계정 주소도
   바뀐다** — 아래 6 의 경고와 같다). (6) 지갑 상태는 v8 로 자동 이행된다(세션·사용자 자격증명을 비우고 등록은 유지) —
   옛 등록(슬롯 번호가 없다)은 첫 로그인 때 `/cia/slot` 으로 슬롯을 되찾는다. **`snap` 모드로 시연한다면** 등록 키 생성이
   Task 13 에서 Snap 쪽(`snap-mode3/src/index.js`)으로 옮겨 가 `src/` 가 바뀌었으므로, `cd snap-mode3 && npm run build`
   로 `dist/` 를 다시 만든 뒤에 MetaMask 에 Snap 을 다시 설치한다(아래 "준비 (처음 한 번)" 절 2). Snap 을 다시
   설치하면 저장된 등록(`snap_manageState`)도 함께 지워지므로 등록부터 다시 해야 한다 — v8 시절의 4속성 등록이
   남아 있었다면 로그인 witness 검사(`validateWitness`)가 `attrs 길이` 로 `bad_witness` 를 던졌을 것이다.
   **V10(2026-10-02, 폐기 체인·거울)은 회로를 바꾸지 않는다** — build/mode3 는 그대로다. 대신 컨트랙트가 바뀌었다: `Mode3Log` 의
   게시 다이제스트가 체인 id·로그 주소를 덮고 접수증 대기열(`requestRevocation`·`pendingSlots`·`isRetired`)이 붙었으며, 거울
   `Mode3Mirror` 가 새로 생겼다. 순서: (1) `npx hardhat compile` (2) 아래 3 으로 **로그와 거울을 새로 배포**하고 출력의 세 줄을
   `.env` 에 반영한다(옛 V9 로그는 새 서명 형식을 받지 않는다) (3) 로그가 바뀌었으므로 아래 "재시연 세트" 를 탄다(상태 파일
   삭제) (4) `mode3_rp_registration.json` 의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 를 지운다 — 팩토리는 이제
   **거울 주소**를 로그 주소로 받으므로 새로 배포해야 한다(**PPID 계정 주소가 바뀐다** — 아래 6 의 경고).
1. `npx hardhat node` (다른 터미널에 상주).
2. `CIA_ADMIN_SECRET=<아무 문자열> node cia.js` — 처음 기동에서 `cia_keys.json`을 만든다. `curl -s 127.0.0.1:4100/cia/public_keys`의 `ethAddress`를 적어 두고 종료한다.
3. `CIA_ETH_ADDRESS=<ethAddress> npx hardhat run scripts/deploy_mode3_log.cjs --network localhost` — `Mode3Log` 와 그것을 가리키는
   `Mode3Mirror`(V10, 같은 체인)를 배포하고 CIA 주소에 1 ETH를 넣는다. 출력의 **세 줄**을 `.env`에 추가한다:
   ```
   CIA_LOG_ADDRESS=0x…          # 캐노니컬 로그 — CIA 가 게시하고, 지갑이 이벤트를 재생해 트리를 만든다
   MODE3_MIRROR_ADDRESS=0x…     # 거울 — RP·지갑 필수(없으면 기동하지 않는다). 서비스 팩토리도 이 주소를 로그로 받는다
   CIA_MIRRORS=31337=0x…        # CIA 가 중계할 거울 목록(chainid=주소, 쉼표로 여럿)
   ```
   **`CIA_CHAIN_RPCS` 에 그 chainid 항목이 반드시 있어야 한다**(예: `CIA_CHAIN_RPCS=31337=http://127.0.0.1:8545`) — CIA 는 거울의
   RPC 를 거기서 찾고, 없으면 `CIA_MIRRORS 의 chainid 31337 에 대한 RPC 가 CIA_CHAIN_RPCS 에 없다` 로 기동하지 않는다. 스크립트도
   마지막 줄에 같은 주의를 찍는다.
3'. `npx hardhat compile` — RP 가 기동 시 `PiCredVerifier`·`Mode3WalletFactory` 를 아티팩트에서 읽어 배포하고, **지갑도 같은 아티팩트로 팩토리·검증자 코드를 대조한다**(2026-09-23 — 지갑 기계에도 `artifacts/` 가 있어야 한다)(`artifacts/` 가
   없으면 RP 로그에 "팩토리 배포 실패", 오프체인 로그인만 된다).
4. `.env`에 `CIA_ADMIN_SECRET=<2의 값>`도 넣는다. (세 서버 모두 `dotenv`로 `.env`를 읽는다. `CIA_*`·`MODE3_*` 키는 이 데모만 쓴다.)
5. RP(mode3_rp.js)는 첫 기동에서 서명키·태그 조각을 만들어 CIA 에 등록하고 **등록 대기** 상태로 뜬다. CIA 관리자 페이지
   (`/admin` → 등록된 서비스 → 승인)에서 승인하면 5초 안에 arid·pk_trace·cert_s 를 받아 mode3_rp_registration.json 에 두고
   활성화된다. CIA 키를 바꾸거나 cia_state.json 을 지웠으면 이 파일도 지운다(그러면 새 키로 다시 승인받아야 한다).
6. RP 는 승인 뒤 팩토리를 배포해 `mode3_rp_registration.json` 에 `factoryAddress` 를 둔다. 재배포하려면 그 필드를 지우거나
   `MODE3_RP_FACTORY_ADDRESS` 로 덮어쓴다. **주의**: 회로를 다시 빌드한 뒤라면 `verifierAddress` 도 함께 지워야 한다 — 그 필드가 남아 있으면
   새 팩토리가 옛 검증기를 그대로 가리킨다(위 0 의 (4)).
   **경고**: 팩토리를 다시 배포하거나 팩토리 생성자 인자 중 하나라도(`MODE3_MAX_ROOT_AGE`, `MODE3_MAX_LIFETIME_BLOCKS`, 검증기
   주소, `arid`(서비스 식별자 — RP 를 다시 등록하면 새로 배정된다), 로그 주소, CIA 키, 서비스 조합 키 — 생성자 9인자 전부) 바꾸면 모든 PPID 계정 주소가 바뀐다 — 옛 계정의 잔액은 옛 팩토리 주소로만
   접근할 수 있으니, 잔액이 있는 데모를 진행 중이면 먼저 빼낸다. 팩토리가 이미 있으면 RP 는 env 대신 **팩토리의 값**을
   쓰고 경고한다(2026-09-23) — env 를 바꿨는데 안 먹는다면 그 경고를 보라.

V10 환경 변수(2026-10-02). **`CIA_RPC_URL` 의 뜻이 프로세스마다 다르다** — CIA 에게는 캐노니컬(폐기 체인) RPC, RP·지갑에게는
자기가 검증·실행하는 응용 체인 RPC 다. 체인 하나 데모에서는 둘 다 :8545 라 차이가 안 보이지만, 폐기 체인을 따로 띄우면 `.env` 에
넣지 말고 프로세스마다 준다(아래 "폐기 체인을 별도 노드로").

| 키 | 누가 | 뜻 |
|---|---|---|
| `CIA_RPC_URL` | CIA | 캐노니컬 `Mode3Log` 가 있는 폐기 체인 RPC(기본 `http://127.0.0.1:8545`). 게시·접수증 서명의 chainid 가 여기서 나온다 |
| `CIA_RPC_URL` | RP·지갑 | 자기 응용 체인 RPC(거울·팩토리·계정이 있는 곳, 기본 같음) |
| `CIA_LOG_ADDRESS` | CIA·RP·지갑 | 캐노니컬 로그. RP 는 `rp_info` 에 **표시만** 하고 읽지 않는다 |
| `MODE3_MIRROR_ADDRESS` | RP·지갑(필수) | 이 체인의 거울. RP 검증기·팩토리·지갑의 증명 root 가 전부 이것 기준 |
| `MODE3_REV_CHAIN_RPC` | 지갑·`hardhat.config.cjs` | 지갑: 캐노니컬을 읽을 RPC(기본 `CIA_RPC_URL`). 트리는 캐노니컬 이벤트를 **거울 epoch 까지만** 재생해 만든다. hardhat: `--network revchain` 의 URL(기본 `http://127.0.0.1:8546`) |
| `HARDHAT_CHAIN_ID` | `hardhat.config.cjs` | `npx hardhat node` 의 chainid(기본 31337). 두 번째 노드(폐기 체인)를 31338 로 띄울 때만 |
| `CIA_MIRRORS` | CIA | `chainid=거울주소,…` — 중계 대상. 각 chainid 가 `CIA_CHAIN_RPCS` 에 있어야 한다 |
| `CIA_CHAIN_RPCS` | CIA | 응용 체인 RPC 맵(세션 발급 + 거울 중계). 비어 있으면 지금처럼 `CIA_RPC_URL` 의 체인 하나로 채워지지만, 그 기본값은 `CIA_MIRRORS` 검사보다 늦게 생기므로 **거울을 쓰면 응용 체인을 명시적으로 적어야 한다** |
| `CIA_MIRROR_HEARTBEAT_BLOCKS` | CIA | 거울 릴레이 안전망 주기 H_X(그 거울 체인의 블록 수, 기본 50, `0` = 릴레이 전체 끔). 뒤처진 거울을 이 주기 안에 옮긴다. 따라잡은 거울을 위해 캐노니컬 하트비트를 새로 만들지는 않는다(2026-10-05) |
| `CIA_MIRROR_RELAY_ON_PUBLISH` | CIA | 캐노니컬 게시 직후 뒤처진 거울에 바로 중계(기본 `1`). `0` 이면 주기 틱만 — 거울 지연을 눈으로 보이는 시연용(2026-10-05) |
| `CIA_MIRROR_POLL_MS` | CIA | 릴레이 틱 간격(기본 5000) |
| `MODE3_CANONICAL_LOG_ADDRESS`·`MODE3_CANONICAL_CHAIN_ID` | 배포 스크립트 | 둘 다 주면 **거울만** 배포한다(남의 체인의 캐노니컬을 가리킴). 별도 노드 구성 전용 — **`.env` 에 넣지 말 것**(배포 명령에만 붙인다. `.env` 에 있으면 단일 노드 재배포가 거울 전용으로 바뀐다) |

`MODE3_MAX_ROOT_AGE`(서비스·계정이 받아들이는 root 나이)는 이제 **거울**의 `lastPublishedBlock` 기준이다 — 거울 릴레이 주기보다
2~3배 크게 둔다(설계 §5, 기본 100 > 50).

선택 env: 지갑의 `MODE3_TTL_BLOCKS`(credential 만료, 기본 300)·`MODE3_HEIGHT_GRID`(max_height 양자화 그리드, 기본 100 — 만료는 지갑이 정하고 CIA 는 그대로 서명), 서비스·컨트랙트의 `MODE3_MAX_LIFETIME_BLOCKS`(지갑이 정한 만료의 상한 L, 기본 400; TTL+GRID 이상이어야 로그인이 된다)·
`CIA_HEARTBEAT_BLOCKS`(하트비트 재게시 주기, 기본 50, 0=끔)·`CIA_HEARTBEAT_POLL_MS`(기본 5000)·
`CIA_CHAIN_RPCS`(발급을 허용할 체인의 RPC 맵, 기본 `"31337=http://127.0.0.1:8545"`, 비면 자기 RPC 하나 — V10 에서 `CIA_MIRRORS` 를 쓰면 명시 필수, 위 표)·
`MODE3_MAX_ROOT_AGE`(지갑과 **RP 오프체인 로그인·재검증·세션 요청도 같은 상한**으로 받아들이는 게시 root 의 최대 나이,
블록, 기본 100 — 온체인 `RootTooOld` 와 같은 값, 하트비트 주기보다 커야 한다)·
`MODE3_RELAYER_INDEX`(트랜잭션 릴레이어로 쓸 hardhat 계정 인덱스, 기본 0)·`MODE3_RP_FACTORY_ADDRESS`·`MODE3_VERIFIER_ADDRESS`,
`MODE3_VKEY_PATH`(CIA 의 개봉 검증용 vkey, 기본 `build/mode3/pi_cred_vkey.json`), `MODE3_RP_LOGIN_LOG`(RP 로그인 로그, 기본
`mode3_rp_logins.jsonl`, 0600 — 개봉 요청의 재료라 비밀로 둔다). 옛 `CIA_TTL_SECONDS`·`CIA_REVOKE_SKEW_SECONDS`·`CIA_CHAIN_IDS`·`CIA_REVOKE_SKEW_BLOCKS` 는
경고와 함께 무시된다(skew 는 2026-09-21 자격증명 이중 구조에서 제거됐다 — 폐기는 리프 하나라 세션 기록이 필요 없다).
`MODE3_ALLOWED_COUNTRIES`(V7 AttrGate 정책의 허용 국가 집합, 쉼표 구분 — 국가 이름(KR,JP) 또는 ISO 3166 numeric(410,392), 스키마 표에
없으면 기동 실패, 기본 `410,392,840,276,250`(= KR,JP,US,DE,FR))·
`MODE3_MIN_AGE`(V7 AttrGate 정책의 최소 나이, 연 단위, 기본 19).

선택: 운영이라면 RP의 `pk_CIA`를 TOFU가 아니라 env로 박는다 — `curl -s 127.0.0.1:4100/cia/public_keys`의 `pk_CIA.x/y`를 `MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y`에. 단 env 로 박으면 RP 는 기동 때 CIA 에 묻지 않으므로 CIA 하트비트 주기와
`MODE3_MAX_ROOT_AGE` 의 대조 경고(하트비트 ≥ maxRootAge 면 전원이 `root_too_old`)가 나오지 않는다 — 두 값은 사람이 맞춘다(2026-09-23 최종 리뷰 M4).

## 다른 기계에 설치 — Windows 11 + WSL2 (2026-10-09)

데모 스택은 전부 로컬(체인·CIA·지갑·RP 가 `127.0.0.1` 에 묶임)이라 **다른 기계에서도 그 기계 안에서 그대로 띄우면 된다.** 외부 주소로
노출하는 길은 없다 — RP 오리진이 `cert_s` 에 서명돼 있고, Snap 의 허용 오리진(`snap-mode3/src/index.js` `WALLET_ORIGINS`)이
`127.0.0.1:5100`/`localhost:5100` 상수이며, 세 서버가 `app.listen(PORT, '127.0.0.1')` 이기 때문이다. 다른 PC 에서 보기만
하려면 SSH 포트 포워딩(`ssh -L 3100:127.0.0.1:3100 -L 4100:127.0.0.1:4100 -L 5100:127.0.0.1:5100 -L 8545:127.0.0.1:8545 …`)이
코드 변경 없이 된다 — 그쪽 브라우저의 오리진도 `127.0.0.1` 이라 인증서·CORS·Snap 이 그대로 맞는다.

**WSL2 에서.** WSL 안에서 리슨하는 포트는 Windows 의 `localhost`/`127.0.0.1` 로 자동 포워딩되므로(루프백 바인딩이어도) Windows 쪽
브라우저·MetaMask 로 `http://127.0.0.1:3100`(RP)·`:5100`(지갑)·`:4100/admin`(관리자)·RPC `http://127.0.0.1:8545`·Snap `localhost:8082` 에
그대로 닿는다. 주의 네 가지:
1. 저장소는 **WSL 파일시스템**(`~/google-oidc-demo`)에 둔다 — `/mnt/c/...` 는 느리고, 상태 파일을 `0600` 으로 쓰는 코드·심링크가
   NTFS 마운트에서 어긋난다.
2. **clone 도 WSL 안에서** 한다 — Windows git 의 `autocrlf` 가 `scripts/*.sh` 를 CRLF 로 바꾸면 `bash scripts/run_tests.sh` 가 깨진다.
3. Node 22 는 WSL 안에 nvm 으로(`nvm install 22`). circom 은 필요 없다(아래처럼 build 를 복사한다).
4. 페이지는 `localhost` 가 아니라 **`127.0.0.1`** 로 연다(이 머신에서와 같은 규칙 — 지갑의 CORS 허용 목록이 `http://127.0.0.1:3100`).

**git 에 없는 것을 챙긴다**(`.gitignore`: `build/`, `artifacts/`, `*.ptau`, `*.zkey`, `.env`, 상태 파일).
- `build/mode3/` — 회로 재빌드는 circom 2.1.9 + `pot21_final.ptau`(2.3GB) 가 필요하니 **복사**한다. 이 머신에서
  `bash scripts/pack_mode3_build.sh` 가 런타임이 읽는 셋(`pi_cred_final.zkey`·`pi_cred_vkey.json`·`pi_cred_js/`, 약 27MB)만 묶고
  `MANIFEST.sha256` 을 넣는다. 받는 쪽은 저장소 루트에서 `tar -xzf … && sha256sum -c build/mode3/MANIFEST.sha256`.
- `artifacts/` — 받는 쪽에서 `npx hardhat compile` 한 번(RP 의 팩토리 배포, 지갑의 참조 코드 대조가 읽는다).
- `.env` — **복사하지 않는다**(비밀값·이 머신의 컨트랙트 주소). 위 "처음 한 번" 1~4 로 새로 만든다. Mode 1/2 키(Google OAuth, V4 주소)는
  Mode 3 에 필요 없다.
- 상태 파일(`cia_keys.json`·`cia_state.json`·`mode3_wallet_state.json`·`mode3_rp_registration.json`) — 가져가지 않는다. 새 체인이라
  새로 시작하고, RP 는 첫 기동에서 등록 → 관리자 승인 → 팩토리 자동 배포 순서로 활성화된다(위 5·6).

```bash
# WSL Ubuntu
nvm install 22
git clone https://github.com/mhjung93/google-oidc-demo.git && cd google-oidc-demo && git checkout feat/mode3-cia && npm install
tar -xzf ~/mode3_build_YYYYMMDD.tar.gz && sha256sum -c build/mode3/MANIFEST.sha256   # 이 머신의 pack_mode3_build.sh 산출물
npx hardhat compile
# 이어서 위 "처음 한 번: 배포와 .env" 1~6, 그다음 "매번: 기동 순서"
```
Snap 모드는 `cd snap-mode3 && npm install && npm run build` 와 MetaMask Flask(아래 "준비 (처음 한 번)")를 더 전제한다. WSL 안에
Chrome 이 없으면 `browser` 테스트 그룹은 `BLOCKED` 로 끝나지만 데모와는 무관하다.

## 매번: 기동 순서

```
npx hardhat node                # 이미 떠 있으면 생략
node cia.js                     # :4100
node mode3_wallet_agent.js      # :5100
node mode3_rp.js                # :3100 (기동 시 CIA 에서 pk_CIA 를 받아 고정 — CIA 가 먼저 떠 있어야 한다)
```

RP 는 등록 파일이 없거나 승인 전이면 CIA 에 등록/조회하므로 CIA 가 먼저 떠 있어야 한다.

**거울 릴레이(V10, 2026-10-05 개정).** CIA 는 캐노니컬 게시(발급·폐기에 따른 등록부 변경, 세션 리프, 정규 하트비트)가 성공하면
**곧바로** 뒤처진 거울에 그 게시를 옮긴다(`CIA_MIRROR_RELAY_ON_PUBLISH`, 기본 켬). 그래서 폐기·발급이 서비스에 보이는 시점은
"캐노니컬 게시 + 거울 체인 tx 하나" 다. 거울마다 `CIA_MIRROR_POLL_MS`(5초) 틱은 안전망으로 남아, 중계가 실패했거나 누가 중간
epoch 만 올려 둔 거울을 `CIA_MIRROR_HEARTBEAT_BLOCKS`(50블록) 안에 따라잡게 한다. **따라잡은 거울을 위해 캐노니컬 하트비트를 새로
만들지는 않는다** — 거울의 신선도는 캐노니컬 정규 하트비트(`CIA_HEARTBEAT_BLOCKS`, 폐기 체인 블록)가 정한다. 그러므로
`CIA_HEARTBEAT_BLOCKS` 의 시간(폐기 체인 블록 × 블록 시간)이 각 응용 체인의 `MODE3_MAX_ROOT_AGE` 시간(응용 체인 블록 × 블록
시간)보다 짧아야 한다 — 아니면 그 체인의 거울이 늙어 전원 `root_too_old`·`RootTooOld` 로 막힌다. hardhat 은 tx 가 있을 때만
블록을 만들므로, 한가한 데모에서 하트비트 주기를 보려면 블록을 따로 캐야 한다. 시연 중 즉시 중계를 손으로 하고 싶으면
관리자 시크릿으로 부른다:

```
curl -s -X POST -H "X-CIA-Admin-Secret: $CIA_ADMIN_SECRET" http://127.0.0.1:4100/cia/admin/relay   # → {"mirrors":[{chainId, epoch, …}]}
```

거울이 이미 캐노니컬을 따라잡았는데 누르면 캐노니컬 하트비트를 하나 더 올리고 그것을 중계한다(epoch +1, 블록·가스를 쓴다 —
관리자용 강제 경로라 주기 릴레이와 달리 하트비트를 만든다).
**첫 로그인(새 사용자 자격증명)** 은 거울이 내 등록부 리프를 실을 때까지 지갑이 최대 30초 기다린다(`registry_unpublished`).
즉시 중계가 켜져 있으면 발급 게시 직후 거울이 따라오므로 보통 몇 초 안에 끝난다. **거울 지연을 시연하려면**
`CIA_MIRROR_RELAY_ON_PUBLISH=0` 으로 CIA 를 띄운다 — 그러면 계정 폐기 직후 거울이 뒤처진 동안 서비스가 옛 root 로 요청을
받다가, 다음 주기 틱이나 위 relay 뒤에 `revalidate_required` 로 바뀌는 장면을 볼 수 있다(자동 각본 13 과 같다).

### 폐기 체인을 별도 노드로 (선택, V10)

> 2026-10-03 실행 확인: `tests/test_mode3_demo_full.mjs` 가 이 구성(폐기 체인 :8546 chainId 31338 + 응용 체인 :8545, 서비스 둘)을
> 격리 스택으로 처음부터 끝까지 돌린다 — 등록·로그인·거래소 술어·온체인 출금·개봉·세션 폐기·계정 폐기(거울 지연)·접수증·복구.
> 4단계 기동 env 는 그 테스트가 자식에게 주는 값과 같다. 2·3단계 배포 스크립트도 같은 날 별도 :8546 노드에 돌려 출력대로 동작함을 확인했다.

설계의 원래 그림(폐기 전용 체인 + 응용 체인의 거울)을 그대로 보이려면 노드를 둘 띄운다. 기본 데모·테스트는 체인 하나로
충분하다(`tests/test_mode3_demo_full.mjs` 를 뺀 모든 테스트는 :8545 하나에 로그와 거울을 함께 둔다). chainid 가 같으면 서명이 두 체인을 구분하지 못하므로
`hardhat.config.cjs` 가 `HARDHAT_CHAIN_ID` 로 두 번째 노드의 chainid 를 바꾼다(기본 31337).

**전제 — 체인 하나 구성에서 옮겨 오면 재시연 세트를 탄다**(아래 "하지 말 것 / 재시연" 의 재시연 세트, 위 "처음 한 번" 0 의 V10
(4)와 같은 이유). 로그를 새로 배포하므로 `cia_state.json` 과 지갑 상태·캐시 파일(`mode3_wallet_state.json`·`mode3_wallet_rcl.json`)을
지우고, `mode3_rp_registration.json` 의 `factoryAddress`·`verifierAddress`·`attrGateAddress` 를 지운다. 이유: CIA 는 빈 새 로그와
로컬 상태(epoch·root)가 어긋나면 기동을 거부하고, RP 는 등록 파일의 옛 팩토리(로그 주소 = 옛 거울)를 그대로 물고 떠서 지갑이 새
거울과 맞지 않는 팩토리를 `bad_factory` 로 거절한다.

1. 폐기 체인: `HARDHAT_CHAIN_ID=31338 npx hardhat node --port 8546` (다른 터미널에 상주).
2. 로그를 폐기 체인에 배포: `CIA_ETH_ADDRESS=<ethAddress> npx hardhat run scripts/deploy_mode3_log.cjs --network revchain`
   (`revchain` = `http://127.0.0.1:8546`, `MODE3_REV_CHAIN_RPC` 로 바꿀 수 있다). 이 단계에서는 `CIA_LOG_ADDRESS` 를 `.env` 에
   넣는다. 스크립트는 한 흐름이라 폐기 체인 위에도 거울을 하나 배포하지만 무해하고, 거울 관련 `.env` 줄은 3단계의 출력으로 채운다.
3. 거울을 응용 체인(:8545)에 배포: `CIA_ETH_ADDRESS=<ethAddress> MODE3_CANONICAL_LOG_ADDRESS=<2의 로그> MODE3_CANONICAL_CHAIN_ID=31338
   npx hardhat run scripts/deploy_mode3_log.cjs --network localhost` — 이 모드는 로그를 배포하지 않고 `canonicalChainId=31338`
   을 가리키는 거울만 배포한다. 이 모드의 출력은 두 노드 구성용이다 — `MODE3_MIRROR_ADDRESS`·`CIA_MIRRORS=31337=…` 와
   "`CIA_CHAIN_RPCS` 에 `31337=http://127.0.0.1:8545` 가 있어야" 만 찍고 `CIA_LOG_ADDRESS` 줄은 찍지 않는다(캐노니컬은 2의 것). (스크립트 없이 손으로 하려면
   `Mode3Mirror(cia, 31338, <로그>, emptyRev, emptyReg)` 를 :8545 에 배포하면 같다 — 빈 root 두 값은 스크립트가 찍는다.)
4. 기동 — `CIA_RPC_URL` 은 `.env` 에 두지 말고 프로세스마다 준다:
   ```
   CIA_RPC_URL=http://127.0.0.1:8546 CIA_CHAIN_RPCS=31337=http://127.0.0.1:8545 node cia.js
   CIA_RPC_URL=http://127.0.0.1:8545 MODE3_REV_CHAIN_RPC=http://127.0.0.1:8546 node mode3_wallet_agent.js
   CIA_RPC_URL=http://127.0.0.1:8545 node mode3_rp.js
   ```
   CIA 는 :8546 에 게시하고 :8545 의 거울로 중계한다(CIA 계정은 두 체인 모두에 가스가 필요하다 — 2·3 이 각각 1 ETH 를 넣는다).
   지갑은 캐노니컬 이벤트를 :8546 에서 읽어 :8545 거울의 epoch 까지만 재생한다. RP 는 :8545 만 본다.

노드 둘이면 블록 높이가 서로 독립이다 — 거울의 root 나이·세션 만료(`max_height`)는 응용 체인(:8545) 블록 기준이고, 캐노니컬
하트비트(`CIA_HEARTBEAT_BLOCKS`)는 폐기 체인 블록 기준이다. 재시연할 때는 두 노드를 함께 다시 띄운다.

지갑 에이전트를 `MODE3_WALLET_SECRETS=snap` 으로 띄우면 MetaMask/Snap 경로가 된다(아래 "MetaMask / Snap 경로" 절). 기본은 `file` 이다.

페이지: 지갑 `http://127.0.0.1:5100/`, RP `http://127.0.0.1:3100/`, CIA 관리자 `http://127.0.0.1:4100/admin`, CIA 사용자 `http://127.0.0.1:4100/account`.

RP 페이지는 반드시 `127.0.0.1`로 연다 — 지갑 에이전트의 CORS 허용 오리진이 `http://127.0.0.1:3100`(`MODE3_RP_ORIGIN`, 쉼표로 여럿 가능)이라 `localhost`로 열면 지갑 호출이 막힌다.

## 언어·전문가 보기 (2026-09-24 UX 개선)

네 페이지 모두 맨 위 안내 바 오른쪽에 토글 둘이 있다.

| 토글 | 하는 일 | `localStorage` 키 | 기본값 |
|---|---|---|---|
| `EN` / `한국어` 버튼 | 화면 문구를 한국어 ↔ English 로 바꾼다 | `mode3.lang` (`ko`\|`en`) | `ko` |
| "전문가 보기" 체크박스 | 아래의 전문가 요소를 켠다 | `mode3.expert` (`1`\|`0`) | 꺼짐 |

둘 다 페이지·오리진마다 브라우저에 기억된다(같은 오리진의 관리자·내 계정 페이지는 설정을 공유하고, 지갑·RP 는 각자
기억한다). 콘솔에서 `Demo.setLang('en')`·`Demo.setExpert(true)` 로도 바꿀 수 있다 — 스크린샷 스크립트가 쓰는 길이다.

**전문가 보기가 켜면 보이는 것**

- 원문 로그 요소 — RP `#log`·`#sessionLog`·`#openLog`, 지갑 `#status`·`#sessionLog`·`#txLog`·`#authLog`,
  관리자·내 계정 `#out`. 이 요소들은 꺼져 있어도 DOM 에 그대로 있다(`textContent` 를 보는 테스트는 영향받지 않는다).
- 결과 카드의 "자세히"(원본 JSON)가 접히지 않고 펼쳐진 채 뜬다.
- 용어 라벨에 원래 기호가 붙는다 — "이 서비스에서의 내 주소 (PPID = Poseidon(uid, s_u, chainid, arid))",
  "로그인 세션 (r_s, pk_i, max_height)", "공개할 속성 조건 (disc_mask, lo[6], hi[6], set_sel, set_root)" 등.
- RP 의 서비스 상태 카드에 `arid`·`cert_s`·`pk_trace`·`Mode3Log`·팩토리·`AttrGate` 주소 한 줄, 로그인 기록 표에
  `세션 r_s`·`폐기 목록 root` 열, 관리자 서비스 표에 `서비스 식별자`(arid) 열이 더 나온다.
- RP (내 세션) 카드의 **"skipSync (stale_root 시연)" 체크박스**(UI 라벨은 그대로다) — 각본 5 시연은 이제 **전문가 보기를
  먼저 켜야** 보인다. 체크박스 이름은 `stale_root` 지만 V9 에서 각본 5(계정 폐기 뒤)의 실제 결과는 등록부만 바뀐
  `stale_registry_root` 다 — 폐기 목록(revocation list) 쪽이 낡았을 때라면 이름 그대로 `stale_root` 가 나온다.

## 페이지 구성 (2026-09-24 UX 개선)

페이지마다 맨 위 안내 바(7단계 진행 표시 + "다음에 할 일" 한 줄 + 다른 페이지로 가는 링크) 아래에 카드가 놓인다.

| 페이지 | 카드 |
|---|---|
| 지갑 `:5100/` | 내 신원 · 로그인 세션 · 트랜잭션 보내기 · MetaMask · Snap(`snap` 모드에서만 보인다). `?authorize=1` 팝업은 "로그인 승인" 카드 하나만 |
| 서비스 `:3100/` | 서비스 상태 · 로그인 · 내 세션 · 로그인 기록 · 승인 개봉 |
| 관리자 `:4100/admin` | 인증 · 최근 결과 / 계정 / 서비스 / 개봉 요청 / 폐기 목록 |
| 내 계정 `:4100/account` | 내 계정 폐기 (하나) |

알아 둘 것:

- 조작 결과는 **결과 카드**(판정 배지 + 한 줄 요약 + 접힌 "자세히")로 뜬다. 세션 폐기도 마찬가지다 — 원문은 전문가
  보기의 로그 요소에 그대로 남는다.
- **되돌릴 수 없는 버튼**은 빨간 테두리로 표시하고 누르면 확인창이 한 번 뜬다 — 관리자의 "계정 폐기"·세션 목록의
  "폐기"·"게시(체인에 올리기)", 지갑의 "이 세션 끝내기(폐기)"·"계정 자기 폐기"·"Snap 초기화", 내 계정 페이지의
  "내 계정 폐기". (서비스·개봉 요청의 "거절" 도 되돌릴 수 없지만 확인창은 없다.)
  **브라우저 자동화는 이 대화상자를 받아야 한다**(`page.on('dialog', d => d.accept())`).
- 관리자 페이지의 **계정 폐기는 경로가 하나다** — (계정) 카드의 uid 칸에 값을 넣고 "계정 폐기" 를 누른다. 목록 행의
  "선택" 버튼은 그 uid 를 칸에 채워 줄 뿐이다.
- 관리자 (인증 · 최근 결과) 카드에 **대기 배지**("승인 대기 서비스 N", "개봉 요청 N", 없으면 "대기 중인 건 없음")가
  있어 승인할 것이 남았는지 한눈에 보인다. RP 페이지에도 "승인 대기"/"활성" 배지가 있다.
- 관리자 시크릿은 요청 헤더로만 나가고 화면·결과 카드·원문 로그 어디에도 실리지 않는다. "이 창에서 기억"(기본 꺼짐)을
  켠 동안만 `sessionStorage` 에 둔다.
- 공통 레이어(`mode3/common/{strings.js,demo.js,demo.css}`)는 세 서버가 각자 **`/common`** 으로 정적 제공한다
  (`cia.js`, `mode3_wallet_agent.js`, `mode3_rp.js`). 이 경로가 404 여도 페이지는 마크업에 박아 둔 **한국어 기본
  문구**로 계속 돈다 — 토글과 안내 바만 사라진다(설계 §5).

## 상태 패널 (2026-09-25 UX 2차)

네 페이지 모두 안내 바 오른쪽, 언어·전문가 토글 왼쪽에 **점 4개**가 있다. 색만으로 구분하지 않는다 — 점마다 라벨이
붙고 `title`·`aria-label` 에 판정 문구가 들어간다.

| 점 | 무엇을 읽는가 |
|---|---|
| 신원 기관 | CIA 의 `GET /mode3/health` |
| 서비스 | RP 의 `GET /mode3/health` |
| 지갑 | 지갑 에이전트의 `GET /mode3/health` |
| 체인 | 신원 기관 → 서비스 → 지갑 **고정 순서**로 처음 `chain` 을 준 응답의 값(체인 id·블록 높이). 먼저 도착한 응답이 아니라 이 순서다 |

점을 누르면 안내 바 아래에 **상태 패널**(`#stackPanel`)이 전폭으로 펼쳐진다 — 역할마다 판정 한 줄, 노랑·빨강이면
원인·조치·사유 코드(`root_too_old`·`registration_pending`·`cia_unavailable`, 서비스 비활성은 서버가 준
`inactiveReason`), 전문가 보기에서는 그 역할의 원본 JSON 까지. 바깥을 누르거나 Esc 로 닫는다.

읽기는 **5초 폴링**, 요청마다 3초 예산이다(서버 쪽 체인 조회 예산 1.2초보다 넉넉하고 폴링 간격보다는 짧다). 탭이 숨겨져 있으면 읽지 않고 다시 보이면 즉시 한 번 읽는다. 실패는
콘솔에 남기지 않고 점 색과 패널 문구로만 말한다. 자기 서버는 상대 주소 없이 `/mode3/health` 로 부르고(같은
오리진이라 CORS 를 타지 않는다), 상대 주소는 `rp_info`·`/wallet/status`·상대 health 응답에서 알아낸다. **아직 주소를
모르는 역할은 빨강이 아니라 회색(모름)** 이다. 응답의 `role` 이 기대와 다르면 오류로 본다(엉뚱한 서버를 초록으로
속이지 않는다).

**판정(설계 §2.2, `tests/test_mode3_stack_judge.js` 가 고정)**

| 점 | 초록 | 노랑 | 빨강 | 회색 |
|---|---|---|---|---|
| 신원 기관 | 아래 어느 것도 아님 | root 나이가 상한의 절반 이상(`rootAge ≥ maxRootAge/2`, 또는 하트비트 간격이 상한 이상), 아직 게시 안 한 폐기가 있음 | root 게시가 상한(`maxRootAge`) 이상으로 오래됨, 응답 없음 | 첫 폴링 전 |
| 서비스 | 승인됨 + 활성 | 승인 대기 | 비활성(사유는 `inactiveReason`), 응답 없음 | 첫 폴링 전 |
| 지갑 | 등록됨 + 신원 기관에 닿음 | 신원 기관에 못 닿음 | 응답 없음 | 아직 등록 전, 주소 모름 |
| 체인 | 셋 중 하나라도 `chain` 을 줌(블록 높이를 보인다) | — | 아무도 체인을 못 읽음 | 첫 폴링 전 |

상한(`maxRootAge`)은 서비스가 체인에서 읽은 값이 정본이고, 서비스가 없으면 신원 기관의 하트비트 간격 2배를 임시로 쓴다.

### `GET /mode3/health`

세 서버(`cia.js`·`mode3_rp.js`·`mode3_wallet_agent.js`)가 모두 연다. 응답 조립은 `lib/mode3_health.js` 한 곳이고,
**민감한 값은 어느 깊이에도 넣지 않는다** — `uid`·PPID·비밀·`sk_u`/`pk_u`·`pk_CIA`·`arid`·`r_s` 가 없다
(`tests/test_mode3_health_shape.js` 가 고정한다). root 는 앞 12자만 남겨 축약한다. 싣는 것은 **이 데모가 공개로 다루기로
한 개수와 오리진뿐이다**(`rpOrigins`·`pendingOpenings`·`accounts`·아래 카운터 등) — 설계상의 선택이다(스펙 §1.1).

```
aa     {"role":"aa","ok":true,"now":…,"chain":{"id":"31337","head":"13"},"root":"1810138…","epoch":0,
        "lastPublishedBlock":"11","rootAge":2,"heartbeatBlocks":0,"pendingLeaves":0,"pendingRps":0,
        "pendingOpenings":0,"accounts":0,"walletOrigin":…,"rpOrigins":[…],
        "mirrors":[{"chainId":"31337","address":"0x…","epoch":"4","lastPublishedBlock":"40","rootAge":3,"behind":1}]}
rp     {"role":"rp",…,"status":"approved","active":true,"inactiveReason":null,"maxRootAge":100,"rootAge":null,
        "sessions":0,"requests":0,"disclosures":0,"predicates":{"countries":5,"minAge":19},"walletAgentOrigin":…,"ciaUrl":…}
wallet {"role":"wallet",…,"secrets":"file","registered":false,"hasCred":false,"sessions":0,"txs":0,"disclosedTxs":0,
        "ciaReachable":true,"rpOrigin":…,"ciaUrl":…}
```

- **V10 `mirrors`(CIA)**: `CIA_MIRRORS` 의 거울마다 `epoch`·`lastPublishedBlock`·`rootAge`(그 체인 head − 마지막 게시 블록)·`behind`
  (캐노니컬 epoch − 거울 epoch). 서비스는 거울만 읽으므로 **`behind > 0` 이면 그만큼의 폐기·발급이 아직 서비스에 안 보인다**.
  거울을 못 읽으면 항목을 빼지 않고 값을 `null` 로 낸다. 같은 목록이 `GET /cia/public_keys` 의 `mirrors`(`{chainId, address}`)와
  `canonicalChainId` 로도 나온다.
- **V10 카드 한 줄씩**: 관리자 (폐기 목록) 카드 아래 "거울 chain X: epoch E (캐노니컬 대비 −n), 마지막 게시 블록 B"(`/mode3/health`
  의 `mirrors`), 서비스 (서비스 상태) 카드 "거울 주소 … / 캐노니컬 로그 …"(`rp_info` 의 `mirrorAddress`·`logAddress`), 지갑
  (로그인 세션) 카드 "거울 epoch E / 캐노니컬 epoch E′"(`/wallet/status` 의 `mirror{address, epoch, lastPublishedBlock}`·
  `canonical{rpc, logAddress, epoch}`). 문구 키는 `admin_mirror_line`·`admin_mirror_unreadable`·`rp_mirror_line`·`wallet_mirror_line`.
- 응답에는 **`Cache-Control: no-store`** 와 `Vary: Origin` 이 늘 붙는다.
- `Access-Control-Allow-Origin` 은 **허용 목록에 있는 `Origin` 으로 물었을 때만** 붙는다(다른 오리진에는 아예 없다).

| 서버 | 허용 오리진 |
|---|---|
| CIA `:4100` | 승인된 서비스들의 origin + 지갑 오리진(`MODE3_WALLET_AGENT_ORIGIN`, 기본 `http://127.0.0.1:5100`) |
| 서비스 `:3100` | 지갑 오리진(`MODE3_WALLET_AGENT_ORIGIN`) + `MODE3_CIA_URL` |
| 지갑 `:5100` | 서비스 오리진 목록(`MODE3_RP_ORIGIN`, 쉼표 구분) + `MODE3_CIA_URL` |

CIA 는 지갑 오리진을 알 방법이 없으므로 **`MODE3_WALLET_AGENT_ORIGIN`** 으로 받는다(승인된 서비스 origin 은 CIA 가
스스로 안다). 기본값이 아닌 포트로 지갑을 띄웠다면 CIA 에도 같은 값을 줘야 한다 — 관리자·내 계정 페이지는 CIA health 의
`walletOrigin` 으로 지갑을 찾으므로, 값이 없으면 지갑 점이 회색(주소 모름)에 머물고 값이 틀리면 CORS 에 막혀 빨강이 된다. 지갑의 `ciaReachable` 은 health 를 줄 때 CIA 의 `/cia/public_keys` 를 1.5초 예산으로 **뒤에서** 찔러 본 결과다 —
응답은 기다리지 않고(그래야 CIA 가 느려도 health 가 늦지 않는다) 결과를 10초 동안 재사용한다. 그래서 CIA 를 내리면
지갑 점은 두세 번의 폴링 뒤에 노랑이 된다.

`requests`·`disclosures`(서비스)와 `txs`·`disclosedTxs`(지갑)는 체험 모드의 4·5단계 판정에 쓰는 **프로세스 안 카운터**다.
개수만 싣고(무엇을 공개했는지는 싣지 않는다) **서버를 다시 띄우면 0 부터** 센다 — 그러면 그 두 단계는 다시 "안 한 것"으로
보인다(화면 표시만 그렇고 실제 세션·트랜잭션과는 무관하다). 서비스 쪽 `requests` 는 세션 요청(`/api/mode3/request`)만
세고 재검증은 세지 않는다 — 재검증은 서비스 페이지가 자기 메모리로 안다.

## 체험 모드 (2026-09-25 UX 2차)

안내 바 오른쪽의 **"체험 모드"** 스위치. 기본은 꺼짐이고 `localStorage` 의 `mode3.tour`(`1` 또는 빈 값)에 기억된다.
켜면 (1) 지금 눌러야 할 버튼에 말풍선 하나(`#tourBubble`)가 붙고, (2) 순서를 앞지르는 버튼이 잠기고 사유 배지가
붙는다. 끄면 말풍선·잠금·배지가 즉시 사라지고 버튼은 페이지의 원래 규칙으로 돌아간다.

**다른 창으로 나른다** — 켜져 있으면 안내 바·카드의 링크에 `?tour=1` 이 붙는다. 그 링크로 열린 창은 값을 자기
저장소에 새기고 **주소창에서는 쿼리를 지운다**(`?tour=0` 이면 끈다). 오리진마다 저장소가 다르기 때문이다. 지갑의
승인 팝업(`?authorize=1`)에는 체험 모드를 만들지 않는다.

**잠금 규칙**

| 페이지·버튼 | 잠기는 조건(상대 health) | 배지 문구 |
|---|---|---|
| 지갑 "등록"(`#registerBtn`) | 서비스가 아직 승인 전(`rp.status !== 'approved'`) | "먼저 관리자가 서비스를 승인해야 합니다" |
| 서비스 "로그인"(`#loginBtn`) | 지갑이 아직 등록 전(`wallet.registered === false`) | "먼저 지갑에서 등록하세요" |

그 밖의 버튼(재검증·요청·트랜잭션·폐기·개봉)은 잠그지 않는다 — 원래 규칙 그대로다. 처리 중인 버튼(`data-tour-busy`)도
폴링이 건드리지 않는다.

**health 를 모르면 잠그지 않는다.** 아직 한 번도 못 읽었거나 그 역할의 응답이 없으면 조건은 "모름"이고, 그때는
페이지의 원래 활성 규칙을 쓴다(막히는 것보다 열려 있는 편이 안전하다). 그래서 상대 서버가 꺼져 있어도 체험 모드가
시연을 멈추지 않는다.

**말풍선과 카드**

- 대상이 이 페이지에 있으면 말풍선이 그 요소 바로 아래에 앉는다(누를 것이 깔려 있으면 오른쪽, 그래도 막히면 그 카드
  아래). 누를 수 있는 요소는 덮지 않지만 **바로 아래 카드의 제목 줄은 가린다** — 배경막 없는 코치마크라 의도된
  겹침이다. 좁은 창(≤900px)에서는 전폭이다.
- 대상이 다른 창에 있으면 안내 바 안에 카드가 뜬다 — "지금은 {당사자} 창에서 진행할 차례입니다" + `?tour=1` 이 붙은
  **"다음 단계로"** 링크.
- 7단계를 모두 마치면 같은 자리에 **"체험 완료"** 카드가 뜬다.

**단계 판정** — 체험 모드가 **켜져 있을 때만** 7단계를 한 곳(`Demo.tour.evaluate`)에서 판정한다. 꺼져 있으면 각
페이지가 1차(2026-09-24)의 자기 규칙으로 안내 바를 그린다.

1~3 단계는 서버 사실(health: 서비스 승인·지갑 등록·세션 수)과 페이지가 자기 눈으로 본 사실을 OR 한다. 4·5 단계도
마찬가지로 페이지 메모리와 서버 카운터(`rp.requests`/`wallet.txs`, `rp.disclosures`/`wallet.disclosedTxs`)를 OR 한다 —
관리자·계정 페이지에는 이용·공개의 페이지 메모리가 없기 때문이다. 6 은 `aa.pendingLeaves > 0` 또는 **이 창이 열려 있는
동안** 관측한 epoch 상승, 7 은 서비스의 개봉 결과(페이지 메모리) 또는 관리자의 `pendingOpenings` 가 1 이상에서 0 으로
떨어지는 관측이다.

> **알려진 비대칭(그대로 두는 것)**: 6단계(폐기·복구)는 **게시하고 나서 새로고침하면 다시 "안 한 것"으로 돌아간다.**
> 게시하면 `pendingLeaves` 가 0 이 되고 epoch 상승은 그 창이 열려 있는 동안에만 기억하기 때문이다. 화면 표시만
> 그렇고 실제 폐기 효력과는 무관하다.

## 시연 각본

버튼 이름은 2026-09-24 UX 개선(설계 `docs/superpowers/specs/2026-09-24-mode3-demo-ux-design.md`) 뒤의 화면 문구다.
괄호 안은 그 버튼이 있는 카드다. 5 의 "skipSync (stale_root 시연)" 처럼 **전문가 보기에서만 보이는** 것은 따로 적었다.

| # | 어디서 | 조작 | 기대 |
|---|---|---|---|
| 0 | 관리자 | (서비스) "목록 불러오기" → 해당 행의 "승인" (RP 첫 기동 뒤 한 번) | RP 페이지가 "승인 대기" → "활성" |
| 1 | 지갑 | (내 신원) "등록" — uid `12345` / pwd `password123` | 결과 카드 `등록됨`, 속성은 AA 기록값(`[1990, 410, 0, 0, 0, 0]`, 지갑 화면에는 `출생연도 1990 · 국가 KR` 로 보인다)이 응답으로 내려온다 — "속성과 선택 공개" 절 참고 |
| 2 | RP | (로그인) "로그인" ("AI 에이전트 허용" 체크 여부) | 결과 카드 `로그인 성공` 과 한 줄 요약("새 세션 …") — PPID·r_s·allowAgent·`새 발급=true` 는 카드의 '자세히'(전문가 보기에서는 펼쳐진 채)와 (로그인 기록) 표에서 본다. 지갑 (내 신원) 카드의 등록부 확인 줄이 `등록부에서 확인됨`(슬롯 N)으로 바뀐다(V9 §8.2) |
| 2a | 지갑 | (트랜잭션 보내기) "보낼 세션" 선택 → "트랜잭션 보내기" | 첫 번째 `deployed=true`·`ok=true`, 두 번째 캐시 히트·`nonce=1` |
| 2b | 지갑 → RP → 관리자 → RP | 지갑 페이지의 txHash 를 RP (승인 개봉) "트랜잭션 해시" 에 붙여 넣고 "해시로 요청" → 관리자에서 승인 → RP "결과 확인" | `uid=12345`, AI 에이전트 허용 여부 |
| 3 | RP | (내 세션) "세션 재검증" | `캐시 히트=true`, 증명 0 ms, 결과 카드 `재검증 성공` |
| 3′ | RP | (내 세션) "세션 요청 보내기" | 세션키 서명 검증 ok |
| 3″ | RP | (로그인) "로그인" (다시) | 새 세션 = `새 발급=true`, **같은 PPID** |
| 4 | 관리자 | (계정) uid 를 넣고 "계정 폐기" → (폐기 목록) "게시(체인에 올리기)" | V9: 계정 폐기 자체가 **등록부 슬롯을 0 으로 즉시 게시**한다(`published:true`, epoch +1) — 뒤이은 "게시" 는 더 낼 것이 없어 `published:false` |
| 4′ | 사용자 페이지 → 관리자 | (4 대신) 내 계정 페이지의 "내 계정 폐기" → 관리자 "게시(체인에 올리기)" | `disabled:true`, 이후 5~8 동일 |
| 4″ | 지갑 → 관리자 → RP | (4 대신, V8) 세션 둘을 만든 뒤 지갑 (로그인 세션) 목록에서 한 세션의 "이 세션 끝내기(폐기)" → 관리자 "게시(체인에 올리기)" → RP 에서 두 세션을 각각 재검증 | **세션 하나만 죽는다** — 폐기한 세션은 지갑에서 이미 사라져 재검증이 404 `no_session`(지갑 밖에서 관리자가 폐기했으면 403 `revoked_session`), 다른 세션은 그대로 ok, 새 로그인도 ok(같은 PPID). 계정 폐기(4)와 달리 `account_disabled` 가 아니다 |
| 5 | RP | **전문가 보기를 켜고** (내 세션) "skipSync (stale_root 시연)" 체크 → "세션 재검증" | 거절 `stale_registry_root`(체크박스 이름은 `stale_root` 지만, V9 의 계정 폐기(4)는 등록부만 바꾸므로 실제 결과는 이것이다 — 아래 "RP 거절 사유" 참고). "세션 요청 보내기" 는 `revalidate_required` |
| 5a | 지갑 | (폐기·게시 뒤) "트랜잭션 보내기" | `revoked` |
| 6 | RP | 체크 해제 → "세션 재검증" → "로그인" | 지갑 `revoked` → 새 로그인은 `account_disabled` |
| 7 | 관리자 | (계정) "복구(다시 쓰게)" | `disabled:false` |
| 8 | RP | (로그인) "로그인" | `새 발급=true`, 성공, **PPID 가 2 와 같다** |
| 9 | RP → 관리자 → RP | (로그인 기록) 행의 "개봉 요청"(또는 (승인 개봉) 카드에 PPID 를 넣고 "개봉 요청") → 관리자 (개봉 요청) "목록 불러오기" → "승인" → RP "결과 확인" | 202 pending → approved → uid=12345 |
| 10 | 관리자 → 지갑 | (계정) 목록 행의 "슬롯 바꿔치기(시연)" → 지갑 "로그인" → 관리자 "되돌리기" → 지갑 "로그인" | 바꿔친 뒤 로그인은 `로그인 실패`(`registry_mismatch`) — 지갑이 로그인을 시도조차 하지 않는다. 되돌린 뒤 로그인은 다시 성공하고 PPID 는 그대로다 |
| 11 | 관리자 → 지갑(전문가 보기) | (계정) 속성을 바꿔 "저장"(활성 자격증명을 물린다) → 지갑 (시연: 비밀 바꾸기) salt 를 바꾸고 범위 "다음 발급" → "적용" → "로그인"; uid 로 같은 절차 반복; "원래대로" → 정상 로그인으로 복구 → 범위 "다음 증명" 으로 salt 를 바꾸고 "적용" → "로그인" | salt·uid 덮어쓰기(발급)는 둘 다 `로그인 실패`(`user_cred_failed` — CIA 가 "bad user credential proof" 로 거절). 증명 덮어쓰기는 `demo_proof_failed` 로 구분된다. 둘 다 "원래대로" 로 덮어쓰기를 풀고 다시 로그인하면 복구된다 |
| 12 | 관리자 | (계정) 목록의 "슬롯" 열 | testuser(`12345`)는 슬롯 0, alice(`67890`)는 슬롯 1 — 등록 순서대로 배정되고, 각자 로그인하면 서로 다른 PPID 를 받는다. V10: 계정 폐기(4·4′)를 거쳐 복구된 계정은 **새 슬롯**(다음 빈 번호)을 받고 지갑 (내 신원) 카드의 슬롯도 그것으로 바뀐다 — 은퇴한 슬롯은 다시 쓰지 않는다 |
| 13 | 지갑 → 관리자 → RP → 관리자 → RP | (V10 거울 지연) 세션 둘을 만든 뒤 관리자 (계정) "세션" 에서 하나를 "폐기" → "게시(체인에 올리기)" → RP 에서 살아 있는 세션 "세션 재검증"·"세션 요청 보내기" → `POST /cia/admin/relay`(위 "매번: 기동 순서") → 다시 "세션 요청 보내기" → "세션 재검증" → 폐기한 세션 재검증 | 게시 직후 관리자 카드의 거울 줄이 "캐노니컬 대비 −1" — 이때 재검증은 `캐시 히트=true` 로 성공하고 세션 요청도 통과한다(서비스는 거울만 본다 = **지연 창**). relay 뒤 거울 줄이 −0 이 되고, 세션 요청은 `revalidate_required` — "세션 요청 보내기" 는 누를 때마다 새로 서명하므로 서명이 낡아서가 아니라 세션에 묶인 root 와 거울 root 의 비교가 실패한 것이다. 재검증은 새 π(`캐시 히트=false`)로 성공, 폐기한 세션은 지갑 403 `revoked_session` |
| 14 | 사용자 페이지 → 체인 → 관리자 → 관리자 → RP | (V10 접수증 강제) 내 계정 페이지의 "내 계정 폐기" — 응답(전문가 보기 원문)의 `receipt` 를 복사 → 아래 "계정 폐기 접수증" 절의 콘솔 명령으로 `requestRevocation` → 관리자 "게시(체인에 올리기)" → (계정) "복구(다시 쓰게)" → RP "로그인" | `pendingSlots()` 가 `[slot]` → 게시가 그 슬롯을 0 으로 실어 통과(`published:true`) 뒤 `[]`, `isRetired(slot)=true`. 복구 뒤 로그인은 성공·**PPID 동일**, 슬롯은 새 번호 |

온체인 실행은 트랜잭션마다 π 를 첨부하고 컨트랙트가 매번 검증한다(가스 실측, `Mode3Wallet.execute()` 정상 실행 — EOA 로 value 0
호출, 계정 배포 제외: V4 회로 387,675, V5 회로 356,441~356,477, V6 회로(2026-09-22, 선택 공개, 공개 입력 23개, 이전 baseline)
mask=0 캐시 π 402,079(402,035–402,091), mask=3(선택 공개) + `AttrGate.claim` 444,973(444,881–444,997) —
`results/mode3_disclosure_bench_20260922.md`. **V7 회로(2026-09-23, 집합 소속 술어, 공개 입력 25개, V8 이전 판)
mask=0 캐시 π 415,991(415,991–416,035), 범위만(mask=1, set 없음) 421,052(420,996–421,076), 집합만(mask=0 + set)
421,436(421,388–421,460), 범위+집합 + `AttrGate.claim`(새 π) 455,138(455,094–455,174)** — `results/mode3_predicates_20260923.md`,
`node scripts/bench_mode3_onchain.mjs` 출력).
**V8 회로(2026-09-24, 세션 폐기, 공개 입력 25개 그대로 — 지금 데모가 쓰는 회로) — gas 는 V7 과 사실상 같다**: mask=0 캐시 π
416,015(416,003–416,059), 범위만 421,076(421,020–421,100), 집합만 421,428(421,368–421,484), 범위+집합 + `AttrGate.claim`
455,162(455,142–455,174), 계정 배포 908,232, `PiCredVerifier` 배포 874,396, `Mode3WalletFactory` 배포 1,483,740
(`results/mode3_session_revocation_20260924.md`). **오프체인 비용은 올랐다**: 제약 27,329 → **37,130**, 증명 시간(pi_cred)
832.8 ms → **1,191.7 ms**, zkey 16.4 MB → **23.4 MB**(검증 10.0 ms 는 그대로). 비멤버십 증명이 하나 더 붙은 값이다.
**컨트랙트 변경 뒤 재측정(2026-09-25 — 지금 값)**: 회로·zkey·`PiCredVerifier.sol` 은 V8 그대로이고, 커밋 `4aa5589` 가 마스크 밖
슬롯 거절(`BadDisclosure`)과 σ_tx 다이제스트 5워드 확장(`max_height`·`allowAgent`·태그)을 넣어 gas 가 조금 올랐다. mask=0 캐시 π
**417,533**(417,509–417,577), 첫 tx **434,665**, 범위만 **422,366**(422,298–422,378), 집합만 **422,982**(422,946–423,026),
범위+집합 + `AttrGate.claim` **456,439**(456,383–456,463), 계정 배포 **939,808**, `Mode3WalletFactory` 배포 **1,517,288**,
`PiCredVerifier` 배포 **874,396**(`results/mode3_review_fixes_20260925.md`). 실행당 +1,300~1,550(+0.31~0.37%)은 다이제스트의
`abi.encode`·keccak 입력이 160바이트 커진 것과 마스크 위생 루프의 calldata 읽기 8회가 합쳐진 값이다 — 공개 입력 수(25)가
그대로라 Groth16 검증 비용은 바뀌지 않았다. 배포 gas 가 3만대 오른 것은 `Mode3Wallet` 바이트코드가 커졌기 때문이고, 팩토리는
그 `creationCode` 를 품고 있어 같이 오른다. `PiCredVerifier` 가 **정확히 0 차이**인 것은 생성된 검증자를 건드리지 않았다는
증거다. 오프체인 비용(제약 37,130, 증명 1,191.7 ms, zkey 23.4 MB)은 회로가 그대로라 V8 과 같다.
root 게시가 `MAX_ROOT_AGE` 블록보다 오래되면 `RootTooOld` 로 멈추므로 CIA 하트비트를 켜 둔다.
트랜잭션은 지갑 페이지에서만 시작한다 — 서비스 페이지는 지갑의 `/wallet/tx` 를 부를 수 없다(CORS).

성명은 로그인마다 새로 발급되고(설계 2026-09-15 §5) 세션 r_s 안에서만 재사용된다. RP 는 r_s 를 로그인 때 한 번 소비하고 그 뒤 세션 식별자로 쓴다. 폐기는 재검증에서 효력을 갖는다.

자격증명은 이중 구조다(설계 2026-09-21). 지갑은 첫 로그인 때 `POST /cia/user_cred` 로 **사용자 자격증명**(C_u, 사용자당 하나 — 속성을 담고
CIA 는 값을 모른다)을 받아 두고, 로그인마다 그 위에 `POST /cia/issue` 로 **세션 자격증명**(C_s)만 새로 받는다(ZKP 없음, 발급이 빠르다).
**계정 폐기 = 사용자 자격증명 리프 하나**이고, 그 사용자의 모든 세션(모든 서비스)이 다음 게시에 함께 무효가 된다. 지갑은 폐기된 사용자
자격증명을 다음 로그인의 동기화에서 알아채 새로 받는다(복구 뒤 8 의 `userCredMs > 0`). 상태 페이지의 "사용자 자격증명" 줄이 있음/없음/폐기됨을 보인다.

9 는 승인된 개봉(설계 2026-09-16 §6)이다. 로그인마다 지갑이 서비스의 조합 키 pk_trace 로 uid 를 암호화한 태그를 증명에 넣고
(조건 ⑤), 서비스는 자기 조각으로 반만 풀어 CIA 에 낸다. 운영자가 승인하면 CIA 가 자기 조각으로 마저 풀어 uid 를 돌려준다 —
서비스 혼자도, CIA 혼자도 열 수 없고, 열리는 것은 그 세션의 uid 하나다. CIA 는 로그인당 아무것도 저장하지 않는다.

0~9·3′·3″·4″·10·12·13·14 는 `tests/test_mode3_demo_stack.mjs`(HTTP)로, 2·3·4 의 라이브러리 판은 `tests/test_mode3_e2e.mjs` 로 고정돼 있다.
11(시연 카드)은 같은 파일의 "각본 11(V9)" 하나로 묶여 있다(UI 버튼 대신 `/wallet/demo/override` 를 직접 부른다).

credential 은 발급 시점 head 기준 300~400 블록(그리드 양자화)에 만료되며 지갑 상태 페이지에 `max_height` 로 보인다.

4′ 은 관리자 없이 사용자가 스스로 폐기하는 경로다(설계 §6.5.1). 인증은 계정 비밀번호이고 지갑 키가 아니다 —
장치를 잃은 사용자에게 지갑 키는 없고 공격자에게는 있기 때문이다. 처리와 게시는 4 와 같고, 복구는 여전히 관리자만 한다.

### 체험 모드로 한 번에

처음 보여 주는 자리라면 위 표를 외우지 않고 체험 모드를 켜고 말풍선만 따라가도 된다.

1. 관리자(`:4100/admin`)를 열고 안내 바의 **"체험 모드"** 를 켠다. 시크릿을 넣고, 말풍선이 가리키는 (서비스)
   "목록 불러오기" → 해당 행 "승인" (1단계).
2. 카드가 "지금은 지갑 창에서 진행할 차례입니다" 로 바뀌면 **"다음 단계로"** 를 누른다 — 새로 열린 지갑 창도
   체험 모드가 켜진 채 뜬다.
3. 지갑에서 말풍선이 가리키는 **"등록"** (2단계).
4. 카드의 링크로 서비스 창을 연다. 등록 전에 열었다면 "로그인" 이 잠긴 채 "먼저 지갑에서 등록하세요" 배지가 붙어
   있고, 등록이 끝나면 **다음 폴링(최대 5초)에 저절로 풀린다**. 말풍선이 가리키는 **"로그인"** (3단계).
5. 그다음은 말풍선을 따라간다 — 세션 재검증(4단계) → 공개할 속성 조건을 골라 트랜잭션(5단계) → 폐기 뒤 관리자에서
   게시(6단계) → 개봉 요청·승인(7단계). 일곱 단계를 마치면 "체험 완료" 카드가 뜬다.

정확한 조작과 기대 결과는 위 표(0~9)가 정본이다. 체험 모드는 순서를 잡아 줄 뿐 새로운 조작을 만들지 않는다.

## 속성과 선택 공개 (설계 2026-09-22)

**속성 출처와 스키마(스펙 2, 2026-10-07).** 속성은 **AA(`cia.js`) 계정 기록**이고 관리자만 바꾼다. 정본은 사람이 읽는 `profile`(스키마 이름 → 값)이고,
회로·서명·Snap 이 쓰는 `attrs`(10진 문자열 6개)는 **공개 스키마**가 정한 규칙으로 인코딩한 값이다. 기본 스키마 `zkd-attrs` v1:
`a₀ birthYear`(int 1900~2100, 범위 술어 가능), `a₁ country`(enum — ISO 3166-1 숫자 코드: KR 410, JP 392, US 840, DE 276, FR 250, GB 826, CN 156,
CA 124, AU 36, SG 702), `a₂ extra1`·`a₃ extra2`(string — NFC·UTF-8 을 Poseidon 으로 64비트(1 ≤ v < 2^64)로 줄인 값, 일방향이라 화면은 `profile` 원문을 보인다),
`a₄`·`a₅` 미사용(항상 0). 범위 술어는 int 슬롯에만, 집합 술어는 int·enum·string 슬롯에만 걸 수 있다 — 어기면 지갑이 400 `predicate_type`.
스키마와 해시는 `GET /cia/attr_schema`(인증 없음)로 공개되고 `/mode3/health.attrSchema`·`/wallet/status.attrSchema`·`rp_info.predicates.attrSchema` 에 id·version·hash 가 실린다.
IdP 는 `CIA_ATTR_SCHEMA_FILE`(JSON)로 다른 스키마를 쓸 수 있다(검증 실패는 기동 거부). 데모 계정 profile 은 그 스키마에 관대하게 맞춘다 —
스키마에 없는 키는 버리고 없는 int·enum 키는 빈 값으로 채우며, 그래도 인코딩되지 않으면(범위 밖 연도, 표에 없는 국가) 기동 거부.
상태 파일은 계정 `attrs` 를 인코딩한 스키마의 해시(`attrSchemaHash`)를 기억하고, **다른 스키마로 띄우면 기동을 거부한다**(다시 인코딩하는
경로는 없다 — 스키마를 되돌리거나 상태 파일을 새로 시작한다). RP 는 CIA 가 준 스키마가 검증에 실패하면 기동 거부, CIA 에 닿지 못하면
기본 스키마 + 경고. 지갑은 검증 실패면 술어가 있는 로그인·tx 를 503 `schema_invalid` 로 거절하고(술어 없는 요청은 그대로), 닿지 못하면
기본 스키마 + 경고로 두고 60초마다 뒤에서 다시 받아 본다(요청마다 CIA 를 부르지 않는다). 데모 계정: `testuser`(uid 12345) `{birthYear: 1990, country: KR}` → `[1990, 410, 0, 0, 0, 0]`,
`alice`(uid 67890) `{birthYear: 2005, country: US}` → `[2005, 840, 0, 0, 0, 0]`. 슬롯 하나는 **64비트**(`[0, 2^64)`, 회로 `Num2Bits(64)`·`LessEqThan(64)`) 범위다 — `lib/mode3_credential.js` 의 `ATTR_MAX`.

**관리자 속성 변경.** CIA 관리자 페이지(또는 `POST /cia/accounts/:uid/attrs` 본문 `{ profile: { birthYear, country, extra1?, extra2? } }` — 전체 교체라
생략한 string 필드는 빈 값(0)이 된다, `requireAdmin`)에서
속성을 바꾸면 그 계정의 **활성 C_u 가 물린다**(등록부 슬롯 0 → 즉시 게시). 인코딩 실패(표에 없는 국가, 범위 밖 연도, 124바이트 넘는 문자열)는
400 `bad_attr`(슬롯·이유), 출생연도·국가의 빈 값도 400 `bad_attr`(이유 `empty` — 출생연도 0 은 "값 없음"인데 온체인 나이 검사를 통과한다,
아래 "수용한 한계"), 예전 `{ attrs: [...] }` 형식은 400 `use_profile`. 저장하는 `profile` 은 정규형이다(국가 코드 `410` 으로 보내도 `KR`,
연도 앞자리 0·앞뒤 공백 제거). 인코딩한 `attrs` 가 지금과 같으면(예: `410` ↔ `KR`) `profile` 만 저장하고 자격증명은 물리지 않는다(`retired: 0`). `GET /cia/accounts` 로 전 계정의 `profile`·`attrs`·`disabled`·`activeCf_u` 를 볼 수 있다.
**상태 파일 v11 이행**: 옛 `attrs` 에서 `profile` 을 되살리되 새 스키마로 표현할 수 없는 값(옛 등급 슬롯 2, 예비 슬롯의 0 아닌 값, 표에 없는 국가 코드)은 버리고,
그래서 `attrs` 가 바뀐 계정은 기동이 활성 자격증명을 물려 슬롯 0 을 자동 게시한다 — 지갑은 다음 로그인에서 재동기화로 새 C_u 를 받는다(기동 전 상태 파일 백업 권장).
시각 상관 주의사항(옛 리프가 게시되는 블록에 세션이 죽고 곧 재로그인하므로 그 게시의
리프 수가 익명 집합)은 이중 구조 설계(2026-09-21 §2)와 같다 — 속성 변경 직후 `/cia/publish` 를 따로 부르지 말고 하트비트 게시에
묶이게 둔다.

**지갑의 재동기화.** 속성이 바뀌면 지갑이 들고 있던 C_u 는 다음 게시 뒤 폐기 트리에 들어간다. 지갑은 로그인 때 이를 알아채(동기화한
트리에 자기 리프가 있으면) 새 사용자 자격증명을 자동으로 받는다. 로그인 없이 먼저 확인하고 싶으면 `POST /wallet/attrs/sync` 로
AA 의 현재 값을 받아 두고(바뀌었으면 지갑이 옛 C_u·세션을 그 자리에서 지운다), 다음 로그인이 새 C_u 위에 세션을 받는다.

**트랜잭션의 선택 공개.** 지갑 페이지 (트랜잭션 보내기) 카드의 "공개할 속성 조건" 을 펼치면 슬롯별 체크박스(미사용 슬롯은 숨고, 정수가 아닌 슬롯의 범위 조건은 비활성) +
"최소"/"최대" 입력, "내 실제 값으로 채우기(체크한 조건)" 버튼(최소 = 최대 = 내 값)이 있다. `POST /wallet/tx` 의 `disclose`(길이 6, 각 원소 `{lo, hi}` 또는 `null`)가 회로 공개 입력 `disc_mask`·`disc_lo[6]`·`disc_hi[6]`
가 된다(V9, PUB_INDEX 15·16..21·22..27 — `lib/mode3_onchain.js`). 지갑은 제출 전에 `lo ≤ 내 속성 ≤ hi` 를 스스로 검사한다 —
안 맞으면 증명을 만들기 전에 400 `disclosure_unsatisfiable`, 형식·범위가 잘못됐으면 400 `bad_disclosure`. `disclose` 가
있으면(mask ≠ 0) 캐시된 π 를 못 쓰고 매번 새로 증명한다.

`set: { slot, members }`(선택, 슬롯 하나) — 화면에서는 같은 카드의 "집합 소속 조건" 고르개 + "허용 원소" 입력이다.
지갑이 `members` 로 root 를 계산해 회로 공개 입력 `set_sel`·`set_root`([28],[29], V9)에
넣는다. 비소속이면(내 속성이 `members`에 없으면) 역시 증명을 만들기 전에 400 `disclosure_unsatisfiable`, 형식이 잘못됐으면
400 `bad_disclosure`. 나이는 "나이 ≥" 입력 옆의 "이 나이 조건으로 채우기" 버튼으로 지정한다 — 이 버튼은
`hi[0] = 올해 − N`(연 단위)로 슬롯 0 을 공개한다(`lo[0]` 는 스키마의 출생연도 min, 기본 1900 — 서비스가 `lo ≥ min` 도 요구한다).

**`AttrGate` v2 (데모 대상).** RP 가 팩토리 다음에 한 번 배포하는 컨트랙트로(`rp_info.attrGateAddress`), 정책은 국가(a₁) ∈
`allowedCountriesRoot`(집합 소속, env `MODE3_ALLOWED_COUNTRIES`)·출생연도(a₀) 기준 나이 ≥ `minAge`(env `MODE3_MIN_AGE`)이다.
`claim()` 은 `Mode3Wallet.execute()` 가 호출 데이터 끝에 붙인 (mask, lo[6], hi[6], set_sel, set_root) 15워드(V9)를 읽어
`mask & 1 == 1`(슬롯 0 공개 필요)·`set_sel == 2 && set_root == allowedCountriesRoot`(집합 소속)·`hi[0] + minAge ≤ yearOf(block.timestamp)`
(나이는 `block.timestamp` 를 연 단위로 바꾼 `yearOf` 기준)를 확인하고 `Claimed` 이벤트를 낸다. 팩토리가 배포한 지갑에서 온
호출만 받는다(`factory.isWallet(msg.sender)`). `mode3_rp.js` 의 `ensureAttrGate` 는 `attrGateFactory` 뿐 아니라 등록 파일의
`attrGatePolicy`(root·minAge)가 지금의 env 값과 다를 때도 재배포한다.

`mode3_rp_registration.json` 에는 `attrGateAddress`(배포된 주소)·`attrGateFactory`(그 배포가 실제로 물린 `factoryAddress`)·
`attrGatePolicy`(그 배포가 물린 `{root, minAge}`) 필드가 있다(`mode3_rp.js` `ensureAttrGate`). **`AttrGate` 는 `attrGateFactory`
가 지금의 `factoryAddress` 와 다르거나 `attrGatePolicy` 가 지금의 env(`MODE3_ALLOWED_COUNTRIES`·`MODE3_MIN_AGE`)와 다를 때만
재배포된다** — 팩토리가 바뀌거나 정책 env 가 바뀐 경우에만 다시 배포하고, 둘 다 같으면 재기동을 반복해도 재배포하지 않는다.
`attrGateFactory`·`attrGatePolicy` 가 없는 옛 등록 파일(이 필드들이 생기기 전)은 이 대조가 항상 "다르다"로 나와 **첫 기동에
`AttrGate` 를 한 번 재배포한다**(주소가 바뀐다 — 이전에 그 주소를 써 둔 데모 스크립트·문서가 있다면 갱신해야 한다).

**로그인 경로 술어(V7).** 온체인 `AttrGate.claim()` 과 별개로, RP 페이지 (로그인) 카드의 "조건 요구(국가·나이)" 체크박스를 켜면 로그인
요청(`POST /api/mode3/login`)에 `require: { countrySet, minAge }` 를 함께 보낸다. RP 는 로그인 성명이 이미 제출한
disclosure(`set`·`disc_lo[0]`·`disc_hi[0]`)로 그 술어를 만족하는지 오프체인에서 검사하고, 만족하지 못하면 로그인 자체를 `{ok:false,
reason: 'predicate_unmet'}` 로 거절한다(200, 컨트랙트 호출 없이 오프체인 판정 — RP env `MODE3_ALLOWED_COUNTRIES`·
`MODE3_MIN_AGE` 기준). 나이는 `hi[0] + minAge ≤ 올해` 에 더해 `lo[0] ≥ 스키마의 출생연도 min`(`rp_info.predicates.birthYearMin`, 기본 1900)을
요구한다 — 출생연도 0("값 없음")인 계정은 지갑이 `lo ≤ 내 값` 을 강제하므로 이 술어를 만들 수 없다. 페이지는 `lo` 로 그 값을 보낸다.

**시나리오 1~6**(설계 §6.3, 위 0~9 각본과 별도로 확인; V7 이후 `AttrGate` 는 국가 **범위** 공개가 아니라 슬롯 1 **집합 소속**을 요구한다 —
문구는 `tests/test_mode3_demo_stack.mjs` 케이스 10–11 에서 그대로 가져왔다):

| # | 조작 | 기대 |
|---|---|---|
| 1 | testuser 등록 | 속성 `[1990, 410, 0, 0, 0, 0]` 이 AA 에서 내려온다(지갑 화면에는 `출생연도 1990 · 국가 KR` 로 보인다, 읽기 전용) |
| 2 | 로그인(mask 0) → (트랜잭션 보내기) "공개할 속성 조건" 에서 슬롯 0 을 `[0, 올해−minAge]` 로 공개 + "집합 소속 조건"=국가(슬롯 1)·"허용 원소"=`MODE3_ALLOWED_COUNTRIES` → "받는 주소"=`attrGateAddress`, "데이터"=`claim()` 셀렉터(`0x4e71d92d`, 지갑 폼 기본값) | `Claimed` 이벤트, `AttrGate.claimed(wallet) == true` |
| 3 | alice(2005, 840)로 같은 슬롯 0 범위 + 허용 집합이 아닌 임의 집합(예: `{840, 392}`)으로 시도 | 840 은 이 임의 집합 안에 있어 지갑의 setPath 는 성공하지만 그 root 가 `allowedCountriesRoot` 와 달라 `claim()` 이 `country` 로 revert(`Executed` success=false, nonce 는 소모). 허용 집합에서 840 을 빼면 지갑이 온체인에 내기 전에 `disclosure_unsatisfiable` 로 막는다 |
| 4 | 슬롯 0 을 `[0, 1980]` 으로 공개 시도(집합 없이) | 지갑이 `disclosure_unsatisfiable`(1990 ∉ [0, 1980], 체인에 보내기 전에 막힌다) |
| 5 | alice(2005, 840): 허용 집합은 그대로 공개하되 슬롯 0 을 정책보다 넓은 구간(`[0, 올해−5]`)으로 공개 | 국가는 실제 허용 집합이라 `country` 는 통과하지만 minAge 를 증명하지 못해 `claim()` 이 `age` 로 revert |
| 6 | 관리자가 testuser 의 예비 1(extra1) 에 문자열을 입력 → 다음 로그인 | 지갑이 옛 C_u 폐기를 알아채 새 C_u 를 받고 로그인 성공, **PPID 동일** |

## 세션 폐기 (V8, 설계 2026-09-24)

계정 폐기(4·4′)는 사용자 자격증명 리프 하나로 그 사용자의 **모든** 세션을 죽인다. V8 은 그 아래 단위를 더한다 — **세션 하나만**
폐기한다. 폐기 트리(RCL)에 세션 리프 `Poseidon(5, Cf_s)` 를 넣고(사용자 리프는 `Poseidon(4, Cf_u)`, **같은 트리·같은 root**),
회로가 비멤버십을 하나 더 증명한다(④′). 공개 입력은 25개 그대로라 서비스·컨트랙트 인터페이스는 바뀌지 않는다.

**누가 폐기하나.** 사용자(지갑)는 등록 키 `sk_u` 서명으로 자기 세션의 `Cf_s` 를 지정하고, 운영자는 관리자 시크릿으로 한다.
서비스는 `Cf_s` 를 모르므로 세션을 폐기할 수 없다.

- 지갑 페이지(`/`) (로그인 세션) 카드의 각 세션 요약 아래 **"이 세션 끝내기(폐기)"** 버튼 → `POST /wallet/session/revoke {r_s}`.
  누르면 확인창이 한 번 뜬다(되돌릴 수 없는 조작). 에이전트가 서명을 만들어
  CIA `/cia/revoke scope=session` 으로 보내고, CIA 가 받아들이면 **게시 전이라도 그 세션을 로컬에서 지운다**.
  결과는 결과 카드로 뜨고(원문은 전문가 보기의 `#sessionLog`), 지갑 페이지는 스스로 팝업을 열지 않는다.
- CIA 관리자 페이지(`/admin`) (계정) 카드 행의 **"세션"** 버튼 → `GET /cia/admin/sessions?uid=` 목록(활성/폐기됨/만료) + 행마다 "폐기".

**AA 가 기록하는 것.** 발급 때 `{Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt}` 을 계정에 남긴다(상태 v8). 전부 발급
때 이미 본 값이라 AA 가 새로 알게 되는 것은 없다 — `arid`·`pk_i` 는 여전히 `C_s` 안이라 못 본다. 남는 것은 **상태**(사용자별 세션
수·발급 시각)다. 만료된 기록은 **하트비트 틱마다, 그리고 그 계정의 다음 발급 때** 지운다(리프는 트리에 남는다 — append-only).
발급 쪽 정리가 같이 있는 이유는 하트비트가 꺼져 있으면(`CIA_HEARTBEAT_BLOCKS=0`) 틱 자체가 설치되지 않기 때문이다.

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /cia/revoke` `{uid, scope:'session', Cf_s, sig_u?, nonce?}` | CIA | 세션 하나 폐기. **관리자 시크릿** 또는 **사용자 서명**(`Poseidon(DOMAIN_MODE3_REVOKESESS, uid, Cf_s, nonce)` 위 `sk_u` EdDSA-Poseidon). 성공 `{inserted, leaf, root, pending}` |
| `GET /cia/admin/sessions?uid=` | CIA(관리자) | 그 계정의 세션 기록 + `expired`(그 체인 head 기준, 못 읽으면 `null`) |
| `POST /wallet/session/revoke` `{r_s}` | 지갑 | 같은 오리진 전용(CORS 없음). 서명 후 CIA 로 중계하고 성공하면 로컬 세션 삭제. 응답 `{revoked:true, inserted, pending}`. 인증은 `r_s` 를 아는 것뿐이다(`/wallet/revalidate` 와 같은 bearer) — **Snap 동의 창은 지갑 페이지가 거치는 절차이고 에이전트는 검증하지 않는다** |
| Snap RPC `consentRevokeSession` `{arid, issuedAt, maxHeight}` | Snap | snap 모드의 **동의 창만**. Snap 에는 Poseidon 이 없어 서명은 에이전트가 세션의 메모리 증인 `sk_u` 로 한다 |

**사유.** "화면 문구" 는 `mode3/common/strings.js` 의 `reasons[코드].ko.title` — 페이지가 결과 카드 제목으로 쓰는 말이다
(원인·조치 두 줄이 그 아래 붙고, 코드 자체도 제목 옆에 작게 그대로 남는다).

| `reason` | 화면 문구 | 어디서 | 상태 코드 | 뜻 |
|---|---|---|---|---|
| `revoked_session` | 이 세션은 폐기됐습니다 | 지갑 `POST /wallet/revalidate`·`/wallet/tx`(`/tx/prepare`) | 403 | 이 **세션 리프**가 폐기 트리에 있다 — 그 세션만 죽는다(지갑이 그 세션을 지운다). 사용자 자격증명은 그대로라 다른 세션·새 로그인은 된다. 계정/자격증명 폐기는 지금까지처럼 `revoked` 다. `mode3/rp.html` 은 둘을 같은 분기로 처리한다(세션 버림) |
| `unknown_session` | 신원 기관에 그 세션 기록이 없습니다 | CIA `POST /cia/revoke scope=session` | 404 | 그 `Cf_s` 기록이 이 계정에 없다(옛 세션이거나 만료 정리로 사라졌다). **서명 검사를 먼저 하므로** 서명 없이 "이 Cf_s 가 이 계정 것인가" 를 떠볼 수는 없다 |
| `expired` | 세션이 만료됐습니다 | CIA `POST /cia/revoke scope=session` | 409 | 그 체인 head > `max_height` — 만료가 이미 막으므로 리프를 넣지 않는다. 경계는 컨트랙트(`block.number > pub[3]`)·서비스와 같다: `head == max_height` 는 아직 산 세션이라 폐기된다 |
| `unknown_session`(중계) | 신원 기관에 그 세션 기록이 없습니다 | 지갑 `POST /wallet/session/revoke` | 404 | CIA 의 404 를 그대로 옮긴 것 — 지갑은 그 `r_s` 세션을 들고 있는데 **AA 쪽에 기록이 없다**(v8 이행 전 세션이거나 만료 정리로 사라졌다). 지갑이 세션 자체를 모르는 `no_session` 과 다르다 |
| `needs_consent` | 다시 승인해야 합니다 | 지갑 `POST /wallet/session/revoke`(snap 모드) | 409 | 그 세션의 메모리 증인이 없다(에이전트 재시작) — 서명할 `sk_u` 가 없다. 지갑 페이지는 사유만 보이고 스스로 팝업을 열지 않는다. RP 페이지에서 그 세션을 한 번 재검증해 재승인(§4.3, 아래 S8)을 거친 뒤 다시 누른다 |
| `not_registered` | 지갑이 등록되지 않았습니다 | 지갑 `POST /wallet/session/revoke` | 409 | 이 에이전트에 등록이 없다 |
| `no_session` | 그 세션을 지갑이 들고 있지 않습니다 | 지갑 `POST /wallet/session/revoke` | 404 | 그 `r_s` 세션을 지갑이 들고 있지 않다(이미 폐기했거나 만료) |

같은 세션을 다시 폐기하면 CIA 는 200 `{inserted:false}` 로 멱등하게 답한다.

**한계(그대로 적는다).**

- **효력은 다음 게시(또는 하트비트) 뒤부터다.** 그 사이의 온체인 실행은 막지 못한다 — 지갑은 스스로 그 세션을 버리지만,
  이미 나간 π·서명을 계정 컨트랙트가 즉시 거부하게 하는 것(세션키 블랙리스트)은 후속이다.
- **상태 v8 이행 전에 발급된 세션은 폐기할 수 없다.** `v7→v8` 은 `sessions = []` 로 시작하므로 기록이 없고, `/cia/revoke` 는
  404 `unknown_session` 으로 답한다 — 그 세션들은 `max_height` 만료로만 끝난다.
- **`CIA_CHAIN_RPCS` 에 없는 chainid 의 세션은 폐기도 정리도 못 한다.** head 를 못 읽어 만료 판정이 실패하고(폐기는
  fail-closed, 정리는 건너뜀) 기록이 남는다. 체인 RPC 장애 때도 같다 — 그동안 세션 폐기는 503 으로 막힌다(안전 쪽 실패).
- **`nonce` 는 메시지 바인딩이지 재생 방지가 아니다.** 같은 요청을 재생해도 같은 세션을 다시 폐기할 뿐이라 멱등하다.
  `nonce` 형식이 잘못되면 401 이다(`/cia/attrs` 는 같은 경우 400 — 사유 코드가 통일돼 있지 않다).
- 지갑의 `POST /wallet/session/revoke` 는 이제 CIA 호출 실패만 502 `cia_unavailable` 이고, 서명·형식 같은 지역 오류는
  500 `{reason:'internal', detail}` 이다(2026-09-24 최종 리뷰 F3).
- **재검증은 술어를 다시 증명하지 않는다**(V7부터의 기존 한계, 세션 폐기와 무관).
- 폐기된 세션 리프는 만료 뒤 죽은 리프지만 트리에서 빠지지 않는다(append-only). 만료된 리프를 접는 **재기준화는 후속**이다
  (설계 §6) — 데모 규모에서는 문제없다.

**V9(2026-10-01)**: 사용자 리프는 더 이상 폐기 트리에 넣지 않는다 — 자격증명 은퇴·계정 폐기 = 등록부 슬롯 0. 이 절의
세션 리프(`Poseidon(5, Cf_s)`)만 지금도 이 폐기 트리를 쓴다("세션 폐기" 는 여기 그대로, "계정/자격증명 폐기" 는 위
"속성과 선택 공개" 절·"RP 거절 사유" 절의 등록부(`regRoot`) 쪽을 본다).

## 계정 폐기 접수증 (V10, 설계 2026-10-02 §4)

계정 폐기(관리자 4, 자기 폐기 4′·지갑 프록시 4″)의 응답에는 **접수증** `receipt` 가 붙는다 — "이 슬롯은 비어 있어야 한다" 는
IdP(CIA)의 약속이다:

```
"receipt": { "slot": 0, "epochAtRequest": "7", "requestedAt": "1790000000", "sig": "0x…",
             "canonicalChainId": "31337", "canonicalLogAddress": "0x…" }
```

`sig` 는 CIA 이더리움 키로 `keccak(D_RECEIPT, canonicalChainId, canonicalLogAddress, slot, epochAtRequest, requestedAt)` 에 한
**EIP-191 personal-sign**(`"\x19Ethereum Signed Message:\n32"` 접두)이다(다이제스트는 `Mode3Log.receiptDigestFor` 와 같은 값, uid 는 넣지 않는다). 평소에는 쓰이지 않는다 — CIA 가 폐기와 함께 그 슬롯을 0 으로
즉시 게시하기 때문이다. **CIA 가 미적댈 때** 사용자(또는 누구든)가 이것을 캐노니컬 로그에 올리면, 그 뒤 CIA 의 모든 게시(하트비트
포함)는 그 슬롯을 0 으로 싣지 않으면 체인이 거절한다(`PendingRevocationNotApplied`) — 게시를 멈추면 root 가 늙어 전원이
`root_too_old` 로 멈추므로 결국 따를 수밖에 없다.

- **어디에 있나.** 응답 본문에만 실린다 — 사용자 페이지는 전문가 보기의 원문(`#out`)에, 지갑 프록시(`POST /wallet/self_revoke`)는
  CIA 응답을 그대로 중계한다. CIA 는 마지막 접수증을 `cia_state.json` 의 `accounts[uid].receipt` 에 두고, 같은 슬롯의 폐기를 다시
  요청하면 같은 접수증을 돌려준다. 지갑은 따로 보관하지 않는다(보관 위치는 설계 §8 의 남은 질문 3).
- **`scope:'credential'`(자격증명만 은퇴 — 속성 변경 등)에는 접수증이 없다.** IdP 가 개시한 은퇴라 사용자가 강제할 요청이 없고,
  접수증이 있으면 같은 슬롯을 다시 채운 뒤에도 누구든 그 슬롯을 강제로 은퇴시킬 수 있기 때문이다.
- **올리는 법**(데모 — 체인 하나면 `--network localhost`, 별도 노드면 `--network revchain`):
  ```
  npx hardhat console --network localhost
  > const log = await ethers.getContractAt("Mode3Log", "<receipt.canonicalLogAddress>")
  > await (await log.requestRevocation(<slot>, "<epochAtRequest>", "<requestedAt>", "<sig>")).wait()
  > await log.pendingSlots()          // [slot]
  ```
  서명이 CIA 것이 아니면 `BadSignature`, 이미 대기 중이거나 은퇴한 슬롯이면 아무 일도 하지 않는다(재전송 안전). 그다음 CIA 게시(관리자
  "게시(체인에 올리기)" 또는 다음 하트비트)가 대기열을 읽어 `(slot, 0)` 을 싣고, 통과하면 `pendingSlots()` 는 `[]`, `isRetired(slot)` 은
  `true` 가 된다. 하트비트가 먼저 실었으면 수동 게시는 `published:false` 지만 결과는 같다.
- **은퇴한 슬롯은 영구다.** 계정 폐기는 CIA 로컬에서도 그 슬롯을 은퇴시키므로(`slotRetired`), 관리자가 복구(`set_disabled false`)한
  뒤의 재발급은 **새 슬롯**(다음 빈 번호)을 받는다. 지갑은 재발급 응답의 슬롯을 따르고 PPID 는 그대로다(PPID 는 슬롯과 무관).
  각본 12·14 가 이것을 본다.

## MetaMask / Snap 경로 (`MODE3_WALLET_SECRETS`, 설계 2026-09-22 metamask-snap)

지갑 에이전트는 등록 비밀(uid·s_u·r_u·sk_u·blind_u)을 어디서 얻을지 `MODE3_WALLET_SECRETS` 로 고른다. 기본은 `file` 이고,
지금까지의 헤드리스 데모·자동 테스트는 모두 `file` 이다. `snap` 은 브라우저 + MetaMask Flask 로 사람이 직접 하는 경로다.
회로·컨트랙트·CIA·서비스 로직·증명 형식은 두 모드가 같다.

| | `file`(기본) | `snap` |
|---|---|---|
| 등록 비밀 보관 | `mode3_wallet_state.json` | MetaMask Snap 의 암호화 상태. 에이전트 파일에는 **공개 부분만**(uid·cm_u·attrs·`Cf_u`·`leaf`) |
| 사용자 동의 | 없음(자동 처리) | Snap 대화상자 — 등록 uid·비밀번호, 로그인 동의, 속성 공개 동의, 자기 폐기 비밀번호. 트랜잭션은 MetaMask 확인 창 |
| RP → 지갑 로그인 | RP 페이지가 `POST /wallet/login` 을 CORS 로 직접 부른다 | RP 페이지가 지갑 페이지 팝업(`/?authorize=1`)을 열고 `postMessage` 로 결과만 받는다(`/wallet/login` 의 CORS 는 닫힌다) |
| 재검증·세션 요청 | RP 페이지가 CORS 로 직접 | 같다(비밀이 필요 없다). 증인이 없으면 `409 needs_consent` → RP 가 재승인 팝업을 연다 |
| 세션 증인 | 상태 파일 | **에이전트 메모리만** — `persist()` 가 제외한다. 에이전트를 재시작하면 재승인이 필요하다 |
| 트랜잭션 전송 | 릴레이어(hardhat 언락 계정 `MODE3_RELAYER_INDEX`), `POST /wallet/tx` | MetaMask `eth_sendTransaction`(사용자 EOA 가 가스). `POST /wallet/tx/prepare` → `/wallet/tx/record` |
| 등록 | 에이전트가 s_u·r_u 를 만든다 | Snap 이 만들고 페이지는 `cm_u` 만 넘긴다. 응답의 `sk_u`·`attrs` 를 Snap 이 보관한다 |
| 자동 테스트 | `chain` 그룹 전 구간 | `tests/test_mode3_wallet_snap.mjs`(시뮬레이터, `chain`) + `tests/test_mode3_browser.mjs`(`browser`) |

### 준비 (처음 한 번)

1. MetaMask **Flask** 를 설치한다 — 로컬 Snap(`local:…`)은 일반 MetaMask 로는 설치되지 않는다.
2. `cd snap-mode3 && npm install && npm run build` — `dist/bundle.js` 를 만들고 `snap.manifest.json` 의 `shasum` 을 갱신한다
   (빌드가 번들을 SES 에서 한 번 평가한다 — `Snap bundle evaluated successfully`). 루트 `node_modules` 는 건드리지 않는다.
3. `cd snap-mode3 && npm run serve` — 포트 **8082** 로 manifest·번들을 띄운다. Snap ID 는 `local:http://localhost:8082` 이고
   에이전트의 기본값이다(바꾸려면 에이전트에 `MODE3_SNAP_ID`).
4. 지갑 에이전트를 snap 모드로 띄운다: `MODE3_WALLET_SECRETS=snap node mode3_wallet_agent.js`.
5. **지갑 페이지는 `http://127.0.0.1:5100` 으로 연다**(`http://localhost:5100` 도 Snap 은 받지만 에이전트가 127.0.0.1 에만 바인딩한다).
   `snap-mode3/src/index.js` 의 `WALLET_ORIGINS` 가 이 두 값 고정이라 **다른 오리진으로 열면 Snap 이 모든 RPC 를
   `unauthorized_origin` 으로 거절한다** — 포트를 바꾸려면 그 상수도 같이 고쳐야 한다. RP 페이지는 기존대로 `http://127.0.0.1:3100`.
6. 지갑을 snap 모드로 처음 쓰기 전에 `mode3_wallet_state.json` 의 `registration` 이 이미 있으면 `already_registered` 로 막힌다 —
   비밀이 파일에 있는 옛 등록과 Snap 의 등록은 서로 다른 보관소다. 새로 시연하려면 "하지 말 것 / 재시연" 의 재시연 세트를 탄다.

### 수동 체크리스트 (`snap` 모드)

자동 테스트가 없는 경로라 사람이 확인한다. 각 단계에서 **어느 창이 뜨는지**가 확인 포인트다.

| # | 어디서 | 조작 | 떠야 할 창 / 확인할 것 |
|---|---|---|---|
| S0 | 지갑(:5100) | 페이지를 연다 | "Snap" 패널이 보이고 uid·비밀번호 폼은 숨는다(= 에이전트가 snap 모드) |
| S1 | 지갑 | (MetaMask · Snap) "MetaMask 연결" | MetaMask 계정 선택 창 → Snap 설치·권한 창. 상태줄에 `계정 0x… · Snap local:http://localhost:8082` |
| S2 | 지갑 | (내 신원) "등록" | **Snap 대화상자 2개**(uid → 비밀번호). 끝나면 상태에 `등록됨`, 속성은 AA 값(`[1990, 410, 0, 0, 0, 0]`, 지갑 화면에는 `출생연도 1990 · 국가 KR` 로 보인다). "Snap 상태 보기" 로 `등록: 예`, `사용자 자격증명 보관` 확인 |
| S3 | RP(:3100) | (로그인) "로그인" | 지갑 오리진의 **팝업 창**이 뜨고 그 안에서 **Snap 로그인 동의 창**(서비스 이름·origin·arid·AI agent 허용)이 뜬다. 승인하면 팝업이 스스로 닫히고 RP 결과 카드에 `로그인 성공`(PPID 는 "자세히" 또는 전문가 보기의 `#log`) |
| S4 | RP | (S3 에서 동의를 **거절**) | RP 결과 카드에 `로그인 실패` + "승인 창에서 거절했습니다" + 코드 `user_denied`. 세션이 생기지 않는다 |
| S5 | RP | (내 세션) "세션 재검증" | 팝업 없이 성공(비밀이 필요 없다). `캐시 히트=true` |
| S6 | 지갑 | (트랜잭션 보내기) "보낼 세션" 선택 → "공개할 속성 조건" 에서 슬롯 0 `[0, 2007]` 공개 + 집합 소속 조건=국가, 허용 원소 KR,JP,US,DE,FR(범위 술어는 정수 슬롯에만 — `predicate_type`) → "받는 주소"=AttrGate, "데이터"=`0x4e71d92d` → "트랜잭션 보내기" | **Snap 속성 공개 동의 창**(슬롯별 범위·대상 주소) → **MetaMask 트랜잭션 확인 창**(첫 번째는 계정 배포, 두 번째가 `claim()`) → 영수증에 `ok=true`, `Claimed` |
| S7 | 지갑 | MetaMask 확인 창에서 **거절** | 페이지에 `user_rejected`. 에이전트 상태는 그대로(nonce 는 컨트랙트가 관리한다) |
| S8 | 터미널 → RP | 지갑 에이전트를 재시작 → RP 에서 (내 세션) "세션 재검증" | 에이전트가 `409 needs_consent` → RP 가 **재승인 팝업**을 연다 → Snap 동의 창(이 세션의 AI agent 허용 값이 그대로 보여야 한다) → 승인하면 재검증이 이어져 성공 |
| S8′ | 관리자 → RP → 지갑 | CIA 관리자 페이지에서 testuser 의 예비 1(extra1) 에 문자열(예: `tier3`) 입력 → `/cia/publish`(시연 편의로 즉시 게시 — 운영에선 위 "관리자 속성 변경" 의 이유로 하트비트에 묶는다) → RP 에서 (로그인) "로그인" | 로그인 동의 창 한 번으로 성공한다(지갑이 옛 C_u 폐기를 알아채 속성을 다시 받고 새 C_u 를 받는다, PPID 동일). 끝난 뒤 "Snap 상태 보기" 로 **속성이 `[1990, 410, <64비트 해시>, 0, 0, 0]` 으로 바뀌었고 `사용자 자격증명 보관: true`** 인지 본다 — 페이지가 `syncAttrs` 뒤에 `updateUserCred` 를 하므로 새 C_u 가 남아 있어야 한다(순서가 뒤집히면 여기서 `false` 가 되고 다음 재검증이 막힌다). 지갑 페이지의 "신원 기관에서 다시 받기" 로도 같은 값을 확인할 수 있다(이쪽은 동의 창이 한 번 더 뜬다) |
| S9 | 지갑 | (MetaMask · Snap) "계정 자기 폐기" | **Snap 비밀번호 대화상자** → 에이전트 `POST /wallet/self_revoke` 가 CIA 로 중계 → 결과 카드 `폐기 요청 접수`("uid … 계정의 폐기를 신원 기관에 요청했습니다 — 되돌릴 수 없습니다"). 관리자 페이지에서 `/cia/publish` 뒤 재검증이 `revoked` 가 되는지 본다 |
| S9′ | 지갑 → 관리자 → RP | (V8) (로그인 세션) 목록에서 한 세션의 "이 세션 끝내기(폐기)" | **Snap 동의 창**(그 세션의 서비스 arid·발급 시각·max_height — 서명은 에이전트가 한다) → 결과 카드 `폐기 요청 접수`("이 세션만 폐기를 요청했습니다 — 다음 게시부터 …"). 관리자 페이지에서 게시한 뒤 RP 에서 그 세션을 재검증하면 죽고(`revoked_session` 또는 세션이 이미 없어 `no_session`) 다른 세션은 산다. 에이전트를 재시작한 직후라면 메모리 증인이 없어 결과 카드 `세션 폐기 실패` + "다시 승인해야 합니다"(코드 `needs_consent`)가 뜬다 — 지갑 페이지는 팝업을 열지 않으므로 RP 에서 그 세션을 한 번 재검증(S8 의 재승인)한 뒤 다시 누른다 |
| S10 | 지갑 | (MetaMask · Snap) "Snap 초기화" | Snap 의 등록이 지워진다. 에이전트 파일의 **공개** 등록은 그대로다(재시연은 재시연 세트로) |

`file` 모드에서 RP 페이지를 브라우저로 여는 경로(RP 페이지가 `/wallet/login` 을 CORS 로 직접 부르는 지금까지의 흐름)는
**자동 테스트가 덮지 않는다** — 브라우저 테스트는 snap 모드만 돌린다. `file` 모드로 데모를 바꿨다면 위 "시연 각본" 0~9 를 손으로 한 번 훑는다.

### `snap` 모드의 한계

- **EOA 가 드러난다.** 트랜잭션 수수료를 MetaMask 의 사용자 계정이 내므로 체인에서 그 EOA 와 PPID 지갑이 이어진다.
  릴레이어를 쓰는 `file` 모드에는 이 연결이 없다. Mode 2 와 같은 데모 한계다.
- **증인은 요청마다 Snap 에서 온다.** 에이전트는 등록 비밀을 디스크에 쓰지 않지만, 세션 동안 `{ s_u, blind_u, attrs, sk_u }` 를
  **메모리에** 들고 재검증·재증명·`tx/prepare` 에 쓴다. "Snap 이 보관한다"는 영속 저장에 대한 보증이지 프로세스 메모리에 대한
  보증이 아니다.
- **에이전트 재시작 = 재승인.** 메모리 증인이 사라져 그 세션의 재검증이 `409 needs_consent` 가 된다(S8).
- 로컬 Snap 이라 **Flask 전용**이고 npm 게시·감사는 범위 밖이다.
- 지갑 페이지 오리진이 `WALLET_ORIGINS` 두 값으로 고정이다(위 준비 5).

## 엔드포인트 (2026-09-22 선택 공개, 2026-09-23 집합 소속 술어 V7 로 바뀌거나 추가된 것)

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /cia/attrs` | CIA | 사용자 서명(`sig_u`)으로 자기 속성 조회(지갑이 `/wallet/attrs/sync` 안에서 부른다) |
| `POST /cia/accounts/:uid/attrs` | CIA(관리자) | 속성 변경({profile}) — 활성 C_u 를 물린다(슬롯 0 즉시 게시) |
| `GET /cia/accounts` | CIA(관리자) | 전 계정의 `attrs`·`profile`·`disabled`·`activeCf_u` |
| `GET /cia/attr_schema` | CIA | 속성 스키마·해시(인증 없음) |
| `POST /wallet/attrs/sync` | 지갑 | AA 최신 속성 재확인, 바뀌었으면 옛 C_u·세션 삭제 |
| `GET /wallet/attr_schema` | 지갑 | 에이전트가 보관한 스키마(페이지용) |
| `POST /wallet/tx` (`disclose`·`set` 필드, V7) | 지갑 | 트랜잭션에 선택 공개 첨부 — `disclose`: `{lo,hi}\|null` × 1..6(int 슬롯만); `set`: `{slot, members}`(선택, 슬롯 하나 — root 를 지갑이 계산). 둘 중 하나라도 있으면(mask ≠ 0 또는 set_sel ≠ 0) 새 π |
| `GET /api/mode3/rp_info` (`attrGateAddress`·`predicates` 필드, V7) | RP | 배포된 `AttrGate` 주소, `predicates: { allowedCountries, allowedCountryNames, allowedCountriesRoot, minAge, birthYearMin, attrSchema }` |
| `POST /api/mode3/login` (`require` 필드, V7) | RP | 로그인 성명이 만족해야 할 오프체인 술어 — `{ countrySet, minAge }`, 미충족 시 `predicate_unmet` |

MetaMask/Snap 경로(2026-09-22 metamask-snap)로 새로 생긴 지갑 라우트:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `GET /wallet/config` | 지갑 | `{ secrets, snapId, walletOrigin, rpcUrl, chainId }` — RP 페이지가 로그인 경로(직접 호출/팝업)를 고르려고 CORS 로 읽는다. 비밀 없음 |
| `POST /wallet/authorize/precheck` | 지갑 | 승인 팝업이 Snap 동의 창 전에 부르는 인증서·팩토리 검증(`{ arid, origin, cert_s, pk_trace, factoryAddress }`). 로그인·재승인이 함께 쓴다. 선택 `r_s` 를 실으면 응답에 `sessionAllowAgent`('0'\|'1')를 얹는다 — 세션이 없거나 `arid` 가 다르면 404 `no_session`(2026-09-23 점검 B-I1) |
| `POST /wallet/session/witness` | 지갑 | 재승인(§4.3) — 재시작으로 사라진 세션 메모리 증인을 `{ r_s, witness, allowAgent }` 로 다시 채운다. `allowAgent`('0'\|'1')는 **필수**이고 팝업이 동의 창에 실제로 쓴 값이다 — 세션의 실제 값과 다르면 409 `allow_agent_mismatch`(2026-09-23 점검 B-I1) |
| `POST /wallet/tx/prepare` | 지갑 | snap 모드의 트랜잭션 1단계 — 증명·서명·`calldata`(필요하면 `deployCalldata`)까지만 만든다 |
| `POST /wallet/tx/record` | 지갑 | 2단계 — MetaMask 가 보낸 `txHash` 의 영수증을 파싱해 `/wallet/tx` 와 같은 형식으로 돌려준다(영수증 전이면 202) |
| `POST /wallet/self_revoke` | 지갑 | 자기 폐기 프록시 — `{ uid, pwd }` 를 CIA `/cia/account/self_revoke` 로 중계한다(`cia.js` 에 CORS 가 없어서). 등록 uid 가 아니면 403 `uid_mismatch` |

V10 폐기 체인·거울(2026-10-02)로 새로 생기거나 바뀐 것:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /cia/admin/relay` | CIA(관리자) | 주기와 무관하게 모든 거울을 지금 갱신한다. `{mirrors:[{chainId, epoch, …}]}`, 거울 하나라도 실패하면 502. 따라잡은 거울에 누르면 캐노니컬 하트비트를 하나 더 올린다 |
| `GET /mode3/health` (`mirrors`) · `GET /cia/public_keys` (`canonicalChainId`·`mirrors`) | CIA | 위 "상태 패널" 절 |
| `POST /cia/revoke scope=account` · `POST /cia/account/self_revoke` · `POST /wallet/self_revoke` (`receipt`) | CIA·지갑 | 응답에 접수증 — 위 "계정 폐기 접수증" 절 |
| `GET /api/mode3/rp_info` (`mirrorAddress`) | RP | 검증기가 읽는 거울. `logAddress` 는 캐노니컬(표시용) |
| `GET /wallet/status` (`mirror`·`canonical`) | 지갑 | `mirror{address, epoch, lastPublishedBlock}`, `canonical{rpc, logAddress, epoch}` |
| `Mode3Log.requestRevocation(slot, epochAtRequest, requestedAt, sig)` · `pendingSlots()` · `isRetired(slot)` | 체인(캐노니컬) | 접수증 대기열 |

폐기 트리 증분 동기화(2026-09-23, `docs/superpowers/specs/2026-09-23-mode3-rcl-incremental-sync-design.md`)로 새로 생기거나 바뀐 것:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `GET /wallet/status` (`rcl` 필드) | 지갑 | `{ leaves, lastSyncedBlock, lastMode, cacheFile }` — 폐기 트리 캐시 상태(리프 수, 마지막 동기화 블록, `restore`\|`delta`\|`bootstrap`\|`fallback`, 캐시 파일 경로). `CIA_LOG_ADDRESS` 미설정이면 `null` |
| `POST /wallet/rcl/reset` | 지갑 | 같은 오리진만, 본문 `{confirm:true}` 필요(없으면 400) — 폐기 트리 캐시 파일을 버린다. 응답 `{ ok:true, deferred }`(진행 중인 동기화와 겹쳤으면 `deferred:true` — 그 동기화가 끝난 뒤 적용) |

`deferred:true` 로 답했다면 **그 동기화가 끝날 때까지는 아무것도 지워지지 않는다** — 그동안 `GET /wallet/status` 의 `rcl` 은 옛 `leaves`·`lastSyncedBlock`·`lastMode` 를 그대로 보이고 캐시 파일도 아직 있다. 실제로 적용됐는지는 `rcl.lastMode === null && rcl.leaves === 0` 으로 확인한다.

## RP 거절 사유 (2026-09-23 점검 C-1)

"화면 문구" 는 `mode3/common/strings.js` 의 `reasons[코드].ko.title`(결과 카드 제목)이다 — 원인·조치가 그 아래 두 줄로
붙고, 코드 자체도 제목 옆에 그대로 남는다.

| `reason` | 화면 문구 | 어디서 | 상태 코드 | 뜻 |
|---|---|---|---|---|
| `root_too_old` | 폐기 목록이 너무 오래 게시되지 않았습니다 | `POST /api/mode3/login`, `POST /api/mode3/revalidate` | 200 `{ok:false, reason}` | 게시된 root 가 `MODE3_MAX_ROOT_AGE` 보다 오래됐다 — CIA 가 하트비트(또는 `/cia/publish`)를 멈추면 온체인 `RootTooOld` 와 함께 오프체인 로그인·재검증도 막힌다. CIA 를 살리고 게시를 기다린다 |
| `bad_factory` | 팩토리 컨트랙트를 믿을 수 없습니다 | `POST /wallet/login`, `POST /wallet/authorize/precheck` | 409 `{reason, detail?}` | 서비스가 준 `factoryAddress` 가 인증서·CIA 키·로그 주소와 다르거나(immutable 대조), **팩토리·검증자 코드가 지갑의 참조 빌드(`artifacts/`)와 다르다**(2026-09-23 참조 코드 대조 — `detail` 이 `factory_code_mismatch`·`verifier_code_mismatch`·`no_code`). 무엇이든 통과시키는 검증자를 가리키는 팩토리는 여기서 막힌다. 지갑 쪽 `artifacts/` 가 낡았으면(컨트랙트를 바꾸고 `npx hardhat compile` 을 안 했으면) 진짜 팩토리도 거절되니 먼저 컴파일한다 |
| `root_too_old` | 폐기 목록이 너무 오래 게시되지 않았습니다 | `POST /api/mode3/request` | 503 | 세션 요청도 같은 상한 — 다만 세션이 이미 있는데 체인 쪽 문제라 5xx 로 구분한다 |
| `factory_constants_unavailable` | 서비스가 체인 설정을 읽지 못했습니다 | 검증기가 없는 동안 RP API 전부(`inactiveReason`) — `/api/mode3/challenge`·`/login`·`/revalidate`·`/request`·`/open` | 503 | 팩토리 `maxRootAge`·`maxLifetime` 조회 실패 — 등록 대기(`registration_pending`)와 구분한다. 아래 "하지 말 것" 의 함정 참고 |
| `predicate_unmet` | 요구한 조건을 만족하지 못했습니다 | `POST /api/mode3/login` (V7, `require` 필드가 있을 때만) | 200 `{ok:false, reason}` | 로그인 성명은 유효하지만 요구한 술어(국가 집합 소속·최소 나이)를 만족하지 못한다 — 컨트랙트 호출 없이 오프체인에서 판정한다. `RP 거절 사유` 절 위쪽 "로그인 경로 술어(V7)" 참고. **요구는 페이지가 `require` 로 싣는다 — 서버 정책 게이트가 아니다(데모 의미). 운영이라면 서버가 강제해야 한다.** **재검증(`revalidate`)은 술어를 다시 증명하지 않는다** — 로그인 때의 술어는 세션 기록에만 남고, 재검증 뒤 `disclosure` 는 갱신된다(후속: 세션에 `require` 를 기억하고 지갑이 같은 술어로 재증명) |
| `predicate_unavailable` | 서비스가 이 조건을 요구할 수 없습니다 | `POST /api/mode3/login` (V7, `require` 필드가 있을 때만) | 200 `{ok:false, reason}` | 서비스의 스키마에 country/birthYear 슬롯이 없어 요구 조건을 검사할 수 없다 — 요구를 끄거나 스키마를 확인 |
| `stale_registry_root` | 등록부 버전이 오래됐습니다 | `POST /api/mode3/login`, `POST /api/mode3/revalidate` | 200 `{ok:false, reason}` | V9 — 지갑이 낸 증명의 등록부 root(`regRoot`)가 서비스가 보는 최신 등록부 root 와 다르다. `stale_root`(b, 폐기 트리 쪽)와 같은 자리의 등록부 판(b‴, `lib/mode3_rp.js`) — 등록부가 바뀐 뒤(슬롯 바꿔치기·은퇴·재발급) 지갑이 옛 등록부로 만든 증명을 들고 온 경우다 |
| `registry_mismatch` | 등록부의 내 자격증명이 바뀌었습니다 | 지갑 `POST /wallet/login`(`ensureUserCred`, 아직 세션이 없을 때만) | 403 | V9 — 체인에 게시된 내 슬롯의 리프가 지갑이 든 자격증명과 다르다. 내가 요청한 재발급이 아니라면 신원 기관의 부정(각본 10 의 "슬롯 바꿔치기") — 지갑은 로그인을 시도하지 않는다. **이미 세션이 있는 상태의 재검증·트랜잭션**(`/wallet/revalidate`·`/wallet/tx`(`/tx/prepare`))이 같은 등록부 불일치를 만나면 `proveSession` 은 둘을 구분하지 않고 `revoked` 로 보고한다(위 "세션 폐기(V8)" 절의 `revoked_session` 행, "계정/자격증명 폐기는 지금까지처럼 `revoked`" 참고) |
| `registry_unpublished` | 등록부 게시 대기 | 지갑 `POST /wallet/login` | 503 | V9 — 방금 받은 새 사용자 자격증명의 슬롯이 30초 안에 체인 등록부에 오르지 않았다. 신원 기관의 게시(하트비트)를 기다렸다가 다시 로그인한다 |
| `registry_slot_unknown` | 슬롯 번호를 몰라 등록부를 확인할 수 없습니다 | 지갑 `POST /wallet/login`·`/wallet/revalidate`·`/wallet/tx`(`/tx/prepare`) | 403 | V9 — 등록에 슬롯 번호가 없다(옛 v8 이하 지갑 상태 파일). 로그인이 `/cia/slot` 으로 슬롯을 되찾기 전까지만 뜬다 |
| `user_cred_failed` | 자격증명 발급이 거절되었습니다 | 지갑 `POST /wallet/login` | 502 | V9 — CIA 의 `/cia/user_cred` 가 `bad user credential proof` 로 거절했다. 시연 카드(설계 §8.3)로 salt·uid 를 바꾼 경우(각본 11)가 흔한 원인 — "원래대로" 로 덮어쓰기를 풀고 다시 로그인한다 |
| `demo_proof_failed` | 증명 생성 실패(시연) | 지갑 `POST /wallet/login`·`/wallet/revalidate`·`/wallet/tx`(`/tx/prepare`) | 409 | V9 — 시연 카드의 증명 덮어쓰기(범위 `prove`)가 걸린 채 새로 증명해야 했다 — 서명된 자격증명·등록부 리프와 어긋난 witness 라 회로가 거절했다(각본 11). 덮어쓰기를 풀고 다시 시도한다 |
| `slot_failed` | 슬롯 번호를 받지 못했습니다 | 지갑 `POST /wallet/login` | 502 | V9 — 슬롯 없는 옛 등록이 CIA 의 `/cia/slot` 조회에 실패했다 |

RP 는 RPC 실패 시 10분 안의 체인 뷰 캐시로 검증을 계속하는데(`headMaxAgeMs`), 그 창 동안은 root 나이(b′) 판정도 **캐시 시점 값에 얼어붙는다** — 실시간 게시 지연을 그동안은 못 본다.

`rp.html` 페이지는 응답 본문의 `{ ok, reason }` 만 읽고 상태 코드는 구분하지 않는다 — `/challenge` 도 같은 봉투를 쓴다(성공 `{ok:true, r_s, …}`, 거절 `{ok:false, reason}`. 2026-09-23 점검 M3 전에는 사유 대신 JS TypeError 가 보였다).

**함정(fail-closed)**: 체인을 새로 띄운(hardhat 재기동) 뒤 **옛 `mode3_rp_registration.json`**(예전 체인의 `factoryAddress`)으로 RP 를 올리면 팩토리 `maxRootAge()` 조회가 그 주소에 컨트랙트가 없어 실패하고, 위 표대로 모든 로그인·재검증·세션 요청이 `503 factory_constants_unavailable` 로 막힌다(5초마다 재시도, 새 체인에 맞는 팩토리가 없는 한 무기한). 증상은 RP 로그의 "팩토리 상수 조회 실패"(fail-closed) 줄로 보인다. 복구는 등록 파일의 `factoryAddress`·`verifierAddress` 를 지우고 재시작하거나(RP 가 새로 배포한다), 아래 재시연 세트를 탄다.

## 수용한 한계 (2026-09-25 전체 코드 리뷰)

2026-09-25 전체 코드 리뷰가 짚었지만 **고치지 않기로 한 것**들이다. 고칠 값이 있다고 본 지적은 커밋 `25d56fe`·`64bae37`·
`8854e87`·`8a7cb62`·`4aa5589`·`d9af457` 로 닫았고(형식 문서 `docs/paper/zkd/security_formal.md` §11), 아래는 남겼다.
각 줄에 왜 지금 안 고치는지를 같이 적는다.

- **uid 존재 열거.** `POST /cia/user_cred`·`POST /cia/attrs` 는 서명을 보기 **전에** `state.accounts[uid]` 를 확인해 404
  `unknown account` 를 낸다 — 인증 없는 호출자가 "이 uid 가 등록됐는가" 를 응답 코드로 안다. **왜 지금 안 고치나**: 데모
  계정은 `DEMO_ACCOUNTS` 에 하드코딩된 둘(12345·67890)뿐이라 열거할 것이 없고, CIA 의 다른 무인증 라우트도 같은 수준이다.
  세션 폐기(`/cia/revoke scope=session`)만은 서명을 먼저 봐 이 누수가 없는데, 그 순서를 나머지 라우트로 넓히는 것은 후속이다.
- **상태가 무한히 자란다.** 서비스의 `logins`·`sessions` 맵과 로그인 로그, 지갑의 증명 캐시, CIA 의 개봉 기록은 비우지 않는다
  (세션 폐기 리프도 append-only — 위 "세션 폐기" 절). **왜 지금 안 고치나**: 데모 규모에서 문제가 되지 않고, 보존 기간을
  정하는 일은 "언제 지워졌나" 라는 새 관측면을 만드는 설계 결정이라 운영 단계의 몫이다.
- **RPC 장애 때 10분 캐시.** RP 는 체인 뷰를 최대 10분(`headMaxAgeMs`) 캐시해 검증을 계속하고, 그동안 root 나이 판정도 캐시
  시점 값에 얼어붙는다(위 "RP 거절 사유" 절 끝에 이미 적혀 있다). **왜 지금 안 고치나**: 가용성 쪽으로 기운 **설계 선택**이다.
  없애면 RPC 가 흔들릴 때마다 로그인·재검증이 통째로 막힌다.
- **동의 창이 `data` 를 보이지 않는다.** Snap·지갑 페이지의 트랜잭션 동의 창은 서비스·오리진·대상(`to`)·금액(`value`)·공개
  항목까지만 보이고 calldata 는 안 보인다. **왜 지금 안 고치나**: 원시 calldata 를 사람이 읽고 판단하게 하려면 ABI 디코딩과
  함수 서명 사전이 필요한 2차 UI 작업이고, 데모의 호출 대상은 `AttrGate.claim` 하나다.
- **snap 증인에 유휴 수명이 없다.** 세션의 메모리 증인(`{s_u, blind_u, attrs, sk_u}`)은 에이전트가 살아 있는 한 남는다
  — 사라지는 경계는 **재시작**뿐이고 그때 `needs_consent` 로 재승인을 받는다. **왜 지금 안 고치나**: 유휴 만료를 넣으려면
  "언제부터 유휴인가, 만료를 사용자에게 어떻게 알리나" 를 정하는 타이머 설계가 먼저다.
- **지갑 `GET /mode3/health` 가 AA 오리진에도 열려 있다.** 허용 오리진이 `RP_ORIGIN` 과 `CIA_URL` 둘이라, AA 오리진의 페이지도
  지갑의 등록 여부·세션 수·트랜잭션 수를 읽을 수 있다. **왜 지금 안 고치나**: 상태 패널이 세 페이지 어디서나 같은 그림을
  그리게 하려는 **의도된 개방**이다. 응답에 비밀값은 없다 — `tests/test_mode3_health.mjs` 가 키 이름뿐 아니라 실제 값
  (등록 uid·`s_u`·`sk_u`·`Cf_u`·`Cf_s`)이 세 응답 어디에도 없는지 확인한다.
- **`countedTxHashes` 가 자란다.** 지갑 에이전트가 `/wallet/tx/record` 의 중복 집계를 막으려고 처리한 트랜잭션 해시를 Set 에
  모은다. **왜 지금 안 고치나**: 메모리에만 있어 재시작이면 사라지고, 한 시연에서 보내는 트랜잭션 수는 손에 꼽는다.
- **세션 라우트의 서비스 대조가 fail-open 이다.** `/wallet/revalidate`·`/wallet/request` 는 요청에 있는 서비스 단서를 **전부**
  세션과 대조한다 — 요청 `Origin` 과 세션 오리진이 둘 다 있으면 같아야 하고, 본문 `arid` 가 있으면 세션 `arid` 와 같아야 한다
  (본문 `arid` 는 공개값이라 그것을 실어도 오리진 대조가 꺼지지 않는다). 남는 fail-open 은 **대조할 단서가 하나도 없을 때**다:
  오리진 쌍이 갖춰지지 않고(브라우저 밖의 서버-대-서버 호출, 또는 커밋 `8a7cb62` 이전에 만들어져 `origin` 이 적히지 않은 세션)
  본문 `arid` 도 없으면 `r_s` 만으로 판정한다. 브라우저는 교차 오리진 요청에 늘 `Origin` 을 붙이므로 브라우저 공격면은
  닫혀 있다. **왜 지금 안 고치나**: 더 조이려면 `arid` 를 필수로 만들어야 하고 그것은 `mode3/rp.html` 과의 계약을 바꾼다.
- **오류 이름의 우선순위.** 마스크 밖 공개 워드가 0 이 아니면서 root 도 낡은 입력은 이제 `StaleRevocationRoot` 가 아니라
  `BadDisclosure` 로 되돌아간다 — 마스크 위생 검사가 외부 `log.root()` 읽기보다 앞에 있기 때문이다(싼 검사를 먼저 하는 순서).
  **왜 지금 안 고치나**: 그 조합을 단언하는 테스트가 없고 어느 JS 도 오류 이름으로 분기하지 않아 관측되는 계약 차이가 없다.
  디버깅할 때 먼저 보이는 이름이 바뀐다는 것만 적어 둔다.

속성 매핑 계층(스펙 2, `docs/superpowers/specs/2026-10-07-mode3-attr-schema-design.md`)의 2026-10-07 최종 리뷰에서 남긴 것:

- **`AttrGate` 는 출생연도의 `hi` 만 본다.** 불변 컨트랙트라 `hi[0] + minAge ≤ 올해` 만 확인하고 `lo[0]` 는 보지 않는다 — 출생연도가
  0("값 없음")인 계정도 `[0, 올해 − minAge]` 를 증명해 온체인 나이 조건을 통과한다. 완화: 관리자 입력은 출생연도·국가의 빈 값을
  거절하고(400 `empty`), RP 의 오프체인 로그인 검사는 `lo[0] ≥ 스키마 min` 을 함께 요구한다. 그래도 0 은 이행 경로로 생길 수 있다 —
  v10→v11 이행은 범위 밖 출생연도(예: 2150)를 0 으로 바꾼다. **왜 지금 안 고치나**: 스펙 2 는 회로·컨트랙트를 바꾸지 않는다(D3) —
  `AttrGate` 에 `lo[0] ≥ min` 을 더하는 것은 컨트랙트 변경·재배포가 필요한 후속이다.
- **스키마는 IdP 서명에 묶이지 않는다(D5).** IdP 가 스키마의 의미(enum 표 등)를 몰래 바꾸면 같은 숫자가 다른 뜻이 된다. 완화는 해시
  공개·대조·경고뿐이다(`/cia/attr_schema`, health·`rp_info`·`/wallet/status` 의 해시, 지갑의 `schemaHash` 대조). **왜 지금 안 고치나**:
  해시를 서명·공개 입력에 넣으려면 회로를 바꿔야 한다(스펙 §10).
- **문자열 해시는 64비트다.** 서로 같은 값을 내는 두 문자열(생일 충돌)은 약 2^32 번의 시도로 찾을 수 있다. 주어진 값과 같은 값을 내는
  다른 문자열(2차 원상)은 약 2^64 번이 든다. 속성 값은 IdP 가 정하고 사용자가 고르지 않으므로 앞의 것은 위협이 되기 어렵다.
  **왜 지금 안 고치나**: 슬롯이 회로에서 64비트(`ATTR_MAX`)라 더 넓히려면 회로 변경이다.
- **지갑·RP 는 CIA 에 닿지 못하면 기본 스키마로 간다.** RP 는 기동 때 한 번 받은 스키마를 프로세스 수명 동안 쓰고 그 스키마로
  `MODE3_ALLOWED_COUNTRIES` 를 인코딩해 `AttrGate` root 를 계산한다 — CIA 가 사용자 정의 스키마인데 기동 때 닿지 못했다면 재기동해야
  맞춰진다. 지갑은 60초마다 뒤에서 다시 받아 본다. **왜 지금 안 고치나**: 기본 스키마가 데모의 유일한 스키마이고, 기동 순서(CIA 먼저)를
  지키면 생기지 않는다.
- **스키마 해시 변경 경고는 프로세스 안에서만 남는다.** 지갑의 `schemaHash` 불일치는 로그 경고뿐이고 상태 파일·화면에 기록되지 않는다.
  **왜 지금 안 고치나**: 지갑은 IdP 를 바꿀 수 없고(스펙 §7), 기록할 곳(지갑 상태·Snap)의 형식을 바꾸는 일이라 후속이다.
- **`CIA_ATTR_SCHEMA_FILE` 을 바꾸면 CIA 가 기동을 거부한다.** 상태 파일의 `attrSchemaHash` 와 다르면 계정 `attrs` 의 뜻이 달라지므로
  막는다. **왜 지금 안 고치나**: 옛 `attrs` 를 새 스키마로 다시 인코딩하는 경로(문자열 원문은 `profile` 에만 있다)는 비범위다.
  스키마를 되돌리거나 재시연 세트로 상태 파일을 새로 시작한다.

## 하지 말 것 / 재시연

- **옛 상태 파일(cia_state.json version 2 이하, mode3_wallet_state.json version 5 이하, 키 없는 mode3_rp_registration.json)을 새 서버에 물리지 않는다.** CIA 는 기동을 거부하고 지갑은 세션을 비운다. `cia_state.json` v3·v4 는 기동 시 v5 로 이행된다(v3 의 used_rs 는 버려지고 기존 서비스 등록은 승인된 것으로 남는다 — v4 의 발급 기록은 형식이 바뀌어 비워진다). `mode3_wallet_state.json` v5 이하는 등록은 유지하고 세션이 비워진다(v6 부터 `registration.userCred` — 없으면 다음 로그인이 새로 받는다). `mode3_rp_registration.json` v2 는 v3 로 이행된다(`X_svc`·`x_svc` 조각은 유지, `factoryAddress`·`verifierAddress` 는 비운다). 그 밖의 옛 형식이거나 origin 이 다른 `mode3_rp_registration.json`은 RP 가 기동 시 새로 등록한다 — 옛 서비스 조각(x_svc)도 버려지므로 이전 로그인 로그의 태그는 더 이상 열 수 없다.
- **CIA 상태 v7 → v8 이행(2026-09-24)**: 기동 시 자동으로 `accounts[uid].sessions = []` 를 만든다(코드 변경 불필요, 폐기 트리·
  epoch·계정은 그대로). 이행 **전에** 발급된 세션은 기록이 없어 세션 단위로 폐기할 수 없다 — `max_height` 만료로만 끝난다.
  새로 발급받은 세션부터 지갑·관리자 페이지의 세션 폐기가 듣는다. 지갑 상태 파일은 이 이행에서 손대지 않는다.
- **옛 상태 파일(version 2 이하)을 새 CIA 에 물리지 않는다.** CIA 가 기동을 거부한다 — 재시연 세트로 새로 시작한다.
- **`cia_state.json`을 지우지 않는다.** 체인의 `RevocationLog.root`와 어긋나 지갑의 `syncRevocationTree`가 root 불일치로 전원을 막는다(Mode 2의 `idp_state.json`과 같은 이유). CIA 는 기동 시 로컬 트리를 온체인 root 와 대조해 어긋나면 `root 불일치`로 기동을 거부하므로, 지웠다면 아래 재시연 세트를 통째로 다시 한다.
- 재시연은 **한 세트로만**: hardhat 노드 재시작 → 위 "처음 한 번" 2~3(재배포, `.env`의 `CIA_LOG_ADDRESS`·`MODE3_MIRROR_ADDRESS`·`CIA_MIRRORS` 갱신) →
  `mode3_rp_registration.json` 의 `factoryAddress`·`verifierAddress`·`attrGateAddress` 삭제(로그 주소가 바뀌면 팩토리도 새로 배포해야
  한다 — 셋을 지우면 RP 가 다시 배포한다. `factoryAddress` 만 지우면 옛 검증기를 다시 물린다) → `cia_state.json`·`mode3_wallet_state.json`·
  `mode3_wallet_rcl.json`·`mode3_rp_registration.json`·`mode3_rp_logins.jsonl` 삭제 → 세 서버 재시작.
  `cia_keys.json`은 그대로 둬도 된다 — 게시 서명이 로그 주소를 덮으므로 같은 키로 재배포해도 옛 로그의 게시를 새 로그에 재생할 수 없다.
  **`snap` 모드로 시연 중이었다면 지갑 페이지의 "Snap 초기화"(`reset`)도 함께 누른다** — 등록 비밀은 상태 파일이 아니라 MetaMask 안에
  있어서 파일만 지우면 Snap 쪽에 옛 등록이 남고 다음 "등록" 이 `already_registered` 로 막힌다.
- **등록 직후 Snap 저장 실패 복구 절차(2026-09-23 점검 주목 Minor)**: `snap` 모드에서 `POST /wallet/register` 가 201 로 이미
  끝난 뒤(에이전트 상태 파일에는 등록이 남았다) 탭이 닫히거나 MetaMask 를 거절해 Snap 쪽 `storeRegistration` 이 실패하면
  Snap 은 `sk_u`·`attrs` 가 빈 `registration_incomplete` 로 굳는다. **부분 복구는 안 된다** — "Snap 초기화" 만 하거나 상태
  파일만 지워도 다시 등록하면 CIA 쪽 uid 가 이미 있어 `cm_u` 가 달라진 만큼 `/cia/register` 가 409 를 내고 같은 골목으로
  돌아온다. 유일한 출구는 **CIA·에이전트·Snap 세 보관소를 한꺼번에 비우는 재시연 세트**(위 문단)뿐이다.
- `mode3_wallet_rcl.json`(지갑의 폐기 트리 체크포인트, 공개 데이터)은 지워도 되고 안 지워도 된다 — 로그 주소가 바뀌면 자동으로
  무시되고, 지우면 첫 로그인이 창세기부터 재생한다. 강제로 다시 재생시키려면 `POST /wallet/rcl/reset`(본문 `{confirm:true}`).
  경로는 `MODE3_WALLET_RCL_CACHE` 로 바꿀 수 있다(기본값은 `MODE3_WALLET_STATE_FILE` 과 같은 디렉터리의 `mode3_wallet_rcl.json`).
- **커밋 `4aa5589`(2026-09-25) 이전에 배포된 서비스 팩토리는 못 쓴다.** 그 커밋이 `Mode3Wallet` 바이트코드를 바꿔서, 지갑의
  참조 코드 대조가 옛 팩토리를 `bad_factory`(`detail: factory_code_mismatch`)로 거절한다. 전에 띄워 둔 데모 스택을 다시
  올린다면 `mode3_rp_registration.json` 의 `factoryAddress`·`verifierAddress` 를 지우고 RP 를 재시작해 **팩토리를 새로
  배포**한다(위 재시연 세트를 통째로 타도 된다). 지갑 쪽 참조는 `artifacts/` 를 런타임에 읽으므로 커밋된 해시 파일은
  없다 — 코드 쪽은 `npx hardhat compile` 이면 끝난다.
  **그 `npx hardhat compile` 이 첫 단계다**(2026-09-25 최종 리뷰 F-5). `artifacts/` 는 gitignore 대상인데 팩토리 **배포**
  (`lib/mode3_onchain.js` `deployFactory`)와 지갑의 **참조 코드 대조**(`verifyReferenceCode`)가 *같은* 디렉터리를 읽는다.
  컴파일하지 않고 띄우면 RP 가 옛 바이트코드로 팩토리를 배포하고 참조 대조는 같은 옛 산출물과 비교하므로 **통과해 버린다** —
  그런데 JS 의 `payloadDigest` 는 새 16워드 형식이라 `factory_code_mismatch` 가 아니라 **모든 `execute` 가 `BadSignature`**
  로 실패한다. 증상이 원인에서 멀어 훨씬 찾기 어렵다.
  같은 이유로 **재배포 기준선은 `4aa5589` 에 고정돼 있지 않다**: solc 가 소스 텍스트의 메타데이터 해시를 바이트코드에 넣으므로
  `Mode3Wallet.sol`·`Mode3WalletFactory.sol` 은 **주석만 고쳐도** 배포 코드가 바뀐다(실측: 최종 리뷰 F-4 의 주석 한 줄로
  `Mode3Wallet`·`Mode3WalletFactory` 의 `deployedBytecode` 가 길이는 그대로인 채 값이 달라졌다 — `PiCredVerifier` 는 그대로).
  그 두 파일을 건드린 커밋 뒤에는 팩토리를 다시 배포한다.
- 데모 계정은 `cia.js`의 `DEMO_ACCOUNTS`(`testuser`/`password123` → uid 12345, `alice`/`alicepw` → uid 67890). 지갑 에이전트는 한 계정만 등록한다.
- `CIA_ADMIN_SECRET` 없이 띄운 CIA 에서 사용자 페이지의 폐기를 누르지 않는다 — 자기 폐기는 시크릿 없이도 되지만 복구(`set_disabled`)와 게시는 503 이라 계정이 되돌릴 수 없게 비활성으로 남는다.
- **한계**: 트랜잭션 해시로 개봉을 요청하는 경로는 체인을 읽을 수 있는 누구나 이 서비스의 트랜잭션에 대해 개봉을 신청할 수 있게
  한다 — CIA 는 여전히 서비스 서명·`wrong_arid`·운영자 승인으로 걸러내고 `D_svc` 는 응답에 나오지 않지만, 신청 자체는 막지 않는다.
  `GET /api/mode3/open/:id` 결과 조회도 인증이 없어 승인 뒤 누구나 uid 를 읽을 수 있다(데모 한정).

## 테스트

- `bash scripts/run_tests.sh chain` — 격리 스택(임시 포트)으로 전 구간. :8545 와 `build/mode3/`의 `pi_cred` zkey·vkey 만 있으면 된다.
  `tests/test_mode3_rcl_sync.mjs` — 증분 동기화(복원·델타·불일치 fallback·fail-closed·동시성). `node scripts/bench_mode3_rcl_sync.mjs` 가 실측을 낸다(`results/mode3_rcl_sync_*.md`).
  격리 CIA(`tests/helpers/isolated_cia.mjs`)는 하트비트를 끄고 뜬다(`CIA_HEARTBEAT_BLOCKS: '0'`) — 게시 없이 `MODE3_MAX_ROOT_AGE`
  (기본 100) 블록을 넘기는 시나리오는 오프체인 로그인·재검증·세션 요청도 `root_too_old` 로 막힌다(정상 fail-closed, 2026-09-23
  점검 C-1). 그런 블록 수를 진행시키는 테스트를 새로 짜면 `publish([])` 로 하트비트를 대신 넣는다.
  **V10(2026-10-02)**: 격리 CIA 는 기본으로(`test_mode3_demo_full.mjs` 를 뺀 모든 테스트) :8545 **하나에 로그와 거울을 함께** 배포하고(`cia.logAddress`·`cia.mirrorAddress`) 거울 릴레이
  주기를 끈다(`CIA_MIRROR_HEARTBEAT_BLOCKS: '0'`) — 두 번째 노드는 띄우지 않는다. 거울은 `POST /cia/admin/relay` 로만 오르므로
  격리 스택(`tests/helpers/isolated_mode3_stack.mjs`)이 `relay()`·`relayIfBehind()`·`withRelay(fn)`(요청 동안 뒤처지면 릴레이)과
  `autoRelay` 옵션(브라우저 각본용 0.5초 펌프)을 준다. `tests/test_cia_mirror_relay.mjs` 는 릴레이 주기·캐노니컬 하트비트 선행·
  수동 relay·`mirrors` 건강 정보·동시성을 본다(주기를 켜고 뜬다). `tests/test_mode3_demo_stack.mjs` 각본 13(거울 지연)·14(접수증
  강제)가 전 구간이다.
  `tests/test_mode3_demo_full.mjs`(2026-10-03)는 **두 체인·두 서비스** 전 구간 각본이다 — :8546 에 폐기 체인 노드(chainId 31338)를
  스스로 띄우고(이미 떠 있으면 chainId 만 확인하고 건드리지 않는다) 끝나면 끈다. 격리 헬퍼의 `twoChains`·`extraRps` 옵션을 쓴다.
- `bash scripts/run_tests.sh browser` — 팝업 로그인·`needs_consent` 재승인·MetaMask 트랜잭션을 실제 페이지로 돌린다
  (`tests/test_mode3_browser.mjs`). `chain` 과 같은 조건에 더해 **설치된 Google Chrome(또는 Chromium)** 이 필요하다 —
  Playwright 가 `channel: 'chrome'` 으로 띄우고, `window.ethereum` 을 스텁해 진짜 `snap-mode3/src/index.js` 의 `onRpcRequest` 를
  물린다. 그래서 `chain` 과 그룹을 나눴다. **Snap 경로(`snap-mode3/`, `mode3/wallet.html`, `mode3/rp.html`, 에이전트의 snap 분기)를
  건드렸으면 이 그룹도 돌린다.** 같은 그룹의 `tests/test_mode3_tour.mjs` 는 **체험 모드와 상태 점**을 본다 —
  서비스를 `?tour=1` 로 열면 로그인이 잠기고, 지갑에서 등록하면 다음 폴링에 풀리며 말풍선이 3→4단계로 옮겨 가고,
  격리 CIA 를 내리면 신원 기관 점이 빨강·지갑 점이 노랑이 되는 것까지(file 모드, MetaMask 없이).
- `node scripts/screenshot_mode3.mjs` — 테스트는 아니고 **화면 캡처**다. `browser` 그룹과 같은 전제(:8545,
  `build/mode3`, Chrome)로 격리 스택을 file 모드로 띄워 네 페이지를 ko·en·전문가(+좁은 창)로 찍는다. 기본 출력은
  `results/mode3_ux_20260924/`(`--out` 으로 바꾼다). **`--tour`** 를 주면 대신 체험 모드 네 장면(서비스 잠김·지갑
  말풍선·잠금 해제·상태 패널)을 `results/mode3_ux_20260925/` 에 찍는다. 끝나면 스택과 브라우저를 내린다.
- `bash scripts/run_tests.sh snap` — Snap RPC 9종의 단위 테스트(`snap-mode3/test/rpc.test.mjs`, 전역 `snap` 객체를 스텁).
  체인도 브라우저도 필요 없지만 `snap-mode3/node_modules` 를 전제하므로(`cd snap-mode3 && npm install`) `unit` 이 아니라
  별도 그룹이다. `node snap-mode3/test/rpc.test.mjs` 로 직접 돌려도 같다.
- `bash scripts/run_tests.sh contract` — `test/Mode3Wallet.test.mjs`(`execute()` 검사 순서·가스). hardhat 인프로세스 체인이라 :8545 가 필요 없다.
  단 `build/mode3/` 의 `pi_cred` zkey·wasm 은 필요하다(`test/Mode3Wallet.test.mjs` 가 실제 π 를 만든다) — 깨끗한 체크아웃에서
  그룹 전체가 실패하면 그 이유다.
- 세션 폐기(V8)는 `tests/test_mode3_session_revoke.mjs`(CIA 단독 — 404·409 `expired`·멱등·사용자 서명/관리자 두 갈래,
  `chain`), `tests/test_mode3_wallet_agent.mjs`·`tests/test_mode3_wallet_snap.mjs`(지갑 라우트·`revoked_session`·snap
  동의, `chain`), `tests/test_mode3_demo_stack.mjs` 각본 4″(전 구간), `tests/test_pi_cred_witness.mjs`(회로 ④′, `circuit`)로
  고정돼 있다.
- `bash scripts/run_tests.sh unit` 의 `tests/test_mode3_cia_state.js` — 상태 v5 이행을 커버한다.
- 개봉은 `tests/test_cia_opening.mjs`(CIA 단독)와 `test_mode3_demo_stack.mjs` 시나리오 9(전 구간)로 고정돼 있다.
- 등록부(V9, 2026-10-01)는 단위 셋 `tests/test_mode3_registry.js`(슬롯 트리 라이브러리)·`tests/test_mode3_v9_lib.js`
  (등록 서명·6슬롯 등)·`tests/test_mode3_cia_state_v9.js`(상태 v8→v9 이행, 모두 `unit`), `tests/test_cia_registry.mjs`
  (CIA 엔드포인트 — 등록·발급·교체·은퇴·계정 폐기·관리자 바꿔치기/되돌리기·재기동 백로그, `chain`), `test/Mode3Log.test.mjs`
  (컨트랙트 — 두 root 갱신·`SlotUpdated`·하트비트·서명 검사·재생 방지, `contract`), `tests/test_mode3_demo_stack.mjs`
  각본 10~12(전 구간)로 고정돼 있다.
