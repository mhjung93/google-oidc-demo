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
| IdP | :4100 | `node cia.js` | `cia_state.json`, `cia_keys.json` |
| 스냅 에이전트 | :5100 | `node mode3_wallet_agent.js` | `mode3_wallet_state.json` |
| 사용자 페이지(web 모드, 선택) | :5100 | `npm run user:build && node mode3_user_static.js` | — (비밀은 브라우저 IndexedDB 에 암호문) — 에이전트 대신 띄운다 |
| RP | :3100 | `node mode3_rp.js` | `mode3_rp_registration.json`, `mode3_rp_logins.jsonl` |
| RP #2 (선택) | :3101 | `bash scripts/run_mode3_rp2.sh` | `mode3_rp2_registration.json`, `mode3_rp2_logins.jsonl` — 아래 "두 번째 RP" 절 |
| 스냅 serve (`snap` 모드에만) | :8082 | `cd snap-mode3 && npm run serve` | — (비밀은 MetaMask 안에) |
| (상태 확인) | 세 서버 공통 | `curl -s http://127.0.0.1:4100/mode3/health` (`:3100`·`:5100` 도 같다) | — |

`GET /mode3/health` 는 2026-09-25 에 붙은 상태 엔드포인트다 — 페이지 위쪽의 상태 점 4개가 이것을 읽는다(아래 "상태 패널" 절).

로그 컨트랙트는 `Mode3Log`(V9, 2026-10-01) 하나다 — 폐기 root(`revRoot`)와 등록부 root(`regRoot`) 둘을 들고 있다.

**V10(2026-10-02, 설계 `docs/superpowers/specs/2026-10-02-mode3-revocation-chain-design.md`)**: 그 `Mode3Log` 는 **폐기 체인의
캐노니컬(정본)** 이 되고, 응용 체인마다 **거울(`Mode3Mirror`)** 이 그 두 root 를 받아 적는다. RP·PPID 계정은 **자기 체인의
거울만** 읽고, IdP 가 캐노니컬 게시를 거울로 중계(릴레이)한다. 회로·증명은 바뀌지 않았다. 기본 데모는 :8545 하나에 로그와 거울을
함께 둔다(같은 체인이어도 RP 는 거울만 읽으므로 "게시 → 릴레이 → RP 가 본다" 순서는 그대로 보인다).

## 두 번째 RP — 같은 사용자, 다른 주소 (2026-09-30)

같은 스냅으로 RP 둘에 로그인하면 **RP 마다 다른 PPID 계정**을 받고, IdP 는 어느 쪽인지 모른다는 것을 눈으로 보이는 구성이다.
RP 서버는 포트·이름·오리진·등록 파일이 전부 환경 변수라 인스턴스를 하나 더 띄우면 되고, IdP 는 오리진별로 RP 를 여럿 등록한다.
막고 있던 것은 스냅의 CORS 허용 오리진이 하나뿐이던 점이었고, 이제 `MODE3_RP_ORIGIN` 이 쉼표 목록을 받는다.

1. 스냅을 두 오리진으로 띄운다(이미 떠 있으면 재시작):
   `MODE3_RP_ORIGIN=http://127.0.0.1:3100,http://127.0.0.1:3101 node mode3_wallet_agent.js`
2. 두 번째 RP 를 띄운다: `bash scripts/run_mode3_rp2.sh` — `:3101`, 이름 `demo-rp2`, 등록 파일 `mode3_rp2_registration.json`, 릴레이어 계정 인덱스 1
   (첫 RP 와 같은 계정을 쓰면 팩토리 배포 nonce 가 겹칠 수 있다). 허용 국가·최소 나이도 바꿔 두면 정책이 RP 마다 다르다는 것까지 보인다.
3. 관리자 페이지(`:4100`)에서 두 번째 RP 등록을 승인한다 — 승인되면 RP 가 자기 팩토리·검증자를 배포한다(`:3101` 로그).
4. `http://127.0.0.1:3101` 을 열어 같은 사용자로 로그인한다. 세션 카드의 PPID 와 계정 주소가 `:3100` 의 것과 다르다.
   zk 스냅 페이지의 세션 목록에는 두 RP 가 나란히 보이고, 각 세션을 따로 폐기할 수 있다.

`GET /mode3/health` 의 스냅 응답에는 허용 목록이 `rpOrigins` 로 실린다(`rpOrigin` 은 첫 항목).
스냅의 세션 라우트는 요청 오리진과 세션의 RP 오리진을 대조하므로(9/25 리뷰 D-4·F-1) 한 RP 페이지가 다른 RP 의 세션을 쓸 수 없다.

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
   (3) IdP: `RevocationLog` 재배포는 필수가 아니다 — 옛 TAG 3 리프는 Poseidon(4, Cf_u) 와 겹치지 않으므로 옛 로그를 그대로 써도 된다.
       새로 배포한다면(아래 3, `.env` 의 `CIA_LOG_ADDRESS` 갱신) `cia_state.json` 도 함께 지워야 한다 — v5→v6 이행은 폐기·pending·epoch 를
       그대로 두므로, 남아 있으면 기동 시 빈 로그와의 root 대조 실패로 종료한다(아래 "재시연 세트" 와 같은 이유).
   (4) RP: `mode3_rp_registration.json` 에서 **`verifierAddress` 와 `factoryAddress` 를 둘 다 지운 뒤** 재시작한다. `factoryAddress` 만 지우면
       RP 가 옛 `verifierAddress`(V4 검증기)를 그대로 다시 써 새 팩토리가 옛 검증기를 가리키고 π 는 여전히 `InvalidProof` 다(`mode3_rp.js` `ensureFactory`).
       env 에 `MODE3_VERIFIER_ADDRESS` 가 있으면 새로 배포한 V5 검증기 주소로 바꾸거나 지운다.
   (5) 상태 파일: 옛 로그를 그대로 쓰면 `cia_state.json` 은 기동 시 v6 로 자동 이행되고(발급 기록만 비움, 폐기 트리 유지) 스냅의
       `mode3_wallet_state.json` 도 v6 로 자동 이행된다(세션·userCred 비움, 등록 유지 — 다음 로그인이 새 C_u 를 받는다). 로그를 새로
       배포했다면 (3) 대로 `cia_state.json` 을 지운다 — 그러면 계정 등록도 사라지므로 스냅 상태 파일도 같이 지우는 편이 맞다.
   로그를 새로 배포하는 쪽을 택하면 아래 "재시연 세트" 를 통째로 한 번 하는 것과 같다.
   회로 V6(2026-09-22, 선택 공개)로 build/mode3 를 또 다시 만들었다 — 순서: (1) `bash scripts/build_mode3_circuit.sh …` (2)
   `npx hardhat compile` (3) RP 등록 파일(`mode3_rp_registration.json`)에서 `verifierAddress`·`factoryAddress`·`attrGateAddress`
   를 **셋 다** 지운 뒤 재시작 — `attrGateAddress` 를 안 지워도 RP 가 알아서 다시 배포하지만(팩토리 주소가 바뀌면 자동으로
   재배포한다, `ensureAttrGate`), 옛 `verifierAddress`·`factoryAddress` 를 남기면 V5 와 같은 문제(새 π 가 옛 검증기에서
   `InvalidProof`)가 난다. (4) IdP 상태는 v7 로 **자동 마이그레이션**된다(코드 변경 불필요) — 계정마다 활성 C_u 를 물려(pending
   에 리프로 넣어) 다음 게시에 나가게 한다. **IdP 기동이 이 v7 이행 리프를 자동 게시한다** — 옛 C_u 로 여전히 증명 가능한
   창이 다음 하트비트까지 열려 있지 않게 한다(2026-09-22 최종 리뷰 Important, Ruling 8). 체인 RPC 가 아직 없으면 게시를
   건너뛰고 경고만 남기므로, 그때는 체인이 뜬 뒤 `/cia/publish` 를 수동으로 호출한다. (5) 스냅 상태도 v7 로 **자동 이행**된다(옛 C_u·세션을 비운다, 등록 자체는 유지) —
   다음 로그인에서 스냅이 새 사용자 자격증명을 자동으로 다시 받는다(`userCredMs > 0`). `RevocationLog` 재배포는 V5 와 같은 이유로
   필수가 아니다.
   회로 V7(2026-09-23, 집합 소속)로 build/mode3 를 다시 만들었다 — 다른 기계의 build/mode3 도 다시 복사. 팩토리·AttrGate 재배포
   필요(V6 증명과 호환 없음).
   회로 V8(2026-09-24, 세션 폐기 — 비멤버십 2개)로 build/mode3 를 또 다시 만들었다(설계
   `docs/superpowers/specs/2026-09-24-mode3-session-revocation-design.md`). **공개 입력은 25개 그대로**라 RP·컨트랙트
   인터페이스는 안 바뀌지만 `contracts/PiCredVerifier.sol` 이 다시 생성되므로 **검증기·팩토리·AttrGate 재배포가 필요하다**
   (V7 검증기는 V8 π 를 `InvalidProof` 로 거절한다). 순서는 V6·V7 과 같다: (1) `bash scripts/build_mode3_circuit.sh …`
   (2) `npx hardhat compile` (3) `mode3_rp_registration.json` 의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 를
   셋 다 지운 뒤 RP 재시작(**팩토리가 바뀌면 PPID 계정 주소도 바뀐다** — 아래 6 의 경고와 같다). (4) IdP 상태는 v8 로 자동
   이행된다(`accounts[uid].sessions = []` — 아래 "세션 폐기(V8)" 절의 주의). 다른 기계의 build/mode3 도 다시 복사한다.
   회로 V9(2026-10-01, 등록부·속성 6슬롯·공개 입력 30)로 build/mode3 를 또 다시 만들었다(설계
   `docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md`). 사용자 자격증명의 활성 여부가 폐기 트리에서
   **등록부(슬롯 트리)** 로 옮겨갔다 — 폐기 트리에는 이제 세션 리프(`Poseidon(5, Cf_s)`)만 남는다(아래 "세션 폐기(V8)"
   절 끝 참고). 순서: (1) `bash scripts/build_mode3_circuit.sh …` (2) `npx hardhat compile` (3) **로그 재배포가 필수다**
   (V5~V8 과 달리 선택이 아니다 — 등록부 root 를 실을 새 컨트랙트가 필요하다): `CIA_ETH_ADDRESS=<ethAddress> npx hardhat
   run scripts/deploy_mode3_log.cjs --network localhost` 가 (로그 이름이 바뀌어) `Mode3Log`(폐기 root·등록부 root 둘을
   들고 있다)를 배포한다 → 출력의 `CIA_LOG_ADDRESS=0x…` 를 `.env` 에 반영한다. (4) `cia_state.json` 은 지우지 않는다 —
   기동 시 v9 로 자동 이행된다(계정마다 슬롯을 배정하고 활성 자격증명의 리프를 계산해 채운 뒤 게시한다). **단** 로그를
   새로 배포했으므로 폐기 트리 쪽(`revoked`)이 빈 새 로그와 어긋나면 IdP 가 기동을 거부한다 — 이때는 "옛 폐기 리프는
   유지한 채 로그 주소만 바꾼 상태 파일"을 쓸 방법이 없으므로(등록부는 새로 시작해도 폐기 트리 쪽은 옛 리프 그대로라
   마찬가지로 어긋난다) 아래 "재시연 세트"(상태 파일을 백업해 두고 새로 시작)를 탄다. (5) `mode3_rp_registration.json`
   의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 셋을 지운 뒤 RP 재시작(**팩토리가 바뀌므로 PPID 계정 주소도
   바뀐다** — 아래 6 의 경고와 같다). (6) 스냅 상태는 v8 로 자동 이행된다(세션·사용자 자격증명을 비우고 등록은 유지) —
   옛 등록(슬롯 번호가 없다)은 첫 로그인 때 `/cia/slot` 으로 슬롯을 되찾는다. **`snap` 모드로 시연한다면** 등록 키 생성이
   Task 13 에서 스냅 쪽(`snap-mode3/src/index.js`)으로 옮겨 가 `src/` 가 바뀌었으므로, `cd snap-mode3 && npm run build`
   로 `dist/` 를 다시 만든 뒤에 MetaMask 에 스냅을 다시 설치한다(아래 "준비 (처음 한 번)" 절 2). 스냅을 다시
   설치하면 저장된 등록(`snap_manageState`)도 함께 지워지므로 등록부터 다시 해야 한다 — v8 시절의 4속성 등록이
   남아 있었다면 로그인 witness 검사(`validateWitness`)가 `attrs 길이` 로 `bad_witness` 를 던졌을 것이다.
   **V10(2026-10-02, 폐기 체인·거울)은 회로를 바꾸지 않는다** — build/mode3 는 그대로다. 대신 컨트랙트가 바뀌었다: `Mode3Log` 의
   게시 다이제스트가 체인 id·로그 주소를 덮고 접수증 대기열(`requestRevocation`·`pendingSlots`·`isRetired`)이 붙었으며, 거울
   `Mode3Mirror` 가 새로 생겼다. 순서: (1) `npx hardhat compile` (2) 아래 3 으로 **로그와 거울을 새로 배포**하고 출력의 세 줄을
   `.env` 에 반영한다(옛 V9 로그는 새 서명 형식을 받지 않는다) (3) 로그가 바뀌었으므로 아래 "재시연 세트" 를 탄다(상태 파일
   삭제) (4) `mode3_rp_registration.json` 의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 를 지운다 — 팩토리는 이제
   **거울 주소**를 로그 주소로 받으므로 새로 배포해야 한다(**PPID 계정 주소가 바뀐다** — 아래 6 의 경고).
   **V11(2026-10-12, 그림 프로토콜 — 설계 `docs/superpowers/specs/2026-10-12-mode3-v11-figure-protocol-design.md`)**: 회로 둘(`pi_cred`
   공개 입력 33·신규 `pi_idp`)이 바뀌었다. 순서: (1) `bash scripts/build_mode3_circuit.sh pot21_final.ptau`(이제 `pi_idp_*` 도 함께
   만든다) (2) `npx hardhat compile` (3) **로그·거울 재배포 + `cia_state.json`·`mode3_wallet_state.json` 새로 시작** — v11 이하
   IdP 상태 파일은 기동을 거부한다(이행이 없다. 이유: auid 는 스냅만 계산할 수 있어 IdP 가 옛 계정의 auid 를 모르고, 등록부 리프
   식·PPID 식이 바뀌었다). 스냅 상태도 재시연 세트와 같게 지운다 — `cia_state.json` 만 새로 시작하면 `file` 모드 스냅이 등록을
   유지한 채 v9 로 자동 이행되는데, 새 IdP 에는 그 계정이 없어 로그인이 502 `issue_failed`, 재등록이 409 `already_registered` 로
   막힌다. (4) `mode3_rp_registration.json` 의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 를 지운다 — PPID 식이 바뀌어
   **모든 계정 주소가 바뀐다**(위 6 의 경고와 같다) (5) 스냅 상태도 함께 새로 시작한다(`mode3_wallet_state.json` 삭제, 위 (3)) —
   v9 자동 이행 코드(`file` 모드는 등록을 유지하고 `snap` 모드는 등록이 비워지는 것)는 IdP 는 그대로 두고 스냅 상태 파일만 옛
   버전으로 남아 있는 경우를 위한 것이다. (6) 다른 기계라면 `bash scripts/pack_mode3_build.sh` 로 `pi_idp` 가 포함된 세트를
   다시 복사한다 (7) `snap` 모드라면 `cd snap-mode3 && npm run build` 뒤 MetaMask 에 스냅을 다시 설치한다.
1. `npx hardhat node` (다른 터미널에 상주).
2. `CIA_ADMIN_SECRET=<아무 문자열> node cia.js` — 처음 기동에서 `cia_keys.json`을 만든다. `curl -s 127.0.0.1:4100/cia/public_keys`의 `ethAddress`를 적어 두고 종료한다.
3. `CIA_ETH_ADDRESS=<ethAddress> npx hardhat run scripts/deploy_mode3_log.cjs --network localhost` — `Mode3Log` 와 그것을 가리키는
   `Mode3Mirror`(V10, 같은 체인)를 배포하고 IdP 주소에 1 ETH를 넣는다. 출력의 **세 줄**을 `.env`에 추가한다:
   ```
   CIA_LOG_ADDRESS=0x…          # 캐노니컬 로그 — IdP 가 게시하고, 스냅이 이벤트를 재생해 트리를 만든다
   MODE3_MIRROR_ADDRESS=0x…     # 거울 — RP·스냅 필수(없으면 기동하지 않는다). RP 팩토리도 이 주소를 로그로 받는다
   CIA_MIRRORS=31337=0x…        # IdP 가 중계할 거울 목록(chainid=주소, 쉼표로 여럿)
   ```
   **`CIA_CHAIN_RPCS` 에 그 chainid 항목이 반드시 있어야 한다**(예: `CIA_CHAIN_RPCS=31337=http://127.0.0.1:8545`) — IdP 는 거울의
   RPC 를 거기서 찾고, 없으면 `CIA_MIRRORS 의 chainid 31337 에 대한 RPC 가 CIA_CHAIN_RPCS 에 없다` 로 기동하지 않는다. 스크립트도
   마지막 줄에 같은 주의를 찍는다.
3'. `npx hardhat compile` — RP 가 기동 시 `PiCredVerifier`·`Mode3WalletFactory` 를 아티팩트에서 읽어 배포하고, **스냅도 같은 아티팩트로 팩토리·검증자 코드를 대조한다**(2026-09-23 — 스냅 기계에도 `artifacts/` 가 있어야 한다)(`artifacts/` 가
   없으면 RP 로그에 "팩토리 배포 실패", 오프체인 로그인만 된다).
4. `.env`에 `CIA_ADMIN_SECRET=<2의 값>`도 넣는다. (세 서버 모두 `dotenv`로 `.env`를 읽는다. `CIA_*`·`MODE3_*` 키는 이 데모만 쓴다.)
5. RP(mode3_rp.js)는 첫 기동에서 서명키·태그 조각을 만들어 IdP 에 등록하고 **등록 대기** 상태로 뜬다. IdP 관리자 페이지
   (`/admin` → 등록된 RP → 승인)에서 승인하면 5초 안에 arid·pk_trace·cert_s 를 받아 mode3_rp_registration.json 에 두고
   활성화된다. IdP 키를 바꾸거나 cia_state.json 을 지웠으면 이 파일도 지운다(그러면 새 키로 다시 승인받아야 한다).
6. RP 는 승인 뒤 팩토리를 배포해 `mode3_rp_registration.json` 에 `factoryAddress` 를 둔다. 재배포하려면 그 필드를 지우거나
   `MODE3_RP_FACTORY_ADDRESS` 로 덮어쓴다. **주의**: 회로를 다시 빌드한 뒤라면 `verifierAddress` 도 함께 지워야 한다 — 그 필드가 남아 있으면
   새 팩토리가 옛 검증기를 그대로 가리킨다(위 0 의 (4)).
   **경고**: 팩토리를 다시 배포하거나 팩토리 생성자 인자 중 하나라도(`MODE3_MAX_ROOT_AGE`, `MODE3_MAX_LIFETIME_BLOCKS`, 검증기
   주소, `arid`(RP 식별자 — RP 를 다시 등록하면 새로 배정된다), 로그 주소, IdP 키, RP 조합 키 — 생성자 9인자 전부) 바꾸면 모든 PPID 계정 주소가 바뀐다 — 옛 계정의 잔액은 옛 팩토리 주소로만
   접근할 수 있으니, 잔액이 있는 데모를 진행 중이면 먼저 빼낸다. 팩토리가 이미 있으면 RP 는 env 대신 **팩토리의 값**을
   쓰고 경고한다(2026-09-23) — env 를 바꿨는데 안 먹는다면 그 경고를 보라.

V10 환경 변수(2026-10-02). **`CIA_RPC_URL` 의 뜻이 프로세스마다 다르다** — IdP 에게는 캐노니컬(폐기 체인) RPC, RP·스냅에게는
자기가 검증·실행하는 응용 체인 RPC 다. 체인 하나 데모에서는 둘 다 :8545 라 차이가 안 보이지만, 폐기 체인을 따로 띄우면 `.env` 에
넣지 말고 프로세스마다 준다(아래 "폐기 체인을 별도 노드로").

| 키 | 누가 | 뜻 |
|---|---|---|
| `CIA_RPC_URL` | IdP | 캐노니컬 `Mode3Log` 가 있는 폐기 체인 RPC(기본 `http://127.0.0.1:8545`). 게시·접수증 서명의 chainid 가 여기서 나온다 |
| `CIA_RPC_URL` | RP·스냅 | 자기 응용 체인 RPC(거울·팩토리·계정이 있는 곳, 기본 같음) |
| `CIA_LOG_ADDRESS` | IdP·RP·스냅 | 캐노니컬 로그. RP 는 `rp_info` 에 **표시만** 하고 읽지 않는다 |
| `MODE3_MIRROR_ADDRESS` | RP·스냅(필수) | 이 체인의 거울. RP 검증기·팩토리·스냅의 증명 root 가 전부 이것 기준 |
| `MODE3_REV_CHAIN_RPC` | 스냅·`hardhat.config.cjs` | 스냅: 캐노니컬을 읽을 RPC(기본 `CIA_RPC_URL`). 트리는 캐노니컬 이벤트를 **거울 epoch 까지만** 재생해 만든다. hardhat: `--network revchain` 의 URL(기본 `http://127.0.0.1:8546`) |
| `HARDHAT_CHAIN_ID` | `hardhat.config.cjs` | `npx hardhat node` 의 chainid(기본 31337). 두 번째 노드(폐기 체인)를 31338 로 띄울 때만 |
| `CIA_MIRRORS` | IdP | `chainid=거울주소,…` — 중계 대상. 각 chainid 가 `CIA_CHAIN_RPCS` 에 있어야 한다 |
| `CIA_CHAIN_RPCS` | IdP | 응용 체인 RPC 맵(세션 발급 + 거울 중계). 비어 있으면 지금처럼 `CIA_RPC_URL` 의 체인 하나로 채워지지만, 그 기본값은 `CIA_MIRRORS` 검사보다 늦게 생기므로 **거울을 쓰면 응용 체인을 명시적으로 적어야 한다** |
| `CIA_MIRROR_HEARTBEAT_BLOCKS` | IdP | 거울 릴레이 안전망 주기 H_X(그 거울 체인의 블록 수, 기본 50, `0` = 릴레이 전체 끔). 뒤처진 거울을 이 주기 안에 옮긴다. 따라잡은 거울을 위해 캐노니컬 하트비트를 새로 만들지는 않는다(2026-10-05) |
| `CIA_MIRROR_RELAY_ON_PUBLISH` | IdP | 캐노니컬 게시 직후 뒤처진 거울에 바로 중계(기본 `1`). `0` 이면 주기 틱만 — 거울 지연을 눈으로 보이는 시연용(2026-10-05) |
| `CIA_MIRROR_POLL_MS` | IdP | 릴레이 틱 간격(기본 5000) |
| `MODE3_CANONICAL_LOG_ADDRESS`·`MODE3_CANONICAL_CHAIN_ID` | 배포 스크립트 | 둘 다 주면 **거울만** 배포한다(남의 체인의 캐노니컬을 가리킴). 별도 노드 구성 전용 — **`.env` 에 넣지 말 것**(배포 명령에만 붙인다. `.env` 에 있으면 단일 노드 재배포가 거울 전용으로 바뀐다) |

`MODE3_MAX_ROOT_AGE`(RP·계정이 받아들이는 root 나이)는 이제 **거울**의 `lastPublishedBlock` 기준이다 — 거울 릴레이 주기보다
2~3배 크게 둔다(설계 §5, 기본 100 > 50).

선택 env: 스냅의 `MODE3_TTL_BLOCKS`(credential 만료, 기본 300)·`MODE3_HEIGHT_GRID`(max_height 양자화 그리드 — 두 데모 스크립트는 5 로 띄운다: hardhat 은 거래가 있을 때만 블록을 만들어 100 이면 데모 내내 같은 값이 보인다. 5 는 IdP 가 발급 시각을 5블록 창까지 좁힐 수 있어 데모 전용이다, 2026-10-21; 기본 100 — 만료는 스냅이 정하고 IdP 는 그대로 서명), RP·컨트랙트의 `MODE3_MAX_LIFETIME_BLOCKS`(스냅이 정한 만료의 상한 L, 기본 400; TTL+GRID 이상이어야 로그인이 된다)·
`CIA_HEARTBEAT_BLOCKS`(하트비트 재게시 주기, 기본 50, 0=끔)·`CIA_HEARTBEAT_POLL_MS`(기본 5000)·
`CIA_CHAIN_RPCS`(발급을 허용할 체인의 RPC 맵, 기본 `"31337=http://127.0.0.1:8545"`, 비면 자기 RPC 하나 — V10 에서 `CIA_MIRRORS` 를 쓰면 명시 필수, 위 표)·
`MODE3_MAX_ROOT_AGE`(스냅과 **RP 오프체인 로그인·재검증·세션 요청도 같은 상한**으로 받아들이는 게시 root 의 최대 나이,
블록, 기본 100 — 온체인 `RootTooOld` 와 같은 값, 하트비트 주기보다 커야 한다)·
`MODE3_RELAYER_INDEX`(트랜잭션 릴레이어로 쓸 hardhat 계정 인덱스, 기본 0)·`MODE3_RP_FACTORY_ADDRESS`·`MODE3_VERIFIER_ADDRESS`,
`MODE3_VKEY_PATH`(IdP 의 개봉 검증용 vkey, 기본 `build/mode3/pi_cred_vkey.json`), `MODE3_RP_LOGIN_LOG`(RP 로그인 로그, 기본
`mode3_rp_logins.jsonl`, 0600 — 개봉 요청의 재료라 비밀로 둔다). 옛 `CIA_TTL_SECONDS`·`CIA_REVOKE_SKEW_SECONDS`·`CIA_CHAIN_IDS`·`CIA_REVOKE_SKEW_BLOCKS` 는
경고와 함께 무시된다(skew 는 2026-09-21 자격증명 이중 구조에서 제거됐다 — 폐기는 리프 하나라 세션 기록이 필요 없다).
`MODE3_ALLOWED_COUNTRIES`(V7 AttrGate 정책의 허용 국가 집합, 쉼표 구분 — 국가 이름(KR,JP) 또는 ISO 3166 numeric(410,392), 스키마 표에
없으면 기동 실패, 기본 `410,392,840,276,250`(= KR,JP,US,DE,FR))·
`MODE3_MIN_AGE`(V7 AttrGate 정책의 최소 나이, 연 단위, 기본 19).

선택: 운영이라면 RP의 `pk_CIA`를 TOFU가 아니라 env로 박는다 — `curl -s 127.0.0.1:4100/cia/public_keys`의 `pk_CIA.x/y`를 `MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y`에. 단 env 로 박으면 RP 는 기동 때 IdP 에 묻지 않으므로 IdP 하트비트 주기와
`MODE3_MAX_ROOT_AGE` 의 대조 경고(하트비트 ≥ maxRootAge 면 전원이 `root_too_old`)가 나오지 않는다 — 두 값은 사람이 맞춘다(2026-09-23 최종 리뷰 M4).

## 다른 기계에 설치 — Windows 11 + WSL2 (2026-10-09)

데모 스택은 전부 로컬(체인·IdP·스냅·RP 가 `127.0.0.1` 에 묶임)이라 **다른 기계에서도 그 기계 안에서 그대로 띄우면 된다.** 외부 주소로
노출하는 길은 없다 — RP 오리진이 `cert_s` 에 서명돼 있고, 스냅의 허용 오리진(`snap-mode3/src/index.js` `WALLET_ORIGINS`)이
`127.0.0.1:5100`/`localhost:5100` 상수이며, 세 서버가 `app.listen(PORT, '127.0.0.1')` 이기 때문이다. 다른 PC 에서 보기만
하려면 SSH 포트 포워딩(`ssh -L 3100:127.0.0.1:3100 -L 4100:127.0.0.1:4100 -L 5100:127.0.0.1:5100 -L 8545:127.0.0.1:8545 …`)이
코드 변경 없이 된다 — 그쪽 브라우저의 오리진도 `127.0.0.1` 이라 인증서·CORS·스냅이 그대로 맞는다.

**WSL2 에서.** WSL 안에서 리슨하는 포트는 Windows 의 `localhost`/`127.0.0.1` 로 자동 포워딩되므로(루프백 바인딩이어도) Windows 쪽
브라우저·MetaMask 로 `http://127.0.0.1:3100`(RP)·`:5100`(스냅)·`:4100/admin`(관리자)·RPC `http://127.0.0.1:8545`·스냅 `localhost:8082` 에
그대로 닿는다. 주의 네 가지:
1. 저장소는 **WSL 파일시스템**(`~/google-oidc-demo`)에 둔다 — `/mnt/c/...` 는 느리고, 상태 파일을 `0600` 으로 쓰는 코드·심링크가
   NTFS 마운트에서 어긋난다.
2. **clone 도 WSL 안에서** 한다 — Windows git 의 `autocrlf` 가 `scripts/*.sh` 를 CRLF 로 바꾸면 `bash scripts/run_tests.sh` 가 깨진다.
3. Node 22 는 WSL 안에 nvm 으로(`nvm install 22`). circom 은 필요 없다(아래처럼 build 를 복사한다).
4. 페이지는 `localhost` 가 아니라 **`127.0.0.1`** 로 연다(이 머신에서와 같은 규칙 — 스냅의 CORS 허용 목록이 `http://127.0.0.1:3100`).

**git 에 없는 것을 챙긴다**(`.gitignore`: `build/`, `artifacts/`, `*.ptau`, `*.zkey`, `.env`, 상태 파일).
- `build/mode3/` — 회로 재빌드는 circom 2.1.9 + `pot21_final.ptau`(2.3GB) 가 필요하니 **복사**한다. 이 머신에서
  `bash scripts/pack_mode3_build.sh` 가 런타임이 읽는 셋(`pi_cred_final.zkey`·`pi_cred_vkey.json`·`pi_cred_js/`, 약 27MB)만 묶고
  `MANIFEST.sha256` 을 넣는다. 받는 쪽은 저장소 루트에서 `tar -xzf … && sha256sum -c build/mode3/MANIFEST.sha256`.
- `artifacts/` — 받는 쪽에서 `npx hardhat compile` 한 번(RP 의 팩토리 배포, 스냅의 참조 코드 대조가 읽는다).
- `.env` — **복사하지 않는다**(비밀값·이 머신의 컨트랙트 주소). 위 "처음 한 번" 1~4 로 새로 만든다. Mode 1/2 키(Google OAuth, V4 주소)는
  Mode 3 에 필요 없다.
- 상태 파일(`cia_keys.json`·`cia_state.json`·`mode3_wallet_state.json`·`mode3_rp_registration.json`) — 가져가지 않는다. 새 체인이라
  새로 시작하고, RP 는 첫 기동에서 등록 → 관리자 승인 → 팩토리 자동 배포 순서로 활성화된다(위 5·6).

```bash
# WSL Ubuntu
nvm install 22
git clone https://github.com/mhjung93/google-oidc-demo.git && cd google-oidc-demo && git checkout feat/mode3-v11 && npm install
tar -xzf ~/mode3_build_YYYYMMDD.tar.gz && sha256sum -c build/mode3/MANIFEST.sha256   # 이 머신의 pack_mode3_build.sh 산출물
npx hardhat compile
# 이어서 위 "처음 한 번: 배포와 .env" 1~6, 그다음 "매번: 기동 순서"
```
스냅 모드는 `cd snap-mode3 && npm install && npm run build` 와 MetaMask Flask(아래 "준비 (처음 한 번)")를 더 전제한다. WSL 안에
Chrome 이 없으면 `browser` 테스트 그룹은 `BLOCKED` 로 끝나지만 데모와는 무관하다.

## 매번: 기동 순서

```
npx hardhat node                # 이미 떠 있으면 생략
node cia.js                     # :4100
node mode3_wallet_agent.js      # :5100
node mode3_rp.js                # :3100 (기동 시 IdP 에서 pk_CIA 를 받아 고정 — IdP 가 먼저 떠 있어야 한다)
```

RP 는 등록 파일이 없거나 승인 전이면 IdP 에 등록/조회하므로 IdP 가 먼저 떠 있어야 한다.

**거울 릴레이(V10, 2026-10-05 개정).** IdP 는 캐노니컬 게시(발급·폐기에 따른 등록부 변경, 세션 리프, 정규 하트비트)가 성공하면
**곧바로** 뒤처진 거울에 그 게시를 옮긴다(`CIA_MIRROR_RELAY_ON_PUBLISH`, 기본 켬). 그래서 폐기·발급이 RP 에 보이는 시점은
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
**첫 로그인(새 사용자 자격증명)** 은 거울이 내 등록부 리프를 실을 때까지 스냅이 최대 30초 기다린다(`registry_unpublished`).
즉시 중계가 켜져 있으면 발급 게시 직후 거울이 따라오므로 보통 몇 초 안에 끝난다. **거울 지연을 시연하려면**
`CIA_MIRROR_RELAY_ON_PUBLISH=0` 으로 IdP 를 띄운다 — 그러면 계정 폐기 직후 거울이 뒤처진 동안 RP 가 옛 root 로 요청을
받다가, 다음 주기 틱이나 위 relay 뒤에 `revalidate_required` 로 바뀌는 장면을 볼 수 있다(자동 각본 13 과 같다).

### 폐기 체인을 별도 노드로 (선택, V10)

> 한 번에(2026-10-16): `TWO_CHAINS=1 bash scripts/demo_web_reset.sh` — 아래 1~4단계를 web 모드(localhost 오리진)로 돈다.

> 2026-10-03 실행 확인: `tests/test_mode3_demo_full.mjs` 가 이 구성(폐기 체인 :8546 chainId 31338 + 응용 체인 :8545, RP 둘)을
> 격리 스택으로 처음부터 끝까지 돌린다 — 등록·로그인·거래소 술어·온체인 출금·개봉·세션 폐기·계정 폐기(거울 지연)·접수증·복구.
> 4단계 기동 env 는 그 테스트가 자식에게 주는 값과 같다. 2·3단계 배포 스크립트도 같은 날 별도 :8546 노드에 돌려 출력대로 동작함을 확인했다.

설계의 원래 그림(폐기 전용 체인 + 응용 체인의 거울)을 그대로 보이려면 노드를 둘 띄운다. 기본 데모·테스트는 체인 하나로
충분하다(`tests/test_mode3_demo_full.mjs` 를 뺀 모든 테스트는 :8545 하나에 로그와 거울을 함께 둔다). chainid 가 같으면 서명이 두 체인을 구분하지 못하므로
`hardhat.config.cjs` 가 `HARDHAT_CHAIN_ID` 로 두 번째 노드의 chainid 를 바꾼다(기본 31337).

**전제 — 체인 하나 구성에서 옮겨 오면 재시연 세트를 탄다**(아래 "하지 말 것 / 재시연" 의 재시연 세트, 위 "처음 한 번" 0 의 V10
(4)와 같은 이유). 로그를 새로 배포하므로 `cia_state.json` 과 스냅 상태·캐시 파일(`mode3_wallet_state.json`·`mode3_wallet_rcl.json`)을
지우고, `mode3_rp_registration.json` 의 `factoryAddress`·`verifierAddress`·`attrGateAddress` 를 지운다. 이유: IdP 는 빈 새 로그와
로컬 상태(epoch·root)가 어긋나면 기동을 거부하고, RP 는 등록 파일의 옛 팩토리(로그 주소 = 옛 거울)를 그대로 물고 떠서 스냅이 새
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
   IdP 는 :8546 에 게시하고 :8545 의 거울로 중계한다(IdP 계정은 두 체인 모두에 가스가 필요하다 — 2·3 이 각각 1 ETH 를 넣는다).
   스냅은 캐노니컬 이벤트를 :8546 에서 읽어 :8545 거울의 epoch 까지만 재생한다. RP 는 :8545 만 본다.

노드 둘이면 블록 높이가 서로 독립이다 — 거울의 root 나이·세션 만료(`max_height`)는 응용 체인(:8545) 블록 기준이고, 캐노니컬
하트비트(`CIA_HEARTBEAT_BLOCKS`)는 폐기 체인 블록 기준이다. 재시연할 때는 두 노드를 함께 다시 띄운다.

스냅 에이전트를 `MODE3_WALLET_SECRETS=snap` 으로 띄우면 MetaMask/Snap 경로가 된다(아래 "MetaMask / 스냅 경로" 절). 기본은 `file` 이다.

페이지: 스냅 `http://127.0.0.1:5100/`, RP `http://127.0.0.1:3100/`, IdP 관리자 `http://127.0.0.1:4100/admin`, IdP 사용자 `http://127.0.0.1:4100/account`.

RP 페이지는 반드시 `127.0.0.1`로 연다 — 스냅 에이전트의 CORS 허용 오리진이 `http://127.0.0.1:3100`(`MODE3_RP_ORIGIN`, 쉼표로 여럿 가능)이라 `localhost`로 열면 스냅 호출이 막힌다.

## 언어·전문가 보기 (2026-09-24 UX 개선)

> **2026-11-05:** 전문가 보기 스위치(`?expert=`, `Demo.setExpert`)는 없앴다 — 화면은 하나다. 아래 "전문가 요소" 는 DOM 에 `.expert` 로 남아 늘 숨겨지며(테스트·디버깅용), 켤 방법은 없다. "AI 에이전트 허용" 체크박스·표시도 같은 날 뺐다(프로토콜 값 allowAgent 는 늘 '0'). 언어 `?lang=` 은 그대로다.

**2026-11-04 부터 맨 위 안내 바(`#demoBar`)는 모든 페이지에서 숨긴다**(`mode3/common/demo.js` `init()` — 마크업은 남아 있고 `hidden`).
언어와 전문가 보기는 URL 매개변수로 바꾼다: `?lang=en`·`?lang=ko`, `?expert=1`·`?expert=0` (예: `http://localhost:3100/?expert=1`).
한 번 주면 아래 `localStorage` 키에 남아 다음 열기에도 유지되므로, 끄려면 `?expert=0` 을 한 번 준다. 콘솔의 `Demo.setLang()`·`Demo.setExpert()` 도 그대로다.
아래 "토글" 설명은 바가 있던 때의 기록이다.

모든 페이지 맨 위 바 오른쪽에 토글 둘이 있었다. **2026-11-03 부터 이 바에는 토글 둘만 남았다** — 9단계 칩·"다음 할 일"·다른 창 링크·체험 모드 스위치는 화면을 어지럽혀 뺐다(아래 "체험 모드" 절 참고).

| 토글 | 하는 일 | `localStorage` 키 | 기본값 |
|---|---|---|---|
| `EN` / `한국어` 버튼 | 화면 문구를 한국어 ↔ English 로 바꾼다 | `mode3.lang` (`ko`\|`en`) | `ko` |
| "전문가 보기" 체크박스 | 아래의 전문가 요소를 켠다 | `mode3.expert` (`1`\|`0`) | 꺼짐 |

둘 다 페이지·오리진마다 브라우저에 기억된다(같은 오리진의 관리자·내 계정 페이지는 설정을 공유하고, 스냅·RP 는 각자
기억한다). 콘솔에서 `Demo.setLang('en')`·`Demo.setExpert(true)` 로도 바꿀 수 있다 — 스크린샷 스크립트가 쓰는 길이다.

**전문가 보기가 켜면 보이는 것**

- 원문 로그 요소 — RP `#log`·`#sessionLog`·`#openLog`, 스냅 `#status`·`#sessionLog`·`#txLog`·`#authLog`,
  관리자·내 계정 `#out`. 이 요소들은 꺼져 있어도 DOM 에 그대로 있다(`textContent` 를 보는 테스트는 영향받지 않는다).
- 결과 카드의 "자세히"(원본 JSON)가 접히지 않고 펼쳐진 채 뜬다.
- 용어 라벨에 원래 기호가 붙는다 — "이 RP 에서의 내 주소 (PPID = Poseidon(uid, salt, chainid, arid))",
  "로그인 세션 (r_s, pk_i, max_height)", "공개할 속성 조건 (disc_mask, lo[6], hi[6], set_sel, set_root)" 등.
- RP 의 RP 상태 카드에 `arid`·`cert_s`·`pk_trace`·`Mode3Log`·팩토리·`AttrGate` 주소 한 줄, 로그인 기록 표에
  `세션 r_s`·`폐기 목록 root` 열, 관리자 RP 표에 `RP 식별자`(arid) 열이 더 나온다.
- RP (내 세션) 카드의 **"skipSync (stale_root 시연)" 체크박스**(UI 라벨은 그대로다) — 각본 5 시연은 이제 **전문가 보기를
  먼저 켜야** 보인다. 체크박스 이름은 `stale_root` 지만 V9 에서 각본 5(계정 폐기 뒤)의 실제 결과는 등록부만 바뀐
  `stale_registry_root` 다 — 폐기 목록(revocation list) 쪽이 낡았을 때라면 이름 그대로 `stale_root` 가 나온다.

## 페이지 구성 (2026-09-24 UX 개선)

페이지마다 맨 위 안내 바(7단계 진행 표시 + "다음에 할 일" 한 줄 + 다른 페이지로 가는 링크) 아래에 카드가 놓인다.

| 페이지 | 카드 |
|---|---|
| 스냅 `:5100/` | (2026-11-03 재구성) 상단 바(zk 스냅 · 탭 · 연결 상태 · 새로고침) + 탭 4개 — **계정**(내 신원·내 속성·상세[auid·salt]) · **연결된 서비스**(로그인 세션, 대기 건이 있을 때만 "체인 반영 대기" 절) · **보내기**(트랜잭션, "공개할 속성 조건" 은 접힘·집합 조건은 전문가 보기) · **설정**(MetaMask · 스냅, 위험 구역: 계정 자기 폐기·스냅 초기화; 전문가 보기면 시연 카드). `snap` 모드는 "MetaMask 연결" 카드를 지나야 탭이 보인다. 아래 표들의 괄호 이름은 그대로 쓴다 — (내 신원)=계정 탭, (로그인 세션)·(체인 반영 대기)=연결된 서비스 탭, (트랜잭션 보내기)=보내기 탭(버튼 이름은 "보내기"), (MetaMask · 스냅)=설정 탭. `?authorize=1` 팝업은 "로그인 승인" 카드 하나만 |
| RP `:3100/` | RP 상태 · 로그인 · 내 세션 · 로그인 기록 · 승인 개봉 |
| 관리자 `:4100/admin` | 인증 · 최근 결과 / 계정 / RP / 개봉 요청 / 폐기 목록 |
| 내 계정 `:4100/account` | 내 계정 폐기 (하나) |

알아 둘 것:

- 조작 결과는 **결과 카드**(판정 배지 + 한 줄 요약 + 접힌 "자세히")로 뜬다. 세션 폐기도 마찬가지다 — 원문은 전문가
  보기의 로그 요소에 그대로 남는다.
- **되돌릴 수 없는 버튼**은 빨간 테두리로 표시하고 누르면 확인창이 한 번 뜬다 — 관리자의 "계정 폐기"·세션 목록의
  "폐기"·"게시(체인에 올리기)", 스냅의 "이 세션 끝내기(폐기)"·"계정 자기 폐기"·"스냅 초기화", 내 계정 페이지의
  "내 계정 폐기". (RP·개봉 요청의 "거절" 도 되돌릴 수 없지만 확인창은 없다.)
  **브라우저 자동화는 이 대화상자를 받아야 한다**(`page.on('dialog', d => d.accept())`).
- 관리자 페이지의 **계정 폐기는 경로가 하나다** — (계정) 카드의 uid 칸에 값을 넣고 "계정 폐기" 를 누른다. 목록 행의
  "선택" 버튼은 그 uid 를 칸에 채워 줄 뿐이다. 같은 자리의 **"계정 삭제"**(2026-11-06)는 등록된 계정이면 먼저 폐기(슬롯 0·게시)한 뒤
  레코드·아이디 색인을 지운다 — 같은 아이디로 다시 가입할 수 있고 관리자 목록에서 사라진다(등록부 슬롯은 uid 없는 빈 칸으로 남아 재사용되지
  않는다). 스냅 쪽 스냅의 등록 비밀은 서버가 지울 수 없으므로 사용자가 zk 스냅 화면 "내 계정" 탭의 "스냅 초기화"(2026-11-14 — 설정 탭은 11-11 에 없어졌다)를 눌러야 새로 등록할 수 있다. 시드
  계정(`CIA_DEMO_ACCOUNTS=1`)은 다음 기동 때 다시 생긴다.
- 관리자 (인증 · 최근 결과) 카드에 **대기 배지**("승인 대기 RP N", "개봉 요청 N", 없으면 "대기 중인 건 없음")가
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
| IdP | IdP 의 `GET /mode3/health` |
| RP | RP 의 `GET /mode3/health` |
| 스냅 | 스냅 에이전트의 `GET /mode3/health` |
| 체인 | IdP → RP → 스냅 **고정 순서**로 처음 `chain` 을 준 응답의 값(체인 id·블록 높이). 먼저 도착한 응답이 아니라 이 순서다 |

점을 누르면 안내 바 아래에 **상태 패널**(`#stackPanel`)이 전폭으로 펼쳐진다 — 역할마다 판정 한 줄, 노랑·빨강이면
원인·조치·사유 코드(`root_too_old`·`registration_pending`·`cia_unavailable`, RP 비활성은 서버가 준
`inactiveReason`), 전문가 보기에서는 그 역할의 원본 JSON 까지. 바깥을 누르거나 Esc 로 닫는다.

읽기는 **5초 폴링**, 요청마다 3초 예산이다(서버 쪽 체인 조회 예산 1.2초보다 넉넉하고 폴링 간격보다는 짧다). 탭이 숨겨져 있으면 읽지 않고 다시 보이면 즉시 한 번 읽는다. 실패는
콘솔에 남기지 않고 점 색과 패널 문구로만 말한다. 자기 서버는 상대 주소 없이 `/mode3/health` 로 부르고(같은
오리진이라 CORS 를 타지 않는다), 상대 주소는 `rp_info`·`/wallet/status`·상대 health 응답에서 알아낸다. **아직 주소를
모르는 역할은 빨강이 아니라 회색(모름)** 이다. 응답의 `role` 이 기대와 다르면 오류로 본다(엉뚱한 서버를 초록으로
속이지 않는다).

**판정(설계 §2.2, `tests/test_mode3_stack_judge.js` 가 고정)**

| 점 | 초록 | 노랑 | 빨강 | 회색 |
|---|---|---|---|---|
| IdP | 아래 어느 것도 아님 | root 나이가 상한의 절반 이상(`rootAge ≥ maxRootAge/2`, 또는 하트비트 간격이 상한 이상), 아직 게시 안 한 폐기가 있음 | root 게시가 상한(`maxRootAge`) 이상으로 오래됨, 응답 없음 | 첫 폴링 전 |
| RP | 승인됨 + 활성 | 승인 대기 | 비활성(사유는 `inactiveReason`), 응답 없음 | 첫 폴링 전 |
| 스냅 | 등록됨 + IdP 에 닿음 | IdP 에 못 닿음 | 응답 없음 | 아직 등록 전, 주소 모름 |
| 체인 | 셋 중 하나라도 `chain` 을 줌(블록 높이를 보인다) | — | 아무도 체인을 못 읽음 | 첫 폴링 전 |

상한(`maxRootAge`)은 RP 가 체인에서 읽은 값이 정본이고, RP 가 없으면 IdP 의 하트비트 간격 2배를 임시로 쓴다.

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

- **V10 `mirrors`(IdP)**: `CIA_MIRRORS` 의 거울마다 `epoch`·`lastPublishedBlock`·`rootAge`(그 체인 head − 마지막 게시 블록)·`behind`
  (캐노니컬 epoch − 거울 epoch). RP 는 거울만 읽으므로 **`behind > 0` 이면 그만큼의 폐기·발급이 아직 RP 에 안 보인다**.
  거울을 못 읽으면 항목을 빼지 않고 값을 `null` 로 낸다. 같은 목록이 `GET /cia/public_keys` 의 `mirrors`(`{chainId, address}`)와
  `canonicalChainId` 로도 나온다.
- **V10 카드 한 줄씩**: 관리자 (폐기 목록) 카드 아래 "거울 chain X: epoch E (캐노니컬 대비 −n), 마지막 게시 블록 B"(`/mode3/health`
  의 `mirrors`), RP (RP 상태) 카드 "거울 주소 … / 캐노니컬 로그 …"(`rp_info` 의 `mirrorAddress`·`logAddress`), 스냅
  (로그인 세션) 카드 "거울 epoch E / 캐노니컬 epoch E′"(`/wallet/status` 의 `mirror{address, epoch, lastPublishedBlock}`·
  `canonical{rpc, logAddress, epoch}`). 문구 키는 `admin_mirror_line`·`admin_mirror_unreadable`·`rp_mirror_line`·`wallet_mirror_line`.
- 응답에는 **`Cache-Control: no-store`** 와 `Vary: Origin` 이 늘 붙는다.
- `Access-Control-Allow-Origin` 은 **허용 목록에 있는 `Origin` 으로 물었을 때만** 붙는다(다른 오리진에는 아예 없다).

| 서버 | 허용 오리진 |
|---|---|
| IdP `:4100` | 승인된 RP 들의 origin + 스냅 오리진(`MODE3_WALLET_AGENT_ORIGIN`, 기본 `http://127.0.0.1:5100`) |
| RP `:3100` | 스냅 오리진(`MODE3_WALLET_AGENT_ORIGIN`) + `MODE3_CIA_URL` |
| 스냅 `:5100` | RP 오리진 목록(`MODE3_RP_ORIGIN`, 쉼표 구분) + `MODE3_CIA_URL` |

IdP 는 스냅 오리진을 알 방법이 없으므로 **`MODE3_WALLET_AGENT_ORIGIN`** 으로 받는다(승인된 RP origin 은 IdP 가
스스로 안다). 기본값이 아닌 포트로 스냅을 띄웠다면 IdP 에도 같은 값을 줘야 한다 — 관리자·내 계정 페이지는 IdP health 의
`walletOrigin` 으로 스냅을 찾으므로, 값이 없으면 스냅 점이 회색(주소 모름)에 머물고 값이 틀리면 CORS 에 막혀 빨강이 된다. 스냅의 `ciaReachable` 은 health 를 줄 때 IdP 의 `/cia/public_keys` 를 1.5초 예산으로 **뒤에서** 찔러 본 결과다 —
응답은 기다리지 않고(그래야 IdP 가 느려도 health 가 늦지 않는다) 결과를 10초 동안 재사용한다. 그래서 IdP 를 내리면
스냅 점은 두세 번의 폴링 뒤에 노랑이 된다.

`requests`·`disclosures`(RP)와 `txs`·`disclosedTxs`(스냅)는 체험 모드의 4·5단계 판정에 쓰는 **프로세스 안 카운터**다.
개수만 싣고(무엇을 공개했는지는 싣지 않는다) **서버를 다시 띄우면 0 부터** 센다 — 그러면 그 두 단계는 다시 "안 한 것"으로
보인다(화면 표시만 그렇고 실제 세션·트랜잭션과는 무관하다). RP 쪽 `requests` 는 세션 요청(`/api/mode3/request`)만
세고 재검증은 세지 않는다 — 재검증은 RP 페이지가 자기 메모리로 안다.

## 체험 모드 (2026-09-25 UX 2차 — **2026-11-03 제거**)

> **2026-11-03: 체험 모드와 안내 바의 단계 표시를 뺐다.** `mode3/common/demo.js` 의 `Demo.init` 이 `Demo.tour.init()` 을 더 부르지 않고 바에는
> 언어·전문가 토글만 그린다. 페이지들의 `renderGuide()`·`Demo.tour.evaluate()` 호출은 그대로 남아 있지만 아무것도 그리지 않는다(잠금·말풍선·카드
> 전부 빈 동작). `tests/test_mode3_tour.mjs` 는 삭제했고 `localStorage` 의 `mode3.tour` 는 더 읽지 않는다. 아래는 제거 전 동작의 기록이다.

안내 바 오른쪽의 **"체험 모드"** 스위치. 기본은 꺼짐이고 `localStorage` 의 `mode3.tour`(`1` 또는 빈 값)에 기억된다.
켜면 (1) 지금 눌러야 할 버튼에 말풍선 하나(`#tourBubble`)가 붙고, (2) 순서를 앞지르는 버튼이 잠기고 사유 배지가
붙는다. 끄면 말풍선·잠금·배지가 즉시 사라지고 버튼은 페이지의 원래 규칙으로 돌아간다.

**다른 창으로 나른다** — 켜져 있으면 안내 바·카드의 링크에 `?tour=1` 이 붙는다. 그 링크로 열린 창은 값을 자기
저장소에 새기고 **주소창에서는 쿼리를 지운다**(`?tour=0` 이면 끈다). 오리진마다 저장소가 다르기 때문이다. 스냅의
승인 팝업(`?authorize=1`)에는 체험 모드를 만들지 않는다.

**잠금 규칙**

| 페이지·버튼 | 잠기는 조건(상대 health) | 배지 문구 |
|---|---|---|
| 스냅 "등록"(`#registerBtn`) | RP 가 아직 승인 전(`rp.status !== 'approved'`) | "먼저 관리자가 RP 를 승인해야 합니다" |
| RP "로그인"(`#loginBtn`) | 스냅이 아직 등록 전(`wallet.registered === false`) | "먼저 스냅에서 등록하세요" |

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

1~3 단계는 서버 사실(health: RP 승인·사용자 속성 등록·세션 수)과 페이지가 자기 눈으로 본 사실을 OR 한다. 4·5 단계도
마찬가지로 페이지 메모리와 서버 카운터(`rp.requests`/`wallet.txs`, `rp.disclosures`/`wallet.disclosedTxs`)를 OR 한다 —
관리자·계정 페이지에는 이용·공개의 페이지 메모리가 없기 때문이다. 6 은 `aa.pendingLeaves > 0` 또는 **이 창이 열려 있는
동안** 관측한 epoch 상승, 7 은 RP 의 개봉 결과(페이지 메모리) 또는 관리자의 `pendingOpenings` 가 1 이상에서 0 으로
떨어지는 관측이다.

> **알려진 비대칭(그대로 두는 것)**: 6단계(폐기·복구)는 **게시하고 나서 새로고침하면 다시 "안 한 것"으로 돌아간다.**
> 게시하면 `pendingLeaves` 가 0 이 되고 epoch 상승은 그 창이 열려 있는 동안에만 기억하기 때문이다. 화면 표시만
> 그렇고 실제 폐기 효력과는 무관하다.

## 시연 각본

> **2026-11-11(사용자 결정) 화면 정리**: zk 스냅 화면(localhost:5100)은 "연결된 서비스" 탭 하나만 남았다(계정·보내기·설정 탭 제거 — 스냅에서 직접 보내는 거래·AttrGate claim·스냅 초기화·스냅 자기 폐기·시연 카드가 화면에서 빠졌다). 첫 등록은 속성 도구(attr.html)의 uid·salt·속성 기록을 쓰고, 인증 창에 속성 도구가 보여 준 auid 를 붙여 넣는다. 스냅을 비우려면 MetaMask 에서 다시 설치한다. zkID 관리자 화면의 계정 카드도 뺐다(목록은 "uid ↔ auid 대응"·"등록부 DB").
>
> **2026-11-11(사용자 결정)**: RP 의 "로그인 상태"(내 세션) 카드 — "세션 재검증"(지금 확인)·skipSync — 는 화면에서 뺐다. 아래 3·5·6, F3, S5·S8 처럼 RP 에서 재검증을 누르는 단계는 화면으로 할 수 없다(API `/wallet/revalidate`·`/api/mode3/revalidate` 는 남아 있다). 로그인 유효성은 RP 화면이 2초마다 자동으로 본다. 스냅 에이전트를 재기동하면 다시 로그인한다(재승인 팝업 경로 없음).

버튼 이름은 2026-09-24 UX 개선(설계 `docs/superpowers/specs/2026-09-24-mode3-demo-ux-design.md`) 뒤의 화면 문구다.
괄호 안은 그 버튼이 있는 카드다. 5 의 "skipSync (stale_root 시연)" 처럼 **전문가 보기에서만 보이는** 것은 따로 적었다.

| # | 어디서 | 조작 | 기대 |
|---|---|---|---|
| 0 | 관리자 | (RP) "목록 불러오기" → 해당 행의 "승인" (RP 첫 기동 뒤 한 번) | RP 페이지가 "승인 대기" → "활성" |
| 1 | 스냅 | (내 신원) "등록" — uid `12345` / pwd `password123` | 결과 카드 `등록됨`, 속성은 내가 등록 폼에 넣은 값(기본 출생연도 1990·국가 KR → `[1990, 410, 0, 0, 0, 0]`) — IdP 는 받지 않는다(D15) — "속성과 선택 공개" 절 참고 |
| 2 | RP | (로그인) "로그인" ("AI 에이전트 허용" 체크 여부) | 결과 카드 `로그인 성공` 과 한 줄 요약("새 세션 …") — PPID·r_s·allowAgent·`새 발급=true` 는 카드의 '자세히'(전문가 보기에서는 펼쳐진 채)와 (로그인 기록) 표에서 본다. 스냅 (내 신원) 카드의 등록부 확인 줄이 `등록부에서 확인됨`(슬롯 N)으로 바뀐다(V9 §8.2). 공개 입력 33(끝의 auid_s·arid_s·r_s 는 RP 만 본다) |
| 2a | 스냅 | (트랜잭션 보내기) "보낼 세션" 선택 → "트랜잭션 보내기" | 첫 번째 `deployed=true`·`ok=true`, 두 번째 캐시 히트·`nonce=1` |
| 2a′ | RP → 스냅 팝업 | (2a 대신, 2026-11-04) RP (온체인 출금) "온체인 출금 실행" → 스냅 팝업 → 스냅 동의 → 승인 | snap 모드에서도 된다(그전에는 web 모드 전용). 가스는 RP 릴레이어가 내므로 스냅 EOA 가 체인에 남지 않는다. 결과는 RP 카드와 `/admin` 트랜잭션 기록에 |
| 2b | 스냅 → RP → 관리자 → RP | zk 스냅 페이지의 txHash 를 RP (승인 개봉) "트랜잭션 해시" 에 붙여 넣고 "해시로 요청" → 관리자에서 승인 → RP "결과 확인" | `uid=12345`, AI 에이전트 허용 여부 |
| 3 | RP | (내 세션) "세션 재검증" | `캐시 히트=true`, 증명 0 ms, 결과 카드 `재검증 성공` |
| 3′ | RP | (내 세션) "세션 요청 보내기" | 세션키 서명 검증 ok |
| 3″ | RP | (로그인) "로그인" (다시) | 새 세션 = `새 발급=true`, **같은 PPID** |
| 4 | 관리자 | (계정) uid 를 넣고 "계정 폐기" → (폐기 목록) "게시(체인에 올리기)" | V9: 계정 폐기 자체가 **등록부 슬롯을 0 으로 즉시 게시**한다(`published:true`, epoch +1) — 뒤이은 "게시" 는 더 낼 것이 없어 `published:false` |
| 4′ | 사용자 페이지 → 관리자 | (4 대신) 내 계정 페이지의 "내 계정 폐기" → 관리자 "게시(체인에 올리기)" | `disabled:true`, 이후 5~8 동일 |
| 4″ | 스냅 → 관리자 → RP | (4 대신, V8) 세션 둘을 만든 뒤 스냅 (로그인 세션) 목록에서 한 세션의 "이 세션 끝내기(폐기)" → 관리자 "게시(체인에 올리기)" → RP 에서 두 세션을 각각 재검증 | **세션 하나만 죽는다** — 폐기한 세션은 스냅에서 이미 사라져 재검증이 404 `no_session`(스냅 밖에서 관리자가 폐기했으면 403 `revoked_session`), 다른 세션은 그대로 ok, 새 로그인도 ok(같은 PPID). 계정 폐기(4)와 달리 `account_disabled` 가 아니다 |
| 5 | RP | **전문가 보기를 켜고** (내 세션) "skipSync (stale_root 시연)" 체크 → "세션 재검증" | 거절 `stale_registry_root`(체크박스 이름은 `stale_root` 지만, V9 의 계정 폐기(4)는 등록부만 바꾸므로 실제 결과는 이것이다 — 아래 "RP 거절 사유" 참고). "세션 요청 보내기" 는 `revalidate_required` |
| 5a | 스냅 | (폐기·게시 뒤) "트랜잭션 보내기" | `revoked` |
| 6 | RP | 체크 해제 → "세션 재검증" → "로그인" | 스냅 `revoked` → 새 로그인은 `account_disabled` |
| 7 | 관리자 | (계정) "복구(다시 쓰게)" | `disabled:false` |
| 8 | RP | (로그인) "로그인" | `새 발급=true`, 성공, **PPID 가 2 와 같다** |
| 9 | RP → 관리자 → RP | (로그인 기록) 행의 "개봉 요청"(또는 (승인 개봉) 카드에 PPID 를 넣고 "개봉 요청") → 관리자 (개봉 요청) "목록 불러오기" → "승인" → RP "결과 확인" | 202 pending → approved → uid=12345 |
| 10 | 관리자 → 스냅 | (계정) 목록 행의 "슬롯 바꿔치기(시연)" → 스냅 "로그인" → 관리자 "되돌리기" → 스냅 "로그인" | 바꿔친 뒤 로그인은 `로그인 실패`(`registry_mismatch`) — 스냅이 로그인을 시도조차 하지 않는다. 되돌린 뒤 로그인은 다시 성공하고 PPID 는 그대로다 |
| 11 | 스냅 → 스냅(전문가 보기) | (내 신원) 속성(예비 1)을 바꿔 "속성 저장" → "로그인"(새 C_u, 같은 PPID) → (시연: 비밀 바꾸기) salt 를 바꾸고 범위 "다음 발급" → "적용" → "로그인"; uid 로 같은 절차 반복; "원래대로" → 정상 로그인으로 복구 → 범위 "다음 증명" 으로 salt 를 바꾸고 "적용" → "로그인" | 속성 저장 뒤 "로그인"은 새 C_u 위에서 성공하고 PPID 는 그대로다. salt·uid 덮어쓰기(발급)는 둘 다 `로그인 실패`(`user_cred_failed` — IdP 가 π_IdP 거절: `bad_idp_proof`). 증명 덮어쓰기는 `demo_proof_failed` 로 구분된다. 둘 다 "원래대로" 로 덮어쓰기를 풀고 다시 로그인하면 복구된다 |
| 12 | 관리자 | (계정) 목록의 "슬롯" 열(2026-11-03: "아이디" 열도 — 아이디로 가입한 계정만, 옛 계정은 `-`) | testuser(`12345`)는 슬롯 0, alice(`67890`)는 슬롯 1 — 등록 순서대로 배정되고, 각자 로그인하면 서로 다른 PPID 를 받는다. V10: 계정 폐기(4·4′)를 거쳐 복구된 계정은 **새 슬롯**(다음 빈 번호)을 받고 스냅 (내 신원) 카드의 슬롯도 그것으로 바뀐다 — 은퇴한 슬롯은 다시 쓰지 않는다 |
| 13 | 스냅 → 관리자 → RP → 관리자 → RP | (V10 거울 지연) 세션 둘을 만든 뒤 관리자 (계정) "세션" 에서 하나를 "폐기" → "게시(체인에 올리기)" → RP 에서 살아 있는 세션 "세션 재검증"·"세션 요청 보내기" → `POST /cia/admin/relay`(위 "매번: 기동 순서") → 다시 "세션 요청 보내기" → "세션 재검증" → 폐기한 세션 재검증 | 게시 직후 관리자 카드의 거울 줄이 "캐노니컬 대비 −1" — 이때 재검증은 `캐시 히트=true` 로 성공하고 세션 요청도 통과한다(RP 는 거울만 본다 = **지연 창**). relay 뒤 거울 줄이 −0 이 되고, 세션 요청은 `revalidate_required` — "세션 요청 보내기" 는 누를 때마다 새로 서명하므로 서명이 낡아서가 아니라 세션에 묶인 root 와 거울 root 의 비교가 실패한 것이다. 재검증은 새 π(`캐시 히트=false`)로 성공, 폐기한 세션은 스냅 403 `revoked_session` |
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
root 게시가 `MAX_ROOT_AGE` 블록보다 오래되면 `RootTooOld` 로 멈추므로 IdP 하트비트를 켜 둔다.
트랜잭션은 zk 스냅 페이지에서만 시작한다 — RP 페이지는 스냅의 `/wallet/tx` 를 부를 수 없다(CORS).

성명은 로그인마다 새로 발급되고(설계 2026-09-15 §5) 세션 r_s 안에서만 재사용된다. RP 는 r_s 를 로그인 때 한 번 소비하고 그 뒤 세션 식별자로 쓴다. 폐기는 재검증에서 효력을 갖는다.

자격증명은 이중 구조다(설계 2026-09-21, V11 에서 발급 경로 통합 — 설계 2026-10-12 §5.2, D11). 스냅은 **사용자 자격증명**(C_u, 사용자당
하나 — 속성을 담고 IdP 는 값을 모른다)과 **세션 자격증명**(C_s, 로그인마다)을 `POST /cia/issue` 요청 하나로 함께 받는다 — 들고 있는
C_u 가 활성 자격증명과 같으면 그대로 쓰고, 다르면(첫 로그인·속성 변경) 그 자리에서 교체·게시한 뒤 서명한다. 세션마다 π_IdP 를
검증하므로 더 이상 "ZKP 없음"이 아니다(V5~V10 과 다르다). **계정 폐기 = 사용자 자격증명 리프 하나**이고, 그 사용자의 모든 세션(모든
RP)이 다음 게시에 함께 무효가 된다. 스냅은 폐기된 사용자 자격증명을 다음 로그인의 동기화에서 알아채 새로 받는다(복구 뒤 8 의
`userCredMs > 0` — `issueMs` 의 별칭이다). 상태 페이지의 "사용자 자격증명" 줄이 있음/없음/폐기됨을 보인다.

9 는 승인된 개봉(설계 2026-09-16 §6)이다. 로그인마다 스냅이 RP 의 조합 키 pk_trace 로 uid 를 암호화한 태그를 증명에 넣고
(조건 ⑤), RP 는 자기 조각으로 반만 풀어 IdP 에 낸다. 운영자가 승인하면 IdP 가 자기 조각으로 마저 풀어 uid 를 돌려준다 —
RP 혼자도, IdP 혼자도 열 수 없고, 열리는 것은 그 세션의 uid 하나다. IdP 는 로그인당 아무것도 저장하지 않는다.

0~9·3′·3″·4″·10·12·13·14 는 `tests/test_mode3_demo_stack.mjs`(HTTP)로, 2·3·4 의 라이브러리 판은 `tests/test_mode3_e2e.mjs` 로 고정돼 있다.
11(시연 카드)은 같은 파일의 "각본 11(V9)" 하나로 묶여 있다(UI 버튼 대신 `/wallet/demo/override` 를 직접 부른다).

credential 은 발급 시점 head 기준 300~400 블록(그리드 양자화)에 만료되며 스냅 상태 페이지에 `max_height` 로 보인다.

4′ 은 관리자 없이 사용자가 스스로 폐기하는 경로다(설계 §6.5.1). 인증은 계정 비밀번호이고 스냅 키가 아니다 —
장치를 잃은 사용자에게 스냅 키는 없고 공격자에게는 있기 때문이다. 처리와 게시는 4 와 같고, 복구는 여전히 관리자만 한다.

### 체험 모드로 한 번에

처음 보여 주는 자리라면 위 표를 외우지 않고 체험 모드를 켜고 말풍선만 따라가도 된다.

1. 관리자(`:4100/admin`)를 열고 안내 바의 **"체험 모드"** 를 켠다. 시크릿을 넣고, 말풍선이 가리키는 (RP)
   "목록 불러오기" → 해당 행 "승인" (1단계).
2. 카드가 "지금은 스냅 창에서 진행할 차례입니다" 로 바뀌면 **"다음 단계로"** 를 누른다 — 새로 열린 스냅 창도
   체험 모드가 켜진 채 뜬다.
3. 스냅에서 말풍선이 가리키는 **"등록"** (2단계).
4. 카드의 링크로 RP 창을 연다. 등록 전에 열었다면 "로그인" 이 잠긴 채 "먼저 스냅에서 등록하세요" 배지가 붙어
   있고, 등록이 끝나면 **다음 폴링(최대 5초)에 저절로 풀린다**. 말풍선이 가리키는 **"로그인"** (3단계).
5. 그다음은 말풍선을 따라간다 — 세션 재검증(4단계) → 공개할 속성 조건을 골라 트랜잭션(5단계) → 폐기 뒤 관리자에서
   게시(6단계) → 개봉 요청·승인(7단계). 일곱 단계를 마치면 "체험 완료" 카드가 뜬다.

정확한 조작과 기대 결과는 위 표(0~9)가 정본이다. 체험 모드는 순서를 잡아 줄 뿐 새로운 조작을 만들지 않는다.

### 실패 각본 (2026-10-11)

위 0~14 는 의도된 실패(`revoked`·`account_disabled`·`stale_registry_root`·`registry_mismatch` 등 11가지)만 보여 준다. 다음 여섯은 테스트로는
고정돼 있지만 각본에 없던 실패다 — 질문이 나오는 순서대로 적었다. 결과 카드의 문구는 `strings.js` 의 reasons 사전에 있다.

| # | 실패 | 재현 | 기대 |
|---|---|---|---|
| F1 | 피싱 RP `bad_rp_cert` | 브라우저에서는 CORS 가 먼저 막으므로(스냅은 `MODE3_RP_ORIGIN` 오리진만 허용) 콘솔로: `I=$(curl -s 127.0.0.1:3100/api/mode3/rp_info)` 로 arid·cert_s·pk_trace 를 받은 뒤 `origin` 만 `http://evil.example` 로 바꿔 `curl -s -X POST 127.0.0.1:5100/wallet/login -H 'Origin: http://127.0.0.1:3100' -H 'Content-Type: application/json' -d '{"arid":…,"origin":"http://evil.example","cert_s":…,"pk_trace":…,"r_s":"1"}'` | 403 `bad_rp_cert` — 인증서는 (arid, origin, pk_trace) 위의 IdP 서명이라 오리진을 바꾸면 검증이 깨진다(G6). 증명은 만들지 않는다 |
| F2 | 하트비트 중단 `root_too_old` | `cia.js` 를 끄고 블록을 `MODE3_MAX_ROOT_AGE`(100)보다 많이 민다: `curl -s -X POST 127.0.0.1:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"hardhat_mine","params":["0x65"]}'` → RP (내 세션) "세션 재검증" | `root_too_old` — 폐기 목록이 100블록 넘게 게시되지 않으면 **오프체인 로그인·재검증도** 막힌다(fail-closed, 점검 C-1). `cia.js` 를 다시 띄우면 다음 하트비트(5초 폴링)가 게시해 재검증이 다시 통과한다 |
| F3 | 세션 만료 `expired` | `cia.js` 를 켠 채 블록을 400 넘게 민다(`"params":["0x1a0"]`, 416블록) → 몇 초 뒤(하트비트가 root 를 새로 게시한 뒤) RP "세션 재검증" → "로그인" | 재검증 `expired`(`head > max_height`, 스냅이 정한 만료 300~400블록). 새 로그인은 성공하고 **PPID 는 같다** |
| F4 | 잘못된 공개 조건 `bad_disclosure` / `disclosure_unsatisfiable` / `predicate_type` | 스냅 (트랜잭션 보내기) "공개할 속성 조건": 출생연도 최소 `2000`·최대 `1990` 으로 "트랜잭션 보내기"; 다음 최소 `0`·최대 `1980`; 국가 슬롯의 범위 체크박스는 비활성이라 콘솔로 `curl -s -X POST 127.0.0.1:5100/wallet/tx -H 'Content-Type: application/json' -d '{"r_s":"<세션>","to":"0x000000000000000000000000000000000000dEaD","disclose":[null,{"lo":"410","hi":"410"}]}'` | 차례로 400 `bad_disclosure`(최소 > 최대), 400 `disclosure_unsatisfiable`(1990 ∉ [0, 1980] — 체인에 보내기 전), 400 `predicate_type`(enum 슬롯에 범위 조건). 셋 다 증명을 만들지 않는다 |
| F5 | 스냅의 잘못된 속성 `bad_attr` | 스냅 (내 신원) 출생연도를 비우고 "속성 저장"; `1800` 으로 "속성 저장"; 콘솔로 `curl -X PUT 127.0.0.1:5100/wallet/profile -H 'Content-Type: application/json' -d '{"profile":{"birthYear":"1800","country":"KR"}}'` | 400 `bad_attr`(reason `empty` — 빈 출생연도는 나이 조건을 통과시키므로 거절, 논의 2 / `range`), IdP 는 부르지 않는다. 어느 것도 자격증명을 물리지 않는다(거절된 요청은 속성을 바꾸지 않음) |
| F6 | 스냅 동의 거부 `user_denied` | `snap` 모드(아래 "MetaMask / 스냅 경로")에서 RP "온체인 출금 실행" → 스냅 팝업의 스냅 동의 창(받는 주소·금액)에서 **거부** (2026-11-05: 로그인에는 더 이상 스냅 동의 창이 없다 — 중복 확인 제거) | 결과 카드 `user_denied`, 거래는 보내지 않는다. 다시 누르면 정상 |

F2·F3 는 공유 :8545 의 블록을 밀어 올리므로 다른 데모 세션의 만료를 앞당긴다(테스트 그룹 `chain` 과 같은 성질). F1·F4·F5 의 콘솔 경로는
`tests/test_mode3_wallet_agent.mjs`, F2·F3 는 `tests/test_mode3_demo_stack.mjs` 가 고정한다.

## 속성과 선택 공개 (설계 2026-09-22, V11 출처 변경 D15 2026-10-12)

**속성 출처와 스키마(D15).** 속성은 **스냅의 `profile`**(사용자가 등록·로그인 전에 입력한 값, 기본 `{birthYear: '1990', country: 'KR'}`)이고
IdP(`cia.js`)는 값을 받지도 저장하지도 않는다(V6 이전의 "IdP 가 속성 값을 모른다" 는 뜻으로 되돌아간다). 정본은 사람이 읽는 `profile`
(스키마 이름 → 값)이고, 회로·서명·스냅이 쓰는 `attrs`(10진 문자열 6개)는 **공개 스키마**가 정한 규칙으로 **스냅이** 인코딩한 값이다.
기본 스키마 `zkd-attrs` v1: `a₀ birthYear`(int 1900~2100, 범위 술어 가능), `a₁ country`(enum — ISO 3166-1 숫자 코드: KR 410, JP 392,
US 840, DE 276, FR 250, GB 826, CN 156, CA 124, AU 36, SG 702), `a₂ extra1`·`a₃ extra2`(string — NFC·UTF-8 을 Poseidon 으로
64비트(1 ≤ v < 2^64)로 줄인 값, 일방향이라 화면은 `profile` 원문을 보인다), `a₄`·`a₅` 미사용(항상 0). 범위 술어는 int 슬롯에만, 집합
술어는 int·enum·string 슬롯에만 걸 수 있다 — 어기면 스냅이 400 `predicate_type`. 스키마는 IdP 가 `GET /cia/attr_schema`(인증 없음)로
공개한다 — **인코딩 규칙의 공통 기준일 뿐 값과는 무관**하다. 스키마와 해시는 `/mode3/health.attrSchema`·`/wallet/status.attrSchema`·
`rp_info.predicates.attrSchema` 에도 id·version·hash 가 실린다. IdP 는 `CIA_ATTR_SCHEMA_FILE`(JSON)로 다른 스키마를 쓸 수 있다(검증
실패는 기동 거부). 스냅은 스키마에 안 맞는 `profile`(범위 밖 연도, 표에 없는 국가, 124바이트 넘는 문자열)을 400 `bad_attr`(슬롯·이유)로
거절하고, 빈 출생연도·국가도 거절한다(이유 `empty` — 출생연도 0 은 "값 없음"인데 온체인 나이 검사를 통과한다, 아래 "수용한 한계"). 스냅은
검증 실패면 술어가 있는 로그인·tx 를 503 `schema_invalid` 로 거절하고(술어 없는 요청은 그대로), IdP 에 닿지 못하면 기본 스키마 + 경고로
두고 60초마다 뒤에서 다시 받아 본다(요청마다 IdP 를 부르지 않는다). 스냅 기본값(데모): `{birthYear: '1990', country: 'KR'}` →
`[1990, 410, 0, 0, 0, 0]`. 슬롯 하나는 **64비트**(`[0, 2^64)`, 회로 `Num2Bits(64)`·`LessEqThan(64)`) 범위다 — `lib/mode3_credential.js`
의 `ATTR_MAX`.

**스냅의 속성 변경(`PUT /wallet/profile { profile }`).** zk 스냅 페이지의 "속성 저장" 이 스키마로 재인코딩하고, 인코딩한
`attrs` 가 지금과 다르면 그 자리에서 **옛 `C_u`·세션·π 캐시를 지운다**(이 호출에서 IdP 는 전혀 불려가지 않는다) — 같으면(예: `410` ↔ `KR`)
`profile` 만 갱신하고 아무것도 지우지 않는다. 다음 **로그인**의 `/cia/issue` 가 새 `C_u` 를 활성 자격증명으로 올려(등록부 슬롯 갱신) 즉시
게시한다 — **PPID 는 그대로다**(auid·arid·chainid 가 안 바뀌므로). snap 모드는 바뀐 `attrs`(`attrsChanged`)를 저장과 동시에 스냅에
반영하고, 증인의 `attrs` 가 스냅 파일과 어긋난 채로 로그인하면 스냅이 파일 값으로 맞춰 새 `C_u` 를 받는 자가 치유 경로를 탄다(아래
"MetaMask / 스냅 경로" S8′). 저장하는 `profile` 은 정규형이다(국가 코드 `410` 으로 보내도 `KR`, 연도 앞자리 0·앞뒤 공백 제거).

**값의 보증은 없다(D15).** 술어(나이·국가)는 "사용자가 주장한 값" 위의 증명이다 — IdP 는 속성을 보지 않으므로 보증할 수 없다. 거래소
데모의 "나이 ≥ 19" 는 선택 공개·집합 소속·온체인 검사라는 메커니즘의 시연이지 값의 진위 보증이 아니다(스펙 §3.3·§13). 보증 주체(IdP 와
분리된 속성 발급자)는 §10 의 후속이다.

**트랜잭션의 선택 공개.** zk 스냅 페이지 (트랜잭션 보내기) 카드의 "공개할 속성 조건" 을 펼치면 슬롯별 체크박스(미사용 슬롯은 숨고, 정수가 아닌 슬롯의 범위 조건은 비활성) +
"최소"/"최대" 입력, "내 실제 값으로 채우기(체크한 조건)" 버튼(최소 = 최대 = 내 값)이 있다. `POST /wallet/tx` 의 `disclose`(길이 6, 각 원소 `{lo, hi}` 또는 `null`)가 회로 공개 입력 `disc_mask`·`disc_lo[6]`·`disc_hi[6]`
가 된다(V9, PUB_INDEX 15·16..21·22..27 — `lib/mode3_onchain.js`). 스냅은 제출 전에 `lo ≤ 내 속성 ≤ hi` 를 스스로 검사한다 —
안 맞으면 증명을 만들기 전에 400 `disclosure_unsatisfiable`, 형식·범위가 잘못됐으면 400 `bad_disclosure`. `disclose` 가
있으면(mask ≠ 0) 캐시된 π 를 못 쓰고 매번 새로 증명한다.

`set: { slot, members }`(선택, 슬롯 하나) — 화면에서는 같은 카드의 "집합 소속 조건" 고르개 + "허용 원소" 입력이다.
스냅이 `members` 로 root 를 계산해 회로 공개 입력 `set_sel`·`set_root`([28],[29], V9)에
넣는다. 비소속이면(내 속성이 `members`에 없으면) 역시 증명을 만들기 전에 400 `disclosure_unsatisfiable`, 형식이 잘못됐으면
400 `bad_disclosure`. 나이는 "나이 ≥" 입력 옆의 "이 나이 조건으로 채우기" 버튼으로 지정한다 — 이 버튼은
`hi[0] = 올해 − N`(연 단위)로 슬롯 0 을 공개한다(`lo[0]` 는 스키마의 출생연도 min, 기본 1900 — RP 가 `lo ≥ min` 도 요구한다).

**`AttrGate` v2 (데모 대상).** RP 가 팩토리 다음에 한 번 배포하는 컨트랙트로(`rp_info.attrGateAddress`), 정책은 국가(a₁) ∈
`allowedCountriesRoot`(집합 소속, env `MODE3_ALLOWED_COUNTRIES`)·출생연도(a₀) 기준 나이 ≥ `minAge`(env `MODE3_MIN_AGE`)이다.
`claim()` 은 `Mode3Wallet.execute()` 가 호출 데이터 끝에 붙인 (mask, lo[6], hi[6], set_sel, set_root) 15워드(V9)를 읽어
`mask & 1 == 1`(슬롯 0 공개 필요)·`set_sel == 2 && set_root == allowedCountriesRoot`(집합 소속)·`hi[0] + minAge ≤ yearOf(block.timestamp)`
(나이는 `block.timestamp` 를 연 단위로 바꾼 `yearOf` 기준)를 확인하고 `Claimed` 이벤트를 낸다. 팩토리가 배포한 스냅에서 온
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
요구한다 — 출생연도 0("값 없음")인 계정은 스냅이 `lo ≤ 내 값` 을 강제하므로 이 술어를 만들 수 없다. 페이지는 `lo` 로 그 값을 보낸다.

**시나리오 1~6**(설계 §6.3, 위 0~9 각본과 별도로 확인; V7 이후 `AttrGate` 는 국가 **범위** 공개가 아니라 슬롯 1 **집합 소속**을 요구한다 —
문구는 `tests/test_mode3_demo_stack.mjs` 케이스 10–11 에서 그대로 가져왔다):

| # | 조작 | 기대 |
|---|---|---|
| 1 | testuser 등록 | 속성 `[1990, 410, 0, 0, 0, 0]` 은 스냅의 기본 `profile`(zk 스냅 화면에는 `출생연도 1990 · 국가 KR` 로 보이고 편집 가능하다, D15) |
| 2 | 로그인(mask 0) → (트랜잭션 보내기) "공개할 속성 조건" 에서 슬롯 0 을 `[0, 올해−minAge]` 로 공개 + "집합 소속 조건"=국가(슬롯 1)·"허용 원소"=`MODE3_ALLOWED_COUNTRIES` → "받는 주소"=`attrGateAddress`, "데이터"=`claim()` 셀렉터(`0x4e71d92d`, 스냅 폼 기본값) | `Claimed` 이벤트, `AttrGate.claimed(wallet) == true` |
| 3 | alice(2005, 840)로 같은 슬롯 0 범위 + 허용 집합이 아닌 임의 집합(예: `{840, 392}`)으로 시도 | 840 은 이 임의 집합 안에 있어 스냅의 setPath 는 성공하지만 그 root 가 `allowedCountriesRoot` 와 달라 `claim()` 이 `country` 로 revert(`Executed` success=false, nonce 는 소모). 허용 집합에서 840 을 빼면 스냅이 온체인에 내기 전에 `disclosure_unsatisfiable` 로 막는다 |
| 4 | 슬롯 0 을 `[0, 1980]` 으로 공개 시도(집합 없이) | 스냅이 `disclosure_unsatisfiable`(1990 ∉ [0, 1980], 체인에 보내기 전에 막힌다) |
| 5 | alice(2005, 840): 허용 집합은 그대로 공개하되 슬롯 0 을 정책보다 넓은 구간(`[0, 올해−5]`)으로 공개 | 국가는 실제 허용 집합이라 `country` 는 통과하지만 minAge 를 증명하지 못해 `claim()` 이 `age` 로 revert |
| 6 | 스냅에서 testuser 의 예비 1(extra1) 에 문자열을 입력해 "속성 저장" → 다음 로그인 | 속성 저장이 옛 C_u 를 그 자리에서 지우고, 로그인이 새 C_u 를 받아 성공, **PPID 동일** |

### 사용자 속성 커밋먼트 → zkID 프로필 → RP 고정 (Phase 1, 2026-11-09)

> **2026-11-13(사용자 결정, 스펙 `2026-11-12-mode3-no-pk-u-design.md`) 등록 키(sk_u·pk_u) 제거 — 스냅 0.4.0·IdP 상태 v13**: IdP 는 사용자 키를 갖지 않는다. 등록·슬롯 조회·발급·세션 폐기 요청을 서명 대신 π_IdP(공개 입력 `ctx`·`tag`, 공개 10개)로 인증한다 — 계정의 비밀은 s_u 하나다. auid·PPID·s_u 유도는 그대로라 **재등록이 없다**.
> - **스냅 0.4.0 재설치**: MetaMask 에서 스냅을 지운 뒤 zk 스냅 화면(http://localhost:5100)에서 다시 연결한다. 0.3.x 스냅도 새 화면과 그대로 돌지만 저장소에 옛 `sk_u` 가 남는다(0.4.0 은 읽을 때 버린다). "내 계정" 탭에서 `sk_u` 줄이 사라진다.
> - **IdP 상태 12 → 13**: 기동 때 저절로 올라가고(계정의 `pk_u` 삭제, 기동 로그에 한 줄) 등록·슬롯은 그대로다. **옛 코드는 v13 파일을 열지 못한다** — 되돌리려면 반영 전 상태 파일 사본이 필요하므로 배포 전에 IdP VM 의 상태 파일을 떠 둔다. 에이전트 상태 파일의 `pk_u`·`sk_u` 는 기동 때 버리고 바로 다시 쓴다.
> - **`pi_idp` 산출물이 함께 가야 한다**: 회로가 바뀌어(`ctx`·`tag`) `build/mode3/pi_idp_*`(zkey·vkey·wasm)를 새로 빌드했다(`bash scripts/build_mode3_circuit.sh pi_idp` — `pi_cred`·`PiCredVerifier.sol` 은 그대로). 지갑과 IdP 가 서로 다른 산출물을 쓰면 모든 요청이 `bad_idp_proof` 다.
> - **배포 순서**(스펙 §6): IdP VM 상태 파일 사본 → VM 에 rsync(코드 + `build/mode3/pi_idp_*`) → IdP 재시작 → 스냅 에이전트 재시작 → 스냅 0.4.0 재설치 → 데모 리셋(아직 배포 안 된 스냅 0.3.0 의 유도 규칙 변경 때문에 함께 한다).
> - **대가**: 등록·슬롯 조회·세션 폐기에도 π_IdP 증명 하나가 든다(발급과 같은 회로 — 시간은 따로 재지 않았다). π_IdP vkey 를 못 읽는 IdP 는 등록부터 503 `idp_vkey_unavailable` 이다.
> - **발급 요청의 `n`**: `/cia/issue` 본문에 지갑이 뽑는 난수 `n` 이 든다(tag 의 ctx 에 들어가 요청마다 tag 가 다르다). Google 계정은 nonce 를 만들 때 쓴 `n` 을 로그인에 다시 싣는다.
> - **기존 결함 수정**: "지갑 연결 해제" 를 한 계정이 있으면 IdP 가 재시작 때 기동을 거부하던 문제를 함께 고쳤다(연결 해제는 `auid` 를 비우고 옛 슬롯 번호를 `slotRetired` 로 남긴다 — 로더가 그 모양을 받는다).
>
> **2026-11-12(사용자 요청) 스냅 0.3.1 — "내 계정" 탭**: zk 스냅 화면(http://localhost:5100)의 "내 계정" 탭이 스냅에 저장된 값 전부(등록·사용자 자격증명·동의 기록·다음 가입 번호)를 보인다(스냅 RPC `getStoredState`). 비밀(salt·sk_u·blind_u)은 가려 두고 "비밀 값 보기" 로 한꺼번에 열며, 탭을 떠나면 다시 가린다. **0.3.1 재설치 필요** — 0.3.0 이하 스냅이면 "스냅이 옛 버전입니다"(`snap_outdated_store`)가 뜬다. 로그인 세션은 스냅이 아니라 스냅 에이전트가 들고 있어 "연결된 서비스" 탭에 그대로 있다.
>
> **2026-11-12(사용자 결정) IdP 가 최신 auid_s 하나를 둔다**: IdP 는 발급에 성공할 때마다 그 계정의 `lastAuidS = { value, at }` 를 덮어쓴다(설계 D1 수정 — 이력은 없고, 세션 기록에는 여전히 auid_s·arid_s 가 없다). IdP 관리자 페이지 "uid ↔ auid 대응" 표의 "최신 auid_s" 열에 보인다. 스냅 연결을 해제하면 지운다. 아래 "한계" 의 D1 신뢰 가정은 이만큼 약해진다 — IdP 는 계정마다 마지막 세션 가명을 실제로 들고 있다.

> **2026-11-14(사용자 요청) 화면 리뷰 반영** — 동작은 그대로, 보이는 것만 바뀌었다:
> - **속성 도구**: salt 는 기본 가림이고 "보기" 로만 연다(스냅의 모든 서비스 주소를 정하는 비밀이다). "커밋먼트 재료" 는 접혀 있고 계정(uid·auid)이 먼저 보인다. 상단 바가 생겨 zk 스냅 화면과 오간다(zk 스냅 화면 상단에도 "속성 도구" 링크).
> - **설정 전 스냅으로 로그인**: 스냅 팝업이 zkID 인증 창으로 가기 **전에** 스냅 설정(설치·salt·백업 확인)을 조용히 보고 "스냅 설정이 끝나지 않았습니다" 로 멈춘다 — 아이디·비밀번호·auid 를 넣은 뒤에야 막히지 않는다.
> - **zk 스냅 화면**: 설정 카드의 비밀번호 칸은 라벨 위·입력칸 아래, 고른 방법(새로 만들기·백업에서 불러오기)만 채운 버튼, 입력 검증 실패는 한 줄, 완료 알림은 탭 위에 따로. "내 계정" 의 가림 문자는 길이가 늘 같고, "백업 다시 만들기" 는 salt 묶음 안에 있다(그 카드의 제목은 "salt 백업 다시 만들기").
> - **zkID**: 인증 창의 첫 칸 이름은 "아이디". 관리자 "uid ↔ auid 대응" 표에 상태 열(활성·계정 폐기됨) — 폐기된 계정과 새 계정에 같은 auid 가 보일 때 어느 쪽이 폐기인지 가린다. 사용자 페이지(/user)는 카드가 한 칸으로 선다.
>
> **2026-11-14(사용자 요청) 화면 리뷰 2차** — 막다른 길 둘과 화면·문구:
> - **"스냅 초기화" 는 zk 스냅 화면 "내 계정" 탭 맨 아래에 있다.** 11-11 에 설정 탭이 빠진 뒤로 버튼에 갈 길이 없었는데 안내 문구(`already_registered`·`account_disabled`)는 초기화하라고 했다. 동작은 그대로다(스냅의 등록·동의 기록과 에이전트의 등록·세션을 지우고 salt 는 남긴다).
> - **IdP 가 거절한 등록은 스냅에 uid 를 남기지 않는다.** 등록 코드 등록(`codeRegister`)이 스냅에 보류 등록(`prepareRegister`, uid 없음)만 먼저 두고, uid 는 IdP 가 받은 뒤 `storeRegistration` 이 채운다. 전에는 스냅 `register({uid})` 가 IdP 응답 전에 uid 를 적어, `auid_taken` 같은 거절 뒤 거절된 계정의 uid 가 스냅에 남고 다음 등록이 `already_registered` 로 막혔다. 보류 등록만 남은 스냅은 "내 계정" 에 "끝나지 않은 등록이 있습니다" 로 보이고, 다시 로그인하면 이어서 등록한다. 스냅 번들은 바뀌지 않았다(`register` RPC 는 남아 있으나 화면이 부르지 않는다).
> - **zkID 사용자 페이지(/user)**: "스냅 연결 해제" 와 "내 계정 폐기" 가 묶음·설명·비밀번호 칸을 따로 갖는다(카드 제목 "스냅 연결 해제 · 계정 폐기"). 연결 해제의 결과는 카드 밖에 보인다 — 전에는 해제가 되면 카드가 숨으면서 결과도 함께 사라졌다. 해제 뒤 스냅 쪽은 MetaMask 재설치가 아니라 "스냅 초기화" 로 비운다(재설치는 salt 를 지운다). "내 정보"(/user/info)도 좁은 한 칸이고, 두 페이지는 상단 메뉴의 왼쪽 끝이 카드와 맞는다.
> - **문구**: `auid_taken`(어느 계정으로 로그인할지), `auid_mismatch`(인증 창에 넣은 auid 가 이 계정의 것과 다르다는 뜻으로), 실패한 스냅 팝업의 작은 제목("요청을 끝내지 못했습니다."), "내 정보" 의 uid 설명(속성 도구는 uid 를 묻지 않는다). 좁은 폭(640px 이하)의 zk 스냅 화면 탭은 한 줄에 서고, 연결된 서비스의 허용 거래 수 설명은 칸 아래로 갔다.
>
> **2026-11-13(사용자 결정, 스펙 `2026-11-13-mode3-snap-random-salt-backup-design.md`) 스냅 기준 신원 — 스냅 0.5.0, 무작위 salt + salt 만 든 백업**: 스냅 하나에 salt 하나다. 시드 유도(`snap_getEntropy`)와 계정 번호는 없어졌다.
> - **식 셋이 바뀌었다**: `auid = Poseidon(T_AUID2, salt)`, `PPID = Poseidon(salt, arid, chainid)`, `C_attr = Poseidon(T_ATTRC4, salt, attrs[0..5])` — uid 가 auid·PPID 에서, blind 가 C_attr 에서 빠졌다. RP 쪽 신원 단위는 IdP 계정이 아니라 스냅(salt)이다. `pi_idp`·`pi_cred` 를 다시 빌드했고(`bash scripts/build_mode3_circuit.sh`) 검증자·팩토리를 다시 배포해야 한다.
> - **0.5.0 재설치 필요**: 권한이 줄어(`snap_getEntropy` 삭제) MetaMask 에서 스냅을 지운 뒤 zk 스냅 화면(http://localhost:5100)에서 다시 연결해 설치한다. 옛 스냅 상태·IdP 상태(13 이하)는 이어 쓰지 않는다 — **데모 리셋이 필요하다**(IdP 는 상태 14 만 받고 옛 파일은 기동을 거부한다. 파일은 지우지 않고 옮겨 둔다).
> - **설치 직후 설정**: 연결하면 탭 대신 "스냅 설정 — salt 와 백업" 카드가 먼저 보인다. "새로 만들기" → 백업 비밀번호(8자 이상) 두 번 → "백업 파일 저장"(파일 고르기, Chrome·Edge) → 화면이 파일을 다시 열어 확인한 뒤에야 스냅이 쓸 수 있게 된다. 그 전에는 가입·로그인·속성 도구가 "스냅 설정이 끝나지 않았습니다" 로 멈춘다. 파일을 고르기 전에는 salt 를 만들지 않는다.
> - **백업에는 salt 만 든다**(`{ version: 4, s_u }`, 봉인 형식은 그대로 `zkd-attr-backup`). **백업 파일과 비밀번호를 모두 잃으면 복구할 수 없다** — PPID 지갑 자산이 잠기고 RP 계정이 끊긴다. 파일은 PC 밖에도 둔다. "내 계정" 탭의 "백업 다시 만들기" 로 새 파일·새 비밀번호의 백업을 만들 수 있다.
> - **복구 시연**: MetaMask 에서 스냅 제거 → zk 스냅 화면에서 다시 연결(설치) → "백업에서 불러오기"(파일 + 비밀번호, 스냅 확인 창) → RP 로그인 → 팝업이 스냅 등록을 되살리고 **같은 PPID** → 속성 도구에서 같은 속성을 넣으면 **같은 C_attr**(프로필을 다시 붙여 넣지 않는다). 속성이 든 옛 형식 백업 파일도 salt 만 꺼내 받는다.
> - **한 스냅은 같은 IdP 에서 활성 계정 하나**: 같은 스냅으로 다른 계정을 등록하면 IdP 가 `auid_taken`(409)으로 거절하고 팝업에 "이 스냅은 이 IdP 에 이미 다른 계정으로 등록돼 있습니다" 가 보인다. 계정에서 스냅 연결을 해제하거나 그 계정을 폐기하면(자기 폐기·관리자 폐기) 그 스냅을 다른 계정에 쓸 수 있다 — 폐기된 계정은 스냅을 쥐지 않는다. "스냅 초기화" 는 등록·동의 기록만 지우고 salt 는 남긴다.
> - **속성 도구**: 백업 내려받기·불러오기·"3. 자동 백업(암호화)"(D20)가 없어졌다. 기록 version 4(blind·계정 번호 없음). 같은 스냅·같은 속성이면 항상 같은 커밋먼트라 기록을 잃어도 다시 만들면 된다. 대가: 속성을 A → B → A 로 바꾸면 IdP 가 예전 값으로 돌아갔다는 것을 안다.
> - **파일 선택 직후의 클릭 무시**: 파일 선택 창에서 파일을 더블클릭하면 두 번째 클릭이 창이 닫힌 뒤 페이지로 떨어져 "취소" 를 눌러 버리던 문제 — 불러오기 영역은 파일을 고른 뒤 0.7초 동안 클릭을 받지 않는다.
> - 아래 11-13 오전·11-12·11-11 메모의 "계정 번호", "시드에서 유도", "시드 복구 시연", "자동 암호화 백업(D20)", "blind" 는 이 메모로 대체됐다.
>
> **2026-11-13(사용자 결정) 속성 도구는 속성만 묻는다**: 속성 도구(http://localhost:5100/attr.html)의 입력은 출생연도·국가·예비 1·2 뿐이다 — uid·계정 번호·salt 칸, "스냅에서 가져오기"·"salt 복사" 버튼, salt 설명을 뺐다. "커밋먼트 만들기" 를 누르면 도구가 ① zkID 로그인 세션에서 uid 를 읽고(`GET {ciaUrl}/cia/user/uid`, 쿠키 — IdP 는 uid 만 돌려주고, 스냅 에이전트 오리진에만 CORS 를 연다) ② 스냅에서 salt 와 계정 번호를 받는다(`getSalt({})` — 번호는 스냅이 고른다).
> - **식에서 uid 가 빠졌다**: `C_attr = Poseidon(T_ATTRC3, s_u, attrs[0..5], blind)`(도메인 `"MODE3ATTRC3"`). uid 는 기록(version 3)과 화면의 "계정" 칸(uid·auid)에만 남는다 — 스냅 팝업이 기록의 uid 로 로그인한 계정과 맞춰 본다. 같은 속성·blind·salt 라도 옛 식(`MODE3ATTRC2`)의 커밋먼트와 값이 다르므로 zkID 프로필에 다시 붙여 넣어야 한다.
> - **zkID 로그인이 먼저다**: 같은 브라우저에서 `{ciaUrl}/user`(스냅 에이전트의 `/wallet/config` 가 알려 주는 주소)에 로그인해 둔다. 로그인하지 않았으면 "zkID 에 먼저 로그인…" 으로 멈추고 아무것도 만들지 않는다. 속성·blind·salt 는 여전히 어디에도 보내지 않는다.
> - **옛 기록·백업**: 저장된 version 1·2 기록은 "다시 만드세요" 로 보인다. version 2 백업 파일은 불러올 때 새 식으로 바꿔 계산한다(커밋먼트 값이 달라진다 — 안내가 뜬다). version 1 은 거부한다.
> - 아래 11-12·11-11 메모의 "계정 번호 칸"·"스냅에서 가져오기"·"시드로 복구할 수 없는 salt 경고"·"uid·salt 는 그대로 두고" 는 이 메모로 대체됐다(칸·버튼·경고가 없다).
>
> **2026-11-12(사용자 결정, 리뷰 I-3·`2026-11-12-mode3-snap-account-index-design.md`) 스냅 0.3.0 — 계정 번호**: 비밀을 계정 번호 k 마다 따로 유도한다(`zkd/mode3/s_u/v2/<k>`). 한 MetaMask 로 계정을 여러 개 만들어도 s_u·sk_u 가 달라 IdP 가 pk_u 로 계정을 묶지 못한다(0.2.0 은 같은 시드면 계정이 달라도 같은 값이었다).
> - **0.3.0 재설치 필요.** 유도 규칙이 v1 → v2 로 바뀌어 0.2.0 으로 등록한 계정은 시드로 되찾을 수 없다 — 데모 리셋 뒤 새로 등록한다. 0.2.0 스냅이 남아 있으면 스냅 창·속성 도구가 `snap_outdated`("스냅이 옛 버전입니다")로 멈춘다.
> - **번호가 남는 곳**: 속성 도구(`/attr.html`)의 "계정 번호" 칸과 그 기록(자동 백업 포함), 에이전트 등록 기록. 칸을 비워 두면 스냅이 고른다(등록된 계정이 있으면 그 번호, 없으면 다음 가입 번호). 번호를 바꾸면 salt 칸이 비므로 "스냅에서 가져오기" 를 다시 누른다.
> - **zk 스냅 화면(http://localhost:5100)**: "연결된 서비스" 아래 "계정 번호" 를 열면 이 계정 번호와 다음 가입 번호가 보이고, 다음 가입 번호를 바꿀 수 있다(Google 가입·새 PC 복구용). "스냅 초기화" 를 해도 다음 가입 번호는 남아, 초기화 뒤 다른 계정은 새 번호를 받는다.
> - **한계**: 상태를 다 잃은 PC 에서 새 계정을 만들면 번호가 0 부터다 — 이미 쓴 번호면 그 계정과 키가 겹친다(번호를 직접 골라야 한다). 기록 없이 0번이 아닌 계정을 되살리려면 번호를 기억해 넣어야 한다.

> **2026-11-12(사용자 결정, 스펙 D21·`2026-11-12-mode3-snap-derived-secrets-design.md`) 스냅 시드 유도 비밀·시드 복구**: 스냅 0.2.0 은 s_u·sk_u 를 MetaMask 시드(`snap_getEntropy`)에서 만든다.
> - **갱신**: `snap_getEntropy` 권한이 늘어 MetaMask 가 새 권한을 승인받아야 한다 — MetaMask 에서 스냅을 지운 뒤 zk 스냅 화면(http://localhost:5100)에서 다시 연결해 0.2.0 을 설치한다(설정 탭의 "스냅 다시 설치" 는 지금 숨겨져 있다). 옛 스냅이 남아 있으면 속성 도구·첫 등록이 "스냅이 옛 버전입니다" 로 안내한다. 이미 등록된 스냅은 저장된 옛(무작위) 비밀을 그대로 쓴다 — 시드 복구를 쓰려면 재시연 세트로 비우고 새로 등록한다. 갱신 때 Flask 가 스냅 상태를 유지하는지: (확인 대기 — 사용자 확인 결과를 여기에 적는다).
> - **속성 도구**: salt 칸은 읽기 전용이고 "스냅에서 가져오기" 로 채운다(직접 입력·새로 뽑기 없음). 옛 기록의 salt 가 스냅 salt 와 다르면 "시드로 복구할 수 없는 salt" 경고.
> - **시드 복구 시연**: 등록·로그인 → MetaMask 에서 스냅 제거(또는 같은 SRP 로 새 브라우저 프로필에 복원) → RP 로그인 → 팝업이 시드에서 같은 비밀을 만들어 등록을 되살리고 **같은 PPID·같은 RP 계정**. 에이전트 상태까지 지운 경우(`/wallet/reset`, 새 PC 역할)도 같다 — 인증 창 등록 모드에 속성 도구의 auid 를 넣으면 IdP 가 같은 비밀 재등록을 복구(201 `restored`)로 받는다.
> - **한계**: 스냅 ID(`local:http://localhost:8082`)가 바뀌면(포트 변경·npm 배포판) 유도값이 바뀐다. 속성(attrs·blind)은 시드에서 나오지 않는다 — 속성 도구 기록·D20 백업에서. 다른 시드의 MetaMask 로는 복구하지 않는다("이 스냅의 비밀이 등록과 다릅니다").

> **2026-11-11(사용자 결정, 스펙 D20) 자동 암호화 백업**: 속성 도구 "3. 자동 백업(암호화)" 에서 백업 비밀번호(8자 이상)를 두 번 넣고 "백업 설정" → 저장할 파일을 한 번 고른다. 그 뒤 커밋먼트를 만들거나 불러올 때마다 그 파일이 암호문으로 덮어써진다(상태 줄에 "마지막 백업"). Chrome·Edge 에서만 된다. 브라우저를 다시 열면 첫 저장 때 파일 쓰기 권한을 한 번 더 물을 수 있다. 복원은 "백업 불러오기" → 그 파일 → 비밀번호. "암호화 백업 내려받기" 도 암호문이다(평문 내려받기 없음). **비밀번호를 잊으면 복원할 수 없다.**

> **2026-11-11(사용자 결정, 스펙 D19) 속성 변경**: 속성 도구(http://localhost:5100/attr.html)에서 **uid·salt 는 그대로 두고** 속성만 바꿔 새 커밋먼트를 만든 뒤, zkID 내 정보의 프로필에 붙여 넣고 저장한다. 저장된 값이 바뀌면 IdP 가 기존 세션을 모두 폐기 트리(RCL)에 넣어 게시하고 사용자 자격증명을 은퇴시킨다(등록부 슬롯 0 — 관리자 화면 "등록부 DB"·RCL 에서 보인다). 다음 서비스 로그인 때 스냅 팝업이 속성 도구 기록의 속성을 스냅 에이전트·스냅에 맞추고 새 자격증명을 받아 슬롯을 다시 채운다. 기록의 salt 가 등록과 다르면 `attr_record_salt_mismatch` 로 멈춘다.

> **2026-11-11(사용자 결정, 스펙 D18)**: RP 로 보내는 부분은 걷어냈다 — zkID ID 토큰에 `name`(C_attr)을 싣지 않고, RP 는 받지도 고정·표시하지도 않는다(RP 마다 같은 값이라 두 RP 가 맞대면 같은 사람임을 안다). 속성 도구·zkID 프로필 저장은 그대로다. 아래의 "ID 토큰 name"·"RP 고정"·`attrCommitChanged` 서술과 시연 순서의 RP 단계는 옛 내용이다.

설계: `docs/superpowers/specs/2026-11-06-mode3-attr-commitment-id-token-design.md`(11-09 개정). 원칙(사용자 결정): **IdP 는 사용자 속성 커밋먼트를
저장하는 것 말고는 zk-Delegation 에 관여하지 않는다.** 커밋먼트 등록은 MetaMask·스냅과 완전히 별개 흐름이고, 커밋먼트에는 RP 관련 값이 없다.

- **속성 도구** `http://localhost:5100/attr.html` — 스냅 에이전트가 서빙하는 **정적 페이지**. 에이전트 상태·RP 와 무관하다. 밖으로 나가는 요청은 uid 를 읽는 `GET {ciaUrl}/cia/user/uid` 하나뿐이고(2026-11-13), salt·계정 번호는 스냅에서 받는다.
  속성(출생연도·국가·예비 1·2)을 넣고 "커밋먼트 만들기" → `C_attr = Poseidon(T_ATTRC4, s_u, attrs[0..5])`(10진, 2026-11-13 — uid·blind 는 식에 없다). 속성은 이 브라우저의
  localStorage(`mode3_attr_tool_v1`)에만 남는다. 지우기만 있다 — 백업 기능은 2026-11-13 에 없앴다(백업은 zk 스냅 화면이 만드는 salt 백업 하나). 번들은 `npm run attr:build`
  (`mode3/attr/dist/`, ignore) — **에이전트를 띄우는 기계에서 한 번** 만들어 둔다(없으면 페이지가 `bundle_missing` 을 보인다).
- **zkID 프로필** `/user` → 로그인 → "프로필" 카드(스냅 등록 여부와 무관하게 보인다) → "이름(속성 커밋먼트)" 에 붙여 넣고 저장(`POST /cia/user/profile`).
  IdP 는 한 줄·256자 이하 문자열로만 보고 뜻을 모른다. 프로필 카드의 "속성 도구 열기" 링크는 2026-11-13 에 뺐다(사용자 요청) — 속성 도구는 `http://localhost:5100/attr.html` 로 직접 연다.
- **ID 토큰**: 발급(`POST /cia/issue`) 응답에 `id_token`(JWT ES256, `iss=CIA_PUBLIC_URL`, `sub=auid_s`, `aud=arid_s`, `name=프로필`, 10분) 이 함께 온다.
  키는 `cia_keys.json` 의 `idTokenJwk`(없으면 기동 때 더한다 — 다른 키는 그대로). `GET /.well-known/openid-configuration`·`GET /.well-known/jwks.json`.
  분리 데모는 `demo_split_start.sh` 가 IdP role.env 에 `CIA_PUBLIC_URL=http://192.168.226.10:4100` 을 넣는다.
- **스냅**은 토큰을 열어 보지 않고 `/wallet/login` 응답에 그대로 싣는다(팝업 → RP 페이지 → `POST /api/mode3/login { …, id_token }`). 스냅·zk 스냅 페이지 변경 없음.
- **RP** 는 `MODE3_CIA_URL` 의 JWKS·discovery 로 토큰을 검증하고 `sub`·`aud` 를 증명의 `auid_s`·`arid_s` 와 맞춘 뒤 `name` 을 계정(PPID)에 고정한다
  (`mode3_rp_accounts.json`, `new_rp.sh` 는 `mode3_rp_<name>_accounts.json`). 응답 `attrCommit`·`attrCommitChanged`(바뀌면 교체하고 알린다). 세션 카드
  "속성 커밋먼트" 줄(앞 12자…뒤 6자, 툴팁 전체). 틀린 토큰은 `bad_id_token` 으로 로그인 거절; 토큰이 없으면(옛 스냅·web 모드) 예전처럼 로그인된다.

시연 순서: 속성 도구에서 만들기 → 복사 → zkID `/user` 프로필 저장 → zkONE "zkID 로 로그인" → 세션 카드에 커밋먼트 → 도구에서 다시 만들어 프로필을 바꾸고
다시 로그인하면 `attrCommitChanged`. **한계**: 커밋먼트가 실제 속성을 여는지는 아직 보이지 않는다(2단계 `pi_attr`, 사용자 승인 뒤). `C_attr` 는 RP 마다 같으므로
두 RP 가 `name` 을 맞대면 같은 사용자임을 알 수 있다(사용자 결정으로 수용 — 설계 §3·§11). 도구의 비밀은 localStorage 평문이다(같은 오리진의 zk 스냅 페이지가 읽을 수 있다).

## 세션 폐기 (V8, 설계 2026-09-24)

계정 폐기(4·4′)는 사용자 자격증명 리프 하나로 그 사용자의 **모든** 세션을 죽인다. V8 은 그 아래 단위를 더한다 — **세션 하나만**
폐기한다. 폐기 트리(RCL)에 세션 리프 `Poseidon(5, Cf_s)` 를 넣고(사용자 리프는 `Poseidon(4, Cf_u)`, **같은 트리·같은 root**),
회로가 비멤버십을 하나 더 증명한다(④′). 공개 입력은 25개 그대로라 RP·컨트랙트 인터페이스는 바뀌지 않는다.

**누가 폐기하나.** 사용자(스냅)는 `s_u` 로 만든 π_IdP(ctx = `Cf_s`·`bound`·`nonce`)로 자기 세션의 `Cf_s` 를 지정하고, 운영자는 관리자 시크릿으로 한다(2026-11-13 부터 — 전에는 등록 키 `sk_u` 서명).
RP 는 `Cf_s` 를 모르므로 세션을 폐기할 수 없다.

- zk 스냅 페이지(`/`) (로그인 세션) 카드의 각 세션 요약 아래 **"이 세션 끝내기(폐기)"** 버튼 → `POST /wallet/session/revoke {r_s}`.
  누르면 확인창이 한 번 뜬다(되돌릴 수 없는 조작). 에이전트가 서명을 만들어
  IdP `/cia/revoke scope=session` 으로 보내고, IdP 가 받아들이면 **게시 전이라도 그 세션을 로컬에서 지운다**.
  결과는 결과 카드로 뜨고(원문은 전문가 보기의 `#sessionLog`), zk 스냅 페이지는 스스로 팝업을 열지 않는다.
- IdP 관리자 페이지(`/admin`) (계정) 카드 행의 **"세션"** 버튼 → `GET /cia/admin/sessions?uid=` 목록(활성/폐기됨/만료) + 행마다 "폐기".

**IdP 가 기록하는 것.** 발급 때 `{Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt}` 을 계정에 남긴다(상태 v8). 전부 발급
때 이미 본 값이라 IdP 가 새로 알게 되는 것은 없다 — `arid`·`pk_i` 는 여전히 `C_s` 안이라 못 본다. 남는 것은 **상태**(사용자별 세션
수·발급 시각)다. 만료된 기록은 **하트비트 틱마다, 그리고 그 계정의 다음 발급 때** 지운다(리프는 트리에 남는다 — append-only).
발급 쪽 정리가 같이 있는 이유는 하트비트가 꺼져 있으면(`CIA_HEARTBEAT_BLOCKS=0`) 틱 자체가 설치되지 않기 때문이다.

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /cia/revoke` `{uid, scope:'session', Cf_s, bound, nonce?, auid_s?, C_u_pt?, C_s_pt?, max_height?, tag?, proof_idp?}` | IdP | 세션 하나 폐기. **관리자 시크릿** 또는 **사용자 인증**(π_IdP — `ctx = Poseidon(D_CTX_REVOKE, Cf_s, bound, nonce)`, `tag = Poseidon(T_TAG, s_u, ctx)`; 2026-11-13 부터, 전에는 `sk_u` 서명). 성공 `{inserted, leaf, root, pending}` |
| `GET /cia/admin/sessions?uid=` | IdP(관리자) | 그 계정의 세션 기록 + `expired`(그 체인 head 기준, 못 읽으면 `null`) |
| `POST /wallet/session/revoke` `{r_s}` | 스냅 | 같은 오리진 전용(CORS 없음). 서명 후 IdP 로 중계하고 성공하면 로컬 세션 삭제. 응답 `{revoked:true, inserted, pending}`. 인증은 `r_s` 를 아는 것뿐이다(`/wallet/revalidate` 와 같은 bearer) — zk 스냅 페이지의 확인(confirm)은 페이지가 거치는 절차이고 에이전트는 검증하지 않는다(2026-11-05: 스냅 동의 창은 뺐다) |
| 스냅 RPC `consentRevokeSession` `{arid, issuedAt, maxHeight}` | 스냅 | 2026-11-05 부터 동의 창 없이 등록 여부만 보고 `{ ok:true }`(zk 스냅 페이지는 더 이상 부르지 않는다). 스냅 에는 Poseidon 이 없어 인증 증명은 에이전트가 세션의 메모리 증인 `s_u` 로 만든다 |

**사유.** "화면 문구" 는 `mode3/common/strings.js` 의 `reasons[코드].ko.title` — 페이지가 결과 카드 제목으로 쓰는 말이다
(원인·조치 두 줄이 그 아래 붙고, 코드 자체도 제목 옆에 작게 그대로 남는다).

| `reason` | 화면 문구 | 어디서 | 상태 코드 | 뜻 |
|---|---|---|---|---|
| `revoked_session` | 이 세션은 폐기됐습니다 | 스냅 `POST /wallet/revalidate`·`/wallet/tx`(`/tx/prepare`) | 403 | 이 **세션 리프**가 폐기 트리에 있다 — 그 세션만 죽는다(스냅이 그 세션을 지운다). 사용자 자격증명은 그대로라 다른 세션·새 로그인은 된다. 계정/자격증명 폐기는 지금까지처럼 `revoked` 다. `mode3/rp.html` 은 둘을 같은 분기로 처리한다(세션 버림) |
| `unknown_session` | IdP 에 그 세션 기록이 없습니다 | IdP `POST /cia/revoke scope=session` | 404 | 그 `Cf_s` 기록이 이 계정에 없다(옛 세션이거나 만료 정리로 사라졌다). **서명 검사를 먼저 하므로** 서명 없이 "이 Cf_s 가 이 계정 것인가" 를 떠볼 수는 없다 |
| `expired` | 세션이 만료됐습니다 | IdP `POST /cia/revoke scope=session` | 409 | 그 체인 head > `max_height` — 만료가 이미 막으므로 리프를 넣지 않는다. 경계는 컨트랙트(`block.number > pub[3]`)·RP 와 같다: `head == max_height` 는 아직 산 세션이라 폐기된다 |
| `unknown_session`(중계) | IdP 에 그 세션 기록이 없습니다 | 스냅 `POST /wallet/session/revoke` | 404 | IdP 의 404 를 그대로 옮긴 것 — 스냅은 그 `r_s` 세션을 들고 있는데 **IdP 쪽에 기록이 없다**(v8 이행 전 세션이거나 만료 정리로 사라졌다). 스냅이 세션 자체를 모르는 `no_session` 과 다르다 |
| `needs_consent` | 다시 승인해야 합니다 | 스냅 `POST /wallet/session/revoke`(snap 모드) | 409 | 그 세션의 메모리 증인이 없다(에이전트 재시작) — 인증 증명을 만들 `s_u` 가 없다. zk 스냅 페이지는 사유만 보이고 스스로 팝업을 열지 않는다. RP 페이지에서 그 세션을 한 번 재검증해 재승인(§4.3, 아래 S8)을 거친 뒤 다시 누른다 |
| `not_registered` | 스냅이 등록되지 않았습니다 | 스냅 `POST /wallet/session/revoke` | 409 | 이 에이전트에 등록이 없다 |
| `no_session` | 그 세션을 스냅이 들고 있지 않습니다 | 스냅 `POST /wallet/session/revoke` | 404 | 그 `r_s` 세션을 스냅이 들고 있지 않다(이미 폐기했거나 만료) |

같은 세션을 다시 폐기하면 IdP 는 200 `{inserted:false}` 로 멱등하게 답한다.

**한계(그대로 적는다).**

- **효력은 다음 게시(또는 하트비트) 뒤부터다.** 그 사이의 온체인 실행은 막지 못한다 — 스냅은 스스로 그 세션을 버리지만,
  이미 나간 π·서명을 계정 컨트랙트가 즉시 거부하게 하는 것(세션키 블랙리스트)은 후속이다.
- **상태 v8 이행 전에 발급된 세션은 폐기할 수 없다.** `v7→v8` 은 `sessions = []` 로 시작하므로 기록이 없고, `/cia/revoke` 는
  404 `unknown_session` 으로 답한다 — 그 세션들은 `max_height` 만료로만 끝난다.
- **`CIA_CHAIN_RPCS` 에 없는 chainid 의 세션은 폐기도 정리도 못 한다.** head 를 못 읽어 만료 판정이 실패하고(폐기는
  fail-closed, 정리는 건너뜀) 기록이 남는다. 체인 RPC 장애 때도 같다 — 그동안 세션 폐기는 503 으로 막힌다(안전 쪽 실패).
- **`nonce` 는 메시지 바인딩이지 재생 방지가 아니다.** 같은 요청을 재생해도 같은 세션을 다시 폐기할 뿐이라 멱등하다.
  `nonce` 형식이 잘못되면 401 이다.
- 스냅의 `POST /wallet/session/revoke` 는 이제 IdP 호출 실패만 502 `cia_unavailable` 이고, 서명·형식 같은 지역 오류는
  500 `{reason:'internal', detail}` 이다(2026-09-24 최종 리뷰 F3).
- **재검증은 술어를 다시 증명하지 않는다**(V7부터의 기존 한계, 세션 폐기와 무관).
- 폐기된 세션 리프는 만료 뒤 죽은 리프지만 트리에서 빠지지 않는다(append-only). 만료된 리프를 접는 **재기준화는 후속**이다
  (설계 §6) — 데모 규모에서는 문제없다.

**V9(2026-10-01)**: 사용자 리프는 더 이상 폐기 트리에 넣지 않는다 — 자격증명 은퇴·계정 폐기 = 등록부 슬롯 0. 이 절의
세션 리프(`Poseidon(5, Cf_s)`)만 지금도 이 폐기 트리를 쓴다("세션 폐기" 는 여기 그대로, "계정/자격증명 폐기" 는 위
"속성과 선택 공개" 절·"RP 거절 사유" 절의 등록부(`regRoot`) 쪽을 본다).

## 계정 폐기 접수증 (V10, 설계 2026-10-02 §4)

계정 폐기(관리자 4, 자기 폐기 4′·스냅 프록시 4″)의 응답에는 **접수증** `receipt` 가 붙는다 — "이 슬롯은 비어 있어야 한다" 는
IdP 의 약속이다:

```
"receipt": { "slot": 0, "epochAtRequest": "7", "requestedAt": "1790000000", "sig": "0x…",
             "canonicalChainId": "31337", "canonicalLogAddress": "0x…" }
```

`sig` 는 IdP 이더리움 키로 `keccak(D_RECEIPT, canonicalChainId, canonicalLogAddress, slot, epochAtRequest, requestedAt)` 에 한
**EIP-191 personal-sign**(`"\x19Ethereum Signed Message:\n32"` 접두)이다(다이제스트는 `Mode3Log.receiptDigestFor` 와 같은 값, uid 는 넣지 않는다). 평소에는 쓰이지 않는다 — IdP 가 폐기와 함께 그 슬롯을 0 으로
즉시 게시하기 때문이다. **IdP 가 미적댈 때** 사용자(또는 누구든)가 이것을 캐노니컬 로그에 올리면, 그 뒤 IdP 의 모든 게시(하트비트
포함)는 그 슬롯을 0 으로 싣지 않으면 체인이 거절한다(`PendingRevocationNotApplied`) — 게시를 멈추면 root 가 늙어 전원이
`root_too_old` 로 멈추므로 결국 따를 수밖에 없다.

- **어디에 있나.** 응답 본문에만 실린다 — 사용자 페이지는 전문가 보기의 원문(`#out`)에, 스냅 프록시(`POST /wallet/self_revoke`)는
  IdP 응답을 그대로 중계한다. IdP 는 마지막 접수증을 `cia_state.json` 의 `accounts[uid].receipt` 에 두고, 같은 슬롯의 폐기를 다시
  요청하면 같은 접수증을 돌려준다. 스냅은 따로 보관하지 않는다(보관 위치는 설계 §8 의 남은 질문 3).
- **`scope:'credential'`(자격증명만 은퇴 — 속성 변경 등)에는 접수증이 없다.** IdP 가 개시한 은퇴라 사용자가 강제할 요청이 없고,
  접수증이 있으면 같은 슬롯을 다시 채운 뒤에도 누구든 그 슬롯을 강제로 은퇴시킬 수 있기 때문이다.
- **올리는 법**(데모 — 체인 하나면 `--network localhost`, 별도 노드면 `--network revchain`):
  ```
  npx hardhat console --network localhost
  > const log = await ethers.getContractAt("Mode3Log", "<receipt.canonicalLogAddress>")
  > await (await log.requestRevocation(<slot>, "<epochAtRequest>", "<requestedAt>", "<sig>")).wait()
  > await log.pendingSlots()          // [slot]
  ```
  서명이 IdP 것이 아니면 `BadSignature`, 이미 대기 중이거나 은퇴한 슬롯이면 아무 일도 하지 않는다(재전송 안전). 그다음 IdP 게시(관리자
  "게시(체인에 올리기)" 또는 다음 하트비트)가 대기열을 읽어 `(slot, 0)` 을 싣고, 통과하면 `pendingSlots()` 는 `[]`, `isRetired(slot)` 은
  `true` 가 된다. 하트비트가 먼저 실었으면 수동 게시는 `published:false` 지만 결과는 같다.
- **은퇴한 슬롯은 영구다.** 계정 폐기는 IdP 로컬에서도 그 슬롯을 은퇴시키므로(`slotRetired`), 관리자가 복구(`set_disabled false`)한
  뒤의 재발급은 **새 슬롯**(다음 빈 번호)을 받는다. 스냅은 재발급 응답의 슬롯을 따르고 PPID 는 그대로다(PPID 는 슬롯과 무관).
  각본 12·14 가 이것을 본다.

## MetaMask / 스냅 경로 (`MODE3_WALLET_SECRETS`, 설계 2026-09-22 metamask-snap)

스냅 에이전트는 등록 비밀(uid·s_u·blind_u)을 어디서 얻을지 `MODE3_WALLET_SECRETS` 로 고른다. 기본은 `file` 이고,
지금까지의 헤드리스 데모·자동 테스트는 모두 `file` 이다. `snap` 은 브라우저 + MetaMask Flask 로 사람이 직접 하는 경로다.
회로·컨트랙트·IdP·RP 로직·증명 형식은 두 모드가 같다.

| | `file`(기본) | `snap` |
|---|---|---|
| 등록 비밀 보관 | `mode3_wallet_state.json` | MetaMask 스냅의 암호화 상태. 에이전트 파일에는 **공개 부분만**(uid·auid·attrs·profile·`Cf_u`) |
| 사용자 동의 | 없음(자동 처리) | 스냅 대화상자는 RP 릴레이 출금의 받는 주소·금액 확인, 자기 폐기 비밀번호, 등록 초기화 확인만(2026-11-05: 등록·로그인·속성 공개·세션 폐기의 동의 창은 중복이라 뺐다). 스냅 "보내기" 트랜잭션은 MetaMask 확인 창 |
| RP → 스냅 로그인 | RP 페이지가 `POST /wallet/login` 을 CORS 로 직접 부른다 | RP 페이지가 zk 스냅 페이지 팝업(`/?authorize=1`)을 열고 `postMessage` 로 결과만 받는다(`/wallet/login` 의 CORS 는 닫힌다) |
| 재검증·세션 요청 | RP 페이지가 CORS 로 직접 | 같다(비밀이 필요 없다). 증인이 없으면 `409 needs_consent` → RP 가 재승인 팝업을 연다 |
| 세션 증인 | 상태 파일 | **에이전트 메모리만** — `persist()` 가 제외한다. 에이전트를 재시작하면 재승인이 필요하다 |
| 트랜잭션 전송 | 릴레이어(hardhat 언락 계정 `MODE3_RELAYER_INDEX`), `POST /wallet/tx` | MetaMask `eth_sendTransaction`(사용자 EOA 가 가스). `POST /wallet/tx/prepare` → `/wallet/tx/record` |
| 등록 | 에이전트가 s_u 를 만든다 | 스냅이 s_u 를 만들고 페이지가 한 번 넘긴다(에이전트가 auid 와 등록용 π_IdP 계산) |
| 자동 테스트 | `chain` 그룹 전 구간 | `tests/test_mode3_wallet_snap.mjs`(시뮬레이터, `chain`) + `tests/test_mode3_browser.mjs`(`browser`) |

### 준비 (처음 한 번)

1. MetaMask **Flask** 를 설치한다 — 로컬 스냅(`local:…`)은 일반 MetaMask 로는 설치되지 않는다.
2. `cd snap-mode3 && npm install && npm run build` — `dist/bundle.js` 를 만들고 `snap.manifest.json` 의 `shasum` 을 갱신한다
   (빌드가 번들을 SES 에서 한 번 평가한다 — `스냅 bundle evaluated successfully`). 루트 `node_modules` 는 건드리지 않는다.
3. `cd snap-mode3 && npm run serve` — 포트 **8082** 로 manifest·번들을 띄운다. 스냅 ID 는 `local:http://localhost:8082` 이고
   에이전트의 기본값이다(바꾸려면 에이전트에 `MODE3_SNAP_ID`).
4. 스냅 에이전트를 snap 모드로 띄운다: `MODE3_WALLET_SECRETS=snap node mode3_wallet_agent.js`.
5. **zk 스냅 페이지는 `http://127.0.0.1:5100` 으로 연다**(`http://localhost:5100` 도 스냅은 받지만 에이전트가 127.0.0.1 에만 바인딩한다).
   `snap-mode3/src/index.js` 의 `WALLET_ORIGINS` 가 이 두 값 고정이라 **다른 오리진으로 열면 스냅이 모든 RPC 를
   `unauthorized_origin` 으로 거절한다** — 포트를 바꾸려면 그 상수도 같이 고쳐야 한다. RP 페이지는 기존대로 `http://127.0.0.1:3100`.
6. 스냅을 snap 모드로 처음 쓰기 전에 `mode3_wallet_state.json` 의 `registration` 이 이미 있으면 `already_registered` 로 막힌다 —
   비밀이 파일에 있는 옛 등록과 스냅의 등록은 서로 다른 보관소다. 새로 시연하려면 "하지 말 것 / 재시연" 의 재시연 세트를 탄다.

### 수동 체크리스트 (`snap` 모드)

자동 테스트가 없는 경로라 사람이 확인한다. 각 단계에서 **어느 창이 뜨는지**가 확인 포인트다.

| # | 어디서 | 조작 | 떠야 할 창 / 확인할 것 |
|---|---|---|---|
| S0 | 스냅(:5100) | 페이지를 연다 | "스냅" 패널이 보이고 uid·비밀번호 폼은 숨는다(= 에이전트가 snap 모드) |
| S1 | 스냅 | (MetaMask · 스냅) "MetaMask 연결" | MetaMask 계정 선택 창 → 스냅 설치·권한 창. 상태줄에 `계정 0x… · 스냅 local:http://localhost:8082` |
| S2 | 스냅 | (내 신원) "등록" | **스냅 대화상자 2개**(uid → 비밀번호). 끝나면 상태에 `등록됨`, 속성은 폼 값(`[1990, 410, 0, 0, 0, 0]`, zk 스냅 화면에는 `출생연도 1990 · 국가 KR` 로 보인다). "스냅 상태 보기" 로 `등록: 예`, `사용자 자격증명 보관` 확인 |
| S3 | RP(:3100) | (로그인) "로그인" | 스냅 오리진의 **팝업 창**이 뜨고, 그 창이 곧 **IdP 로그인 페이지**(`/login?return=1&auid=…`)로 바뀐다 — 아이디·비밀번호만 넣는다(auid 는 스냅이 넘겨 숨겨진다). 성공하면 창이 스냅으로 돌아와 스냅 동의 창 없이 증명·로그인을 끝내고 스스로 닫힌다(2026-11-05: 스냅 로그인 동의 창·"IdP 인증 창 열기" 버튼·별도 인증 창을 모두 없앴다). RP 결과 카드에 `로그인 성공`(PPID 는 "자세히" 또는 전문가 보기의 `#log`) |
| S4 | RP | (S3 에서 동의를 **거절**) | RP 결과 카드에 `로그인 실패` + "승인 창에서 거절했습니다" + 코드 `user_denied`. 세션이 생기지 않는다 |
| S5 | RP | (내 세션) "세션 재검증" | 팝업 없이 성공(비밀이 필요 없다). `캐시 히트=true` |
| S6 | 스냅 | (트랜잭션 보내기) "보낼 세션" 선택 → "공개할 속성 조건" 에서 슬롯 0 `[0, 2007]` 공개 + 집합 소속 조건=국가, 허용 원소 KR,JP,US,DE,FR(범위 술어는 정수 슬롯에만 — `predicate_type`) → "받는 주소"=AttrGate, "데이터"=`0x4e71d92d` → "트랜잭션 보내기" | (2026-11-05: 스냅 속성 공개 동의 창 없이) **MetaMask 트랜잭션 확인 창**(첫 번째는 계정 배포, 두 번째가 `claim()`) → 영수증에 `ok=true`, `Claimed` |
| S3′ | RP(:3100) | (2026-11-05 B안) 로그인 뒤 "내 자산" 은 KRW 0 · ETH 0 → "KRW 1,000,000 입금(시연)" → 수량(기본 0.1) 넣고 "ETH 구매" | KRW 는 RP 메모리 장부(시연), ETH 는 세션 계정(PPID 의 CREATE2 주소)의 **실제 체인 잔액** — 구매하면 RP 릴레이어가 시세(4,210,000원/ETH 고정)로 KRW 를 깎고 그 수량의 ETH 를 세션 계정으로 보낸다(RP 관리자 거래 기록에 `구매` 한 줄). 요청은 모두 세션키 서명(`/api/mode3/request` 본문 `deposit:<ms>`·`buy:<eth>:<ms>`, 재전송은 `request_replayed`). BTC 는 잔액 목록에서 뺐다(시세표 장식에만) |
| S6′ | RP(:3100) → 스냅 팝업 | (2026-11-04) (온체인 출금) 받는 주소·금액(**ETH 단위**, 기본 0.01 — 2026-11-05 전에는 wei) 입력 → "온체인 출금 실행" | 스냅 오리진의 **팝업 창**에 "{RP} — 트랜잭션 승인"과 받는 주소·금액 → **스냅 동의 창**(RP 오리진·대상 주소·금액) → 승인하면 팝업이 증명·서명을 만들어 **RP 릴레이**(`/api/mode3/relay`, 가스는 RP 릴레이어)로 보내고 영수증 뒤 닫힌다. RP 결과 카드 `전송 성공 — 0x…`, RP 관리자(`/admin`) 트랜잭션 기록에 한 줄 |
| S7 | 스냅 | MetaMask 확인 창에서 **거절** | 페이지에 `user_rejected`. 에이전트 상태는 그대로(nonce 는 컨트랙트가 관리한다) |
| S8 | 터미널 → RP | 스냅 에이전트를 재시작 → RP 에서 (내 세션) "세션 재검증" | 에이전트가 `409 needs_consent` → RP 가 **재승인 팝업**을 연다 → 팝업이 동의 창 없이 세션의 AI agent 허용 값으로 증인을 다시 채우고 닫힌다(2026-11-05) → 재검증이 이어져 성공 |
| S8′ | 스냅 → RP → 스냅 | (내 신원) 예비 1(extra1) 에 문자열(예: `tier3`) 입력 → "속성 저장"(`PUT /wallet/profile` — `attrsChanged` 를 바로 스냅에 반영, 옛 `C_u`·세션 삭제) → RP 에서 (로그인) "로그인" | IdP 로그인 한 번으로 성공한다(스냅이 새 `C_u` 를 발급받는다, PPID 동일). 끝난 뒤 "스냅 상태 보기" 로 **속성이 `[1990, 410, <64비트 해시>, 0, 0, 0]` 으로 바뀌었고 `사용자 자격증명 보관: true`** 인지 본다 — 로그인 응답의 자가 치유 경로가 `syncAttrs` 뒤에 `updateUserCred` 순서로 스냅에 반영하므로 새 `C_u` 가 남아 있어야 한다(순서가 뒤집히면 여기서 `false` 가 되고 다음 재검증이 막힌다) |
| S9 | 스냅 | (MetaMask · 스냅) "계정 자기 폐기" | **스냅 비밀번호 대화상자** → 에이전트 `POST /wallet/self_revoke` 가 IdP 로 중계 → 결과 카드 `폐기 요청 접수`("uid … 계정의 폐기를 IdP 에 요청했습니다 — 되돌릴 수 없습니다"). 관리자 페이지에서 `/cia/publish` 뒤 재검증이 `revoked` 가 되는지 본다 |
| S9′ | 스냅 → 관리자 → RP | (V8) (로그인 세션) 목록에서 한 세션의 "이 세션 끝내기(폐기)" | 페이지의 확인 창(2026-11-05: 스냅 동의 창은 뺐다 — 서명은 에이전트가 한다) → 결과 카드 `폐기 요청 접수`("이 세션만 폐기를 요청했습니다 — 다음 게시부터 …"). 관리자 페이지에서 게시한 뒤 RP 에서 그 세션을 재검증하면 죽고(`revoked_session` 또는 세션이 이미 없어 `no_session`) 다른 세션은 산다. 에이전트를 재시작한 직후라면 메모리 증인이 없어 결과 카드 `세션 폐기 실패` + "다시 승인해야 합니다"(코드 `needs_consent`)가 뜬다 — zk 스냅 페이지는 팝업을 열지 않으므로 RP 에서 그 세션을 한 번 재검증(S8 의 재승인)한 뒤 다시 누른다 |
| S10 | 스냅 | (MetaMask · 스냅) "스냅 초기화" | 스냅의 등록이 지워진다. 에이전트 파일의 **공개** 등록은 그대로다(재시연은 재시연 세트로) |

`file` 모드에서 RP 페이지를 브라우저로 여는 경로(RP 페이지가 `/wallet/login` 을 CORS 로 직접 부르는 지금까지의 흐름)는
**자동 테스트가 덮지 않는다** — 브라우저 테스트는 snap 모드만 돌린다. `file` 모드로 데모를 바꿨다면 위 "시연 각본" 0~9 를 손으로 한 번 훑는다.

### `snap` 모드의 한계

- **EOA 가 드러난다.** 트랜잭션 수수료를 MetaMask 의 사용자 계정이 내므로 체인에서 그 EOA 와 PPID 스냅이 이어진다.
  릴레이어를 쓰는 `file` 모드에는 이 연결이 없다. Mode 2 와 같은 데모 한계다.
- **증인은 요청마다 스냅에서 온다.** 에이전트는 등록 비밀을 디스크에 쓰지 않지만, 세션 동안 `{ s_u, blind_u, attrs }` 를
  **메모리에** 들고 재검증·재증명·`tx/prepare` 에 쓴다. "스냅이 보관한다"는 영속 저장에 대한 보증이지 프로세스 메모리에 대한
  보증이 아니다.
- **에이전트 재시작 = 재승인.** 메모리 증인이 사라져 그 세션의 재검증이 `409 needs_consent` 가 된다(S8).
- 로컬 스냅 이라 **Flask 전용**이고 npm 게시·감사는 범위 밖이다.
- zk 스냅 페이지 오리진이 `WALLET_ORIGINS` 두 값으로 고정이다(위 준비 5).
- **에이전트 HTTP 는 같은 기계의 사용자 하나를 가정한다**(2026-10-26 리뷰 D2, 두 모드 공통). 에이전트는 `Host` 가
  `localhost:PORT`·`127.0.0.1:PORT`·`[::1]:PORT`·`MODE3_WALLET_PUBLIC_ORIGIN` 의 호스트·`MODE3_WALLET_ALLOWED_HOSTS`(쉼표 목록)
  가 아니면 `421 bad_host`, 공개 GET(`/`·`/common/*`·`/wallet/config`·`/mode3/health`·`/wallet/attr_schema`) 밖의 요청에
  남의 `Origin`(RP CORS 라우트 `/wallet/revalidate`·`/wallet/request`·file 모드 `/wallet/login` 은 허용 RP 오리진도 받는다)이나
  교차 사이트 `Sec-Fetch-Site` 가 오면 `403 bad_origin` 으로 막는다. 이것으로 **DNS 리바인딩 페이지와 교차 사이트 브라우저 요청**은
  `r_s`·`tx/prepare` 의 서명된 calldata·비밀에 닿지 못한다. 하지만 두 헤더가 없는 요청(curl·로컬 프로세스)은 그대로 통과하므로,
  **같은 기계의 다른 OS 사용자·프로세스는 루프백으로 여전히 에이전트를 부를 수 있다** — 다중 사용자 기계에서는 돌리지 않는다.

## IdP 페이지·폐기 상한 (2026-10-22)

설계 `docs/superpowers/specs/2026-10-22-mode3-idp-pages-design.md`(사용자·RP 운영자의 입구를 IdP 페이지로 옮김), `docs/superpowers/specs/2026-10-22-mode3-revocation-counter-bound-design.md`(세션 폐기에 허용 거래 수). **`snap`·`file` 모드 기준이다 — web 모드(바로 위 "브라우저 전용 사용자 페이지" 절)는 아직 손대지 않았다**(설계 §10 비목표. §4·§5.3 을 사용자 코어로 옮겨야 web 모드가 따라온다).

### 무엇이 바뀌었나

- 사용자가 직접 찾아가는 입구가 zk 스냅 페이지(`:5100`)가 아니라 **IdP 페이지**로 옮겼다. zk 스냅 페이지는 그대로 있지만 이제는 팝업·관리 창 쪽에 가깝다. `/account`는 `/user`로 가지 않는다 — `/account`는 Google/OIDC 계정 관리(Google 재로그인·Google 계정 자기 폐기), `/user`는 데모 계정(가입·로그인·커밋먼트 등록·계정 폐기)이다(서로 상단 링크로 오간다).
- `/user`(새): 사용자 가입(2026-11-03 부터 아이디·비밀번호 — uid는 IdP가 순번으로 배정하고 아이디는 로그인 열쇠)·로그인·~~커밋먼트 등록~~(**2026-11-09 제거** — 스냅 등록은 서비스 첫 로그인 중 `/login?purpose=register` 로; `POST /cia/auth/code { purpose:'register' }` → 등록 코드·uid, `/cia/register`(code) 응답에 `issue_code`)·속성 커밋먼트 프로필(2026-11-09)·내 등록 상태·계정 폐기(옛 `/account` 기능). 2026-11-03 부터 로그인 화면으로 열리고 등록·폐기 카드는 로그인 뒤에만 보인다.
- 관리자 `/admin` RP 목록의 승인된 행에는 **"인증서 회수"**(2026-11-06)가 있다 — 그 RP 를 다시 승인 대기로 돌려(조합 키는 그대로라 팩토리·계정 주소 불변) "발급 요청 → 승인" 과정을 다시 보일 수 있다. RP 서버는 활성 중에도 30초마다(`MODE3_RP_RECHECK_MS`, 0 이면 끔) zkID 에 등록 상태를 다시 물어 회수를 알아채면 비활성으로 돌아가 폴링을 재개한다. 한계: 이미 받은 cert_s 자체는 IdP 서명이라 스냅에서는 계속 검증되고, 실제로 막히는 것은 공개 RP 목록(스냅 CORS)·개봉 요청·RP 자신의 비활성 전환이다.
- `/rp`(새): RP 운영자 가입·로그인·**새 RP 만들기**(이름 + **서비스 주소** → 1회용 RP 키 + 포트·호스트가 채워진 `scripts/new_rp.sh` 실행 명령) · **인증서 발급 요청**(2026-11-06). zkONE·zkTWO는 지금처럼 키 없이 자동 등록되지만, 운영자가 같은 이름·주소로 "새 RP 만들기"를 하면 그 등록이 운영자에게 묶이고, 표의 "인증서 발급 요청" → 관리자 `/admin` 승인 → "발급됨" 순으로 인증서가 나간다(승인 권한은 관리자에게만 있다).
  - 묶는 규칙: "새 RP 만들기"는 **이미 들어와 있는 운영자 없는 등록** 중 이름·주소가 둘 다 같은 것을 슬롯에 묶는다(이미 승인된 것이면 바로 "인증서 발급됨"). 반대로 슬롯을 먼저 만든 뒤 들어오는 **키 없는** 등록은 묶이지 않는다(묶이면 키로 쓸 슬롯을 가짜 서버가 차지할 수 있다) — 그 슬롯은 키(`MODE3_RP_KEY`)로 등록한 RP 만 차지하고, 슬롯 주소와 origin 이 다르면 `origin_mismatch`(400). 서비스 주소는 RP 가 보내는 origin 과 글자 그대로 같아야 하므로 정규형(소문자 호스트, 80·443 생략, 경로 없음)만 받고, `new_rp.sh` 기본값(`http://localhost:PORT`, `--host IP` 면 `http://IP:PORT`)과 다른 주소(127.0.0.1·https·기본 포트)는 명령에 `--public-origin` 이 붙는다.
  - 남는 위험(데모 범위): 운영자 없는 pending 등록은 **운영자 계정을 가진 누구나** 같은 이름·주소로 슬롯을 만들어 묶고 발급할 수 있고, 그 등록이 진짜 서버의 것인지 가짜 선점인지 화면만으로는 구별할 수 없다(발급 뒤 진짜 서버는 `service_key_mismatch` 로 막힌다). 운영자 가입이 열려 있으므로 관리자 승인과 동급의 권한이 가입만으로 생기는 셈이다 — 실서비스라면 운영자 계정 승인 또는 키 등록을 필수로 해야 한다. 거부된 주소는 다른 운영자가 넘겨받을 수 있고 그때 옛 슬롯은 "주소를 넘김"(retired)이 된다.
- `/login`: zkONE 등에 로그인할 때 **스냅 팝업 창이 갔다가 돌아오는** IdP 로그인 페이지(RP가 직접 IdP로 리디렉션하지 않는다 — RP-hiding 전제를 지킨다; 2026-11-05 전에는 스냅 팝업이 따로 여는 창이었고 그 postMessage 경로도 아직 받는다). 아이디·비밀번호 두 칸을 받는다 — **auid** 는 스냅이 쿼리(`auid=`)로 넘겨 칸이 숨겨진다(없으면 칸이 보인다). 1회용 인증 코드를 내어 `?return=1` 이면 스냅 `/?authorize=1&idp_nonce=…&idp_code=…` 로 돌려보내고, 그 코드가 있어야 `/cia/issue`가 발급한다(`CIA_ISSUE_AUTH=code`, 아래).
- zk 스냅 페이지의 "내 신원" 카드에 **auid·salt 복사 버튼**(2026-11-04 부터 라벨은 `salt`)이 생겼다 — 인증 창에 넣을 값이다.
- RP 허용 오리진이 **동적**이다 — 스냅 에이전트가 `GET /cia/rp_origins`를 10초마다 읽어 기동 env(`MODE3_RP_ORIGIN`)와 합친다. 새 RP가 승인되면 스냅을 재기동하지 않아도 그 RP에 로그인된다.

### 시연 순서(2026-10-22)

지금까지의 순서(승인 → 스냅에서 등록 → RP 로그인)에 입구가 하나 더 생겼다. zkONE·zkTWO는 리셋 스크립트가 그대로 띄우므로 ①(새 RP 만들기)은 **새 RP(zkTHREE 등)를 보일 때만** 필요하다. 다만 ②(관리자 승인)는 `AUTO_APPROVE`를 켜지 않은 기본값에서는 zkONE·zkTWO도 아직 승인 대기(pending)라 건너뛸 수 없다 — 그 둘만으로 시연한다면 ②부터 시작한다(먼저 zkONE·zkTWO를 승인).

1. `/rp`는 운영자 로그인 화면으로 열린다(2026-11-03 재구성, `/user`와 같은 모양). "운영자 계정 만들기"(아이디·비밀번호·확인) → 로그인 → "새 RP 만들기"에 이름(예: `zkTHREE`) 입력 → 받은 키와 명령(`bash scripts/new_rp.sh zkTHREE <port> <key> …`)을 복사해 터미널에서 실행.
2. RP 서버가 등록 요청을 보내면 `/rp`의 내 RP 표가 "등록됨"으로 바뀌고(5초마다 갱신) 인증서 열에 **"인증서 발급 요청"** 버튼이 나온다 — 누르면 "승인 대기"가 되고, **zkID 관리자가 `/admin`의 RP 목록("발급 요청됨" 배지)에서 승인**하면 IdP 가 조각·인증서를 내고 운영자 표는 "발급됨", RP 는 몇 초 안에 활성화된다(2026-11-06 — 운영자 자체 승인은 없다). 분리 데모의 zkONE·zkTWO 도 운영자 계정을 그때 만들어 같은 이름·주소(2026-11-10 RP 터널 뒤로는 브라우저로 여는 주소 그대로 `http://localhost:3100`, `http://localhost:3101` — `http://` 는 빼도 된다, 2026-11-11)로 "새 RP 만들기"를 하면 들어와 있던 등록이 묶여 같은 흐름을 탄다(이미 승인된 등록이면 바로 "발급됨"으로 보인다 — 요청→승인 장면을 보이려면 승인 전 등록이어야 한다).
3. `/user`는 **로그인 화면**으로 열린다(2026-11-03 재구성). "계정 만들기"를 눌러 **아이디·비밀번호·비밀번호 확인**을 넣고 가입한다(uid는 IdP가 배정하고 아이디는 로그인 열쇠다. 영문·숫자로 시작하는 3~32자, 대소문자 무시, 중복이면 `id_taken`).
4. 가입하면 바로 로그인된다(2026-11-06). **로그인한 뒤에만** 프로필(속성 커밋먼트)·계정 관리 카드가 보인다. **2026-11-09(사용자 결정): `/user` 에는 스냅 등록 카드가 없다** — zkID 가입·속성 커밋먼트에는 스냅이 끼지 않고, 스냅 등록은 아래 7 의 첫 로그인 중에 일어난다.
5. (2026-11-09 부터 이 단계 없음 — 예전 "커밋먼트 등록 → 스냅 팝업" 은 Google 등록(`?google=1`, 테스트·수동 확인용)에만 남았다.)
6. (2026-11-05 부터 auid 를 복사해 둘 필요가 없다 — 스냅이 IdP 로그인 페이지에 자동으로 넘긴다. salt 는 스냅 "계정" 탭의 상세에서 보이지만 어디에도 보내지 않는다.)
7. zkONE(또는 zkTHREE)에서 "로그인" → 스냅 팝업이 **MetaMask 를 연결**하고(미등록 스냅이면 **등록 모드** 인증 창 `/login?purpose=register` — auid 칸 없이 아이디·비밀번호만 → 등록 코드·uid 를 들고 돌아와 스냅이 비밀을 만들고 `/cia/register` → IdP 가 함께 준 발급 코드로 바로 발급) 곧 **IdP 로그인 페이지**로 바뀐다 → 아이디(또는 uid)·비밀번호를 넣고 제출 → 창이 스냅으로 돌아와 발급·증명을 끝내고 닫히며 로그인 성공(스냅 동의 창 없음).
8. 거래 2건을 보낸 뒤 그 세션을 스냅 "로그인 세션" 카드에서 **허용 거래 수(기본값은 현재 nonce)**를 넣어 폐기 → 관리자 "게시" → 같은 RP에 **새 세션으로 재로그인**(⑦와 같다) → 스냅의 "체인 반영 대기" 카드에서 "지금 반영"을 눌러 옛 세션키의 체인 쪽 상한도 올린다(아래 "폐기 상한" 절). 거울 중계 뒤 거울의 `sessionBoundOf(pk_i)`(관리자 "폐기 세션 목록"의 pk_i 로 조회) 가 c+1 인지로도 확인할 수 있다.
9. 이후 단계(세션 재검증·선택 공개·개봉 요청 등)는 위 "시연 각본" 0~14와 같다.

### 환경 변수

- `CIA_ISSUE_AUTH`(IdP — 데모 리셋 스크립트의 기본은 `code`, 코드 자체의 기본은 `key`): `code`면 데모 계정의 `/cia/issue`가 위 ⑤의 1회용 인증 코드(`auth_code`)를 요구한다. `key`면 옛 방식(서명만, 인증 창 없이 발급) — `demo_web_reset.sh`·`demo_split_start.sh`(와 그 둘을 부르는 스냅 리셋 둘) 모두 `ISSUE_AUTH=key`로 끌 수 있다(각 스크립트 상단 사용법 주석). Google(래퍼) 계정은 이 정책과 무관하게 지금처럼 `id_token`으로 발급한다.
- `CIA_DEMO_ACCOUNTS`(IdP, 기본 미설정): `1`이면 기동 때 데모 시드 계정(testuser/12345·alice/67890)을 심는다. 네 리셋 스크립트는 **설정하지 않는다** — 리셋한 데모는 `/user` 가입으로만 계정이 생긴다. 옛 데모 계정으로 손으로 확인하려면 `CIA_DEMO_ACCOUNTS=1`을 직접 얹어 띄운다.
- `MODE3_RP_KEY`(RP): `/rp`의 "새 RP 만들기"가 낸 1회용 키. `scripts/new_rp.sh`가 넣어 주므로 보통 손으로 줄 일은 없다 — `bash scripts/new_rp.sh --help`로 전체 옵션(이름·포트·키, `--host`로 분리 데모의 RP VM, `--relayer`·`--countries`·`--min-age`·`--require-disclosure`, `--stop`).
- `MODE3_ROOT_WINDOW`(RP, 기본 20): 계정 컨트랙트가 대체된 root 를 더 받는 블록 수(위 "root 유효 창" 절). 팩토리 immutable 이라 바꾸면 팩토리 재배포.

### 폐기 상한(카운터, 세션 폐기)

설계 `2026-10-22-mode3-revocation-counter-bound-design.md`. 세션을 폐기할 때 **허용 거래 수 c**를 함께 받는다 — 그 세션키로 보낸 거래 중 `nonce < c`인 것만 계속 유효하고(c=0이면 전부 차단), 로그인·재검증은 상한과 무관하게 폐기 리프가 있으면 바로 막힌다(지금과 같다). 공개 입력이 33개에서 34개(`counter`)로 늘어 **회로·zkey·검증 컨트랙트가 다시 생성됐다** — 위 "하지 말 것 / 재시연"의 재시연 세트가 다시 필요하다(V11과 같은 이유로 상태 파일 이행 없음).

전파 지연(캐노니컬 게시 → 거울 중계) 동안에는 옛 root를 보는 RP가 상한 반영 전 거래를 여전히 받아 줄 수 있어, 스냅은 **응용 체인의 계정 컨트랙트에도 같은 상한**을 올릴 수 있다 — 폐기한 세션과 같은 계정의 **살아 있는 다른 세션**으로 `setSessionBound`를 실행하는 보통의 거래 하나다(스냅 "체인 반영 대기" 카드 → "지금 반영", 위 시연 순서 ⑥). 살아 있는 다른 세션이 없으면(세션이 그 하나뿐이었다면) "같은 RP에 다시 로그인하면 반영할 수 있습니다"로 막힌다 — 그 경우 체인 쪽 상한은 중계가 끝날 때까지 기다리는 수밖에 없다.

### root 유효 창 + 거울 세션 counter (2026-10-25)

설계 `docs/superpowers/specs/2026-10-25-mode3-root-window-session-counter-design.md`. 그전에는 계정 컨트랙트가 두 root(폐기·등록부) 모두 **최신**만 받아, 내가 증명을 만든 뒤 MetaMask 승인 사이에 **다른 사용자**의 세션 폐기·신규 등록이 거울에 실리면 내 거래가 `StaleRevocationRoot`/`StaleRegistryRoot` 로 튕겼다(미팅 덱 "Race Condition (1)"). 이제:

- 로그·거울(`Mode3Log`·`Mode3Mirror`, 공통 베이스 `Mode3RootHistory`)이 **대체된 root 의 블록**을 최근 16개까지 기억하고, 계정 컨트랙트는 팩토리 생성자 `rootWindow`(G 블록, 기본 **20**, RP env `MODE3_ROOT_WINDOW`) 안의 옛 root 도 받는다. 창 안에서는 타인의 폐기·등록이 내 거래를 튕기지 않는다.
- 그 대신 **폐기된 세션**은 창과 무관하게 막힌다: 스냅이 세션을 폐기할 때 세션키 `pk_i` 를 세션키 서명으로 묶어 IdP 에 알리고, IdP 는 다음 게시 페이로드에 `(pk_i, 허용 거래 수 c)` 를 실어 거울이 `sessionBoundOf[pk_i]` 로 공개한다(낮추기만). 계정 컨트랙트는 자기 호출 상한(`setSessionBound`, 선택 기능)과 거울 값 중 **낮은 쪽**을 적용해 `nonce ≥ c` 를 `SessionBounded` 로 거절한다. 거울이 받기 전까지의 거래는 채굴 순서 문제(Race (2))로 남는다 — 지연 실행 큐가 별도 후속이다.
- 관리자 폐기(스냅을 거치지 않음)·옛 스냅의 폐기는 `pk_i` 가 없어 거울 counter 없이 RCL 리프만 — 그 세션은 **거울 반영 뒤에도 G(20) 블록 동안** 대체 직전 root 로 만든 증명으로 거래할 수 있고, 창이 닫힌 뒤 회로의 구간 검사로 막힌다. 계정 폐기·자격증명 은퇴(등록부만 바뀜)도 같다. 도난 세션을 운영자가 끊을 때는 이 G 블록을 감안하고, 사용자가 스냅에서 그 세션을 (같은 또는 더 낮은 허용 거래 수로) 다시 폐기하면 `pk_i` 가 붙어 즉시 막힌다.
- **재시연 세트가 필요하다**: 로그·거울 컨트랙트가 바뀌고(게시 다이제스트 도메인 `MODE3_LOG_V4`) 팩토리·계정 생성자 인자가 늘어 CREATE2 주소가 바뀐다 — 로그·거울 재배포(`scripts/deploy_mode3_log.cjs`), IdP 상태 파일 새로, RP 등록 파일의 `factoryAddress`·`verifierAddress` 삭제(RP 가 다시 배포한다). 옛 팩토리로 로그인하면 스냅이 `bad_factory`(rootWindow 조회 실패)로 거절한다.
- 스냅이 받아들이는 `rootWindow` 범위는 0..200 블록이다(0 = 최신 root 와, 같은 블록에서 대체된 직전 root 만). 창이 클수록 **은퇴한 자격증명**의 옛 π 가 그만큼 더 통과하므로(세션 폐기는 counter 가 막아 무관) 데모 외에는 블록 시간에 맞춰 줄인다(12 s 체인 ≈ 10).

### 시연: Race (2) — 폐기 전파 지연 (2026-11-12)

폐기한 세션키의 거래가 거울이 `(pk_i, c)` 를 받기 **전**에는 통과하고 **뒤**에는 `SessionBounded` 로 막히는 것(위 절의 Race (2))을 RP 출금 하나로 보인다.

- 켜는 것(분리 데모 스크립트 기본값): IdP `CIA_REVOKE_PUBLISH_AFTER_BLOCKS=3`(스냅의 세션 폐기를 받은 뒤 응용 체인 블록이 3개 지나면 IdP 가 스스로 게시·거울 중계, 스크립트 `REVOKE_PUBLISH_AFTER`, 0 = 끔), 스냅 에이전트 `MODE3_DEMO_RACE=1`(빈 블록을 만드는 `POST /wallet/demo/mine`, 스크립트 `DEMO_RACE`). 둘 다 시연 전용이고 코드 기본은 꺼짐이다. 에이전트를 손으로 띄우면 `MODE3_DEMO_RACE=1` 을 붙인다 — 없으면 팝업이 `demo_race_off` 로 멈춘다.
  - 부작용: 켜 두면 스냅 "로그인 세션" 카드의 세션 폐기도 3블록 뒤 자동 게시된다 — 위 "시연 순서" ⑧ 의 관리자 "게시" 를 보이려면 `REVOKE_PUBLISH_AFTER=0` 으로 띄운다.
- 순서: RP(zkONE) 에 zkID 로 로그인 → 출금 카드의 **"시연: Race (2) — 보내기 전에 멈춤"** 체크 → "ETH 출금" → 스냅 동의 창 확인 → 스냅 창이 증명·세션키 서명 뒤 멈춘다 →
  - **"2블록 뒤 보내기"**: 스냅 창이 이 세션을 폐기하고(허용 거래 수 = 현재 nonce — 들고 있는 거래가 대상) 블록을 2개 진행한 뒤 보낸다 → 거울 반영 전이라 **통과**(RP: "이 세션은 이미 폐기됐지만 거울 반영 전이라 통과했습니다").
  - 다시 로그인해 같은 순서로 **"5블록 뒤 보내기"** → 3블록째에 IdP 가 게시·중계해 거울이 상한을 받았으므로 **막힘**(RP: `session_bounded` "폐기된 세션의 거래가 막혔습니다", 자세히에 `SessionBounded`).
  - 스냅 창 진행 줄에 "폐기 뒤 k/N블록 · 거울 상한 c+1"(반영 전은 `-`)이 보인다.
- 줄은 평소 화면에 보이고 "시연 숨기기" 로 접는다(이 브라우저에만 기억). 숨겨 두면 체크돼 있어도 멈추지 않는다.
- 주의
  - **세션 수명**: 분리 데모는 `TTL_BLOCKS=5`·`HEIGHT_GRID=5` 가 기본이라(자연 만료 시연) max_height 가 로그인 헤드 + 5~9 다. "5블록 뒤" 가 그보다 늦으면 폐기 자체가 `expired` 로 거절되거나 거래가 만료로 막혀 `SessionBounded` 가 나오지 않는다. 이 시연을 할 때는 `TTL_BLOCKS` 를 늘려(예: 30) 띄우고, 로그인 직후 바로 출금한다.
  - 블록 사이에 1.5초를 둬 IdP 의 게시·중계가 끝날 틈을 준다(IdP 는 200 ms 마다 헤드를 본다). 체인이 아주 느리면 5블록 쪽이 통과할 수 있다 — 스냅 창의 거울 상한 표시로 확인한다.
  - root 유효 창(20블록) 안이라 옛 root 는 그대로 받아들여진다 — 막는 것은 세션 counter 뿐이다.
  - RP 는 승인 창을 5분(`POPUP_TIMEOUT_MS`) 기다린다 — 멈춘 채 그보다 오래 두면 RP 가 창을 닫고 `timeout` 으로 끝난다.
  - 자동 테스트: `tests/test_cia_revoke_publish_after.mjs`(chain), `tests/test_mode3_browser.mjs` 의 "시연 Race (2)" 두 케이스(browser).

### 스냅 재설치

스냅 번들이 다시 빌드됐다(등록 확인 창이 uid·비밀번호 프롬프트 없이 확인 하나로 줄었고, 세션 폐기 동의 창에 허용 거래 수가 추가됐다) — **체크섬이 바뀌었으므로** MetaMask에 이미 설치된 스냅은 자동으로 갱신되지 않는다. `cd snap-mode3 && npm install && npm run build` 뒤, MetaMask에서 기존 스냅을 지우고 zk 스냅 페이지에서 다시 연결/설치한다(위 "MetaMask / 스냅 경로" 준비 절과 같다). 리셋 스크립트의 요약 줄도 이 안내를 찍는다.

**2026-11-05 — 중복 확인 제거.** 스냅 번들이 다시 바뀌었다: 등록·Google 등록(`register`·`prepareRegister`)·로그인 동의(`consentLogin`)·세션 폐기(`consentRevokeSession`)·salt 표시(`showSalt`)의 확인 창을 뺐고, `consentDisclosure` 는 RP 릴레이 출금(`{ relay:true }`)만 묻는다(남은 대화상자: 릴레이 출금 확인, 자기 폐기 비밀번호, 등록 초기화 확인). 같은 이유로 `cd snap-mode3 && npm run build` 뒤 MetaMask 에서 스냅을 지우고 다시 설치해야 한다. 함께 바뀐 로그인 흐름: 스냅 팝업 창이 IdP 로그인 페이지(`/login?return=1&auid=…`)로 갔다가 `/?authorize=1&idp_nonce=…&idp_code=…` 로 돌아온다 — 별도 인증 창·"IdP 인증 창 열기" 버튼·auid 손 입력이 없어졌다.

**2026-11-06 — 스냅 설치 창 반복 제거.** zk 스냅 페이지·팝업이 연결할 때마다 `wallet_requestSnaps` 를 불렀고, `local:` 스냅은 그 요청마다 MetaMask 가 재설치 창을 띄워 로그인·등록·재승인마다 "스냅 설치" 가 반복됐다. 이제 `wallet_getSnaps` 로 이미 설치·허용돼 있으면 요청하지 않는다(설치 창은 처음 한 번만). 그 대신 **번들이 바뀐 뒤에는 자동으로 다시 깔리지 않으므로** 스냅 설정 탭의 **"스냅 다시 설치"** 버튼(또는 MetaMask 에서 스냅 삭제 뒤 재연결)으로 명시적으로 갱신한다 — 등록 비밀·동의 기록은 그대로 남는다.

### Google 로 등록·로그인·자기 폐기(스냅 모드, 2026-10-26)

- 켜짐이 기본이다: 스크립트가 IdP 에 `MODE3_OIDC_CLIENT_ID` 를 넘긴다(환경변수 → 없으면 이 VM `.env` 의 `GOOGLE_CLIENT_ID`, Mode 1 공유 ID — 값은 출력하지 않는다). 끄려면 `OIDC=0`. 환경변수가 미설정이고 `.env` 에서 `GOOGLE_CLIENT_ID` 를 얻은 경우(공유 ID 폴백)에는 스크립트가 값 없는 경고 줄을 출력한다(IdP 기동 경고는 이 경로에서 발동하지 않는다). 공유 ID 의 위험은 선행 스펙 §5 에서 다룬다.
- Google 콘솔의 승인된 JavaScript 오리진에 `http://localhost:5100` 이 있어야 한다. Google 버튼은 zk 스냅 페이지·팝업(localhost:5100)에만 뜬다 — IdP(사설 IP)의 `/account` 에서는 안 된다.
  - (2026-11-06) `/user` 의 "Google 계정으로 등록" 은 Google 로그인이 **스냅 팝업**(localhost:5100) 안에서 일어나므로 IdP 를 VM 주소(`192.168.226.10`)로 열어도 동작한다 — 스냅 오리진(health 의 `walletOrigin`)이 localhost 가 아니면 숨는다. 스냅은 꼭 `http://localhost:5100` 이어야 한다(`127.0.0.1` 은 Google 이 다른 오리진으로 본다). **같은 날 사용자 결정으로 이 버튼은 평소 화면에서 뺐다** — `/user?google=1` 로 열 때만 보인다(자동 테스트·수동 확인용). Google 로그인(RP 로그인 팝업의 Google 버튼)과 스냅의 Google 자기 폐기는 그대로다.
  - 반면 `/account`(Google 재로그인·Google 계정 자기 폐기)는 IdP 페이지 자체에 Google 버튼을 그리므로 IdP 를 `localhost` 로 열어야 한다. VM 데모에서 보여 주려면 발표 PC 에서 `ssh -L 4100:localhost:4100 zkd@192.168.226.10` 을 열어 둔 채 `http://localhost:4100/account` 로 간다. (2026-11-11 사용자 결정: `/user` 의 "Google 로 등록한 계정 관리" 링크는 뺐다 — `/account` 는 주소로만 연다.) 스냅에도 Google 자기 폐기가 있으므로 `/account` 는 기기를 잃은 경우에만 필요하다.
- 스냅이 바뀌었다(보류 등록 `prepareRegister`). `cd snap-mode3 && npm run build` 뒤 MetaMask 에서 스냅을 다시 설치하고 zk 스냅 페이지 "스냅 초기화".
- 수동 확인(실제 Google, 1회):
  1. IdP `/user` → "Google 로 등록" → 팝업의 스냅 확인 → 팝업의 Google 버튼 → `/user` 에 "Google 계정 등록됨 — uid …".
  2. RP 로그인 → 팝업의 Google 버튼(IdP 로그인 페이지 없음; 2026-11-05 부터 스냅 동의 창도 없음) → 로그인 성공 → 거래.
  3. zk 스냅 페이지 "계정 자기 폐기" → Google 버튼 → 폐기 요청됨 → 다음 RP 로그인 거절(account_disabled).
- 등록이 Google 단계에서 끊기면 다시 "Google 로 등록" 하면 된다 — 스냅이 같은 보류 비밀을 다시 쓴다. 버리려면 "스냅 초기화".
  IdP 등록은 됐는데 스냅 저장 전에 끊겼으면(팝업이 닫힘 등) 'Google 로 등록'을 다시 누르면 Google 로그인 없이 스냅 저장을 마저 한다.
- IdP 만 다시 띄워 래퍼를 켜거나 끈 경우 에이전트도 다시 띄운다 — 에이전트는 IdP 의 oidc 설정을 처음 받은 값으로 고정한다(받지 못한 경우만 다시 읽는다).

### RP 계정에 Google·네이버 로그인 연결 (2026-11-10, 스펙 `docs/superpowers/specs/2026-11-10-mode3-rp-social-logins-design.md`)

> **2026-11-11(사용자 결정, 스펙 개정 1) Google 은 zkID 래퍼**: RP 로그인 창의 "Google 계정으로 로그인" 을 누르면 스냅 팝업이 열리고, 팝업 안의 Google 버튼으로 받은 토큰으로 zkID 와 같은 발급·증명을 거쳐 PPID 세션이 된다(IdP 로그인 페이지로 가지 않는다). 미등록 스냅이면 첫 로그인이 Google 등록이다 — Google 버튼을 두 번(등록·발급) 누른다. Google 계정마다 별도 zkID 계정이라 아이디 계정과 PPID 가 다르고, 아이디 계정으로 등록된 스냅은 `snap_other_account` 로 멈춘다(바꾸려면 MetaMask 에서 스냅 재설치). 첫 등록은 기본 속성이고 속성 도구 기록·D19 속성 맞추기는 쓰지 않는다. **Google Cloud Console 의 승인된 JavaScript 원본에 `http://localhost:5100` 이 있어야 한다**(버튼이 스냅 팝업에 뜬다). 네이버 로그인과 내 계정의 Google·네이버 "연결" 은 아래 그대로 RP 직접이다.

11-09 의 "zkID 계정에 Google·네이버 연결" 은 걷어냈다(사용자 지적: 연결된 로그인은 RP 가 지원하는 기능). zkID 인증 창은 다시 아이디·비밀번호만 받는다.

- **모델**: RP(zkONE·zkTWO)마다 계정이 따로다. 계정 하나에 로그인 수단 세 칸 — zkID(PPID)·Google·네이버. 처음 쓰는 수단으로 로그인하면 그 칸만 채운 새 계정이 생긴다.
  나머지는 로그인한 뒤 상단 메뉴 **"내 계정"** 탭에서 연결·해제한다(마지막 수단은 해제할 수 없다). 다른 계정에 이미 붙은 수단은 연결을 거부한다(계정 병합 없음).
  zkONE 에서 연결한 것은 zkTWO 에 아무 영향이 없다.
- **로그인 창**: "zkID 로 로그인" 은 지금처럼 스냅 팝업. "Google 계정으로 로그인" 은 그 자리에 Google 버튼(GIS), "네이버로 로그인" 은 네이버를 다녀온다 — 둘 다 스냅을 거치지 않는다.
  (RP 에 Google 설정이 없고 IdP 가 Google 래퍼를 켰으면 Google 버튼은 예전 래퍼 로그인 — web 모드가 쓴다.)
- **자산**: KRW · ETH(내 계정 = PPID 스마트 계정, zkID 로 연결돼 있을 때) · ETH(거래소 보관). Google·네이버 세션에서 산 ETH 는 거래소 보관 장부에 쌓이고, 출금은 RP 릴레이어가
  자기 돈으로 보낸다. 온체인 출금의 **출금 출처**: "내 계정" 은 zkID 세션(스냅 증명)일 때만, "거래소 보관" 은 늘. 계정·장부는 `mode3_rp_accounts.json`(version 2)에 남는다.
- **zk 를 거치지 않는 지점(데모 대비)**: zkID 자격증명을 폐기해도 Google·네이버 로그인은 된다(PPID 계정 출금만 막힌다) · zkTWO 의 국가·나이 요구는 소셜 로그인에 적용되지 않는다 ·
  두 RP 가 같은 Google 클라이언트·네이버 앱을 쓰면 sub 이 같아 두 RP 가 같은 사람임을 안다(zkID 는 RP 마다 다른 PPID) · 거래소 보관은 수탁이다 · localhost 에서 쿠키는 포트로 격리되지 않는다(이름만 다르다 — `zkone.sid`·`zktwo.sid`·`cia.sid`).
  zkID 로 로그인해 생긴 쿠키 세션은 그 zkID 세션(r_s)과 함께 끝난다(폐기·로그아웃).
- **주소(분리 데모, snap 모드)**: 브라우저는 zkONE `http://localhost:3100`, zkTWO `http://localhost:3101`, IdP `http://localhost:4100` 으로 연다 — `demo_split_start.sh` 가 이 VM 에 SSH 터널 셋을 연다
  (`SPLIT_RP_TUNNEL`·`SPLIT_IDP_TUNNEL`, 0 이면 VM 주소). RP 공개 주소가 바뀌면 RP 가 스스로 새로 등록한다 — IdP 관리자 페이지에서 다시 승인한다.
- **설정(사용자)**:
  - Google 콘솔 승인된 JavaScript 원본에 `http://localhost:3100`·`http://localhost:3101`(그리고 기존 `http://localhost:4100`·`http://localhost:5100`). 클라이언트 ID 는 IdP 래퍼와 같은 값을 RP 에도 준다.
  - 네이버 개발자센터 애플리케이션 Callback URL 에 `http://localhost:3100/api/rp/naver/callback`·`http://localhost:3101/api/rp/naver/callback`. Client ID·Secret 은 환경변수 또는 이 VM `.env` 의
    `MODE3_NAVER_CLIENT_ID`·`MODE3_NAVER_CLIENT_SECRET` — 스크립트가 **RP `role.env` 에만** `MODE3_RP_NAVER_*` 로 옮긴다(출력은 on/off 만).
  - RP env: `MODE3_RP_GOOGLE_CLIENT_ID`, `MODE3_RP_NAVER_CLIENT_ID`·`_SECRET`·`_REDIRECT_URI`(기본 `${MODE3_RP_PUBLIC_ORIGIN}/api/rp/naver/callback`), `MODE3_RP_SESSION_SECRET`(없으면 기동마다 무작위 — 재기동하면 다시 로그인).
- **시연 순서**: zkONE 에서 zkID 로 로그인 → 내 계정 → Google 연결 → 로그아웃 → Google 로 로그인(같은 계정·같은 잔고) → 네이버 연결 → zkTWO 에서 Google 로 로그인(새 계정 — RP 마다 따로).
- **미확인(실제 네이버)**: Callback 에 `http://localhost` 가 허용되는지, 토큰 교환에 `client_secret` 과 PKCE `code_verifier` 를 함께 보내도 되는지, 앱 하나에 Callback 을 여러 개 등록할 수 있는지 —
  자동 테스트는 네이버 흉내 발급자로만 돌렸다.

### 한계

- **에이전트(`file`) 모드에는 Google(OIDC 래퍼) 등록이 없다**(`/wallet/register` 가 `not_snap_mode` 로 거절) — 스냅 모드는 위 절, web 모드는 아래 "Google 로 등록·자기 폐기" 절.
- **전파 지연**: 거울이 `(pk_i, c)` 를 받기 전까지는 폐기한 세션키의 거래가 통과할 수 있다(Race (2), 채굴 순서) — 타 사용자의 폐기·등록이 내 거래를 튕기는 쪽(Race (1))은 root 유효 창으로 없앴다(위 절).
- **인증 창은 스냅이 열지만 피싱될 수 있다** — 악의적 페이지가 같은 `/login` URL을 새 창으로 열어 비밀번호를 입력하게 유도할 수 있다. 코드만으로는 발급이 되지 않으므로(등록 비밀·서명이 따로 필요하다) 그 1회 발급 시도는 막히지만, 빼낸 **uid·비밀번호 자체**로는 계정 자기 폐기(`/cia/account/self_revoke`)나 코드 재발급까지 할 수 있어 영향이 1회 발급 시도에 그치지 않는다 — 검증되지 않은 우려이며 별도 완화는 아직 없다.
- 분리 구성(IdP가 `192.168.226.10`처럼 사설 IP)에서는 Google 버튼이 뜨지 않는다(기존 한계, "Google로 등록" 절과 같다). 2026-11-09 부터 분리 데모는 IdP 를 `localhost:4100` 터널로 연다(위 "Google·네이버 로그인 연결" 절).
- **이 절의 시연 순서는 컨트롤러의 E2E 실행으로 아직 확인되지 않았다**(이 작업은 리셋·시연을 직접 돌리지 않는다) — 실제로 돌려 본 뒤 다른 점이 있으면 이 절을 고친다.

## 브라우저 전용 사용자 페이지 (web 모드, 2026-10-15)

설계 `docs/superpowers/specs/2026-10-15-mode3-browser-user-page-design.md`, 구현 계획
`docs/superpowers/plans/2026-10-15-mode3-browser-user-page.md`(스펙과 다른 결정은 그 계획의 "스펙 대비 결정 R1~R12" 가 우선한다).
스냅·Node 에이전트 설치 없이 **브라우저만**으로 사용자 쪽(등록·로그인 팝업·재검증·세션 요청·트랜잭션·선택 공개·세션 폐기)을 돌리는
세 번째 경로다 — 비밀은 이 브라우저의 IndexedDB 에 비밀번호로 암호화해 두고, 가스는 RP 의 릴레이가 댄다. 회로·토큰·컨트랙트·IdP
라우트의 의미는 `file`·`snap` 모드와 같다.

### 구성

스냅 자리에 에이전트(`mode3_wallet_agent.js`) 대신 정적 서버 `node mode3_user_static.js` 를 같은 포트(:5100)에 띄운다 — 포트가
같아 둘을 동시에 띄울 수 없다. env 이름은 에이전트와 같다: `MODE3_CIA_URL`, `MODE3_RP_ORIGIN`, `CIA_RPC_URL`,
`MODE3_REV_CHAIN_RPC`, `CIA_LOG_ADDRESS`, `MODE3_MIRROR_ADDRESS`, `MODE3_TTL_BLOCKS`, `MODE3_HEIGHT_GRID`, 선택
`MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y`, `MODE3_RELAY_PATH`(web 모드 전용 — 에이전트는 읽지 않는다).

정적 서버의 라우트:

| 경로 | CORS | 설명 |
|---|---|---|
| `GET /` | — | `mode3/user/index.html` |
| `GET /dist/*` | — | `npm run user:build` 산출물(esbuild 번들, 커밋하지 않음) |
| `GET /common/*` | — | `mode3/common/`(strings.js 등) |
| `GET /zk/:name` | — | 회로 산출물 6개(`pi_cred`·`pi_idp` 의 wasm·zkey·vkey) — `Cache-Control: immutable` |
| `GET /user/config` | 같은 오리진만 | 페이지 부팅 설정(walletOrigin·ciaUrl·rpcUrl·chainId·logAddress·mirrorAddress·rpOrigins 등) |
| `GET /wallet/config` | RP 오리진 | `{ secrets: 'web', snapId: null, walletOrigin, rpcUrl, chainId }` — 비밀 없음 |
| `GET /mode3/health` | RP·IdP 오리진 | 존재 신호(등록·자격증명·세션 수 등 6개) — 위 "상태 패널" 절과 같은 형식 |
| `POST /wallet/presence` | 같은 오리진만 | 사용자 페이지가 `health` 에 실릴 불리언 2개·정수 4개를 알린다(재시작하면 초깃값) |

**COOP/COEP 헤더를 내지 않는다**(R1) — `same-origin`/`require-corp` 는 RP 가 연 팝업의 `window.opener` 를 끊어 아래 팝업
프로토콜이 깨진다. snarkjs·ffjavascript 의 브라우저 빌드는 `SharedArrayBuffer` 없이도 워커로 멀티스레드가 된다.

IdP(`cia.js`)는 사용자 오리진(`MODE3_WALLET_AGENT_ORIGIN`, 기본 `http://127.0.0.1:5100`)에만 CORS 를 연다 —
`POST`+`OPTIONS` `/cia/register`·`/cia/issue`·`/cia/slot`·`/cia/revoke`·`/cia/account/self_revoke`, `GET`
`/cia/public_keys`·`/cia/attr_schema`. 관리자 헤더가 필요한 라우트·관리자 전용 라우트는 CORS 가 없다(그대로).

RP(`mode3_rp.js`)는 사용자 오리진에만 `POST /api/mode3/relay`·`GET /api/mode3/relay/:txHash` 를 연다 — 아래 "릴레이" 절.

### 기동 순서

> **한 번에(2026-10-16):** `bash scripts/demo_web_reset.sh` — 전부 내림 → Mode 3 상태 파일 백업 → hardhat 새로 → 로그·거울 배포 → 번들 빌드 → IdP·사용자 페이지·zkONE·zkTWO 를 **localhost 오리진**으로 기동. RP 는 승인 대기로 두고(`AUTO_APPROVE=1` 이면 자동 승인), 로그는 `/tmp/mode3-demo/`. `TWO_CHAINS=1` 이면 아래 "폐기 체인을 별도 노드로" 구성(캐노니컬 로그 :8546 chainId 31338, 거울 :8545)으로 띄운다. 브라우저도 localhost 주소로 열고, IdP 를 초기화했으면 사용자 페이지의 "모두 지우기"로 등록을 맞춘다.
> **관리자 비밀번호(2026-11-05, 사용자 요청):** 관리자 페이지는 비밀번호 화면을 먼저 보인다. IdP `/admin` 은 `CIA_ADMIN_SECRET`(두 스크립트의 기본값 `idp`), RP `/admin` 은 `MODE3_RP_ADMIN_SECRET`(없으면 RP 이름 소문자 — zkONE `zkone`, zkTWO `zktwo`). RP 의 로그인 기록·거래 기록·개봉 요청/조회 API 는 `X-RP-Admin-Secret` 헤더가 없으면 401 이다(세션 목록 `GET /api/mode3/sessions` 는 고객 페이지가 쓰므로 그대로 열려 있다). 맞은 비밀번호는 그 탭의 sessionStorage 에만 남아 탭을 닫으면 다시 묻는다. `ADMIN_OPEN=1` 로 띄우면 IdP 관리자만 예전처럼 비밀번호 없이 열린다.
>
> **데모 설정(2026-10-21):** 두 스크립트(`demo_web_reset.sh`·`demo_split_start.sh`)는 데모 편의로 다음을 기본으로 켠다 — 모두 **데모 전용**이며 코드 기본값은 꺼짐이다. ① `CIA_ADMIN_OPEN=1`: IdP 관리자 경로가 시크릿을 묻지 않는다 — **2026-11-05 부터 기본은 끔(`ADMIN_OPEN=1` 로 켬)**, 위 관리자 비밀번호 참고. 2026-11-03 리뷰 뒤: 목록 GET 은 그대로 열려 있지만 상태를 바꾸는 POST 는 `X-CIA-Admin-Secret` 헤더가(자리표시 `open` 이라도) 있어야 한다 — 교차 사이트 폼으로 승인·게시가 눌리지 않게(관리자 페이지·데모 스크립트는 이미 헤더를 보낸다). ② `MODE3_HEIGHT_GRID=5`: 만료(max_height) 올림 단위(`HEIGHT_GRID=100` 으로 원래대로). ③ `MODE3_DEMO_GENERATION=<실행 시각>`: 사용자 페이지가 기억한 세대와 다르면 브라우저의 옛 등록·세션을 스스로 지운다(리셋마다 "모두 지우기"를 누르지 않게; 이 설정 이전에 등록한 브라우저만 처음 한 번 수동). ④ zkTWO 에 `MODE3_REQUIRE_DISCLOSURE=1`: 로그인 때 국가 집합·나이 술어를 서버가 요구한다(없으면 `predicate_unmet`) — zkONE 은 누구나. 2026-11-03 리뷰 뒤: **재검증에도** 같은 요구를 적용한다. 스냅 에이전트는 로그인 때의 술어를 재검증 π 에 다시 싣으므로 속성이 그대로면 통과하고, 바뀌었으면 `predicate_unmet` 으로 세션이 끝나 다시 로그인해야 한다(web 모드 코어는 술어 없이 재검증하므로 zkTWO 재검증이 실패한다 — web 모드는 일시 중지 상태). 그 밖에 RP 관리자 페이지의 거래 기록(`GET /api/mode3/txs`, 메모리만)·거래 해시 복사 버튼, RP 페이지의 "입금·구매(시연)"(옛 "출금 신청"→"현재 잔액 확인" 자리 — `body:'balance'` 세션 요청에 KRW 장부와 세션 계정의 실제 ETH 잔액을 돌려준다; 2026-11-05 B안, 위 S3′), 사용자 페이지 세션 폐기 → RP 로그아웃 알림, RP 가 모르는 세션의 로그아웃도 묘비(사용자 페이지가 지운다).
> **스냅 모드 한 번에(2026-10-22):** `bash scripts/demo_snap_reset.sh`(한 머신) / `bash scripts/demo_split_snap_reset.sh`(VM 분리 — 스냅 에이전트 :5100 은 스냅이 허용하는 오리진이라 한 머신 스냅 데모와 동시에 못 띄운다; web 분리 리셋은 `demo_split_reset.sh`) — 같은 순서로 스냅 자리에 에이전트(`MODE3_WALLET_SECRETS=snap`)와 스냅 서버(:8082)를 띄운다(`WALLET_MODE=snap` 의 demo_web_reset.sh). 브라우저에는 MetaMask Flask 가 필요하고, 리셋 뒤 MetaMask 안의 옛 등록은 zk 스냅 페이지의 "스냅 초기화" 로 지운다(데모 세대 자동 정리는 web 모드 전용).
> **복구 코드(2026-10-21, web 모드):** 등록 비밀 s_u 는 32바이트 시드에서 유도된다(`registrationSecretsFromSeed`, lib/mode3_wallet.js). 사용자 페이지 보관 상태 카드의 "복구 코드 보기"가 `zkd1.`+base64url(시드)를 보여 주고(어디에도 보내지 않는다), "복구 코드로 복구"는 uid + 코드로 비밀을 되살린 뒤 IdP 의 슬롯 되찾기(`POST /cia/slot`, π_IdP 인증)로 계정·비밀을 확인하고 등록 상태를 다시 만든다 — 같은 uid·s_u 라 모든 RP 의 PPID 가 그대로다(다음 로그인이 새 C_u). 시드 없는 옛 등록은 `zkd0.`+base64url(s_u‖32바이트 — 옛 sk_u 자리. 2026-11-13 부터 읽을 때 무시하고 쓸 때 0). Google(래퍼) 계정 복구는 아직 범위 밖(uid 를 토큰에서 얻어야 한다). 페이지는 기동 때 `navigator.storage.persist()` 도 요청한다(iOS 7일 삭제·Chrome 용량 정리 완화).
> **참고(2026-10-22, `snap`·`file` 모드):** 사용자·RP 운영자의 입구가 IdP 페이지(`/user`·`/rp`)로 옮겨 가고 세션 폐기에 허용 거래 수(카운터)가 붙었다 — **web 모드(이 절)는 아직 그대로다.** 위 "MetaMask / 스냅 경로" 절 뒤의 "IdP 페이지·폐기 상한" 절 참고.

```
npx hardhat node                       # 이미 떠 있으면 생략
node cia.js                            # :4100
npm run user:build                     # mode3/user/dist 번들(esbuild) — 소스를 바꿀 때마다 다시
node mode3_user_static.js              # :5100 (npm run user:static 도 같다) — 에이전트 대신
node mode3_rp.js                       # :3100
```

### 금고(비밀 보관)

등록할 때 **이 브라우저용 금고 비밀번호**를 정한다(8자 이상 권장). 비밀번호 → PBKDF2(SHA-256, 310,000회, salt 16바이트) →
AES-GCM-256 키이고, 이 키로 비밀(`s_u`·`blind_u`·세션 개인키)만 암호문으로 묶는다 — 그 밖의 등록·속성·세션 정보는
평문으로 IndexedDB(`mode3-user`)에 있다. 잠금 해제 키는 추출 불가(`extractable:false`) `CryptoKey` 로 IndexedDB 에 두고
30분(`UNLOCK_TTL_MS`) 뒤 자동으로 잠기며, "잠그기" 버튼으로 바로 잠글 수도 있다. 팝업과 메인 탭이 이 잠금 상태를 공유한다(R3).

- **비밀번호를 잊으면 복구할 수 없다.** IdP 에는 uid 가 그대로 남아 있어 재등록이 409 로 막힌다 — "하지 말 것 / 재시연" 의
  재시연 세트가 유일한 출구다.
- 기존 금고가 있는 상태에서 등록을 다시 시도하면, 넣은 비밀번호가 기존 금고 비밀번호와 다르면 `bad_password` 로 막힌다.
- **보안 메모(R3)**: 비밀 보관의 경계가 스냅(확장 샌드박스)에서 페이지(IndexedDB)로 내려온다 — XSS 한 건이면 비밀이
  유출되고, 이 사이트의 데이터를 지우면 비밀도 함께 사라지며, 해제돼 있는 동안의 키는 같은 오리진의 어떤 스크립트도 쓸 수
  있다. 아래 "한계" 절 참고.

### 팝업 프로토콜 (`?authorize=1`)

사용자 페이지를 `?authorize=1` 로 열면 준비되는 즉시 `window.opener` 에 `{ type: 'mode3-authorize-ready' }` 를 보낸다(스펙
§4.2). RP 페이지는 이 신호를 받은 뒤 아래 5종 중 하나를 `postMessage` 로 보내고, 팝업은 `${요청 type}-result` 로 답한다.
팝업은 **`window.opener` 가 보낸 메시지만** 받는다.

| 요청 `type` | 화면 | 응답 요지 |
|---|---|---|
| `mode3-config` | 없음 | RP 오리진만 실린 공개 설정 — **`uid` 를 싣지 않는다**(R5) |
| `mode3-precheck` | 없음 | 인증서·팩토리 검증(동의 창 전) |
| `mode3-authorize` | 승인·거절 버튼 | `reauth:true` 가 오면 승인 창 없이 세션·인증서만 확인하고 `{ ok:true, reauth:true }`(R12) |
| `mode3-revalidate` | 캐시 히트면 화면 없음 | `skipSync:true` 면 저장된 증명 캐시를 그대로 재제출 |
| `mode3-request` | 승인 버튼 | 세션 서명 |

`ev.origin` 이 요청에 적힌(인증서의) 오리진과 다르면 `origin_mismatch`, 내 세션이 아닌 RP 가 요청하면 `no_session` 으로
거절한다.

### 릴레이 (`POST /api/mode3/relay`)

사용자 페이지는 `Mode3Wallet.execute` calldata 를 만들기만 하고, RP 의 릴레이어 계정이 가스를 내고 대신 보낸다
(`{ to, data }`, `value` 는 0 으로 고정). 검사 순서:

1. 활성 — IdP 승인·팩토리 배포 전이면 503 `relay_inactive`
2. 본문 형식 — `value≠0`·주소/hex 형식 아님 → 400 `relay_bad_calldata`(`detail: 'value'|'format'`)
3. `execute` 선택자·공개 입력 33개·`pub[1]`(`arid`)이 이 RP 인지 → 400 `relay_bad_calldata`(`detail: 'selector'|'arid'`)
4. `to === factory.computeAddress(pub[0])`(`pub[0]` 이 PPID) 가 아니면 400 `relay_bad_target`
5. 같은 `to` 로 분당 `MODE3_RELAY_RATE`(기본 10) 초과면 429 `relay_rate_limited`
6. 그 주소에 코드가 없으면 릴레이어가 `factory.deploy(ppid)` 를 먼저 보낸다
7. `estimateGas` 가 되돌려지거나(`detail` 에 컨트랙트 오류 이름 — `NonceMismatch`·`InvalidProof`·`BadSignature` 등) 추정 가스가
   `MODE3_RELAY_GAS_CAP`(기본 1,200,000)을 넘으면 400 `relay_gas`
8. 전송 → `{ txHash, deployed, deployTxHash }`. 진행 상태는 `GET /api/mode3/relay/:txHash` 로 본다.

CORS 는 사용자 오리진만 연다.

### 한계

- **비밀 격리가 스냅(확장 샌드박스)에서 페이지(IndexedDB)로 내려간다.** XSS 한 건이면 비밀이 유출되고, 이 사이트의 데이터를
  지우면(사용자가 지우든, 브라우저가 지우든) 비밀도 함께 사라지며, 해제 중인 키는 같은 오리진 스크립트가 쓸 수 있다.
- **릴레이가 검열할 수 있다.** RP 가 `/api/mode3/relay` 요청을 거부하거나 지연시킬 수 있고, 사용자 페이지로서는 그것을
  강제할 방법이 없다.
- **릴레이가 증명을 검증하기 전에 계정을 배포한다.** 위 6번(배포)이 7번(가스 추정 — 여기서 컨트랙트가 증명·서명을 본다)보다
  앞이라, PPID 를 바꿔 보내면 매번 다른 `to` 가 나와 5번의 속도 제한을 우회하면서 릴레이어에게 배포 가스를 떠안길 수 있다.
  데모에서는 세 서버가 `127.0.0.1` 에 묶여 있고 hardhat 가스라 무해하지만, 실제 네트워크라면 치명적이다. 후속: 배포 전
  오프체인 Groth16 검증, 또는 배포 자체에 전역 한도.
- **web 모드는 팩토리·검증자 참조 코드 대조(`verifyReferenceCode`)를 생략한다** — `file`/`snap` 모드의 `bad_factory`
  (`detail: factory_code_mismatch`/`verifier_code_mismatch`)에 해당하는 검사가 없다.
- **web 모드는 발급 코드 정책(`CIA_ISSUE_AUTH=code`)을 쓰지 않는다** — web 코어(사용자 페이지·`mode3_user_static.js`)는
  1회용 인증 코드(`auth_code`)를 보내지 않으므로, `ISSUE_AUTH=code`로 켜면 `/cia/issue` 로그인이 막힌다(두 리셋 스크립트
  모두 기본값을 `WALLET_MODE`에 따라 고른다 — `snap`은 `code`, `web`은 `key`, 2026-10-23).
- `auid_s`·`arid_s` 의 calldata 노출은 그대로다(위 "수용한 한계"의 "설계 노출" 항목과 같은 결정 — web 모드가 새로 만들지도,
  고치지도 않는다).
- **두 탭을 동시에 열면** read-modify-write 경쟁으로 한쪽의 쓰기가 유실될 수 있다.
- **증명 캐시는 세션당 1개**다 — 선택 공개 조건이 있는 트랜잭션을 보낸 뒤 재검증은 기본 π(조건 없는 증명)로 되돌아간다.

### 다른 기계에서 web 모드로

위 "다른 기계에 설치" 절의 `build/mode3/` 묶음(`scripts/pack_mode3_build.sh`)과 `npm install` 에 더해 `npm run user:build`
한 번이 필요하다(esbuild devDependency). 브라우저는 최신 Chrome·Edge·Firefox 면 된다 — 스냅·MetaMask 는 필요 없다.
회로 산출물은 Cache API(`mode3-zk-v1`)에 캐시되므로, `build/mode3` 를 다시 만들었다면 사용자 페이지의 "모두 지우기" 버튼이나
브라우저의 이 사이트 데이터 삭제로 캐시를 비운 뒤 새로고침한다. (페이지는 `/zk/*` 를 `cache: 'no-store'` 로 받아 브라우저 HTTP
캐시를 우회하므로, Cache API 만 비우면 된다)

### Google 로 등록·자기 폐기 (OIDC 래퍼, 2026-10-16)

설계 `docs/superpowers/specs/2026-10-16-mode3-oidc-wrapper-design.md`. web 모드(사용자 페이지) 전용이다 — 스냅·에이전트(file)
모드에는 없다.

IdP(`cia.js`)가 Google ID 토큰을 **체인 밖에서** `jose` 로 검증해(RS256, `iss`·`aud`·`exp` — 모르는 `kid` 는 JWKS 를 다시 받아본
뒤에도 없으면 무효로 본다) `uid = SHA-256("<provider>|<sub>") mod 2^250`(`provider` 는 설정값, 기본 `google`)으로 계정을
만든다. 회로·PS 토큰·로그인·폐기 트리는 바뀌지 않는다. 등록 nonce 는 `"reg:" + SHA-256(tag)` — `tag = Poseidon(T_TAG, s_u, Poseidon(D_CTX_REG, n))`(2026-11-13 부터; 전에는 `pk_u` 의 해시. auid 는 넣지 않는다 —
토큰 발급 전에는 알 수 없고, 등록용 π_IdP 가 uid·auid 와 같은 `s_u` 를 강제한다), 발급 nonce 는 `"issue:" + SHA-256(tag)`(ctx 에 `arid_s`·`chainid`·`allowAgent`·지갑 난수 `n`), 자기 폐기 nonce 는 `"revoke:" + 32바이트 hex` 다. Google
토큰은 등록·자기 폐기 요청에만 쓰고 저장·로그하지 않는다. IdP 는 토큰을 받는 순간 Google 계정과 uid 를 연결할 수 있다 —
데모 계정의 uid·비밀번호와 같은 신뢰 수준이다.

**준비**: Google 콘솔의 Mode 1 OAuth 클라이언트에 승인된 JavaScript 원본으로 `http://localhost:5100`·`http://localhost:4100`
을 추가한다(리다이렉트 URI 는 필요 없다 — Google 은 `127.0.0.1` 원본을 받지 않는다). env: IdP `MODE3_OIDC_CLIENT_ID`(없으면
`GOOGLE_CLIENT_ID`; 둘 다 없거나 빈 문자열이면 꺼짐 — Google 행이 숨고 데모 계정만 된다), 선택 `MODE3_OIDC_ISSUER`(기본
`https://accounts.google.com`)·`MODE3_OIDC_JWKS_URL`(기본 `https://www.googleapis.com/oauth2/v3/certs`)·
`MODE3_OIDC_PROVIDER`(기본 `google`). **Mode 3 전용 OAuth 클라이언트를 따로 만들어(같은 두 원본) `MODE3_OIDC_CLIENT_ID` 로
지정하기를 권한다** — `GOOGLE_CLIENT_ID` 폴백으로 Mode 1 클라이언트를 함께 쓰면 Mode 1 `server.js` 의 `/login?custom_nonce=` 가
고른 nonce 로 같은 `aud` 의 토큰을 받게 해 주므로, 그 토큰을 얻은 사람이 남의 Google 신원을 자기 키로 등록(`reg:`)하거나 되돌릴
수 없게 폐기(`revoke:`)할 수 있다(스펙 §5 "클라이언트 ID 공유 위험"). 폴백으로 켜지면 IdP 가 기동 때
`[cia] 경고: OIDC 래퍼가 Mode 1 의 클라이언트 ID(GOOGLE_CLIENT_ID)를 함께 쓴다 …` 를 남긴다. **사용자 오리진을 localhost 로 통일**한다: 정적 서버
`MODE3_WALLET_PUBLIC_ORIGIN=http://localhost:5100`, IdP·RP 의 `MODE3_WALLET_AGENT_ORIGIN=http://localhost:5100`; 브라우저도
사용자 페이지를 `http://localhost:5100/`, 계정 페이지를 `http://localhost:4100/account` 로 연다. IdP 의
`public_keys.oidc.enabled` 이고 hostname 이 `localhost` 일 때만 사용자 페이지에 "또는 Google 계정으로 등록:" 행(GIS 버튼)이
보인다. `127.0.0.1` 로 열면 IdP CORS 가 설정된 오리진에만 열려 있어 `oidc` 설정을 읽지 못하고, `walletOrigin` 이 localhost 로
설정돼 있으면 "Google 로그인은 http://localhost 주소에서만 됩니다 — http://localhost:5100/ 로 여세요" 안내만 보인다(Google
등록 행은 뜨지 않는다).

**켜고 끄기**: (1) RP(`mode3_rp.js`)는 IdP `/cia/public_keys` 의 `oidc` 를 기동 때 한 번만 읽는다(pk_CIA TOFU 와 같은 응답) —
IdP 에서 Google 을 켜거나 끈 뒤에는 RP 도 재시작해야 모달의 Google 버튼이 따라온다. (2) RP 에 `MODE3_PK_CIA_X/Y` 를 env 로
고정하면 그 조회를 건너뛰므로 `rp_info.oidc.enabled=false` 다 — Google 버튼은 꺼진 채로 남는다. (3) `.env` 에 (Mode 1 용)
`GOOGLE_CLIENT_ID` 가 있으면 라이브 IdP 는 **다음 재시작 때 Google 을 자동으로 켠다**(위 경고도 찍힌다). 켜지 않으려면 기동 env
에 `GOOGLE_CLIENT_ID=`(빈 값)을 준다 — dotenv 는 이미 있는 키를 덮지 않는다(격리 테스트 하네스가 쓰는 방법).

**수동 체크리스트**(스펙 §6): 사용자 페이지에서 "또는 Google 계정으로 등록:" 행으로 Google 로 등록 → zkONE 로그인(RP 모달의
Google 버튼) → zkTWO 로그인 → 계정 페이지(`:4100/account`)의 "Google 로 등록한 계정은 Google 로 폐기:" 행으로 자기 폐기 →
재검증이 `revoked`, 다음 로그인이 `account_disabled` 인지 본다. 재시연 세트에 "Google 로 등록한 브라우저의 모두 지우기" 를
추가한다.

**사유**(짧게):

| 사유 | HTTP | 설명 |
|---|---|---|
| `oidc_disabled` | 503 | IdP 에 클라이언트 ID 없음(Google 등록이 꺼짐) |
| `oidc_invalid` | 401 | 서명·`iss`·`aud`·`exp`·형식 오류, 모르는 `kid` 포함 |
| `oidc_nonce_mismatch` | 400 | 토큰의 nonce 가 이 요청에 묶여 있지 않음 |
| `oidc_unavailable` | 502 | JWKS 를 받지 못함 — 타임아웃·연결 거부·DNS·HTTP 오류(토큰을 확인하지 못한 경우는 무효로 보지 않는다) |
| `gsi_unavailable` | 페이지 전용 | GIS 스크립트 로드 실패 |
| `gsi_origin` | 페이지 전용 | hostname 이 `localhost` 가 아님 — 안내 문구로 대체 |

`completeRegistration` 의 로컬 형식 오류도 400 `oidc_invalid` 로 합친다. 다른 Google 계정의 토큰으로 자기 폐기를 시도하면
사용자 코어가 IdP 를 부르지 않고 403 `uid_mismatch` 로 막는다(이 스냅의 계정만 폐기할 수 있다).

**한계**(스펙 §8): Google 외 발급자는 확인하지 않았다(같은 env 로 OIDC 호환 발급자가 동작할 수는 있다). 이메일·이름은
표시하지 않는다. 스냅·에이전트(file) 모드에는 Google 등록이 없다. 계정 연결은 없다(한 uid 에 여러 발급자를 묶지 않는다).

## 엔드포인트 (2026-09-22 선택 공개, 2026-09-23 집합 소속 술어 V7 로 바뀌거나 추가된 것)

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `GET /cia/accounts` | IdP(관리자) | 전 계정의 `disabled`·`activeCf_u`·`slot`·`tampered`·`registryLeaf`(더 이상 `attrs`·`profile` 없음 — D15) |
| `GET /cia/attr_schema` | IdP | 속성 스키마·해시(인증 없음) |
| `PUT /wallet/profile` (V11) | 스냅 | 사용자가 `profile` 을 바꾼다 — 스키마로 재인코딩하고, 바뀌었으면 옛 `C_u`·세션·π 캐시를 그 자리에서 지운다(IdP 는 부르지 않는다, 다음 로그인의 `/cia/issue` 가 새 `C_u` 를 받는다) |
| `GET /wallet/attr_schema` | 스냅 | 에이전트가 보관한 스키마(페이지용) |
| `POST /wallet/tx` (`disclose`·`set` 필드, V7) | 스냅 | 트랜잭션에 선택 공개 첨부 — `disclose`: `{lo,hi}\|null` × 1..6(int 슬롯만); `set`: `{slot, members}`(선택, 슬롯 하나 — root 를 스냅이 계산). 둘 중 하나라도 있으면(mask ≠ 0 또는 set_sel ≠ 0) 새 π |
| `GET /api/mode3/rp_info` (`attrGateAddress`·`predicates` 필드, V7) | RP | 배포된 `AttrGate` 주소, `predicates: { allowedCountries, allowedCountryNames, allowedCountriesRoot, minAge, birthYearMin, attrSchema }` |
| `POST /api/mode3/login` (`require` 필드, V7) | RP | 로그인 성명이 만족해야 할 오프체인 술어 — `{ countrySet, minAge }`, 미충족 시 `predicate_unmet` |
| `GET /attr.html`, `GET /attr/dist/attr.js` (2026-11-09) | 스냅(정적) | 속성 커밋먼트 도구 — 에이전트 상태를 읽지 않는 공개 GET (2026-11-13: 페이지가 `/wallet/config` 의 `ciaUrl` 로 IdP `GET /cia/user/uid` 를 부른다) |
| `GET /cia/user/uid` (2026-11-13) | IdP(사용자 세션) | `{ uid }` 만 — 속성 도구가 로그인한 uid 를 읽는다. 쿠키 CORS 는 스냅 에이전트 오리진(`WALLET_AGENT_ORIGIN`)에만, 로그인 안 했으면 401 |
| `POST /cia/user/profile` (2026-11-09) | IdP(사용자 세션) | `{ name }` — 한 줄·256자 이하, 빈 값이면 지움 → `profile`; `GET /cia/user/me` 에 `profile` |
| `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json` (2026-11-09) | IdP | ID 토큰(ES256) 발견 문서·공개 JWK — 인증·CORS 없음 |
| `POST /cia/issue` → 응답 `id_token` (2026-11-09) | IdP | `sub=auid_s`·`aud=arid_s`·`name=프로필`, 10분 |
| `POST /wallet/login` → 응답 `id_token` (2026-11-09) | 스냅 | IdP 토큰을 그대로 전달 |
| `POST /api/mode3/login` (`id_token` 필드) → 응답 `attrCommit`·`attrCommitChanged` (2026-11-09) | RP | 검증·결속(`sub`·`aud`) 뒤 `name` 을 계정에 고정; 틀리면 `bad_id_token` |

MetaMask/Snap 경로(2026-09-22 metamask-snap)로 새로 생긴 스냅 라우트:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `GET /wallet/config` | 스냅 | `{ secrets, snapId, walletOrigin, rpcUrl, chainId }` — RP 페이지가 로그인 경로(직접 호출/팝업)를 고르려고 CORS 로 읽는다. 비밀 없음 |
| `POST /wallet/authorize/precheck` | 스냅 | 승인 팝업이 스냅을 부르기 전에(IdP 로그인 페이지로 가기 전에도) 부르는 인증서·팩토리 검증(`{ arid, origin, cert_s, pk_trace, factoryAddress }`). 로그인·재승인이 함께 쓴다. 선택 `r_s` 를 실으면 응답에 `sessionAllowAgent`('0'\|'1')를 얹는다 — 세션이 없거나 `arid` 가 다르면 404 `no_session`(2026-09-23 점검 B-I1) |
| `POST /wallet/session/witness` | 스냅 | 재승인(§4.3) — 재시작으로 사라진 세션 메모리 증인을 `{ r_s, witness, allowAgent }` 로 다시 채운다. `allowAgent`('0'\|'1')는 **필수**이고 팝업이 precheck 에서 받은 세션 값이다 — 세션의 실제 값과 다르면 409 `allow_agent_mismatch`(2026-09-23 점검 B-I1) |
| `POST /wallet/tx/prepare` | 스냅 | snap 모드의 트랜잭션 1단계 — 증명·서명·`calldata`(필요하면 `deployCalldata`)까지만 만든다 |
| `POST /wallet/tx/record` | 스냅 | 2단계 — MetaMask 가 보낸 `txHash` 의 영수증을 파싱해 `/wallet/tx` 와 같은 형식으로 돌려준다(영수증 전이면 202) |
| `POST /wallet/self_revoke` | 스냅 | 자기 폐기 프록시 — `{ uid, pwd }` 를 IdP `/cia/account/self_revoke` 로 중계한다(`cia.js` 에 CORS 가 없어서). 등록 uid 가 아니면 403 `uid_mismatch` |

V10 폐기 체인·거울(2026-10-02)로 새로 생기거나 바뀐 것:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /cia/admin/relay` | IdP(관리자) | 주기와 무관하게 모든 거울을 지금 갱신한다. `{mirrors:[{chainId, epoch, …}]}`, 거울 하나라도 실패하면 502. 따라잡은 거울에 누르면 캐노니컬 하트비트를 하나 더 올린다 |
| `GET /mode3/health` (`mirrors`) · `GET /cia/public_keys` (`canonicalChainId`·`mirrors`) | IdP | 위 "상태 패널" 절 |
| `POST /cia/revoke scope=account` · `POST /cia/account/self_revoke` · `POST /wallet/self_revoke` (`receipt`) | IdP·스냅 | 응답에 접수증 — 위 "계정 폐기 접수증" 절 |
| `GET /api/mode3/rp_info` (`mirrorAddress`) | RP | 검증기가 읽는 거울. `logAddress` 는 캐노니컬(표시용) |
| `GET /wallet/status` (`mirror`·`canonical`) | 스냅 | `mirror{address, epoch, lastPublishedBlock}`, `canonical{rpc, logAddress, epoch}` |
| `Mode3Log.requestRevocation(slot, epochAtRequest, requestedAt, sig)` · `pendingSlots()` · `isRetired(slot)` | 체인(캐노니컬) | 접수증 대기열 |

폐기 트리 증분 동기화(2026-09-23, `docs/superpowers/specs/2026-09-23-mode3-rcl-incremental-sync-design.md`)로 새로 생기거나 바뀐 것:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `GET /wallet/status` (`rcl` 필드) | 스냅 | `{ leaves, lastSyncedBlock, lastMode, cacheFile }` — 폐기 트리 캐시 상태(리프 수, 마지막 동기화 블록, `restore`\|`delta`\|`bootstrap`\|`fallback`, 캐시 파일 경로). `CIA_LOG_ADDRESS` 미설정이면 `null` |
| `POST /wallet/rcl/reset` | 스냅 | 같은 오리진만, 본문 `{confirm:true}` 필요(없으면 400) — 폐기 트리 캐시 파일을 버린다. 응답 `{ ok:true, deferred }`(진행 중인 동기화와 겹쳤으면 `deferred:true` — 그 동기화가 끝난 뒤 적용) |

`deferred:true` 로 답했다면 **그 동기화가 끝날 때까지는 아무것도 지워지지 않는다** — 그동안 `GET /wallet/status` 의 `rcl` 은 옛 `leaves`·`lastSyncedBlock`·`lastMode` 를 그대로 보이고 캐시 파일도 아직 있다. 실제로 적용됐는지는 `rcl.lastMode === null && rcl.leaves === 0` 으로 확인한다.

V11(그림 프로토콜, 2026-10-12)로 바뀌거나 추가된 것:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /cia/issue` | IdP | 본문 `{ uid, auid_s, arid_s, C_u_pt, C_s_pt, chainid, allowAgent, max_height, n, tag, proof_idp }` — `(C_u, C_s, π_IdP)`, 요청은 `tag = Poseidon(T_TAG, s_u, Poseidon(D_CTX_ISSUE, arid_s, chainid, allowAgent, n))` 로 증명에 묶인다(2026-11-13 부터 — `sig_u` 는 없다. `n` 은 지갑이 요청마다 뽑는 난수). `C_u` 가 바뀌면(첫 로그인·속성 변경 뒤) 등록부 슬롯을 갱신·게시한 뒤 토큰을 낸다 — 옛 `/cia/user_cred` 를 흡수했다(D11) |
| `POST /api/mode3/challenge` | RP | 응답에 `r_rp`(250비트 난수, D6) 가 더해진다 — 세션 가명·`C_s` blind 의 재료, IdP 에는 보내지 않는다 |

web 모드(브라우저 전용 사용자 페이지, 2026-10-15)로 새로 생긴 것:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /api/mode3/relay` | RP | `{ to, data }`(value 0 고정) — 사용자 페이지가 만든 `execute` calldata 를 릴레이어가 대신 보낸다. 위 "릴레이" 절의 검사 8단계, 응답 `{ txHash, deployed, deployTxHash }`. CORS 는 사용자 오리진만 |
| `GET /api/mode3/relay/:txHash` | RP | 영수증 조회 — 아직이면 `{ ok:true, pending:true }`, 끝나면 `{ ok:true, pending:false, status, blockNumber, gasUsed, to }` |
| `GET /user/config` | 사용자 정적 서버 | 같은 오리진만 — 페이지 부팅 설정(비밀 없음) |
| `POST /wallet/presence` | 사용자 정적 서버 | 같은 오리진만 — `GET /mode3/health` 에 실릴 불리언 2개·정수 4개(`registered`·`hasCred`·`sessions`·`rpCount`·`txs`·`disclosedTxs`) |

## RP 거절 사유 (2026-09-23 점검 C-1)

"화면 문구" 는 `mode3/common/strings.js` 의 `reasons[코드].ko.title`(결과 카드 제목)이다 — 원인·조치가 그 아래 두 줄로
붙고, 코드 자체도 제목 옆에 그대로 남는다.

| `reason` | 화면 문구 | 어디서 | 상태 코드 | 뜻 |
|---|---|---|---|---|
| `root_too_old` | 폐기 목록이 너무 오래 게시되지 않았습니다 | `POST /api/mode3/login`, `POST /api/mode3/revalidate` | 200 `{ok:false, reason}` | 게시된 root 가 `MODE3_MAX_ROOT_AGE` 보다 오래됐다 — IdP 가 하트비트(또는 `/cia/publish`)를 멈추면 온체인 `RootTooOld` 와 함께 오프체인 로그인·재검증도 막힌다. IdP 를 살리고 게시를 기다린다 |
| `bad_factory` | 팩토리 컨트랙트를 믿을 수 없습니다 | `POST /wallet/login`, `POST /wallet/authorize/precheck` | 409 `{reason, detail?}` | RP 가 준 `factoryAddress` 가 인증서·IdP 키·로그 주소와 다르거나(immutable 대조), **팩토리·검증자 코드가 스냅의 참조 빌드(`artifacts/`)와 다르다**(2026-09-23 참조 코드 대조 — `detail` 이 `factory_code_mismatch`·`verifier_code_mismatch`·`no_code`). 무엇이든 통과시키는 검증자를 가리키는 팩토리는 여기서 막힌다. 스냅 쪽 `artifacts/` 가 낡았으면(컨트랙트를 바꾸고 `npx hardhat compile` 을 안 했으면) 진짜 팩토리도 거절되니 먼저 컴파일한다 |
| `root_too_old` | 폐기 목록이 너무 오래 게시되지 않았습니다 | `POST /api/mode3/request` | 503 | 세션 요청도 같은 상한 — 다만 세션이 이미 있는데 체인 쪽 문제라 5xx 로 구분한다 |
| `factory_constants_unavailable` | RP 가 체인 설정을 읽지 못했습니다 | 검증기가 없는 동안 RP API 전부(`inactiveReason`) — `/api/mode3/challenge`·`/login`·`/revalidate`·`/request`·`/open` | 503 | 팩토리 `maxRootAge`·`maxLifetime` 조회 실패 — 등록 대기(`registration_pending`)와 구분한다. 아래 "하지 말 것" 의 함정 참고 |
| `predicate_unmet` | 요구한 조건을 만족하지 못했습니다 | `POST /api/mode3/login` (V7, `require` 필드가 있을 때만) | 200 `{ok:false, reason}` | 로그인 성명은 유효하지만 요구한 술어(국가 집합 소속·최소 나이)를 만족하지 못한다 — 컨트랙트 호출 없이 오프체인에서 판정한다. `RP 거절 사유` 절 위쪽 "로그인 경로 술어(V7)" 참고. **요구는 페이지가 `require` 로 싣는다 — 서버 정책 게이트가 아니다(데모 의미). 운영이라면 서버가 강제해야 한다.** **재검증(`revalidate`)은 술어를 다시 증명하지 않는다** — 로그인 때의 술어는 세션 기록에만 남고, 재검증 뒤 `disclosure` 는 갱신된다(후속: 세션에 `require` 를 기억하고 스냅이 같은 술어로 재증명) |
| `predicate_unavailable` | RP 가 이 조건을 요구할 수 없습니다 | `POST /api/mode3/login` (V7, `require` 필드가 있을 때만) | 200 `{ok:false, reason}` | RP 의 스키마에 country/birthYear 슬롯이 없어 요구 조건을 검사할 수 없다 — 요구를 끄거나 스키마를 확인 |
| `stale_registry_root` | 등록부 버전이 오래됐습니다 | `POST /api/mode3/login`, `POST /api/mode3/revalidate` | 200 `{ok:false, reason}` | V9 — 스냅이 낸 증명의 등록부 root(`regRoot`)가 RP 가 보는 최신 등록부 root 와 다르다. `stale_root`(b, 폐기 트리 쪽)와 같은 자리의 등록부 판(b‴, `lib/mode3_rp.js`) — 등록부가 바뀐 뒤(슬롯 바꿔치기·은퇴·재발급) 스냅이 옛 등록부로 만든 증명을 들고 온 경우다 |
| `bad_r_s` | 세션 난수가 맞지 않습니다 | `POST /api/mode3/login`, `POST /api/mode3/revalidate` | 200 `{ok:false, reason}` | V11(D6) — 토큰의 `r_s`(공개 입력 [32])가 RP 가 이 세션에서 소비한 챌린지 `r_s` 와 다르다. 토큰의 `C_s` 가 `r_s` 를 덮으므로 다른 세션용 토큰을 재전송할 수 없다 |
| `bad_arid_s` | 이 세션용 토큰이 아닙니다 | `POST /api/mode3/login`, `POST /api/mode3/revalidate` | 200 `{ok:false, reason}` | V11(D7) — `arid_s`(공개 입력 [31])가 RP 가 자기 `r_rp` 로 재계산한 값과 다르다 — 다른 RP 나 다른 챌린지용 토큰이다. IdP 는 `r_rp` 를 몰라 이 값을 못 만든다(G4) |
| `registry_mismatch` | 등록부의 내 자격증명이 바뀌었습니다 | 스냅 `POST /wallet/login`(`ensureUserCred`, 아직 세션이 없을 때만) | 403 | V9 — 체인에 게시된 내 슬롯의 리프가 스냅이 든 자격증명과 다르다. 내가 요청한 재발급이 아니라면 IdP 의 부정(각본 10 의 "슬롯 바꿔치기") — 스냅은 로그인을 시도하지 않는다. **이미 세션이 있는 상태의 재검증·트랜잭션**(`/wallet/revalidate`·`/wallet/tx`(`/tx/prepare`))이 같은 등록부 불일치를 만나면 `proveSession` 은 둘을 구분하지 않고 `revoked` 로 보고한다(위 "세션 폐기(V8)" 절의 `revoked_session` 행, "계정/자격증명 폐기는 지금까지처럼 `revoked`" 참고) |
| `registry_unpublished` | 등록부 게시 대기 | 스냅 `POST /wallet/login` | 503 | V9 — 방금 받은 새 사용자 자격증명의 슬롯이 30초 안에 체인 등록부에 오르지 않았다. IdP 의 게시(하트비트)를 기다렸다가 다시 로그인한다 |
| `registry_slot_unknown` | 슬롯 번호를 몰라 등록부를 확인할 수 없습니다 | 스냅 `POST /wallet/login`·`/wallet/revalidate`·`/wallet/tx`(`/tx/prepare`) | 403 | V9 — 등록에 슬롯 번호가 없다(옛 v8 이하 스냅 상태 파일). 로그인이 `/cia/slot` 으로 슬롯을 되찾기 전까지만 뜬다 |
| `user_cred_failed` | IdP 가 π_IdP 를 거절했습니다 | 스냅 `POST /wallet/login` | 502 | V11 — IdP 의 `/cia/issue` 가 π_IdP 를 거절했다(`bad_idp_proof`). 시연 카드(설계 §8.3)로 salt·uid 를 바꾼 경우(각본 11)가 흔한 원인 — "원래대로" 로 덮어쓰기를 풀고 다시 로그인한다 |
| `demo_proof_failed` | 증명 생성 실패(시연) | 스냅 `POST /wallet/login`·`/wallet/revalidate`·`/wallet/tx`(`/tx/prepare`) | 409 | V9 — 시연 카드의 증명 덮어쓰기(범위 `prove`)가 걸린 채 새로 증명해야 했다 — 서명된 자격증명·등록부 리프와 어긋난 witness 라 회로가 거절했다(각본 11). 덮어쓰기를 풀고 다시 시도한다 |
| `slot_failed` | 슬롯 번호를 받지 못했습니다 | 스냅 `POST /wallet/login` | 502 | V9 — 슬롯 없는 옛 등록이 IdP 의 `/cia/slot` 조회에 실패했다 |

web 모드(브라우저 전용 사용자 페이지, 2026-10-15)로 새로 생긴 사유 — RP 의 릴레이:

| `reason` | 화면 문구 | 어디서 | 상태 코드 | 뜻 |
|---|---|---|---|---|
| `relay_inactive` | RP 의 릴레이가 아직 동작하지 않습니다 | `POST /api/mode3/relay` | 503 | RP 가 IdP 의 승인·활성화 전이라 검증기나 계정 팩토리가 없다 |
| `relay_bad_calldata` | 릴레이가 트랜잭션 데이터를 거절했습니다 | `POST /api/mode3/relay` | 400 `{detail}` | `value≠0`(`detail:'value'`), `execute` 형식·공개 입력 33개가 아님(`'selector'`), 또는 공개 입력의 `arid` 가 이 RP 가 아님(`'arid'`), 주소/hex 형식이 아님(`'format'`) |
| `relay_bad_target` | 릴레이가 받는 주소를 거절했습니다 | `POST /api/mode3/relay` | 400 | `to` 가 calldata 의 PPID(`pub[0]`)로 이 RP 팩토리가 계산한 주소와 다르다 — 다른 RP 세션이거나 calldata 조작 |
| `relay_rate_limited` | 릴레이 요청이 너무 잦습니다 | `POST /api/mode3/relay` | 429 | 같은 계정 주소(`to`)로 분당 `MODE3_RELAY_RATE`(기본 10) 초과 |
| `relay_gas` | 릴레이의 가스 추정이 실패했습니다 | `POST /api/mode3/relay` | 400 `{detail}` | (필요하면 계정 배포 뒤) `estimateGas` 가 되돌려졌다(`detail` 이 컨트랙트 오류 이름 — `NonceMismatch`·`InvalidProof`·`BadSignature` 등) 또는 추정 가스가 `MODE3_RELAY_GAS_CAP`(기본 1,200,000)을 넘었다 |

같은 web 모드로 새로 생긴 사유 — 사용자 페이지(`mode3/user`)와 승인 팝업(postMessage 결과, HTTP 상태 코드 없음):

| `reason` | 화면 문구 | 어디서 | 뜻 |
|---|---|---|---|
| `locked` | 사용자 금고가 잠겨 있습니다 | 사용자 페이지 — 등록 비밀·세션키가 필요한 동작 | 해제 뒤 30분이 지났거나 "잠그기" 를 눌렀거나 잠금 해제 창을 취소했다 |
| `bad_password` | 금고 비밀번호가 맞지 않습니다 | 사용자 페이지 — 금고 등록·잠금 해제 | 넣은 비밀번호로 금고가 열리지 않는다(확인값 복호화 실패) — 기존 금고가 있는 상태의 재등록도 같은 검사를 거친다 |
| `zk_assets_unavailable` | 증명 키를 쓸 수 없습니다 | 사용자 페이지 — 증명 생성 | `/zk/*` 에서 회로 파일(wasm·zkey·vkey)을 못 받았거나 받은 zkey·vkey 가 짝이 아니다 |
| `storage_unavailable` | 이 브라우저의 저장소를 쓸 수 없습니다 | 사용자 페이지 — 기동 | IndexedDB 를 열지 못했다(사이트 데이터 차단·시크릿 창 제한·미지원 브라우저) |
| `origin_mismatch` | 요청을 보낸 오리진이 맞지 않습니다 | 승인 팝업 — `mode3-config`·`mode3-precheck`·`mode3-authorize`·`mode3-revalidate`·`mode3-request` | 메시지 오리진이 요청에 적힌(인증서의) RP 오리진과 다르거나, 모르는 RP 가 설정을 물었다 |

RP 는 RPC 실패 시 10분 안의 체인 뷰 캐시로 검증을 계속하는데(`headMaxAgeMs`), 그 창 동안은 root 나이(b′) 판정도 **캐시 시점 값에 얼어붙는다** — 실시간 게시 지연을 그동안은 못 본다.

`rp.html` 페이지는 응답 본문의 `{ ok, reason }` 만 읽고 상태 코드는 구분하지 않는다 — `/challenge` 도 같은 봉투를 쓴다(성공 `{ok:true, r_s, …}`, 거절 `{ok:false, reason}`. 2026-09-23 점검 M3 전에는 사유 대신 JS TypeError 가 보였다).

**함정(fail-closed)**: 체인을 새로 띄운(hardhat 재기동) 뒤 **옛 `mode3_rp_registration.json`**(예전 체인의 `factoryAddress`)으로 RP 를 올리면 팩토리 `maxRootAge()` 조회가 그 주소에 컨트랙트가 없어 실패하고, 위 표대로 모든 로그인·재검증·세션 요청이 `503 factory_constants_unavailable` 로 막힌다(5초마다 재시도, 새 체인에 맞는 팩토리가 없는 한 무기한). 증상은 RP 로그의 "팩토리 상수 조회 실패"(fail-closed) 줄로 보인다. 복구는 등록 파일의 `factoryAddress`·`verifierAddress` 를 지우고 재시작하거나(RP 가 새로 배포한다), 아래 재시연 세트를 탄다.

## 수용한 한계 (2026-09-25 전체 코드 리뷰)

2026-09-25 전체 코드 리뷰가 짚었지만 **고치지 않기로 한 것**들이다. 고칠 값이 있다고 본 지적은 커밋 `25d56fe`·`64bae37`·
`8854e87`·`8a7cb62`·`4aa5589`·`d9af457` 로 닫았고(형식 문서 `docs/paper/zkd/security_formal.md` §11), 아래는 남겼다.
각 줄에 왜 지금 안 고치는지를 같이 적는다.

- **uid 존재 열거.** `POST /cia/issue`·`POST /cia/slot` 는 증명을 보기 **전에** `state.accounts[uid]` 를 확인해 404
  `unknown account` 를 낸다 — 인증 없는 호출자가 "이 uid 가 등록됐는가" 를 응답 코드로 안다. **왜 지금 안 고치나**: 데모
  계정은 `DEMO_ACCOUNTS` 에 하드코딩된 둘(12345·67890)뿐이라 열거할 것이 없고, IdP 의 다른 무인증 라우트도 같은 수준이다.
  세션 폐기(`/cia/revoke scope=session`)만은 서명을 먼저 봐 이 누수가 없는데, 그 순서를 나머지 라우트로 넓히는 것은 후속이다.
- **상태가 무한히 자란다.** RP 의 `logins`·`sessions` 맵과 로그인 로그, 스냅의 증명 캐시, IdP 의 개봉 기록은 비우지 않는다
  (세션 폐기 리프도 append-only — 위 "세션 폐기" 절). **왜 지금 안 고치나**: 데모 규모에서 문제가 되지 않고, 보존 기간을
  정하는 일은 "언제 지워졌나" 라는 새 관측면을 만드는 설계 결정이라 운영 단계의 몫이다.
- **RPC 장애 때 10분 캐시.** RP 는 체인 뷰를 최대 10분(`headMaxAgeMs`) 캐시해 검증을 계속하고, 그동안 root 나이 판정도 캐시
  시점 값에 얼어붙는다(위 "RP 거절 사유" 절 끝에 이미 적혀 있다). **왜 지금 안 고치나**: 가용성 쪽으로 기운 **설계 선택**이다.
  없애면 RPC 가 흔들릴 때마다 로그인·재검증이 통째로 막힌다.
- **동의 창이 `data` 를 보이지 않는다.** 스냅·zk 스냅 페이지의 트랜잭션 동의 창은 RP·오리진·대상(`to`)·금액(`value`)·공개
  항목까지만 보이고 calldata 는 안 보인다. **왜 지금 안 고치나**: 원시 calldata 를 사람이 읽고 판단하게 하려면 ABI 디코딩과
  함수 서명 사전이 필요한 2차 UI 작업이고, 데모의 호출 대상은 `AttrGate.claim` 하나다.
- **snap 증인에 유휴 수명이 없다.** 세션의 메모리 증인(`{s_u, blind_u, attrs}`)은 에이전트가 살아 있는 한 남는다
  — 사라지는 경계는 **재시작**뿐이고 그때 `needs_consent` 로 재승인을 받는다. **왜 지금 안 고치나**: 유휴 만료를 넣으려면
  "언제부터 유휴인가, 만료를 사용자에게 어떻게 알리나" 를 정하는 타이머 설계가 먼저다.
- **스냅 `GET /mode3/health` 가 IdP 오리진에도 열려 있다.** 허용 오리진이 `RP_ORIGIN` 과 `CIA_URL` 둘이라, IdP 오리진의 페이지도
  스냅의 등록 여부·세션 수·트랜잭션 수를 읽을 수 있다. **왜 지금 안 고치나**: 상태 패널이 세 페이지 어디서나 같은 그림을
  그리게 하려는 **의도된 개방**이다. 응답에 비밀값은 없다 — `tests/test_mode3_health.mjs` 가 키 이름뿐 아니라 실제 값
  (등록 uid·`s_u`·`Cf_u`·`Cf_s`)이 세 응답 어디에도 없는지 확인한다.
- **`countedTxHashes` 가 자란다.** 스냅 에이전트가 `/wallet/tx/record` 의 중복 집계를 막으려고 처리한 트랜잭션 해시를 Set 에
  모은다. **왜 지금 안 고치나**: 메모리에만 있어 재시작이면 사라지고, 한 시연에서 보내는 트랜잭션 수는 손에 꼽는다.
- **세션 라우트의 RP 대조가 fail-open 이다.** `/wallet/revalidate`·`/wallet/request` 는 요청에 있는 RP 단서를 **전부**
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
  0("값 없음")인 계정도 `[0, 올해 − minAge]` 를 증명해 온체인 나이 조건을 통과한다. 완화: 스냅 입력(`PUT /wallet/profile`)은
  출생연도·국가의 빈 값을 거절하고(400 `empty`), RP 의 오프체인 로그인 검사는 `lo[0] ≥ 스키마 min` 을 함께 요구한다. 그래도 0 은
  이행 경로로 생길 수 있다 — v10→v11 이행은 범위 밖 출생연도(예: 2150)를 0 으로 바꾼다. **왜 지금 안 고치나**: 스펙 2 는 회로·컨트랙트를 바꾸지 않는다(D3) —
  `AttrGate` 에 `lo[0] ≥ min` 을 더하는 것은 컨트랙트 변경·재배포가 필요한 후속이다.
- **스키마는 IdP 서명에 묶이지 않는다(D5).** IdP 가 스키마의 의미(enum 표 등)를 몰래 바꾸면 같은 숫자가 다른 뜻이 된다. 완화는 해시
  공개·대조·경고뿐이다(`/cia/attr_schema`, health·`rp_info`·`/wallet/status` 의 해시, 스냅의 `schemaHash` 대조). **왜 지금 안 고치나**:
  해시를 서명·공개 입력에 넣으려면 회로를 바꿔야 한다(스펙 §10).
- **문자열 해시는 64비트다.** 서로 같은 값을 내는 두 문자열(생일 충돌)은 약 2^32 번의 시도로 찾을 수 있다. 주어진 값과 같은 값을 내는
  다른 문자열(2차 원상)은 약 2^64 번이 든다. 속성 값은 사용자가 스냅 `profile`에 직접 입력하고(D15, 아래 "속성 값 보증 없음" 참고)
  IdP 는 값을 받지도 보지도 않으므로, 충돌을 노려도 바꿀 수 있는 건 자기 자신이 들고 있는 속성값뿐이다 — 애초에 그 값의 진위를
  보증하는 장치가 없다. **왜 지금 안 고치나**: 슬롯이 회로에서 64비트(`ATTR_MAX`)라 더 넓히려면 회로 변경이다.
- **스냅·RP 는 IdP 에 닿지 못하면 기본 스키마로 간다.** RP 는 기동 때 한 번 받은 스키마를 프로세스 수명 동안 쓰고 그 스키마로
  `MODE3_ALLOWED_COUNTRIES` 를 인코딩해 `AttrGate` root 를 계산한다 — IdP 가 사용자 정의 스키마인데 기동 때 닿지 못했다면 재기동해야
  맞춰진다. 스냅은 60초마다 뒤에서 다시 받아 본다. **왜 지금 안 고치나**: 기본 스키마가 데모의 유일한 스키마이고, 기동 순서(IdP 먼저)를
  지키면 생기지 않는다.
- **스키마 해시 변경 경고는 프로세스 안에서만 남는다.** 스냅의 `schemaHash` 불일치는 로그 경고뿐이고 상태 파일·화면에 기록되지 않는다.
  **왜 지금 안 고치나**: 스냅은 IdP 를 바꿀 수 없고(스펙 §7), 기록할 곳(스냅 상태·스냅)의 형식을 바꾸는 일이라 후속이다.
- **`CIA_ATTR_SCHEMA_FILE` 을 바꾸면 IdP 가 기동을 거부한다.** 상태 파일의 `attrSchemaHash` 와 다르면 계정 `attrs` 의 뜻이 달라지므로
  막는다. **왜 지금 안 고치나**: 옛 `attrs` 를 새 스키마로 다시 인코딩하는 경로(문자열 원문은 `profile` 에만 있다)는 비범위다.
  스키마를 되돌리거나 재시연 세트로 상태 파일을 새로 시작한다.
- **속성 값 보증 없음(V11 D15, 2026-10-12).** 속성은 스냅의 `profile`(사용자 입력)이고 IdP 는 값을 받지도 저장하지도 않는다 — 거래소
  데모의 "나이 ≥ 19" 는 선택 공개·집합 소속·온체인 검사라는 **메커니즘의 시연**이지 값의 진위를 보증하는 것이 아니다. **왜 지금 안
  고치나**: 값을 보증하려면 IdP 와 분리된 속성 발급자가 필요하고, 이는 범위 밖 후속이다(스펙 §10).
- **설계 노출 — 요청 본문을 남기는 IdP 라면 RP 협력 없이도 연결할 수 있다(V11, 2026-10-12, 컨트롤러 판정: 설계는 바꾸지 않는다).**
  π_RP 공개 입력 `auid_s`·`arid_s`(`pub[30]`·`pub[31]`)는 `/wallet/tx` → `Mode3Wallet.execute` 의 calldata 에 그대로 실리고,
  IdP 는 `/cia/issue` 요청 본문에서 같은 값을 받는다(D3). 요청 본문을 남기는 IdP 라면 그 값을 체인의 calldata 와
  맞춰 uid ↔ PPID 계정 ↔ RP ↔ 트랜잭션을 이을 수 있다 — V10 에는 없던 결정적 연결이다(후퇴). "IdP 는 이 값을 기록하지
  않는다"(설계 D1)는 코드가 강제하는 암호학적 보장이 아니라 신뢰 가정이다. **왜 지금 안 고치나**: 완화에는 설계 변경(공개 입력에서
  빼고 회로·컨트랙트를 재생성하거나, 요청 본문 비보존을 운영 정책·감사로 강제)이 필요하고 **사용자 결정 대기**다 — 후보는 스펙
  §9 참고.

## 하지 말 것 / 재시연

- **옛 상태 파일(cia_state.json version 2 이하, mode3_wallet_state.json version 5 이하, 키 없는 mode3_rp_registration.json)을 새 서버에 물리지 않는다.** IdP 는 기동을 거부하고 스냅은 세션을 비운다. `cia_state.json` v3·v4 는 기동 시 v5 로 이행된다(v3 의 used_rs 는 버려지고 기존 RP 등록은 승인된 것으로 남는다 — v4 의 발급 기록은 형식이 바뀌어 비워진다). `mode3_wallet_state.json` v5 이하는 등록은 유지하고 세션이 비워진다(v6 부터 `registration.userCred` — 없으면 다음 로그인이 새로 받는다). `mode3_rp_registration.json` v2 는 v3 로 이행된다(`X_svc`·`x_svc` 조각은 유지, `factoryAddress`·`verifierAddress` 는 비운다). 그 밖의 옛 형식이거나 origin 이 다른 `mode3_rp_registration.json`은 RP 가 기동 시 새로 등록한다 — 옛 RP 조각(x_svc)도 버려지므로 이전 로그인 로그의 태그는 더 이상 열 수 없다.
- **IdP 상태 v7 → v8 이행(2026-09-24)**: 기동 시 자동으로 `accounts[uid].sessions = []` 를 만든다(코드 변경 불필요, 폐기 트리·
  epoch·계정은 그대로). 이행 **전에** 발급된 세션은 기록이 없어 세션 단위로 폐기할 수 없다 — `max_height` 만료로만 끝난다.
  새로 발급받은 세션부터 스냅·관리자 페이지의 세션 폐기가 듣는다. 스냅 상태 파일은 이 이행에서 손대지 않는다.
- **옛 상태 파일(`cia_state.json` version 11 이하)을 새 IdP 에 물리지 않는다.** IdP 가 기동을 거부한다(V11 은 이행 없음) — 재시연 세트로 새로 시작한다.
- **`cia_state.json`을 지우지 않는다.** 체인의 `RevocationLog.root`와 어긋나 스냅의 `syncRevocationTree`가 root 불일치로 전원을 막는다(Mode 2의 `idp_state.json`과 같은 이유). IdP 는 기동 시 로컬 트리를 온체인 root 와 대조해 어긋나면 `root 불일치`로 기동을 거부하므로, 지웠다면 아래 재시연 세트를 통째로 다시 한다.
- 재시연은 **한 세트로만**: hardhat 노드 재시작 → 위 "처음 한 번" 2~3(재배포, `.env`의 `CIA_LOG_ADDRESS`·`MODE3_MIRROR_ADDRESS`·`CIA_MIRRORS` 갱신) →
  `mode3_rp_registration.json` 의 `factoryAddress`·`verifierAddress`·`attrGateAddress` 삭제(로그 주소가 바뀌면 팩토리도 새로 배포해야
  한다 — 셋을 지우면 RP 가 다시 배포한다. `factoryAddress` 만 지우면 옛 검증기를 다시 물린다) → `cia_state.json`·`mode3_wallet_state.json`·
  `mode3_wallet_rcl.json`·`mode3_rp_registration.json`·`mode3_rp_logins.jsonl` 삭제 → 세 서버 재시작.
  `cia_keys.json`은 그대로 둬도 된다 — 게시 서명이 로그 주소를 덮으므로 같은 키로 재배포해도 옛 로그의 게시를 새 로그에 재생할 수 없다.
  **`snap` 모드로 시연 중이었다면 zk 스냅 페이지의 "스냅 초기화"(`reset`)도 함께 누른다** — 등록 비밀은 상태 파일이 아니라 MetaMask 안에
  있어서 파일만 지우면 스냅 쪽에 옛 등록이 남고 다음 "등록" 이 `already_registered` 로 막힌다.
  **web 모드로 시연 중이었다면 사용자 페이지의 "모두 지우기"(또는 127.0.0.1:5100 의 사이트 데이터 삭제)도 함께 한다** —
  스냅 초기화에 해당한다.
- **등록 직후 스냅 저장 실패 복구 절차(2026-09-23 점검 주목 Minor)**: `snap` 모드에서 `POST /wallet/register` 가 201 로 이미
  끝난 뒤(에이전트 상태 파일에는 등록이 남았다) 탭이 닫히거나 MetaMask 를 거절해 스냅 쪽 `storeRegistration` 이 실패하면
  스냅은 `attrs` 가 빈 `registration_incomplete` 로 굳는다. **부분 복구는 안 된다** — "스냅 초기화" 만 하거나 상태
  파일만 지워도 다시 등록하면 IdP 쪽에 그 uid 가 이미 등록돼 있어 `/cia/register` 가 409 를 내고 같은 골목으로
  돌아온다. 유일한 출구는 **IdP·에이전트·스냅 세 보관소를 한꺼번에 비우는 재시연 세트**(위 문단)뿐이다.
- `mode3_wallet_rcl.json`(스냅의 폐기 트리 체크포인트, 공개 데이터)은 지워도 되고 안 지워도 된다 — 로그 주소가 바뀌면 자동으로
  무시되고, 지우면 첫 로그인이 창세기부터 재생한다. 강제로 다시 재생시키려면 `POST /wallet/rcl/reset`(본문 `{confirm:true}`).
  경로는 `MODE3_WALLET_RCL_CACHE` 로 바꿀 수 있다(기본값은 `MODE3_WALLET_STATE_FILE` 과 같은 디렉터리의 `mode3_wallet_rcl.json`).
- **커밋 `4aa5589`(2026-09-25) 이전에 배포된 RP 팩토리는 못 쓴다.** 그 커밋이 `Mode3Wallet` 바이트코드를 바꿔서, 스냅의
  참조 코드 대조가 옛 팩토리를 `bad_factory`(`detail: factory_code_mismatch`)로 거절한다. 전에 띄워 둔 데모 스택을 다시
  올린다면 `mode3_rp_registration.json` 의 `factoryAddress`·`verifierAddress` 를 지우고 RP 를 재시작해 **팩토리를 새로
  배포**한다(위 재시연 세트를 통째로 타도 된다). 스냅 쪽 참조는 `artifacts/` 를 런타임에 읽으므로 커밋된 해시 파일은
  없다 — 코드 쪽은 `npx hardhat compile` 이면 끝난다.
  **그 `npx hardhat compile` 이 첫 단계다**(2026-09-25 최종 리뷰 F-5). `artifacts/` 는 gitignore 대상인데 팩토리 **배포**
  (`lib/mode3_onchain.js` `deployFactory`)와 스냅의 **참조 코드 대조**(`verifyReferenceCode`)가 *같은* 디렉터리를 읽는다.
  컴파일하지 않고 띄우면 RP 가 옛 바이트코드로 팩토리를 배포하고 참조 대조는 같은 옛 산출물과 비교하므로 **통과해 버린다** —
  그런데 JS 의 `payloadDigest` 는 새 16워드 형식이라 `factory_code_mismatch` 가 아니라 **모든 `execute` 가 `BadSignature`**
  로 실패한다. 증상이 원인에서 멀어 훨씬 찾기 어렵다.
  같은 이유로 **재배포 기준선은 `4aa5589` 에 고정돼 있지 않다**: solc 가 소스 텍스트의 메타데이터 해시를 바이트코드에 넣으므로
  `Mode3Wallet.sol`·`Mode3WalletFactory.sol` 은 **주석만 고쳐도** 배포 코드가 바뀐다(실측: 최종 리뷰 F-4 의 주석 한 줄로
  `Mode3Wallet`·`Mode3WalletFactory` 의 `deployedBytecode` 가 길이는 그대로인 채 값이 달라졌다 — `PiCredVerifier` 는 그대로).
  그 두 파일을 건드린 커밋 뒤에는 팩토리를 다시 배포한다.
- 데모 계정은 `cia.js`의 `DEMO_ACCOUNTS`(`testuser`/`password123` → uid 12345, `alice`/`alicepw` → uid 67890). 스냅 에이전트는 한 계정만 등록한다.
- `CIA_ADMIN_SECRET` 없이 띄운 IdP 에서 사용자 페이지의 폐기를 누르지 않는다 — 자기 폐기는 시크릿 없이도 되지만 복구(`set_disabled`)와 게시는 503 이라 계정이 되돌릴 수 없게 비활성으로 남는다.
- **한계**: 트랜잭션 해시로 개봉을 요청하는 경로는 체인을 읽을 수 있는 누구나 이 RP 의 트랜잭션에 대해 개봉을 신청할 수 있게
  한다 — IdP 는 여전히 RP 서명·`wrong_arid`·운영자 승인으로 걸러내고 `D_svc` 는 응답에 나오지 않지만, 신청 자체는 막지 않는다.
  `GET /api/mode3/open/:id` 결과 조회도 인증이 없어 승인 뒤 누구나 uid 를 읽을 수 있다(데모 한정).

## 테스트

- `bash scripts/run_tests.sh chain` — 격리 스택(임시 포트)으로 전 구간. :8545 와 `build/mode3/`의 `pi_cred` zkey·vkey, (V11) `pi_idp` zkey·vkey·wasm 이 있으면 된다.
  `tests/test_mode3_rcl_sync.mjs` — 증분 동기화(복원·델타·불일치 fallback·fail-closed·동시성). `node scripts/bench_mode3_rcl_sync.mjs` 가 실측을 낸다(`results/mode3_rcl_sync_*.md`).
  격리 IdP(`tests/helpers/isolated_cia.mjs`)는 하트비트를 끄고 뜬다(`CIA_HEARTBEAT_BLOCKS: '0'`) — 게시 없이 `MODE3_MAX_ROOT_AGE`
  (기본 100) 블록을 넘기는 시나리오는 오프체인 로그인·재검증·세션 요청도 `root_too_old` 로 막힌다(정상 fail-closed, 2026-09-23
  점검 C-1). 그런 블록 수를 진행시키는 테스트를 새로 짜면 `publish([])` 로 하트비트를 대신 넣는다.
  **V10(2026-10-02)**: 격리 IdP 는 기본으로(`test_mode3_demo_full.mjs` 를 뺀 모든 테스트) :8545 **하나에 로그와 거울을 함께** 배포하고(`cia.logAddress`·`cia.mirrorAddress`) 거울 릴레이
  주기를 끈다(`CIA_MIRROR_HEARTBEAT_BLOCKS: '0'`) — 두 번째 노드는 띄우지 않는다. 거울은 `POST /cia/admin/relay` 로만 오르므로
  격리 스택(`tests/helpers/isolated_mode3_stack.mjs`)이 `relay()`·`relayIfBehind()`·`withRelay(fn)`(요청 동안 뒤처지면 릴레이)과
  `autoRelay` 옵션(브라우저 각본용 0.5초 펌프)을 준다. `tests/test_cia_mirror_relay.mjs` 는 릴레이 주기·캐노니컬 하트비트 선행·
  수동 relay·`mirrors` 건강 정보·동시성을 본다(주기를 켜고 뜬다). `tests/test_mode3_demo_stack.mjs` 각본 13(거울 지연)·14(접수증
  강제)가 전 구간이다.
  `tests/test_mode3_demo_full.mjs`(2026-10-03)는 **두 체인·두 RP** 전 구간 각본이다 — :8546 에 폐기 체인 노드(chainId 31338)를
  스스로 띄우고(이미 떠 있으면 chainId 만 확인하고 건드리지 않는다) 끝나면 끈다. 격리 헬퍼의 `twoChains`·`extraRps` 옵션을 쓴다.
  **web 모드(2026-10-15)** 의 `chain` 테스트 넷은 `tests/test_mode3_user_static.mjs`(정적 서버 라우트 — `/user/config`·
  `/wallet/config`·`/mode3/health`·`/wallet/presence`·`/zk/*`), `tests/test_cia_cors.mjs`(IdP 가 사용자 오리진에 연 CORS 7
  라우트), `tests/test_mode3_rp_relay.mjs`(`POST /api/mode3/relay` 검사 8단계와 `relay_*` 사유), `tests/test_mode3_user_core.mjs`
  (`mode3/user/core` — 메모리 kv·진짜 snarkjs 로 등록·로그인·재검증·세션 요청·트랜잭션을 Node 에서)다. 정적 서버·코어 테스트는
  esbuild 번들을 스스로 만든다. Google(OIDC 래퍼, 2026-10-16) 의 `chain` 테스트 둘은 `tests/test_cia_oidc_register.mjs`
  (IdP 의 id_token 등록·폐기 10케이스 — 격리 IdP 를 두 번 띄운다, `startIsolatedCia({ oidc: true })`)·
  `tests/test_mode3_user_core_oidc.mjs`(사용자 코어의 prepare/complete·id_token 자기 폐기·uid_mismatch, 7케이스 — 격리
  스택의 `oidc`·`walletHost` 옵션)다.
- `bash scripts/run_tests.sh browser` — 팝업 로그인·`needs_consent` 재승인·MetaMask 트랜잭션을 실제 페이지로 돌린다
  (`tests/test_mode3_browser.mjs`). `chain` 과 같은 조건에 더해 **설치된 Google Chrome(또는 Chromium)** 이 필요하다 —
  Playwright 가 `channel: 'chrome'` 으로 띄우고, `window.ethereum` 을 스텁해 진짜 `snap-mode3/src/index.js` 의 `onRpcRequest` 를
  물린다. 그래서 `chain` 과 그룹을 나눴다. **스냅 경로(`snap-mode3/`, `mode3/wallet.html`, `mode3/rp.html`, 에이전트의 snap 분기)를
  건드렸으면 이 그룹도 돌린다.** (같은 그룹에 있던 `tests/test_mode3_tour.mjs` — 체험 모드·상태 점 — 는 2026-11-03 체험 모드 제거와 함께 삭제했다.) **web 모드**는 같은 그룹의
  `tests/test_mode3_user_web.mjs` — 각본 A(등록·로그인 팝업·재검증·세션 요청·트랜잭션·selective disclosure proof·세션 폐기, 7개)와
  각본 B(잠금·잠긴 상태의 팝업·시연 거절·오리진 위조·두 번째 RP·증명 키 캐시·모두 지우기, 7개)를 실제 Chrome 에서 돈다. 번들을 스스로 만든다.
  Google(OIDC 래퍼, 2026-10-16) 은 `tests/test_mode3_user_web_oidc.mjs` — 각본 G1~G10, GIS 를 `addInitScript` 스텁으로
  대체해 localhost 오리진의 사용자 페이지에서 돈다.
- `node scripts/screenshot_mode3.mjs` — 테스트는 아니고 **화면 캡처**다. `browser` 그룹과 같은 전제(:8545,
  `build/mode3`, Chrome)로 격리 스택을 file 모드로 띄워 네 페이지를 ko·en·전문가(+좁은 창)로 찍는다. 기본 출력은
  `results/mode3_ux_20260924/`(`--out` 으로 바꾼다). 스냅은 탭 구조(2026-11-03)라 스크립트가 보내기 탭과 접힌 조건을 열어
  찍는다. `--tour`(체험 모드 네 장면)는 체험 모드 제거와 함께 2026-11-03 에 삭제됐다. 끝나면 스택과 브라우저를 내린다.
- `bash scripts/run_tests.sh snap` — 스냅 RPC 9종의 단위 테스트(`snap-mode3/test/rpc.test.mjs`, 전역 `snap` 객체를 스텁).
  체인도 브라우저도 필요 없지만 `snap-mode3/node_modules` 를 전제하므로(`cd snap-mode3 && npm install`) `unit` 이 아니라
  별도 그룹이다. `node snap-mode3/test/rpc.test.mjs` 로 직접 돌려도 같다.
- `bash scripts/run_tests.sh contract` — `test/Mode3Wallet.test.mjs`(`execute()` 검사 순서·가스). hardhat 인프로세스 체인이라 :8545 가 필요 없다.
  단 `build/mode3/` 의 `pi_cred` zkey·wasm 은 필요하다(`test/Mode3Wallet.test.mjs` 가 실제 π 를 만든다) — 깨끗한 체크아웃에서
  그룹 전체가 실패하면 그 이유다.
- 세션 폐기(V8)는 `tests/test_mode3_session_revoke.mjs`(IdP 단독 — 404·409 `expired`·멱등·사용자 서명/관리자 두 갈래,
  `chain`), `tests/test_mode3_wallet_agent.mjs`·`tests/test_mode3_wallet_snap.mjs`(스냅 라우트·`revoked_session`·snap
  동의, `chain`), `tests/test_mode3_demo_stack.mjs` 각본 4″(전 구간), `tests/test_pi_cred_witness.mjs`(회로 ④′, `circuit`)로
  고정돼 있다.
- `bash scripts/run_tests.sh unit` 의 `tests/test_mode3_cia_state.js` — 상태 v13(2026-11-13: v12 는 `pk_u` 를 지우고 이행), v11 이하 기동 거부를 커버한다.
- `bash scripts/run_tests.sh unit` 의 web 모드(2026-10-15) 셋 — 외부 의존 없이 브라우저 공통 코드를 Node 에서 본다:
  `tests/test_browser_sha256.js`(순수 JS SHA-256·`node:crypto` shim, 오라클은 진짜 `node:crypto`), `tests/test_secret_box.mjs`
  (금고 암복호 — PBKDF2 310,000회 + AES-GCM-256, WebCrypto), `tests/test_browser_node_shims.js`(번들용 `node:fs`·`node:path`·
  `node:url` shim). Google(OIDC 래퍼, 2026-10-16) 유닛 둘도 외부 의존이 없다 — `tests/test_mode3_oidc_nonce.js`(uid·nonce
  유도 — `uidOf`·`regNonce`·`newRevokeNonce`, 3)·`tests/test_mode3_oidc_verifier.mjs`(jose 검증기 — 발급자 스텁
  `tests/helpers/oidc_issuer_stub.mjs`, 5).
- 개봉은 `tests/test_cia_opening.mjs`(IdP 단독)와 `test_mode3_demo_stack.mjs` 시나리오 9(전 구간)로 고정돼 있다.
- 속성 커밋먼트(Phase 1, 2026-11-09)는 `tests/test_mode3_attr_commit.mjs`(unit), `tests/test_cia_accounts.mjs` 마지막 케이스(프로필·discovery·JWKS·토큰 클레임),
  `tests/test_mode3_demo_stack.mjs` "속성 커밋먼트(Phase 1)"(운반·고정·변경·변조 거절·하위호환), `tests/test_mode3_browser.mjs`(도구 페이지 — 정적 자원 외 무요청·
  Node 재계산 일치·지우기·백업; `/user` 프로필 카드)로 고정돼 있다. 브라우저 테스트는 `scripts/build_attr_tool.mjs` 로 번들을 스스로 만든다.
- 등록부(V9, 2026-10-01)는 단위 셋 `tests/test_mode3_registry.js`(슬롯 트리 라이브러리)·`tests/test_mode3_credential_v11.js`·
  `tests/test_pi_idp_witness.mjs`·`tests/test_mode3_wallet_lib.js`(등록값·auid·π_IdP·인증 증명 등)·`tests/test_mode3_cia_state.js`
  (상태 v13·v12 이행·v11 이하 기동 거부, 모두 `unit`), `tests/test_cia_registry.mjs`
  (IdP 엔드포인트 — 등록·발급·교체·은퇴·계정 폐기·관리자 바꿔치기/되돌리기·재기동 백로그, `chain`), `test/Mode3Log.test.mjs`
  (컨트랙트 — 두 root 갱신·`SlotUpdated`·하트비트·서명 검사·재생 방지, `contract`), `tests/test_mode3_demo_stack.mjs`
  각본 10~12(전 구간)로 고정돼 있다.
