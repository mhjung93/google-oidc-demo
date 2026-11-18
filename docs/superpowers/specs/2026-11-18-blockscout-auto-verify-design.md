# 로컬 Blockscout 컨트랙트 자동 검증 + 리셋 대상 바로잡기 (설계, 2026-11-18)

- 상태: **구현됨(2026-11-18 12:06, 사용자 지시로 스펙을 검토한 세션이 구현).** §6 의 1~2 와 3 의 `Mode3Mirror` 까지 실제 Blockscout 에서 확인했다(제출 3초 뒤 `ok`). 팩토리·`AttrGate`·지갑(B6)은 서비스 승인·첫 로그인 뒤에 확인한다. 아래는 처음 상태 —
  **초안 — 구현 대기(옆 세션이 맡는다).** 방향은 사용자 승인(2026-11-18 대화): "실행 중 배포되는 것까지 다 검증되게", 구현은 이 문서만 남기고 다른 세션에서.
  예상 소요 50분~1시간 반(가장 불확실한 것은 §6 의 실제 검증 — API 필드·viaIR 재현).
- 검토 반영(2026-11-18 11:22, 다른 세션이 코드와 대조): B4(immutable 위치의 출처)·B7·B8(ok 판정 시점)·B9(색인 대기는 재시도 횟수 밖)·B10(종료는 pid 파일)·§2(build-info 고르기)·§3(스크립트 테스트)·§5(같은 파일의 미커밋 수정).
- 범위: `scripts/demo_split_start.sh` 의 3b(Blockscout 초기화) 수정, 새 감시자 `scripts/blockscout_verify_watch.mjs`, 단위 테스트 하나.
- 비범위: 컨트랙트·회로·VM 코드(`mode3_rp.js`·`cia.js`) — 바꾸지 않는다. 폐기 체인(:8548, `Mode3Log`)은 이 Blockscout 가 색인하지 않으므로 제외.
  `demo_web_reset.sh`(한 머신 데모)는 지금 Blockscout 단계가 없으므로 손대지 않는다.

## 0. 확인한 사실(2026-11-18 11:08 KST, 읽기만)

| 확인 | 결과 |
|---|---|
| 로컬 Blockscout | `.local/blockscout/compose.yml`(git ignore). backend `v9.0.2`, `CHAIN_ID=31339`, `ETHEREUM_JSONRPC_HTTP_URL=http://host.docker.internal:8547/`. `verifier`(ghcr.io/blockscout/smart-contract-verifier, Solidity 만, Sourcify 끔) + `MICROSERVICE_SC_VERIFIER_ENABLED: 'true'`. proxy 가 `127.0.0.1:4000:80`. |
| **같은 compose 로 스택이 두 벌** | `zkid-blockscout`(10:42 생성, proxy :4000 — **화면에 보이는 쪽**, 저장소에 이 이름이 없다 = 수동 `-p`)와 `blockscout`(10:45, 리셋 스크립트가 만듦 — proxy 는 `Bind for 127.0.0.1:4000 failed: port is already allocated` 로 Created 상태). 둘 다 31339 를 색인한다. |
| 리셋이 안 먹는 이유 | `demo_split_start.sh:183-184` 의 `docker compose down -v`·`up -d` 가 기본 프로젝트 이름(디렉터리명 `blockscout`)에만 걸린다 → 보이는 `zkid-blockscout` 의 색인은 그대로, 중복 스택만 생긴다. 로그 `/tmp/mode3-split/blockscout_reset.log`. |
| 검증 도구 | `@nomicfoundation/hardhat-verify` 설치됨(toolbox). `hardhat.config.cjs` 에 `etherscan.customChains`·응용 체인 네트워크 이름 없음(`revchain` 만). 이 설계는 hardhat-verify 를 쓰지 않고 Blockscout REST 를 직접 부른다(§3.4 — 팩토리 지갑까지 한 경로로). |
| 컴파일 설정 | solc `0.8.24`, `optimizer {enabled, runs:200}`, 일부 파일 `viaIR: true`(파일별 override — `hardhat.config.cjs:13-45`). 표준 입력은 `artifacts/build-info/*.json` 의 `input` 을 그대로 쓴다(override 가 이미 반영돼 있다). |

### 응용 체인(31339)에 올라오는 컨트랙트

| 컨트랙트 | 누가·언제 | 생성자 인자 |
|---|---|---|
| `Mode3Mirror` | `scripts/deploy_mode3_log.cjs:53-54`(리셋 때) | `(cia, canonicalChainId, logAddress, emptyRoot, emptyReg)` |
| `PiCredVerifier` | RP 기동 때 `mode3_rp.js:235` → `lib/mode3_onchain.js:228` `deployVerifier`(환경변수·등록 파일에 있으면 재사용) | 없음 |
| `Mode3WalletFactory` | RP 기동 때 `mode3_rp.js:237` → `deployFactory`(`lib/mode3_onchain.js:244`) | `(verifier, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, log, maxRootAge, maxLifetime, rootWindow)` |
| `AttrGate` | RP `mode3_rp.js:313`(zkTWO 등 속성 요구 RP) → `deployAttrGate` | `(factory, setRoot, minAge)` |
| `Mode3Wallet`(계정마다) | `factory.deploy(ppid)` — RP 릴레이어 `mode3_rp.js:752`, 스냅 에이전트 `mode3_wallet_agent.js:1524`. **CREATE2**(`new Mode3Wallet{salt: bytes32(ppid)}`, `contracts/Mode3WalletFactory.sol:50`). **팩토리는 이벤트를 내지 않는다.** | `(ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge, maxLifetime, rootWindow)` (`contracts/Mode3Wallet.sol:82-85`) — `ppid` 말고는 팩토리의 `public immutable` 게터와 같다. |

지갑마다 immutable(`ppid`)이 달라 런타임 바이트코드가 다르다 — Blockscout 의 "같은 바이트코드" 자동 표시에 기대지 말고 **하나씩 검증**한다.

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| B1 | 3b 의 compose 호출을 `docker compose -p "${BLOCKSCOUT_PROJECT:-zkid-blockscout}"` 로 바꾼다(`down -v`·`up -d` 둘 다). | 화면에 보이는 스택이 `zkid-blockscout` 다. 이름을 환경변수로 열어 두어 다른 머신에서 바꿀 수 있게. |
| B2 | 중복 스택 `blockscout` 은 **구현 때 한 번** `cd .local/blockscout && docker compose -p blockscout down -v` 로 정리한다(사용자 확인 뒤). 스크립트에 상시 정리 코드는 넣지 않는다. | 스크립트가 남긴 것만 지운다. `zkid-blockscout` 은 건드리지 않는다. |
| B3 | 검증은 **호스트의 감시자 한 프로세스**(`scripts/blockscout_verify_watch.mjs`)가 응용 체인을 0번 블록부터 따라가며 한다. VM·RP·에이전트 코드는 바꾸지 않는다. | 배포 지점이 VM(RP)·로컬(에이전트) 여럿이다 — 체인을 보면 한 곳에서 다 잡힌다. 모든 `WALLET_MODE` 에 같다. |
| B4 | 판별은 **배포된 런타임 코드 대조**: 직접 배포 tx(`receipt.contractAddress`)는 `eth_getCode` 를 artifact `deployedBytecode` 와 비교한다(immutable 자리를 0 으로 가리고 비교). immutable 위치는 **artifact 에 없다** — hardhat artifact 에는 `deployedLinkReferences` 뿐이고, 위치는 build-info 의 `output.contracts[<sourceName>][<이름>].evm.deployedBytecode.immutableReferences`(`{ id: [{ start, length }] }`)에 있다. 맞는 artifact 가 없으면 건너뛴다(로그만). | 테스트·벤치 컨트랙트(`AcceptAllPiCredVerifier` 등)가 섞여도 오검증하지 않는다. |
| B5 | 직접 배포의 생성자 인자 = `tx.input` 에서 artifact `bytecode` 길이만큼 뗀 나머지(hex). | 표준 방식. |
| B6 | 지갑은 **팩토리 호출 tx** 로 찾는다: `to` 가 B4 로 판별된 팩토리이고 `input` 이 `deploy(uint256)` 셀렉터면 `ppid` 를 디코드 → 주소 = `factory.computeAddress(ppid)`(또는 `isWallet` 확인) → 생성자 인자 = `abi.encode(ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge, maxLifetime, rootWindow)`(팩토리 게터로 읽음). 실패한 tx(`status 0`)는 건너뛴다. | 팩토리가 이벤트를 내지 않는다. 컨트랙트를 바꾸지 않는다(비범위). |
| B7 | 제출은 Blockscout REST `POST /api/v2/smart-contracts/{address}/verification/via/standard-input`(multipart: `compiler_version`(build-info 의 `solcLongVersion`, `v` 접두 포함 형식은 구현 때 확인), `contract_name`(`contracts/X.sol:X` 또는 `X` — 확인), `license_type`(`none`), `autodetect_constructor_args=false`, `constructor_args`, `files[0]`=표준 입력 JSON). 응답·필드 이름은 **v9.0.2 에서 실제로 확인**한다(§6). 이 POST 는 검증을 **접수**할 뿐이고 결과는 나중에 나온다 — 200 을 받았다고 `ok` 로 적지 않는다(B8). 실패하면 `/api/v2/smart-contracts/verification/config` 로 허용 값을 본다. | hardhat-verify 는 직접 배포만 편하다. 한 경로로 통일. |
| B8 | 제출 전에 Blockscout 가 그 주소를 색인했는지 `GET /api/v2/addresses/{address}` 의 `is_contract` 로 확인하고, 아직이면 다음 회차로 미룬다. 이미 `is_verified` 면 건너뛴다. **`ok` 는 제출 뒤 다음 회차들에서 `is_verified` 가 참이 된 것을 보고 적는다**(제출하고 기다리는 동안의 상태는 `submitted`). 정해진 시간(기본 60초) 안에 참이 되지 않으면 그 제출은 실패로 치고 B9 의 재시도로 넘긴다. 결과는 메모리 집합 + 로그로만(상태 파일 없음 — 다시 띄우면 0번부터 다시 보고 `is_verified` 로 거른다). | 리셋 직후 색인이 늦다. 상태 파일을 늘리지 않는다. |
| B9 | 감시자 주기 3초, 한 회차에 새 블록만. 실패는 `WARN` 한 줄 + 다음 회차 재시도(주소별 최대 5회, 그 뒤 포기 로그). **"아직 색인 안 됨"(B8 의 `is_contract` 대기)은 이 5회에 넣지 않는다** — 리셋 직후 색인이 늦고, 지갑은 팩토리의 내부 호출(CREATE2)로 만들어져 Blockscout 가 컨트랙트로 알아보는 데 더 걸릴 수 있다. 색인 대기는 주소별로 따로 길게(기본 10분) 두고, 넘기면 `skip(not_indexed)` 로그 뒤 포기한다. 데모 기동을 막지 않는다. | 데모가 Blockscout 에 묶이지 않게. |
| B10 | 스크립트 연결: 3b 뒤·응용 체인 배포 뒤에 `setsid nohup node scripts/blockscout_verify_watch.mjs > "$LOGS/blockscout_verify.log"` 로 띄우고 pid 를 `$LOGS/blockscout_verify.pid` 에 적는다. 내릴 때는 `stop_local` 안에서 **pid 파일로** 내린다 — 그 pid 의 `/proc/<pid>/cmdline` 에 `blockscout_verify_watch.mjs` 가 있을 때만 `kill` 하고 파일을 지운다. `stop_local` 의 기존 목록(`포트:명령줄`)에 더하는 방식은 쓸 수 없다: 그 반복문은 **그 포트를 듣는 프로세스**만 찾는데(`ss -ltnp`) 감시자는 포트를 듣지 않는다. 새로 띄우기 전에도 같은 방법으로 옛 감시자를 먼저 내린다(두 벌이 돌지 않게). `BLOCKSCOUT_VERIFY=0` 이면 띄우지 않는다. Blockscout 단계가 건너뛰어졌으면(compose 없음·docker 없음·`BLOCKSCOUT_RESET=0` 이고 :4000 응답 없음) 감시자도 띄우지 않는다. | 기존 기동·내림 패턴 그대로. |
| B11 | 설정은 환경변수: `BS_URL`(기본 `http://127.0.0.1:4000`), `BS_RPC`(기본 `http://127.0.0.1:8547`), `BS_POLL_MS`(3000). 비밀 없음. | 하드코딩 금지 규칙. |

## 2. 감시자 모양(`scripts/blockscout_verify_watch.mjs`)

- 순수 함수는 `lib/blockscout_verify.mjs` 로 떼어 테스트한다:
  - `loadArtifacts(names)` → `{ name, sourceName, abi, bytecode, deployedBytecode, immutableRefs, buildInfoPath }`(build-info 는 **반드시 그 artifact 옆 `<이름>.dbg.json` 의 `buildInfo` 경로가 가리키는 파일 하나**다. "그 `sourceName` 을 담은 build-info" 로 찾으면 안 된다 — `PiCredVerifier` 는 build-info 5개에 들어 있고 그중 4개(지갑·팩토리·AttrGate 의 viaIR 컴파일 job 등)는 **배포되는 것과 다른 바이트코드**를 낸다(2026-11-18 확인: artifact 와 같은 것은 dbg 가 가리키는 단일 소스·비-viaIR job 하나). `Mode3Wallet`(3개)·`Mode3WalletFactory`(2개)는 어느 job 이든 같은 코드지만 같은 규칙을 쓴다. `immutableRefs` 도 그 build-info 의 `output` 에서 읽는다 — B4).
  - `matchRuntime(code, artifacts)` → 이름 또는 null(immutable 가림 비교).
  - `ctorArgsFromCreation(input, artifact)` → hex.
  - `walletCtorArgs(factoryValues, ppid)` → hex.
- 대상 이름 목록: `Mode3Mirror`, `PiCredVerifier`, `Mode3WalletFactory`, `AttrGate`, `Mode3Wallet`.
- 로그 한 줄 형식: `verify <이름> <주소> ok|skip(<이유>)|WARN(<이유>)`.

## 3. 테스트

- `tests/test_blockscout_verify.mjs`(`unit` 그룹 — `scripts/run_tests.sh` 에 추가): artifact 만으로
  (1) 각 대상의 `deployedBytecode`(immutable 자리에 임의 값을 채운 것)가 자기 이름으로 판별되고 다른 이름과 섞이지 않는다,
  (2) `bytecode + abi.encode(args)` 에서 `ctorArgsFromCreation` 이 args 를 되돌린다,
  (3) `walletCtorArgs` 가 `Mode3Wallet` 생성자 ABI 로 디코드했을 때 순서가 §0 표와 같다.
  (4) `loadArtifacts` 가 고른 build-info 의 `deployedBytecode` 가 artifact 의 것과 같다(다섯 대상 모두 — `PiCredVerifier` 에서 잘못 고르면 여기서 걸린다),
  (5) immutable 을 가린 비교가 `immutableReferences` 가 있는 대상(`Mode3Wallet` 11곳·팩토리 10곳·`AttrGate`·`Mode3Mirror` 3곳)에서 실제로 그 자리만 가린다.
- `scripts/demo_split_start.sh` 를 고친 뒤 `tests/test_demo_split_passkey_web.mjs` 도 돌린다 — "사전 검사(BLOCKED)가 모든 `docker` 호출보다 앞" 이라는 순서 단언과 `bash -n` 이 있다. 3b 의 compose 줄과 감시자 기동 줄이 이 순서를 깨지 않아야 한다.
- 체인·Blockscout 가 필요한 확인은 테스트가 아니라 §6 의 수동 확인으로 한다(외부 의존 없는 `unit` 계약을 지킨다).

## 4. 문서

- `docs/MODE3_DEMO.md` 의 분리 데모 절에 한 단락: Blockscout 리셋 대상(`BLOCKSCOUT_PROJECT`), 자동 검증(`BLOCKSCOUT_VERIFY=0`), 로그 위치.
- `demo_split_start.sh` 머리 사용법 주석에 `BLOCKSCOUT_VERIFY=0`·`BLOCKSCOUT_PROJECT=…` 두 줄.

## 5. 위험·주의

- **viaIR 재현**: 표준 입력을 build-info 에서 그대로 쓰면 같은 바이트코드가 나와야 한다. 다르면 대개 `compiler_version` 문자열·`contract_name` 형식 문제다. 그래도 안 맞으면 `metadata.bytecodeHash` 차이를 의심한다.
- **verifier 의 solc 내려받기**: 처음 한 번 `binaries.soliditylang.org` 에서 0.8.24 를 받는다(인터넷 필요). 실패 로그는 `docker logs zkid-blockscout-verifier-1`.
- **artifact 와 배포 코드 불일치**: VM 에 올라간 `artifacts/` 와 로컬 `artifacts/` 가 다르면(SYNC 안 함) 판별이 `skip(no_match)` 로 끝난다 — 그 경우 `SYNC=1` 로 다시 띄운다.
- **다른 세션과 같은 파일**: `demo_split_start.sh` 는 자주 고쳐진다 — 수정 직전에 다시 읽는다. 2026-11-18 11:22 현재 다른 세션의 **미커밋 수정**이 이 파일에 있다(공통 환경변수 `COMMON` 에 `MODE3_WALLET_KIND=$WALLET_MODE` 한 줄, `tests/test_demo_split_passkey_web.mjs` 에 그 단언) — 그 커밋이 들어간 뒤에 시작하거나, 그 줄을 지우지 않게 주의한다.
- **CLAUDE.md**: 파일 수정·테스트 실행·중복 스택 정리(B2)·실제 체인 검증 요청은 각각 사용자 확인 뒤.

## 5b. 구현하며 확인한 것(2026-11-18)

- **B7 의 필드는 문서대로 맞다**(v9.0.2): `compiler_version=v0.8.24+commit.e11b9ed9`(build-info `solcLongVersion` 앞에 `v`), `contract_name=<이름>`, `license_type=none`, `autodetect_constructor_args=false`, `constructor_args`(0x 없는 hex), `files[0]`(표준 입력 JSON). `GET /api/v2/smart-contracts/verification/config` 의 `verification_options` 에 `standard-input` 이 있다.
- **검증이 `internal error` 로 실패하던 원인은 verifier 의 컴파일러 폴더 권한**이었다: compose 가 이름 붙은 볼륨을 `/compilers` 에 붙였는데 root 소유라 verifier(uid 1001)가 받은 solc 를 쓰지 못했다(`fetching evm compiler: Permission denied`). `.local/blockscout/compose.yml`(저장소 밖)에서 `SMART_CONTRACT_VERIFIER__SOLIDITY__COMPILERS_DIR` 을 `/tmp/solidity-compilers` 로 바꾸고 볼륨 마운트를 뺐다(옛 파일은 `compose.yml.bak-20261118`). §5 의 "viaIR 재현" 걱정은 `Mode3Mirror`(viaIR)에서 문제가 없었다.
- **B2 정리 완료**: 중복 스택 `blockscout` 을 `docker compose -p blockscout down -v` 로 지웠다.
- 감시자의 추가 환경변수: `BS_VERIFY_WAIT_MS`(60000), `BS_INDEX_WAIT_MS`(600000). 로그 상태에 `submitted(try n/5)` 가 더 있다.
- 단위 테스트는 `artifacts/`(git 에 없다)를 읽는다 — 없으면 `BLOCKED: npx hardhat compile` 로 끝난다. `unit` 그룹의 "외부 의존 없음" 과는 다르지만 스펙대로 `unit` 에 두었다(`lib/mode3_onchain.js` 를 쓰는 다른 테스트도 같은 산출물을 전제한다).

## 6. 완료 확인(수동)

1. 중복 스택 정리(B2) 뒤 `docker ps` 에 `blockscout-*` 없음, `zkid-blockscout-*` 만.
2. `WALLET_MODE=<지금 모드> bash scripts/demo_split_start.sh` → 로그에 Blockscout 초기화 성공(포트 충돌 없음), `http://127.0.0.1:4000` 이 새 체인 0번부터.
3. (`ok` 는 `is_verified` 를 본 뒤에만 찍힌다 — B8.) RP 승인 뒤 `$LOGS/blockscout_verify.log` 에 `Mode3Mirror`·`PiCredVerifier`·`Mode3WalletFactory`(둘)·(zkTWO)`AttrGate` 가 `ok`.
4. 서비스 첫 로그인(지갑 배포) 뒤 그 `Mode3Wallet` 이 `ok`, Blockscout 화면에서 소스·생성자 인자가 보인다.
5. `bash scripts/demo_split_start.sh stop` 뒤 감시자 프로세스가 남지 않는다.
