# Mode 3 데모 — 기동과 시연

설계: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md`
UI 스펙: `docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md`
온체인 실행: `docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md`

Mode 2 데모(:3000/:4000/:5001)와 **공존**한다. 포트·상태 파일이 다르고 코드를 공유하지 않는다.

## 프로세스와 포트

| 프로세스 | 포트 | 명령 | 상태 파일 |
|---|---|---|---|
| hardhat 노드 | :8545 | `npx hardhat node` | — |
| CIA | :4100 | `node cia.js` | `cia_state.json`, `cia_keys.json` |
| 지갑 에이전트 | :5100 | `node mode3_wallet_agent.js` | `mode3_wallet_state.json` |
| RP | :3100 | `node mode3_rp.js` | `mode3_rp_registration.json`, `mode3_rp_logins.jsonl` |

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
1. `npx hardhat node` (다른 터미널에 상주).
2. `CIA_ADMIN_SECRET=<아무 문자열> node cia.js` — 처음 기동에서 `cia_keys.json`을 만든다. `curl -s 127.0.0.1:4100/cia/public_keys`의 `ethAddress`를 적어 두고 종료한다.
3. `CIA_ETH_ADDRESS=<ethAddress> npx hardhat run scripts/deploy_mode3_log.cjs --network localhost` — `RevocationLog`를 배포하고 CIA 주소에 1 ETH를 넣는다. 출력의 `CIA_LOG_ADDRESS=0x…`를 `.env`에 추가한다.
3'. `npx hardhat compile` — RP 가 기동 시 `PiCredVerifier`·`Mode3WalletFactory` 를 아티팩트에서 읽어 배포한다(`artifacts/` 가
   없으면 RP 로그에 "팩토리 배포 실패", 오프체인 로그인만 된다).
4. `.env`에 `CIA_ADMIN_SECRET=<2의 값>`도 넣는다. (세 서버 모두 `dotenv`로 `.env`를 읽는다. `CIA_*`·`MODE3_*` 키는 이 데모만 쓴다.)
5. RP(mode3_rp.js)는 첫 기동에서 서명키·태그 조각을 만들어 CIA 에 등록하고 **등록 대기** 상태로 뜬다. CIA 관리자 페이지
   (`/admin` → 등록된 서비스 → 승인)에서 승인하면 5초 안에 arid·pk_trace·cert_s 를 받아 mode3_rp_registration.json 에 두고
   활성화된다. CIA 키를 바꾸거나 cia_state.json 을 지웠으면 이 파일도 지운다(그러면 새 키로 다시 승인받아야 한다).
6. RP 는 승인 뒤 팩토리를 배포해 `mode3_rp_registration.json` 에 `factoryAddress` 를 둔다. 재배포하려면 그 필드를 지우거나
   `MODE3_RP_FACTORY_ADDRESS` 로 덮어쓴다. **주의**: 회로를 다시 빌드한 뒤라면 `verifierAddress` 도 함께 지워야 한다 — 그 필드가 남아 있으면
   새 팩토리가 옛 검증기를 그대로 가리킨다(위 0 의 (4)).
   **경고**: 팩토리를 다시 배포하거나 `MODE3_MAX_ROOT_AGE` 를 바꾸면 모든 PPID 계정 주소가 바뀐다 — 옛 계정의 잔액은 옛
   팩토리 주소로만 접근할 수 있으니, 잔액이 있는 데모를 진행 중이면 먼저 빼낸다.

선택 env: 지갑의 `MODE3_TTL_BLOCKS`(credential 만료, 기본 300)·`MODE3_HEIGHT_GRID`(max_height 양자화 그리드, 기본 100 — 만료는 지갑이 정하고 CIA 는 그대로 서명), 서비스·컨트랙트의 `MODE3_MAX_LIFETIME_BLOCKS`(지갑이 정한 만료의 상한 L, 기본 400; TTL+GRID 이상이어야 로그인이 된다)·
`CIA_HEARTBEAT_BLOCKS`(하트비트 재게시 주기, 기본 50, 0=끔)·`CIA_HEARTBEAT_POLL_MS`(기본 5000)·
`CIA_CHAIN_RPCS`(발급을 허용할 체인의 RPC 맵, 기본 `"31337=http://127.0.0.1:8545"`, 비면 자기 RPC 하나)·
`MODE3_MAX_ROOT_AGE`(지갑이 받아들이는 게시 root 의 최대 나이, 블록, 기본 100 — 하트비트 주기보다 커야 한다)·
`MODE3_RELAYER_INDEX`(트랜잭션 릴레이어로 쓸 hardhat 계정 인덱스, 기본 0)·`MODE3_RP_FACTORY_ADDRESS`·`MODE3_VERIFIER_ADDRESS`,
`MODE3_VKEY_PATH`(CIA 의 개봉 검증용 vkey, 기본 `build/mode3/pi_cred_vkey.json`), `MODE3_RP_LOGIN_LOG`(RP 로그인 로그, 기본
`mode3_rp_logins.jsonl`, 0600 — 개봉 요청의 재료라 비밀로 둔다). 옛 `CIA_TTL_SECONDS`·`CIA_REVOKE_SKEW_SECONDS`·`CIA_CHAIN_IDS`·`CIA_REVOKE_SKEW_BLOCKS` 는
경고와 함께 무시된다(skew 는 2026-09-21 자격증명 이중 구조에서 제거됐다 — 폐기는 리프 하나라 세션 기록이 필요 없다).

선택: 운영이라면 RP의 `pk_CIA`를 TOFU가 아니라 env로 박는다 — `curl -s 127.0.0.1:4100/cia/public_keys`의 `pk_CIA.x/y`를 `MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y`에.

## 매번: 기동 순서

```
npx hardhat node                # 이미 떠 있으면 생략
node cia.js                     # :4100
node mode3_wallet_agent.js      # :5100
node mode3_rp.js                # :3100 (기동 시 CIA 에서 pk_CIA 를 받아 고정 — CIA 가 먼저 떠 있어야 한다)
```

RP 는 등록 파일이 없거나 승인 전이면 CIA 에 등록/조회하므로 CIA 가 먼저 떠 있어야 한다.

페이지: 지갑 `http://127.0.0.1:5100/`, RP `http://127.0.0.1:3100/`, CIA 관리자 `http://127.0.0.1:4100/admin`, CIA 사용자 `http://127.0.0.1:4100/account`.

RP 페이지는 반드시 `127.0.0.1`로 연다 — 지갑 에이전트의 CORS 허용 오리진이 `http://127.0.0.1:3100`(`MODE3_RP_ORIGIN`)이라 `localhost`로 열면 지갑 호출이 막힌다.

## 시연 각본

| # | 어디서 | 조작 | 기대 |
|---|---|---|---|
| 0 | 관리자 | 등록된 서비스 → 승인 (RP 첫 기동 뒤 한 번) | RP 페이지가 "등록 대기" → 활성 |
| 1 | 지갑 | 등록 (`12345` / `password123`, 속성 4칸 기본값) | `등록됨` |
| 2 | RP | 로그인 (AI agent 허용 체크 여부) | `새 발급=true`, 로그인 성공, PPID, 세션 r_s, allowAgent 표시 |
| 2a | 지갑 | 세션 선택 → 트랜잭션 보내기 | 첫 번째 `deployed=true`·`ok=true`, 두 번째 캐시 히트·`nonce=1` |
| 2b | 지갑 → RP → 관리자 → RP | 지갑 페이지의 txHash 를 RP "해시로 개봉"에 붙여 넣기 → 승인 → 결과 확인 | `uid=12345`, AI agent 허용 여부 |
| 3 | RP | 세션 재검증 | `캐시 히트=true`, 증명 0 ms, ok |
| 3′ | RP | 세션 요청 | 세션키 서명 검증 ok |
| 3″ | RP | 로그인 (다시) | 새 세션 = `새 발급=true`, **같은 PPID** |
| 4 | 관리자 | 계정 폐기 → 게시 | `published:true`, epoch +1 |
| 4′ | 사용자 페이지 → 관리자 | (4 대신) 내 계정 폐기 → 게시 | `disabled:true`, 이후 5~8 동일 |
| 5 | RP | "동기화 생략" 체크 → 세션 재검증 | 거절 `stale_root`. 세션 요청은 `revalidate_required` |
| 5a | 지갑 | (폐기·게시 뒤) 트랜잭션 보내기 | `revoked` |
| 6 | RP | 체크 해제 → 세션 재검증 → 로그인 | 지갑 `revoked` → 새 로그인은 `account_disabled` |
| 7 | 관리자 | 복구 | `disabled:false` |
| 8 | RP | 로그인 | `새 발급=true`, 성공, **PPID 가 2 와 같다** |
| 9 | RP → 관리자 → RP | 로그인 기록 아래 PPID 로 "개봉 요청" → 관리자 "개봉 요청 → 승인" → RP "결과 확인" | 202 pending → approved → uid=12345 |

온체인 실행은 트랜잭션마다 π 를 첨부하고 컨트랙트가 매번 검증한다(가스 실측: V4 회로 387,675(Task 3 값), V5 회로 356,441~356,477(실행마다 π 바이트에 따라 수십 가스 차이) —
`Mode3Wallet.execute()` 정상 실행, EOA 로 value 0 호출, 계정 배포 제외; `tests/test_mode3_wallet_agent.mjs` 의 tx 케이스 출력. Task 8 이 다시 측정한다). root 게시가 `MAX_ROOT_AGE` 블록보다 오래되면 `RootTooOld` 로 멈추므로 CIA 하트비트를 켜 둔다.
트랜잭션은 지갑 페이지에서만 시작한다 — 서비스 페이지는 지갑의 `/wallet/tx` 를 부를 수 없다(CORS).

성명은 로그인마다 새로 발급되고(설계 2026-09-15 §5) 세션 r_s 안에서만 재사용된다. RP 는 r_s 를 로그인 때 한 번 소비하고 그 뒤 세션 식별자로 쓴다. 폐기는 재검증에서 효력을 갖는다.

자격증명은 이중 구조다(설계 2026-09-21). 지갑은 첫 로그인 때 `POST /cia/user_cred` 로 **사용자 자격증명**(C_u, 사용자당 하나 — 속성을 담고
CIA 는 값을 모른다)을 받아 두고, 로그인마다 그 위에 `POST /cia/issue` 로 **세션 자격증명**(C_s)만 새로 받는다(ZKP 없음, 발급이 빠르다).
**계정 폐기 = 사용자 자격증명 리프 하나**이고, 그 사용자의 모든 세션(모든 서비스)이 다음 게시에 함께 무효가 된다. 지갑은 폐기된 사용자
자격증명을 다음 로그인의 동기화에서 알아채 새로 받는다(복구 뒤 8 의 `userCredMs > 0`). 상태 페이지의 "사용자 자격증명" 줄이 있음/없음/폐기됨을 보인다.

9 는 승인된 개봉(설계 2026-09-16 §6)이다. 로그인마다 지갑이 서비스의 조합 키 pk_trace 로 uid 를 암호화한 태그를 증명에 넣고
(조건 ⑤), 서비스는 자기 조각으로 반만 풀어 CIA 에 낸다. 운영자가 승인하면 CIA 가 자기 조각으로 마저 풀어 uid 를 돌려준다 —
서비스 혼자도, CIA 혼자도 열 수 없고, 열리는 것은 그 세션의 uid 하나다. CIA 는 로그인당 아무것도 저장하지 않는다.

0~9·3′·3″ 은 `tests/test_mode3_demo_stack.mjs`(HTTP)로, 2·3·4 의 라이브러리 판은 `tests/test_mode3_e2e.mjs` 로 고정돼 있다.

속성 4칸은 사용자가 고르는 값이고 CIA 는 보지 못한다(설계 2026-09-14 §2). 등록 뒤 값을 바꾸려면 지갑 페이지의 **속성 변경** 버튼
(`POST /wallet/attrs`) — 새 사용자 자격증명을 받고, 옛 것은 CIA 가 폐기 리프로 pending 에 넣어 다음 게시에 나간다. 그래서 지갑은
기존 세션을 그 자리에서 모두 지우며(`sessionsDropped`), 다음 로그인은 새 자격증명 위에 세션만 받는다(`userCredMs = 0`).
시각 상관에 주의: 옛 리프가 게시되는 블록에 그 사용자의 세션이 전부 죽고 곧 같은 PPID 로 재로그인하므로, CIA 와 서비스가 결탁하면 그 게시의
리프 수(데모에선 보통 1)가 익명 집합이다 — 속성 변경 직후 `/cia/publish` 를 따로 부르지 말고 하트비트 게시에 묶이게 두는 것이 완화다(설계 2026-09-21 §2).
credential 은 발급 시점 head 기준 300~400 블록(그리드 양자화)에 만료되며 지갑 상태 페이지에 `max_height` 로 보인다.

4′ 은 관리자 없이 사용자가 스스로 폐기하는 경로다(설계 §6.5.1). 인증은 계정 비밀번호이고 지갑 키가 아니다 —
장치를 잃은 사용자에게 지갑 키는 없고 공격자에게는 있기 때문이다. 처리와 게시는 4 와 같고, 복구는 여전히 관리자만 한다.

## 하지 말 것 / 재시연

- **옛 상태 파일(cia_state.json version 2 이하, mode3_wallet_state.json version 5 이하, 키 없는 mode3_rp_registration.json)을 새 서버에 물리지 않는다.** CIA 는 기동을 거부하고 지갑은 세션을 비운다. `cia_state.json` v3·v4 는 기동 시 v5 로 이행된다(v3 의 used_rs 는 버려지고 기존 서비스 등록은 승인된 것으로 남는다 — v4 의 발급 기록은 형식이 바뀌어 비워진다). `mode3_wallet_state.json` v5 이하는 등록은 유지하고 세션이 비워진다(v6 부터 `registration.userCred` — 없으면 다음 로그인이 새로 받는다). `mode3_rp_registration.json` v2 는 v3 로 이행된다(`X_svc`·`x_svc` 조각은 유지, `factoryAddress`·`verifierAddress` 는 비운다). 그 밖의 옛 형식이거나 origin 이 다른 `mode3_rp_registration.json`은 RP 가 기동 시 새로 등록한다 — 옛 서비스 조각(x_svc)도 버려지므로 이전 로그인 로그의 태그는 더 이상 열 수 없다.
- **옛 상태 파일(version 2 이하)을 새 CIA 에 물리지 않는다.** CIA 가 기동을 거부한다 — 재시연 세트로 새로 시작한다.
- **`cia_state.json`을 지우지 않는다.** 체인의 `RevocationLog.root`와 어긋나 지갑의 `syncRevocationTree`가 root 불일치로 전원을 막는다(Mode 2의 `idp_state.json`과 같은 이유). CIA 는 기동 시 로컬 트리를 온체인 root 와 대조해 어긋나면 `root 불일치`로 기동을 거부하므로, 지웠다면 아래 재시연 세트를 통째로 다시 한다.
- 재시연은 **한 세트로만**: hardhat 노드 재시작 → 위 "처음 한 번" 2~3(재배포, `.env`의 `CIA_LOG_ADDRESS` 갱신) →
  `mode3_rp_registration.json` 의 `factoryAddress` 삭제(로그 주소가 바뀌면 팩토리도 새로 배포해야 한다 — 삭제하면 RP 가 다시
  배포한다) → `cia_state.json`·`mode3_wallet_state.json`·`mode3_rp_registration.json`·`mode3_rp_logins.jsonl` 삭제 → 세 서버 재시작.
  `cia_keys.json`은 그대로 둬도 된다 — 게시 서명이 로그 주소를 덮으므로 같은 키로 재배포해도 옛 로그의 게시를 새 로그에 재생할 수 없다.
- 데모 계정은 `cia.js`의 `DEMO_ACCOUNTS`(`testuser`/`password123` → uid 12345, `alice`/`alicepw` → uid 67890). 지갑 에이전트는 한 계정만 등록한다.
- `CIA_ADMIN_SECRET` 없이 띄운 CIA 에서 사용자 페이지의 폐기를 누르지 않는다 — 자기 폐기는 시크릿 없이도 되지만 복구(`set_disabled`)와 게시는 503 이라 계정이 되돌릴 수 없게 비활성으로 남는다.
- **한계**: 트랜잭션 해시로 개봉을 요청하는 경로는 체인을 읽을 수 있는 누구나 이 서비스의 트랜잭션에 대해 개봉을 신청할 수 있게
  한다 — CIA 는 여전히 서비스 서명·`wrong_arid`·운영자 승인으로 걸러내고 `D_svc` 는 응답에 나오지 않지만, 신청 자체는 막지 않는다.
  `GET /api/mode3/open/:id` 결과 조회도 인증이 없어 승인 뒤 누구나 uid 를 읽을 수 있다(데모 한정).

## 테스트

- `bash scripts/run_tests.sh chain` — 격리 스택(임시 포트)으로 전 구간. :8545 와 `build/mode3/`의 `pi_cred` zkey·vkey 만 있으면 된다.
- `bash scripts/run_tests.sh contract` — `test/Mode3Wallet.test.mjs`(`execute()` 검사 순서·가스). hardhat 인프로세스 체인이라 :8545 가 필요 없다.
- `bash scripts/run_tests.sh unit` 의 `tests/test_mode3_cia_state.js` — 상태 v5 이행을 커버한다.
- 개봉은 `tests/test_cia_opening.mjs`(CIA 단독)와 `test_mode3_demo_stack.mjs` 시나리오 9(전 구간)로 고정돼 있다.
