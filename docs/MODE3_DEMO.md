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
| Snap serve (`snap` 모드에만) | :8082 | `cd snap-mode3 && npm run serve` | — (비밀은 MetaMask 안에) |

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

지갑 에이전트를 `MODE3_WALLET_SECRETS=snap` 으로 띄우면 MetaMask/Snap 경로가 된다(아래 "MetaMask / Snap 경로" 절). 기본은 `file` 이다.

페이지: 지갑 `http://127.0.0.1:5100/`, RP `http://127.0.0.1:3100/`, CIA 관리자 `http://127.0.0.1:4100/admin`, CIA 사용자 `http://127.0.0.1:4100/account`.

RP 페이지는 반드시 `127.0.0.1`로 연다 — 지갑 에이전트의 CORS 허용 오리진이 `http://127.0.0.1:3100`(`MODE3_RP_ORIGIN`)이라 `localhost`로 열면 지갑 호출이 막힌다.

## 시연 각본

| # | 어디서 | 조작 | 기대 |
|---|---|---|---|
| 0 | 관리자 | 등록된 서비스 → 승인 (RP 첫 기동 뒤 한 번) | RP 페이지가 "등록 대기" → 활성 |
| 1 | 지갑 | 등록 (`12345` / `password123`) | `등록됨`, 속성은 AA 기록값(`[1990, 410, 2, 0]`)이 응답으로 내려온다 — "속성과 선택 공개" 절 참고 |
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

온체인 실행은 트랜잭션마다 π 를 첨부하고 컨트랙트가 매번 검증한다(가스 실측, `Mode3Wallet.execute()` 정상 실행 — EOA 로 value 0
호출, 계정 배포 제외: V4 회로 387,675, V5 회로 356,441~356,477, **V6 회로(2026-09-22, 선택 공개, 공개 입력 23개) mask=0 캐시 π
402,079(402,035–402,091), mask=3(선택 공개) + `AttrGate.claim` 444,973(444,881–444,997)** — `results/mode3_disclosure_bench_20260922.md`,
`node scripts/bench_mode3_onchain.mjs` 출력). root 게시가 `MAX_ROOT_AGE` 블록보다 오래되면 `RootTooOld` 로 멈추므로 CIA 하트비트를 켜 둔다.
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

credential 은 발급 시점 head 기준 300~400 블록(그리드 양자화)에 만료되며 지갑 상태 페이지에 `max_height` 로 보인다.

4′ 은 관리자 없이 사용자가 스스로 폐기하는 경로다(설계 §6.5.1). 인증은 계정 비밀번호이고 지갑 키가 아니다 —
장치를 잃은 사용자에게 지갑 키는 없고 공격자에게는 있기 때문이다. 처리와 게시는 4 와 같고, 복구는 여전히 관리자만 한다.

## 속성과 선택 공개 (설계 2026-09-22)

**속성 출처.** 속성 4칸(`a₀` 출생연도, `a₁` 국가(ISO 3166 numeric), `a₂` 등급, `a₃` 예비)은 더 이상 사용자가 지갑에서 입력하지
않는다 — **AA(`cia.js`) 계정 기록**이고 관리자만 바꾼다. 데모 계정: `testuser`(uid 12345) `[1990, 410, 2, 0]`, `alice`(uid 67890)
`[2005, 840, 1, 0]`. `POST /wallet/register` 응답의 `attrs` 는 AA 가 내려준 값이고, 본문에 attrs 를 실어 보내도 무시된다.

**관리자 속성 변경.** CIA 관리자 페이지(또는 `POST /cia/accounts/:uid/attrs`, `requireAdmin`)에서 속성을 바꾸면 그 계정의
**활성 C_u 가 물린다**(폐기 리프가 pending 에 들어가 다음 게시에 나간다 — CIA 상태 v7). `GET /cia/accounts` 로 전 계정의
`attrs`·`disabled`·`activeCf_u` 를 볼 수 있다. 시각 상관 주의사항(옛 리프가 게시되는 블록에 세션이 죽고 곧 재로그인하므로 그 게시의
리프 수가 익명 집합)은 이중 구조 설계(2026-09-21 §2)와 같다 — 속성 변경 직후 `/cia/publish` 를 따로 부르지 말고 하트비트 게시에
묶이게 둔다.

**지갑의 재동기화.** 속성이 바뀌면 지갑이 들고 있던 C_u 는 다음 게시 뒤 폐기 트리에 들어간다. 지갑은 로그인 때 이를 알아채(동기화한
트리에 자기 리프가 있으면) 새 사용자 자격증명을 자동으로 받는다. 로그인 없이 먼저 확인하고 싶으면 `POST /wallet/attrs/sync` 로
AA 의 현재 값을 받아 두고(바뀌었으면 지갑이 옛 C_u·세션을 그 자리에서 지운다), 다음 로그인이 새 C_u 위에 세션을 받는다.

**트랜잭션의 선택 공개.** 지갑 페이지의 트랜잭션 폼에 슬롯별(a₀..a₃) 체크박스 + lo/hi 입력, "정확히 공개" 버튼(lo = hi = 내 값)이
있다. `POST /wallet/tx` 의 `disclose`(길이 4, 각 원소 `{lo, hi}` 또는 `null`)가 회로 공개 입력 `disc_mask`·`disc_lo[4]`·`disc_hi[4]`
가 된다. 지갑은 제출 전에 `lo ≤ 내 속성 ≤ hi` 를 스스로 검사한다 — 안 맞으면 증명을 만들기 전에 400 `disclosure_unsatisfiable`,
형식·범위가 잘못됐으면 400 `bad_disclosure`. `disclose` 가 있으면(mask ≠ 0) 캐시된 π 를 못 쓰고 매번 새로 증명한다.

**`AttrGate` (데모 대상).** RP 가 팩토리 다음에 한 번 배포하는 컨트랙트로(`rp_info.attrGateAddress`), 정책은 국가(a₁) = 410,
출생연도(a₀) ≤ 2007 고정이다. `claim()` 은 `Mode3Wallet.execute()` 가 호출 데이터 끝에 붙인 (mask, lo[4], hi[4]) 9워드를 읽어
`mask & 0x3 == 0x3`(슬롯 0·1 공개 필요)·`lo[1] == hi[1] == countryEq`·`hi[0] ≤ birthYearMax` 를 확인하고 `Claimed` 이벤트를 낸다.
팩토리가 배포한 지갑에서 온 호출만 받는다(`factory.isWallet(msg.sender)`).

`mode3_rp_registration.json` 에는 `attrGateAddress`(배포된 주소)와 `attrGateFactory`(그 배포가 실제로 물린 `factoryAddress`) 두
필드가 있다(`mode3_rp.js` `ensureAttrGate`). **`AttrGate` 는 `attrGateFactory` 가 지금의 `factoryAddress` 와 다를 때만 재배포된다**
— 즉 팩토리가 실제로 바뀐 경우에만 다시 배포하고, 같은 팩토리로 재기동을 반복해도 재배포하지 않는다. `attrGateFactory` 가 없는
옛 등록 파일(이 필드가 생기기 전)은 이 대조가 항상 "다르다"로 나와 **첫 기동에 `AttrGate` 를 한 번 재배포한다**(주소가 바뀐다 —
이전에 그 주소를 써 둔 데모 스크립트·문서가 있다면 갱신해야 한다).

**시나리오 1~5** (설계 §6.3, 위 0~9 각본과 별도로 확인):

| # | 조작 | 기대 |
|---|---|---|
| 1 | testuser 등록 | 속성 `[1990, 410, 2, 0]` 이 AA 에서 내려온다(지갑 화면은 읽기 전용) |
| 2 | 로그인(mask 0) → 트랜잭션 폼에서 슬롯 0 을 `[0, 2007]`, 슬롯 1 을 `[410, 410]` 으로 공개 → `to`=`attrGateAddress`, `data`=`claim()` 셀렉터(`0x4e71d92d`, 지갑 폼 기본값) | `Claimed` 이벤트, `AttrGate.claimed(wallet) == true` |
| 3 | alice(2005, 840)로 같은 시도 | `claim()` 이 `country` 로 revert(`Executed` success=false, nonce 는 소모) |
| 4 | 슬롯 0 을 `[0, 1980]` 으로 공개 시도 | 지갑이 `disclosure_unsatisfiable`(1990 ∉ [0, 1980], 체인에 보내기 전에 막힌다) |
| 5 | 관리자가 testuser 의 a₂ 를 3 으로 변경 → 다음 로그인 | 지갑이 옛 C_u 폐기를 알아채 새 C_u 를 받고 로그인 성공, **PPID 동일** |

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
| S1 | 지갑 | "MetaMask 연결" | MetaMask 계정 선택 창 → Snap 설치·권한 창. 상태줄에 `계정 0x… · Snap local:http://localhost:8082` |
| S2 | 지갑 | "등록" | **Snap 대화상자 2개**(uid → 비밀번호). 끝나면 상태에 `등록됨`, 속성은 AA 값(`[1990, 410, 2, 0]`). "Snap 상태 보기" 로 `등록: 예`, `사용자 자격증명 보관` 확인 |
| S3 | RP(:3100) | "Mode 3 로그인" | 지갑 오리진의 **팝업 창**이 뜨고 그 안에서 **Snap 로그인 동의 창**(서비스 이름·origin·arid·AI agent 허용)이 뜬다. 승인하면 팝업이 스스로 닫히고 RP 에 `로그인 성공 PPID=…` |
| S4 | RP | (S3 에서 동의를 **거절**) | RP 에 `로그인 실패 — 지갑: user_denied`. 세션이 생기지 않는다 |
| S5 | RP | "세션 재검증" | 팝업 없이 성공(비밀이 필요 없다). `캐시 히트=true` |
| S6 | 지갑 | 세션 선택 → 슬롯 0 `[0, 2007]`·슬롯 1 `[410, 410]` 공개 → `to`=AttrGate, `data`=`0x4e71d92d` → "트랜잭션 보내기" | **Snap 속성 공개 동의 창**(슬롯별 범위·대상 주소) → **MetaMask 트랜잭션 확인 창**(첫 번째는 계정 배포, 두 번째가 `claim()`) → 영수증에 `ok=true`, `Claimed` |
| S7 | 지갑 | MetaMask 확인 창에서 **거절** | 페이지에 `user_rejected`. 에이전트 상태는 그대로(nonce 는 컨트랙트가 관리한다) |
| S8 | 터미널 → RP | 지갑 에이전트를 재시작 → RP 에서 "세션 재검증" | 에이전트가 `409 needs_consent` → RP 가 **재승인 팝업**을 연다 → Snap 동의 창(이 세션의 AI agent 허용 값이 그대로 보여야 한다) → 승인하면 재검증이 이어져 성공 |
| S8′ | 관리자 → RP → 지갑 | CIA 관리자 페이지에서 testuser 의 a₂ 를 3 으로 변경 → `/cia/publish` → RP 에서 "Mode 3 로그인" | 로그인 동의 창 한 번으로 성공한다(지갑이 옛 C_u 폐기를 알아채 속성을 다시 받고 새 C_u 를 받는다, PPID 동일). 끝난 뒤 "Snap 상태 보기" 로 **속성이 `[1990, 410, 3, 0]` 으로 바뀌었고 `사용자 자격증명 보관: true`** 인지 본다 — 페이지가 `syncAttrs` 뒤에 `updateUserCred` 를 하므로 새 C_u 가 남아 있어야 한다(순서가 뒤집히면 여기서 `false` 가 되고 다음 재검증이 막힌다). 지갑 페이지의 "AA 에서 속성 다시 받기" 로도 같은 값을 확인할 수 있다(이쪽은 동의 창이 한 번 더 뜬다) |
| S9 | 지갑 | "자기 폐기" | **Snap 비밀번호 대화상자** → 에이전트 `POST /wallet/self_revoke` 가 CIA 로 중계 → `자기 폐기 완료`. 관리자 페이지에서 `/cia/publish` 뒤 재검증이 `revoked` 가 되는지 본다 |
| S10 | 지갑 | "Snap 초기화" | Snap 의 등록이 지워진다. 에이전트 파일의 **공개** 등록은 그대로다(재시연은 재시연 세트로) |

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

## 엔드포인트 (2026-09-22 선택 공개로 바뀌거나 추가된 것)

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `POST /cia/attrs` | CIA | 사용자 서명(`sig_u`)으로 자기 속성 조회(지갑이 `/wallet/attrs/sync` 안에서 부른다) |
| `POST /cia/accounts/:uid/attrs` | CIA(관리자) | 속성 변경 — 활성 C_u 를 물린다(폐기 리프 pending) |
| `GET /cia/accounts` | CIA(관리자) | 전 계정의 `attrs`·`disabled`·`activeCf_u` |
| `POST /wallet/attrs/sync` | 지갑 | AA 최신 속성 재확인, 바뀌었으면 옛 C_u·세션 삭제 |
| `POST /wallet/tx` (`disclose` 필드) | 지갑 | 트랜잭션에 선택 공개 첨부 — `{lo,hi}\|null` × 4, mask ≠ 0 이면 새 π |
| `GET /api/mode3/rp_info` (`attrGateAddress` 필드) | RP | 배포된 `AttrGate` 주소 |

MetaMask/Snap 경로(2026-09-22 metamask-snap)로 새로 생긴 지갑 라우트:

| 메서드/경로 | 프로세스 | 설명 |
|---|---|---|
| `GET /wallet/config` | 지갑 | `{ secrets, snapId, walletOrigin, rpcUrl, chainId }` — RP 페이지가 로그인 경로(직접 호출/팝업)를 고르려고 CORS 로 읽는다. 비밀 없음 |
| `POST /wallet/authorize/precheck` | 지갑 | 승인 팝업이 Snap 동의 창 전에 부르는 인증서·팩토리 검증(`{ arid, origin, cert_s, pk_trace, factoryAddress }`). 로그인·재승인이 함께 쓴다 |
| `POST /wallet/session/witness` | 지갑 | 재승인(§4.3) — 재시작으로 사라진 세션 메모리 증인을 `{ r_s, witness }` 로 다시 채운다 |
| `POST /wallet/tx/prepare` | 지갑 | snap 모드의 트랜잭션 1단계 — 증명·서명·`calldata`(필요하면 `deployCalldata`)까지만 만든다 |
| `POST /wallet/tx/record` | 지갑 | 2단계 — MetaMask 가 보낸 `txHash` 의 영수증을 파싱해 `/wallet/tx` 와 같은 형식으로 돌려준다(영수증 전이면 202) |
| `POST /wallet/self_revoke` | 지갑 | 자기 폐기 프록시 — `{ uid, pwd }` 를 CIA `/cia/account/self_revoke` 로 중계한다(`cia.js` 에 CORS 가 없어서). 등록 uid 가 아니면 403 `uid_mismatch` |

## 하지 말 것 / 재시연

- **옛 상태 파일(cia_state.json version 2 이하, mode3_wallet_state.json version 5 이하, 키 없는 mode3_rp_registration.json)을 새 서버에 물리지 않는다.** CIA 는 기동을 거부하고 지갑은 세션을 비운다. `cia_state.json` v3·v4 는 기동 시 v5 로 이행된다(v3 의 used_rs 는 버려지고 기존 서비스 등록은 승인된 것으로 남는다 — v4 의 발급 기록은 형식이 바뀌어 비워진다). `mode3_wallet_state.json` v5 이하는 등록은 유지하고 세션이 비워진다(v6 부터 `registration.userCred` — 없으면 다음 로그인이 새로 받는다). `mode3_rp_registration.json` v2 는 v3 로 이행된다(`X_svc`·`x_svc` 조각은 유지, `factoryAddress`·`verifierAddress` 는 비운다). 그 밖의 옛 형식이거나 origin 이 다른 `mode3_rp_registration.json`은 RP 가 기동 시 새로 등록한다 — 옛 서비스 조각(x_svc)도 버려지므로 이전 로그인 로그의 태그는 더 이상 열 수 없다.
- **옛 상태 파일(version 2 이하)을 새 CIA 에 물리지 않는다.** CIA 가 기동을 거부한다 — 재시연 세트로 새로 시작한다.
- **`cia_state.json`을 지우지 않는다.** 체인의 `RevocationLog.root`와 어긋나 지갑의 `syncRevocationTree`가 root 불일치로 전원을 막는다(Mode 2의 `idp_state.json`과 같은 이유). CIA 는 기동 시 로컬 트리를 온체인 root 와 대조해 어긋나면 `root 불일치`로 기동을 거부하므로, 지웠다면 아래 재시연 세트를 통째로 다시 한다.
- 재시연은 **한 세트로만**: hardhat 노드 재시작 → 위 "처음 한 번" 2~3(재배포, `.env`의 `CIA_LOG_ADDRESS` 갱신) →
  `mode3_rp_registration.json` 의 `factoryAddress` 삭제(로그 주소가 바뀌면 팩토리도 새로 배포해야 한다 — 삭제하면 RP 가 다시
  배포한다) → `cia_state.json`·`mode3_wallet_state.json`·`mode3_rp_registration.json`·`mode3_rp_logins.jsonl` 삭제 → 세 서버 재시작.
  `cia_keys.json`은 그대로 둬도 된다 — 게시 서명이 로그 주소를 덮으므로 같은 키로 재배포해도 옛 로그의 게시를 새 로그에 재생할 수 없다.
  **`snap` 모드로 시연 중이었다면 지갑 페이지의 "Snap 초기화"(`reset`)도 함께 누른다** — 등록 비밀은 상태 파일이 아니라 MetaMask 안에
  있어서 파일만 지우면 Snap 쪽에 옛 등록이 남고 다음 "등록" 이 `already_registered` 로 막힌다.
- 데모 계정은 `cia.js`의 `DEMO_ACCOUNTS`(`testuser`/`password123` → uid 12345, `alice`/`alicepw` → uid 67890). 지갑 에이전트는 한 계정만 등록한다.
- `CIA_ADMIN_SECRET` 없이 띄운 CIA 에서 사용자 페이지의 폐기를 누르지 않는다 — 자기 폐기는 시크릿 없이도 되지만 복구(`set_disabled`)와 게시는 503 이라 계정이 되돌릴 수 없게 비활성으로 남는다.
- **한계**: 트랜잭션 해시로 개봉을 요청하는 경로는 체인을 읽을 수 있는 누구나 이 서비스의 트랜잭션에 대해 개봉을 신청할 수 있게
  한다 — CIA 는 여전히 서비스 서명·`wrong_arid`·운영자 승인으로 걸러내고 `D_svc` 는 응답에 나오지 않지만, 신청 자체는 막지 않는다.
  `GET /api/mode3/open/:id` 결과 조회도 인증이 없어 승인 뒤 누구나 uid 를 읽을 수 있다(데모 한정).

## 테스트

- `bash scripts/run_tests.sh chain` — 격리 스택(임시 포트)으로 전 구간. :8545 와 `build/mode3/`의 `pi_cred` zkey·vkey 만 있으면 된다.
- `bash scripts/run_tests.sh browser` — 팝업 로그인·`needs_consent` 재승인·MetaMask 트랜잭션을 실제 페이지로 돌린다
  (`tests/test_mode3_browser.mjs`). `chain` 과 같은 조건에 더해 **설치된 Google Chrome(또는 Chromium)** 이 필요하다 —
  Playwright 가 `channel: 'chrome'` 으로 띄우고, `window.ethereum` 을 스텁해 진짜 `snap-mode3/src/index.js` 의 `onRpcRequest` 를
  물린다. 그래서 `chain` 과 그룹을 나눴다. **Snap 경로(`snap-mode3/`, `mode3/wallet.html`, `mode3/rp.html`, 에이전트의 snap 분기)를
  건드렸으면 이 그룹도 돌린다.**
- `bash scripts/run_tests.sh snap` — Snap RPC 9종의 단위 테스트(`snap-mode3/test/rpc.test.mjs`, 전역 `snap` 객체를 스텁).
  체인도 브라우저도 필요 없지만 `snap-mode3/node_modules` 를 전제하므로(`cd snap-mode3 && npm install`) `unit` 이 아니라
  별도 그룹이다. `node snap-mode3/test/rpc.test.mjs` 로 직접 돌려도 같다.
- `bash scripts/run_tests.sh contract` — `test/Mode3Wallet.test.mjs`(`execute()` 검사 순서·가스). hardhat 인프로세스 체인이라 :8545 가 필요 없다.
- `bash scripts/run_tests.sh unit` 의 `tests/test_mode3_cia_state.js` — 상태 v5 이행을 커버한다.
- 개봉은 `tests/test_cia_opening.mjs`(CIA 단독)와 `test_mode3_demo_stack.mjs` 시나리오 9(전 구간)로 고정돼 있다.
