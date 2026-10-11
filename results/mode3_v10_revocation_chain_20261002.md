# Mode 3 온체인 실측 — V10 폐기 전용 체인과 체인별 거울 (2026-10-02)

설계: `docs/superpowers/specs/2026-10-02-mode3-revocation-chain-design.md` · 계획: `docs/superpowers/plans/2026-10-02-mode3-v10-revocation-chain.md`.
Task 1–10 으로 컨트랙트(`Mode3Log` V3 — 접수증 대기열, `Mode3Mirror` — 체인별 거울)·CIA(캐노니컬 게시 + 릴레이)·
지갑 에이전트(거울 뷰로 증명·캐시 키 chainid)·RP(거울만 읽음)·데모 스택·런북이 V10 으로 이행을 마친 뒤, 이
실측(Task 11)이 새로 생긴 것(거울 배포·갱신, 접수증 제출·강제 게시)과 기존 execute gas 가 거울을 거쳐도 그대로인지를
잰다.

V10 의 핵심 변화: 폐기 상태(세션 폐기 root·등록부 root)의 정본을 폐기 체인의 `Mode3Log` 하나에 두고, 응용 체인은
`Mode3Mirror` 가 같은 IdP 서명을 그대로 받아 하트비트 주기로 갱신한다. `Mode3Wallet`(계정 컨트랙트)과 RP 검증기는
**캐노니컬이 아니라 거울**을 읽는다(`IMode3Roots` 인터페이스, 설계 §2). 사용자의 폐기 요청은 IdP 서명 접수증
(`requestRevocation`)으로 폐기 체인 대기열에 올려 다음 `publish` 가 그 슬롯을 0 으로 실어야만 통과하도록 강제할 수
있다(설계 §4). 회로(`pi_cred`)·`PiCredVerifier`·공개 입력 30개 순서는 **바뀌지 않았다**(계획의 Global Constraints) —
그래서 회로·증명/검증 시간은 이번에 재실행하지 않고 `results/mode3_v9_registry_20261002.md` 의 값을 그대로 인용한다.

**벤치 스크립트 자체의 수정(이 작업에서 같이 함)**: `scripts/bench_mode3_onchain.mjs` 는 V9 때 작성돼 `deployFactory`·
`createRpVerifier` 에 캐노니컬 `cia.logAddress` 를 넘기고 있었다 — V10 에서는 계정 컨트랙트도 RP 검증기도 거울
(`cia.mirrorAddress`)을 읽어야 하므로(`mode3_rp.js` 의 실제 배선과 같다), 그대로 두면 로그인이 `bad_factory` 409 로
전부 실패했다(이번 실행 중 실제로 한 번 재현·확인). 두 곳 다 `cia.mirrorAddress` 로 고쳤다. 또한 첫 로그인은 새
사용자 자격증명의 등록부 슬롯이 거울에 반영될 때까지 최대 30초를 기다리는데(`mode3_wallet_agent.js`), 격리 CIA 는
거울 하트비트를 꺼 두므로(`CIA_MIRROR_HEARTBEAT_BLOCKS=0`) 누군가 릴레이를 눌러 주지 않으면 그 30초를 그대로
태운다 — `tests/helpers/isolated_mode3_stack.mjs` 가 이미 제공하는 `stack.withRelay()` 로 첫 로그인(과 접수증 사이클의
재발급 로그인)을 감쌌다. 둘 다 벤치 스크립트 쪽 결함이지 V10 설계·구현의 결함은 아니다(다른 Task 들이 쓰는 데모
스택·테스트 헬퍼는 처음부터 거울 주소를 바르게 넘겼다).

## 측정 조건

- CPU: AMD Ryzen 9 5950X(16 코어) · Node v22.20.0 · snarkjs(Groth16, BN254) — V9 와 같은 머신, `/proc/cpuinfo`·`node -v`
  로 다시 확인했다.
- 커밋: `6f4d755`(V10 Task 1–10 완료) · 측정 일시: 2026-10-02 17:45 KST(`date` 실행값).
- hardhat 로컬 노드(:8545, 이 작업을 시작하기 전부터 떠 있던 것 — 새로 띄우거나 끄지 않았다, PID 132915). 온체인
  벤치는 그 위에 격리 CIA + 지갑 에이전트(임시 포트, 임시 상태 파일)를 띄운다 — 개발용 :4100/:5100/:3100 은 건드리지
  않는다. 캐노니컬 `Mode3Log` 와 거울 `Mode3Mirror` 가 **같은 :8545 노드 위**에 있다(격리 스택은 체인 하나뿐이라
  `canonicalChainId`·거울 체인 id 가 둘 다 31337 — 서로 다른 체인에 걸친 릴레이 지연은 이 벤치로 재지 않는다).
- N=10, 중앙값 (최소–최대). 접수증 사이클(requestRevocation·강제 publish)만 N=5 다 — 데모 계정이 `testuser` 하나뿐이라
  (`cia.js` `DEMO_ACCOUNTS`) 매 사이클이 자기 폐기 → 접수증 제출 → 강제 게시 → 관리자 재활성 → 재로그인(새 슬롯
  재발급, 실제 Groth16 증명 포함)을 다 돌아야 해 전체 벤치 N 과 같이 10 으로 잡으면 비용이 크다 — N≥3 조건은
  만족한다(브리프 §Step 1).
- 스크립트: `node scripts/bench_mode3_onchain.mjs 10`. 먼저 `node scripts/bench_mode3_onchain.mjs 1` 로 한 번 더
  돌려 로직이 끝까지 도는지 확인한 뒤(§6.1) N=10 을 실행했다(§6.2).
- 중앙값은 `med(a) = [...a].sort((x,y)=>x-y)[Math.floor(a.length/2)]` — 짝수 N(=10)에서는 가운데 두 값 중 **큰
  쪽**(upper-middle)을 쓴다. V9 쪽 비교값도 같은 스크립트의 같은 함수로 냈다.
- **회로·증명/검증 시간은 이번에 재실행하지 않았다** — `pi_cred` 회로·zkey 는 V10 에서 바뀌지 않았으므로(Global
  Constraints) `bench_pi_cred.mjs` 를 다시 돌리는 대신 V9 실측값을 그대로 인용한다. `npm run zk:*` 류도 실행하지
  않았다.
- 온체인 벤치(`bench_mode3_onchain.mjs`)는 겹치는 다른 테스트·벤치 없이 **단독으로** 돌렸다(CPU 경합이 증명 시간을
  튀게 한다는 V9 문서의 교훈 — 이번엔 증명 시간 자체를 재지 않지만 gas 측정 중에도 다른 프로세스를 띄우지 않았다).

## 1. 회로 — 제약·공개 입력·증명/검증 시간 (변경 없음, V9 값 인용)

| 항목 | V9(`results/mode3_v9_registry_20261002.md`) | V10 |
|---|--:|--:|
| R1CS 제약(비선형) | 34,934 | 변경 없음(회로 미수정) |
| Wires | 34,966 | 변경 없음 |
| Private Inputs | 131 | 변경 없음 |
| 공개 입력 수 | 30 | 변경 없음 |
| 증명 시간(중앙값, N=10) | 1,271.3 ms | 재실행 안 함 — 위 값 인용 |
| 검증 시간(중앙값, N=10) | 11.3 ms | 재실행 안 함 — 위 값 인용 |
| zkey 크기 | 22,316,319 B | 변경 없음(`build/mode3/pi_cred_final.zkey`) |

## 2. execute() gas — 네 가지 공개 변형 (재실측, V9 대비 거의 동일을 확인)

계정 컨트랙트(`Mode3Wallet`)가 이제 캐노니컬이 아니라 거울을 읽지만(팩토리 생성자의 `logAddress` = `cia.mirrorAddress`),
`IMode3Roots` 인터페이스·검사 로직은 그대로라 거의 같은 값이 나와야 한다 — 실제로 네 변형 모두 차이가 0.01% 미만(잡음
범위)이다.

| 변형 | V9 | V10(이번 실측) | 차이 |
|---|--:|--:|--:|
| mask=0, 캐시 π | 455,939 | 455,947 | +8 (+0.002%) |
| 범위만(mask=1) | 462,283 | 462,307 | +24 (+0.005%) |
| 집합만(mask=0+set) | 462,931 | 462,931 | 0 |
| 범위+집합+claim(새 π) | 497,385 | 497,381 | −4 (−0.001%) |
| 첫 tx(mask=0, 계정 배포 tx 는 별도) | 473,027 | 473,035 | +8 (+0.002%) |

**해석**: 네 변형 모두 수 gas 단위(EVM 실행 비용의 noise 범위)로만 갈려, "계정이 이제 거울을 읽는다"는 변화가
execute() 쪽 gas 에는 사실상 영향이 없다는 예상을 확인한다 — 거울과 캐노니컬이 같은 4개 getter(`MODE3_ROOTS_ABI`)를
구현해 외부 호출 비용(콜 자체 + SLOAD)이 동일하기 때문으로 보인다.

## 3. 배포 gas (거울 배포 신규)

| 항목 | V9 | V10(이번 실측) | 차이 |
|---|--:|--:|--:|
| 계정 배포(factory.deploy, CREATE2) | 995,731 | 995,719 | −12 (잡음) |
| PiCredVerifier 배포 | 976,980 | 976,980 | 0 |
| Mode3WalletFactory 배포 | 1,577,919 | 1,577,907 | −12 (잡음) |
| Mode3Log 배포¹ | 1,104,315 | **1,688,767** | +584,452 (+52.9%) |
| Mode3Mirror 배포¹ (신규) | 해당 없음 | **874,921** | V10 신규 |

¹ `node scripts/bench_mode3_onchain.mjs 1`(N=1)과 `node scripts/bench_mode3_onchain.mjs 10`(N=10) 둘 다에서 같은
값(1,688,767 / 874,921)이 나왔다 — 생성자 인자(ciaAddress·빈 root 둘, 거울은 canonicalChainId·canonicalLogAddress
까지)에 분기하지 않아 결정적이므로 N=10 중앙값이 N=1 과 같다. `lib/mode3_onchain.js` 의 `deployLog()`(벤치 전용)로
더미 `Mode3Log` 를 하나 배포하고, `tests/helpers/mode3_chain.mjs` 의 `deployMode3Mirror()` 로 그 더미를 캐노니컬로
가리키는 더미 `Mode3Mirror` 를 하나 더 배포했다(둘 다 스택의 `cia.logAddress`/`cia.mirrorAddress` 에는 연결하지
않는다).

**Mode3Log 배포 gas 가 크게 오른 이유(+52.9%)**: V10 의 `Mode3Log` 는 V9 대비 접수증 대기열 기능(`requestRevocation`,
`pendingSlots` 동적 배열, `isRetired` 매핑, `receiptDigestFor`, `RevocationRequested`·`SlotRetired` 이벤트, `publish`
안의 대기열 검사 분기)을 통째로 더 들고 있다 — 바이트코드가 그만큼 커진 결과로 보인다(항목별 분해는 하지 않았다).

## 4. 게시·릴레이·접수증 gas

| 항목 | V9 | V10(이번 실측) | 차이 |
|---|--:|--:|--:|
| 등록부 슬롯 게시(슬롯 1개, `SlotUpdated` 1건) | 52,480 | **57,832** | +5,352 (+10.2%) |
| 폐기 리프 게시(리프 1개) | 49,771 | **52,514** | +2,743 (+5.5%) |
| 하트비트 게시(리프 0, 슬롯 0) | 46,176(1건) | **48,907**(1건, 이번 N=10 실행에서 관측) | +2,731 (+5.9%) |
| Mode3Mirror 갱신(강제 릴레이, N=10) | 해당 없음 | **45,113** (45,101–47,913) | V10 신규 |
| requestRevocation(접수증 제출, N=5)² | 해당 없음 | **100,912** (81,000–100,920) | V10 신규 |
| 강제 publish(pending 슬롯 1개, N=5)² | 해당 없음 | **76,008** (75,988–77,996) | V10 신규 |

² 데모 계정이 하나뿐이라 자기 폐기 → `requestRevocation` → 강제 `/cia/publish` → 관리자 재활성 → 재로그인(새 슬롯
재발급)을 5 번 돌려 얻은 값이다 — 매 사이클이 서로 다른 등록부 슬롯을 쓰므로(`acct.slotRetired` 뒤 재발급은 항상 새
슬롯을 받는다, `cia.js`) 두 번째부터가 "같은 슬롯 재제출(no-op)"은 아니다. `requestRevocation` 값이 1회차(81,000)와
2~5회차(100,920 근방)로 갈리는 것은 관측했지만 정확한 원인은 추가로 분해하지 않았다 — SSTORE 콜드/웜 비용만으로는
설명되지 않아(매 사이클이 처음 건드리는 새 저장 슬롯이라 이론상 비슷해야 한다) 근거 불충분으로 단정하지 않는다.

**V9 대비 기존 게시 행이 전부 오르는 이유(등록부 슬롯 +10.2%·리프 +5.5%·하트비트 +5.9%)**: `Mode3Log.publish()` 가
이제 매번 대기열 검사(온체인 `pendingSlots` 길이·`isRetired` 대조)를 거치므로 — 이번 실행에선 대기열이 비어 있는
정상 경로라도 그 확인 자체에 SLOAD 가 추가된 것으로 보인다(V9 문서가 §5 에서도 "항목별 분해는 하지 않았다"고 적은
것과 같은 수준의 해석이다).

## 5. 로그인 지연 (N=10, 중앙값 (최소–최대), ms)

| 항목 | V9 | V10(이번 실측) |
|---|--:|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1,626 (1,580–4,901) | 1,504 (1,471–7,084) |
| ├ 첫 로그인(사용자 자격증명 신규 발급 + 등록부 게시 대기 포함) | 4,901 | **7,084** |
| ├ 체인 동기화 syncMs | 56 (54–510) | 78 (77–511) |
| ├ 사용자 자격증명 발급 userCredMs(첫 로그인 775, 이후 재사용) | 0 (0–775) | 0 (0–723) |
| ├ CIA 세션 발급 issueMs(ZKP 없음, sig_u 검증 + 서명) | 134 (123–260) | 127 (117–232) |
| ├ 증명 proveMs(pi_cred, 온체인 벤치 내부) | 1,343 (1,303–2,075) | 1,220 (1,182–1,887) |
| 서비스 verifyLogin(Groth16 + σ + root) | 36 (35–354) | 35 (33–320) |
| 재검증 왕복(캐시 π) | 58 (55–63) | 81 (80–84) |
| 재검증 verifyLogin | 37 (34–40) | 34 (32–35) |

**첫 로그인이 V9(4,901 ms)보다 더 느려진 이유(7,084 ms)**: V10 에서는 새 사용자 자격증명의 등록부 슬롯이 **거울**에
반영될 때까지 기다린다(`mode3_wallet_agent.js`, 캐노니컬만으로는 부족하다 — RP·계정 컨트랙트가 거울을 보기 때문).
격리 CIA 는 거울 하트비트를 꺼 두므로(`CIA_MIRROR_HEARTBEAT_BLOCKS=0`) 이 벤치는 `stack.withRelay()` 로 그 폴링
구간에 0.4초마다 강제 릴레이를 펌프질해 30초 타임아웃을 피한다 — 그래도 "슬롯 게시(캐노니컬) → 릴레이 호출 →
거울 publish tx 채굴 → 폴링이 2초 간격으로 알아챔"의 추가 왕복이 들어가 V9 보다 느리다. 운영 환경에서는
`CIA_MIRROR_HEARTBEAT_BLOCKS` 주기 릴레이가 이 역할을 대신하므로, 이 7,084 ms 는 "거울 릴레이를 사람이 직접 눌러
주는" 벤치 한정 수치에 가깝다 — 실제 운영 지연과 나란히 놓지 않는다.

## 6. 해석

- **거울을 두는 비용**: 체인마다 거울을 하나 더 두는 구조적 비용은 (a) 배포 1회 874,921 gas, (b) 갱신마다 45,113 gas
  (하트비트 게시 48,907 gas 와 비슷한 규모 — 거울이 해시 3개만 받아 캐노니컬의 리프·슬롯 배열 유무와 무관하게 거의
  고정 비용이다). execute() 쪽에는 거의 비용이 없다(§2) — 계정이 거울을 보느냐 캐노니컬을 보느냐는 외부 호출 하나의
  대상만 바뀔 뿐 호출 비용 자체는 같다.
- **강제 게시의 비용**: 접수증을 체인에 올리는 비용(requestRevocation, 1회차 81,000 gas)에 더해, 그 접수증을 따르는
  강제 publish(76,008 gas)는 일반 등록부 슬롯 게시(57,832 gas)보다 비싸다(+18,176 gas, +31.4%) — 대기열 검사 ·
  `isRetired` 영구 기록(콜드 SSTORE)이 더해지기 때문으로 보인다. 즉 "IdP 가 느릴 때 사용자가 직접 강제하는" 경로는
  정상 폐기 경로보다 한 번은 더 비싸지만, 그 뒤로는 같은 슬롯이 영구 은퇴해 재사용 공격을 막는 대가다.
- **로그인 지연은 거울 릴레이 주기에 좌우된다**: 첫 로그인의 느려짐(§5)은 V10 설계 자체의 구조적 비용이라기보다,
  이 벤치가 거울 하트비트 없이 강제로 펌프질하는 조건을 재는 것이다 — 운영 기본값(런북에 적힌 거울 하트비트 주기)
  아래서는 사용자가 등록부 게시를 기다리는 평균 시간이 그 주기의 절반 정도로 수렴할 것으로 예상되나, 이 벤치는 그
  운영 조건을 재현하지 않았다(격리 스택은 항상 거울 하트비트를 꺼 둔다, `tests/helpers/isolated_cia.mjs`).

## 7. 측정 방법 — 원본 출력

### 7.1 `node scripts/bench_mode3_onchain.mjs 1` (로직 확인용, N=1)

```
## Mode 3 온체인 실행 실측 (N=1, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 7085 (7085–7085) |
| ├ 첫 로그인(사용자 자격증명 신규 발급 + 등록부 게시 대기 포함) | 7085 ms |
| ├ 체인 동기화 syncMs | 505 (505–505) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 721 ms, 이후 재사용) | 721 (721–721) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 234 (234–234) |
| ├ 증명 proveMs (pi_cred V9) | 1927 (1927–1927) |
| 서비스 verifyLogin (Groth16 + σ + root) | 341 (341–341) |
| 재검증 왕복(캐시 π) | 85 (85–85) |
| 재검증 verifyLogin | 34 (34–34) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 217 (217–217) |
| execute gas (mask=0, 캐시 π, N회) | 455939 (455939–455939) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 473083 |
| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | 1647 (1647–1647) |
| execute gas (mask=1 + set, 새 π + claim, N회) | 497417 (497417–497417) |
| execute gas (범위만, mask=1, to=dEaD, N회) | 462319 (462319–462319) |
| execute gas (집합만, mask=0 + set, to=dEaD, N회) | 462923 (462923–462923) |
| 계정 배포 gas (factory.deploy, CREATE2) | 995719 |
| PiCredVerifier 배포 gas | 976980 |
| Mode3WalletFactory 배포 gas | 1577931 |
| Mode3Log 배포 gas | 1688767 |
| Mode3Log 등록부 슬롯 게시 gas (슬롯 1개, SlotUpdated 1건) | 57864 |
| Mode3Log 폐기 리프 게시 gas (리프 1개) | 52490 |
| Mode3Log 하트비트 게시 gas (리프 0, 슬롯 0) | 48927 |
| Mode3Mirror 배포 gas | 874921 |
| Mode3Mirror 갱신 gas (강제 릴레이, N회) | 47933 (47933–47933) |
| Mode3Log requestRevocation gas (접수증 제출, N=1) | 81000 (81000–81000) |
| Mode3Log 강제 publish gas (pending 슬롯 1개, N=1) | 77964 (77964–77964) |
| zkey 크기 | 22316319 bytes |
| 공개 입력 수 | 30 |
```

실행 뒤 `ps aux` 로 `cia.js`·`mode3_wallet_agent.js` 잔여 프로세스가 없음을 확인했다.

### 7.2 `node scripts/bench_mode3_onchain.mjs 10` (이 문서의 본 실측)

```
## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1504 (1471–7084) |
| ├ 첫 로그인(사용자 자격증명 신규 발급 + 등록부 게시 대기 포함) | 7084 ms |
| ├ 체인 동기화 syncMs | 78 (77–511) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 723 ms, 이후 재사용) | 0 (0–723) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 127 (117–232) |
| ├ 증명 proveMs (pi_cred V9) | 1220 (1182–1887) |
| 서비스 verifyLogin (Groth16 + σ + root) | 35 (33–320) |
| 재검증 왕복(캐시 π) | 81 (80–84) |
| 재검증 verifyLogin | 34 (32–35) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 214 (211–216) |
| execute gas (mask=0, 캐시 π, N회) | 455947 (455891–455947) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 473035 |
| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | 1450 (1424–1628) |
| execute gas (mask=1 + set, 새 π + claim, N회) | 497381 (497349–497417) |
| execute gas (범위만, mask=1, to=dEaD, N회) | 462307 (462251–462331) |
| execute gas (집합만, mask=0 + set, to=dEaD, N회) | 462931 (462875–462967) |
| 계정 배포 gas (factory.deploy, CREATE2) | 995719 |
| PiCredVerifier 배포 gas | 976980 |
| Mode3WalletFactory 배포 gas | 1577907 |
| Mode3Log 배포 gas | 1688767 |
| Mode3Log 등록부 슬롯 게시 gas (슬롯 1개, SlotUpdated 1건) | 57832 |
| Mode3Log 폐기 리프 게시 gas (리프 1개) | 52514 |
| Mode3Log 하트비트 게시 gas (리프 0, 슬롯 0) | 48907 |
| Mode3Mirror 배포 gas | 874921 |
| Mode3Mirror 갱신 gas (강제 릴레이, N회) | 45113 (45101–47913) |
| Mode3Log requestRevocation gas (접수증 제출, N=5) | 100912 (81000–100920) |
| Mode3Log 강제 publish gas (pending 슬롯 1개, N=5) | 76008 (75988–77996) |
| zkey 크기 | 22316319 bytes |
| 공개 입력 수 | 30 |
```

실행 뒤 `ps aux` 로 `cia.js`·`mode3_wallet_agent.js` 잔여 프로세스가 없음을 확인했고, hardhat 노드(:8545)는 이
작업을 시작하기 전과 같은 프로세스(PID 132915)로 계속 떠 있다(블록 번호만 `0x157b` → `0x162a` 로 진행했다 — 이
작업이 새로 띄우거나 끈 적 없다). 이 벤치 외에 다른 테스트·벤치는 동시에 돌리지 않았다.
