# Mode 3 속성 술어 확장(V7, 집합 소속) 실측 — 2026-09-23

설계: `docs/superpowers/specs/2026-09-23-mode3-predicates-design.md`. V6(선택 공개, `results/mode3_disclosure_bench_20260922.md`)
대비 회로 V7(집합 소속 술어: `set_sel`·`set_root` 공개 입력 2개 추가, AttrGate v2 — `allowedCountriesRoot`·`minAge`·`yearOf(block.timestamp)`)의
비용을 잰다.

측정 환경: AMD Ryzen 9 5950X(16코어), Node v22.20.0, snarkjs(Groth16, BN254), hardhat 로컬 노드(:8545, 이 작업 세션에서
기동·측정 후 종료). N=10, 중앙값 (최소–최대). 명령:

```
node scripts/bench_pi_cred.mjs pot21_final.ptau
npx snarkjs r1cs info build/mode3/pi_cred.r1cs      # 제약·공개 입력 수 확인용(bench_pi_cred.mjs 는 제약 수를 안 찍음)
node scripts/bench_mode3_onchain.mjs
```

`build/mode3/pi_cred_final.zkey`는 이미 V7 회로로 만들어져 있었다(2026-09-23 15:40 생성) — `bench_pi_cred.mjs`는 zkey가
있으면 재사용만 하고(셋업은 없을 때만), 이 측정에서 새로 만들지 않았다. `scripts/build_mode3_circuit.sh`는 실행하지 않았다.

**Fix round 1(2026-09-23) 갱신**: §1·§4 의 pi_cred 수치와 §2·§4 의 온체인 수치를 모두 **같은 재실행 1회**의 stdout으로
다시 맞췄다(리뷰 지적 1 — 이전 판은 §1 이 3회 중 다른 실행값을 잘못 옮겨 §4 원본과 어긋나 있었다). §2 에 "범위만" gas
행을 추가했다(리뷰 지적 2 — 브리프가 요구한 네 가지 disclosure 변형: 공개 0 / 범위만 / 집합만 / 범위+집합 중 "범위만"이
빠져 있었다). `scripts/bench_mode3_onchain.mjs` 에 항목 6(범위만, mask=1·set 없음·to=dEaD)을 새로 추가했다(항목 7 = 기존
집합만, 번호만 밀림).

## 1. 회로 제약·ZKP 시간 (pi_cred / π_rp)

| 항목 | V6 (2026-09-22) | V7 (2026-09-23, 이번 실측) |
|---|--:|--:|
| R1CS 제약 | 25,369 | **27,329** (`npx snarkjs r1cs info`, +1,960) |
| 공개 입력 수 | 23 | **25** (`set_sel`·`set_root` 추가) |
| Wires | — | 27,356 |
| Private Inputs | — | 88 |
| 증명 시간 (중앙값, N=10) | 608.6 (594.4–993.1) ms (witness 제외) / 809.0 (798.6–1,209.9) ms (witness+prove) | **832.8 ms**(witness+prove, `bench_pi_cred.mjs` 는 두 단계를 분리해 찍지 않음) |
| 검증 시간 (중앙값, N=10) | 10.7 (7.1–12.6) ms | **10.0 ms** |
| zkey 크기 | 15,433,687 bytes | **16,405,887 bytes** |

V6 열은 `results/mode3_disclosure_bench_20260922.md` §1·§4 원본 stdout에서 그대로 옮겼다. V7의 witness/prove 분리값은 이번
스크립트 출력에 없어 합산값만 실었다(`bench_pi_cred.mjs`의 표 형식이 V6 당시의 `bench_zkp_inventory.mjs`와 달라 항목이 정확히
1:1 대응하지 않는다 — 열을 억지로 맞추지 않았다). 이 표의 숫자는 §4 원본 stdout(pi_cred 실행)과 그대로 같은 실행 1회의 값이다.

## 2. 온체인 실측 (N=10, `bench_mode3_onchain.mjs`)

Fix round 1 에서 1회 재실행했다(항목 6 "범위만" 신설 뒤). 이번 실행은 하트비트 레이스(§3) 없이 첫 시도에 성공했다.
이전 판(Task 9 최초 제출)에서는 3회 실행 모두 성공했고 gas 값은 잡음 범위 안에서 거의 같았다(예: mask=0 캐시 π 실행값이
415,979~416,059 사이) — 아래 표는 이번 재실행 1회의 값이며, 이전 판과 수 gas~수십 gas 차이가 나는 행은 그 잡음 범위 안이다.

| 항목 | V6 (2026-09-22, 재실측판) | V7 (2026-09-23, 이번 실측) |
|---|--:|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1,037 (1,020–4,608) ms | **1,059 (1,046–4,726) ms** |
| ├ 체인 동기화 syncMs | 29 (28–210) | **25 (24–246)** |
| ├ 사용자 자격증명 발급 userCredMs (π_u, 첫 로그인만) | 0 (0–1,909) | **0 (0–1,914)** |
| ├ CIA 세션 발급 issueMs | 123 (120–246) | **125 (120–248)** |
| ├ 증명 proveMs (pi_cred) | 841 (822–1,412) | **863 (848–1,468)** |
| 서비스 verifyLogin (Groth16 + σ + root) | 35 (34–386) | **36 (33–323)** |
| 재검증 왕복(캐시 π) | 31 (30–37) | **27 (26–31)** |
| 재검증 verifyLogin | 33 (32–35) | **34 (32–34)** |
| /wallet/tx 왕복(mask=0, 캐시 π) | 153 (151–155) | **163 (160–164)** |
| **execute gas (공개 0: mask=0, 캐시 π, N회)** | 402,130 (402,118–402,174) | **415,991 (415,991–416,035)** |
| **execute gas (첫 tx, 계정 배포 별도)** | 419,262 | **433,067** |
| /wallet/tx 왕복(mask=1 + AttrGate.claim, 새 π) | 985 (980–1,006)(V6은 mask=3) | **1,038 (1,028–1,245)**(mask=1 + set) |
| **execute gas (범위+집합: 새 π + claim, N회)** | 444,509 (444,449–444,553)(V6은 범위만, mask=3) | **455,138 (455,094–455,174)**(범위+집합, mask=1+set) |
| **execute gas (범위만: mask=1, set 없음, to=dEaD, N회)** | — (V6에 이 항목 없음) | **421,052 (420,996–421,076)** |
| **execute gas (집합만: mask=0 + set, to=dEaD, N회)** | — (V6에 없음) | **421,436 (421,388–421,460)** |
| 계정 배포 gas (factory.deploy, CREATE2) | 852,198 | **908,232** |
| PiCredVerifier 배포 gas | 833,149 | **873,724** |
| Mode3WalletFactory 배포 gas | 1,425,083 | **1,483,728** |
| RevocationLog 게시 gas (리프 1) | 43,900 | **43,900** |
| RevocationLog 하트비트 gas (리프 0) | 40,285, 40,305, 40,305, 40,285, 40,285 | **40,305, 40,285, 40,285, 40,305, 40,285, 40,305, 40,285, 40,305, 40,285, 40,273** |
| zkey 크기 | 15,433,687 bytes | **16,405,887 bytes** |
| 공개 입력 수 | 23 | **25** |

브리프가 요구한 네 가지 disclosure 변형 — **공개 0** 415,991 / **범위만** 421,052 / **집합만** 421,436 / **범위+집합**
455,138(+ 새 π 생성·`AttrGate.claim` 로직까지 포함된 값이라 나머지 셋과는 "추가 gas"만 단순 비교할 수 없다. 범위+집합은
claim 콜 자체의 `SSTORE`·`require`·`Claimed` 이벤트가 섞여 있다).

주의: V6 "mask=3"과 V7 "mask=1 + set"은 시나리오가 다르다(V6은 선택 공개 마스크 비트 2개 모두 켠 범위 공개, V7은 마스크
비트 0(연령 범위)만 켜고 집합 소속(`set`)을 별도로 얹은 것 — AttrGate v2 정책이 국가는 집합, 나이는 범위로 나눠 요구하기
때문). 두 행을 절대값으로 직접 비교하지 않는다.

**gas 증가분(V6 mask=0 대비 V7 의 각 disclosure-only 변형).**
- 집합만 − V6 mask=0 = 421,436 − 402,130 = **+19,306 gas**.
- 범위만 − V6 mask=0 = 421,052 − 402,130 = **+18,922 gas**.
- V7 mask=0(disclosure 없음) − V6 mask=0 = 415,991 − 402,130 = **+13,861 gas** — "집합 소속"도 "범위 공개"도 켜지 않은
  순수 mask=0 실행조차 V6 대비 오른 것은, V7 검증자가 공개 입력 2개(`set_sel`·`set_root`, 미사용은 `0n`/`0n` 고정값으로
  항상 전달 — `sel = 2` 는 집합 소속을 실제로 쓰는 값)를 추가로 검증하기 때문으로 보인다(추정, 항목별로 분해하지 않음).
- **V7 안에서 범위만·집합만이 서로 얼마나 다른지**: 집합만(421,436) − 범위만(421,052) = **+384 gas** — 집합 소속 검사
  (Poseidon 경로 포함)가 범위 검사보다 근소하게 더 비싸다. 이 차이는 실행 1회 값이라 반복 측정으로 재확인하지 않았다.

이 세 disclosure-only 변형(mask=0/범위만/집합만) 은 모두 "항상 붙는 11워드 꼬리 + AttrGate 호출 없이 컨트랙트가 검증만
하는 execute()" 라 gas 차이가 회로 검증자 쪽 공개 입력 개수·값에서 온다 — calldata 꼬리 자체의 워드 수는 세 경우 모두
같다(11워드, V7 설계 §1).

## 3. 재현성 메모 (bench 스크립트 자체의 플레이키니스)

`bench_mode3_onchain.mjs`의 선택 공개 항목들(범위+집합 + `AttrGate.claim`, 범위만, 집합만)이 지갑 트랜잭션을 여러 번
보내는 동안, 격리 CIA 스택의 하트비트 타이머(이 스크립트가 넘기는 `CIA_HEARTBEAT_BLOCKS=5`·`CIA_HEARTBEAT_POLL_MS=300`)가
자동으로 `publishNow`를 여러 번 돌린다. 스크립트 뒷부분에서 명시적으로 호출하는 `POST /cia/revoke` → `POST /cia/publish`가
이 자동 하트비트와 겹치면 `cia.js`의 "게시는 한 번에 하나만 돈다" 가드(409, `publish already in progress`)에 걸려
스크립트 전체가 예외로 죽는다. Task 9 최초 제출 세션에서 첫 두 번의 실행이 이렇게 실패했다:

```
Error: publish {"error":"publish already in progress"}
    at file:///home/node1phi/Desktop/google-oidc-demo/scripts/bench_mode3_onchain.mjs:147:34
```

그 두 번의 실패는 모두 신규 disclosure-only 항목까지는 에러 없이 통과한 뒤, 그 다음 RevocationLog 게시 단계에서 난
것이었다 — 즉 disclosure-only 항목 자체는 실패한 적이 없다. 그 세션의 재시도 3회, 그리고 Fix round 1 의 재실행(항목
"범위만" 추가 후) 1회 모두 성공했다(총 4/6 성공, 실패 2건은 모두 이 레이스). 이 레이스는 `bench_mode3_onchain.mjs`가
스스로 만든 하트비트 환경과 명시적 게시 호출 사이의 타이밍 문제로 보이며, 이 작업(Task 9)의 범위(측정·문서·spec 정정)
에서는 스크립트나 `cia.js`를 고치지 않았다 — 별도 수정 작업이 필요하면 후속 과제로 남긴다.

## 4. 원본 stdout (Fix round 1 재실행, §1·§2 표와 같은 실행)

```
$ node scripts/bench_pi_cred.mjs pot21_final.ptau
## pi_cred 실측

| 항목 | 값 |
|---|--:|
| 증명 시간 (중앙값, 10회) | 832.8 ms |
| 검증 시간 (중앙값, 10회) | 10.0 ms |
| zkey 크기 | 16.4 MB |
| 공개 입력 수 | 25 |

$ npx snarkjs r1cs info build/mode3/pi_cred.r1cs
[INFO]  snarkJS: Curve: bn-128
[INFO]  snarkJS: # of Wires: 27356
[INFO]  snarkJS: # of Constraints: 27329
[INFO]  snarkJS: # of Private Inputs: 88
[INFO]  snarkJS: # of Public Inputs: 25
[INFO]  snarkJS: # of Labels: 152289
[INFO]  snarkJS: # of Outputs: 0

$ node scripts/bench_mode3_onchain.mjs
## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1059 (1046–4726) |
| ├ 체인 동기화 syncMs | 25 (24–246) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 1914 ms, 이후 재사용) | 0 (0–1914) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 125 (120–248) |
| ├ 증명 proveMs (pi_cred V6) | 863 (848–1468) |
| 서비스 verifyLogin (Groth16 + σ + root) | 36 (33–323) |
| 재검증 왕복(캐시 π) | 27 (26–31) |
| 재검증 verifyLogin | 34 (32–34) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 163 (160–164) |
| execute gas (mask=0, 캐시 π, N회) | 415991 (415991–416035) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 433067 |
| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | 1038 (1028–1245) |
| execute gas (mask=1 + set, 새 π + claim, N회) | 455138 (455094–455174) |
| execute gas (범위만, mask=1, to=dEaD, N회) | 421052 (420996–421076) |
| execute gas (집합만, mask=0 + set, to=dEaD, N회) | 421436 (421388–421460) |
| 계정 배포 gas (factory.deploy, CREATE2) | 908232 |
| PiCredVerifier 배포 gas | 873724 |
| Mode3WalletFactory 배포 gas | 1483728 |
| RevocationLog 게시 gas (리프 1) | 43900 |
| RevocationLog 하트비트 gas (리프 0) | 40305, 40285, 40285, 40305, 40285, 40305, 40285, 40305, 40285, 40273 |
| zkey 크기 | 16405887 bytes |
| 공개 입력 수 | 25 |
```

`pi_cred`의 콘솔 출력에 있는 "pi_cred V6" 문자열(로그인 하위 항목)은 `bench_mode3_onchain.mjs`의 하드코딩된 라벨 텍스트다
(회로가 V6이라는 뜻이 아니라 이 스크립트가 항목 라벨을 V7로 갱신하지 않은 것 — 이번 작업에서 바꾸라는 지시를 받은 줄은
머리 주석·"공개 입력 수" 행·신규 disclosure-only 항목뿐이라 이 라벨은 그대로 뒀다).

## 5. 남은 것

- §1에서 V7의 witness/prove 분리 시간을 못 실었다(스크립트 출력 형식 차이) — 필요하면 `bench_zkp_inventory.mjs` 계열
  스크립트로 다시 잴 것.
- §2의 gas 증가분 분해(호출 데이터 꼬리 vs 회로 검증자 공개 입력 처리 vs `AttrGate` claim 로직)는 완전히는 하지 않았다
  (범위만 vs 집합만의 +384 gas 차이만 확인).
- §3의 하트비트/명시적 게시 레이스는 재현 가능하지만(누적 2/6) 근본 수정은 이 작업 범위 밖이다.
- `POST /api/mode3/revalidate` 는 술어를 다시 증명하지 않는다 — 로그인 때의 술어는 세션 기록에만 남고, 재검증 뒤
  `disclosure` 는 갱신된다(후속: 세션에 `require` 를 기억하고 지갑이 같은 술어로 재증명).
