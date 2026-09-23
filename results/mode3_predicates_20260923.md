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

## 1. 회로 제약·ZKP 시간 (pi_cred / π_rp)

| 항목 | V6 (2026-09-22) | V7 (2026-09-23, 이번 실측) |
|---|--:|--:|
| R1CS 제약 | 25,369 | **27,329** (`npx snarkjs r1cs info`, +1,960) |
| 공개 입력 수 | 23 | **25** (`set_sel`·`set_root` 추가) |
| Wires | — | 27,356 |
| Private Inputs | — | 88 |
| 증명 시간 (중앙값, N=10) | 608.6 (594.4–993.1) ms (witness 제외) / 809.0 (798.6–1,209.9) ms (witness+prove) | **833.2 ms**(witness+prove, `bench_pi_cred.mjs` 는 두 단계를 분리해 찍지 않음) |
| 검증 시간 (중앙값, N=10) | 10.7 (7.1–12.6) ms | **9.7 ms** |
| zkey 크기 | 15,433,687 bytes | **16,405,887 bytes** |

V6 열은 `results/mode3_disclosure_bench_20260922.md` §1·§4 원본 stdout에서 그대로 옮겼다. V7의 witness/prove 분리값은 이번
스크립트 출력에 없어 합산값만 실었다(`bench_pi_cred.mjs`의 표 형식이 V6 당시의 `bench_zkp_inventory.mjs`와 달라 항목이 정확히
1:1 대응하지 않는다 — 열을 억지로 맞추지 않았다).

## 2. 온체인 실측 (N=10, `bench_mode3_onchain.mjs`)

3회 반복 실행 결과는 잡음 범위 안에서 거의 동일했다(gas 값은 완전히 안정, ms 값은 수 ms~수십 ms 편차). 아래 표는 3회 중
마지막(3회차) 실행값을 대표로 싣는다 — 3회 모두 성공했다.

| 항목 | V6 (2026-09-22, 재실측판) | V7 (2026-09-23, 이번 실측) |
|---|--:|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1,037 (1,020–4,608) ms | **1,057 (1,048–4,768) ms** |
| ├ 체인 동기화 syncMs | 29 (28–210) | **25 (24–249)** |
| ├ 사용자 자격증명 발급 userCredMs (π_u, 첫 로그인만) | 0 (0–1,909) | **0 (0–1,899)** |
| ├ CIA 세션 발급 issueMs | 123 (120–246) | **124 (119–247)** |
| ├ 증명 proveMs (pi_cred) | 841 (822–1,412) | **865 (853–1,535)** |
| 서비스 verifyLogin (Groth16 + σ + root) | 35 (34–386) | **35 (33–309)** |
| 재검증 왕복(캐시 π) | 31 (30–37) | **27 (26–31)** |
| 재검증 verifyLogin | 33 (32–35) | **33 (32–34)** |
| /wallet/tx 왕복(mask=0, 캐시 π) | 153 (151–155) | **162 (159–167)** |
| **execute gas (mask=0, 캐시 π, N회)** | 402,130 (402,118–402,174) | **416,047 (416,003–416,059)** |
| **execute gas (첫 tx, 계정 배포 별도)** | 419,262 | **433,147** |
| /wallet/tx 왕복(mask=1 + AttrGate.claim, 새 π) | 985 (980–1,006)(V6은 mask=3) | **1,047 (1,023–1,238)**(mask=1 + set) |
| **execute gas (범위+집합, 새 π + claim, N회)** | 444,509 (444,449–444,553)(V6은 범위만, mask=3) | **455,142 (455,118–455,186)**(범위+집합, mask=1+set) |
| **execute gas (집합만, mask=0 + set, to=dEaD, N회)** | — (V6에 없음) | **421,472 (421,416–421,484)** |
| 계정 배포 gas (factory.deploy, CREATE2) | 852,198 | **908,220** |
| PiCredVerifier 배포 gas | 833,149 | **873,724** |
| Mode3WalletFactory 배포 gas | 1,425,083 | **1,483,752** |
| RevocationLog 게시 gas (리프 1) | 43,900 | **43,868** |
| RevocationLog 하트비트 gas (리프 0) | 40,285, 40,305, 40,305, 40,285, 40,285 | **40,305, 40,273, 40,285, 40,305, 40,273, 40,285, 40,273, 40,285** |
| zkey 크기 | 15,433,687 bytes | **16,405,887 bytes** |
| 공개 입력 수 | 23 | **25** |

주의: V6 "mask=3"과 V7 "mask=1 + set"은 시나리오가 다르다(V6은 선택 공개 마스크 비트 2개 모두 켠 범위 공개, V7은 마스크
비트 0(연령 범위)만 켜고 집합 소속(`set`)을 별도로 얹은 것 — AttrGate v2 정책이 국가는 집합, 나이는 범위로 나눠 요구하기
때문). 두 행을 절대값으로 직접 비교하지 않는다.

**gas 증가분(V6 mask=0 대비 V7 mask=0+set, 즉 신규 6번째 항목 "집합만").** 421,472 − 402,130(V6 mask=0, 재실측판) =
**+19,342 gas** — 이것이 `set_sel`·`set_root` 공개 입력 2개(호출 데이터 꼬리 2워드) + 회로 검증자 쪽 공개 입력 2개 증가분의
근사 비용이다(V6 mask=0은 "항상 붙는 9워드 꼬리"만 있었고, V7의 "집합만" 행은 그 위에 `set` 슬롯을 얹은 것이라 완전히
분해된 값은 아니다 — 항목별 분해는 하지 않았다).

**동일 회로 버전 내 mask=0 자체 증가(V6 mask=0 402,130 → V7 mask=0 416,047, +13,917 gas)** 도 존재한다 — 이는 "집합 소속"을
켜지 않은 순수 mask=0 실행에서도 V7 검증자가 공개 입력 2개(`set_sel=2`·`set_root=0`, 미사용 상태로 항상 전달)를 추가로
검증하기 때문으로 보인다(항목별로 분해하지 않음, 추정).

## 3. 재현성 메모 (bench 스크립트 자체의 플레이키니스)

`bench_mode3_onchain.mjs`의 항목 5·6(선택 공개 + `AttrGate.claim`, 집합만)이 지갑 트랜잭션을 여러 번 보내는 동안, 격리
CIA 스택의 하트비트 타이머(이 스크립트가 넘기는 `CIA_HEARTBEAT_BLOCKS=5`·`CIA_HEARTBEAT_POLL_MS=300`)가 자동으로
`publishNow`를 여러 번 돌린다. 스크립트 뒷부분에서 명시적으로 호출하는 `POST /cia/revoke` → `POST /cia/publish`가 이
자동 하트비트와 겹치면 `cia.js`의 "게시는 한 번에 하나만 돈다" 가드(409, `publish already in progress`)에 걸려 스크립트
전체가 예외로 죽는다. 실제로 이번 세션에서 첫 두 번의 실행이 이렇게 실패했다:

```
Error: publish {"error":"publish already in progress"}
    at file:///home/node1phi/Desktop/google-oidc-demo/scripts/bench_mode3_onchain.mjs:147:34
```

이 두 번의 실패는 모두 항목 6(집합만, `dEaD` 전송)까지는 에러 없이 통과한 뒤, 그 다음 RevocationLog 게시 단계에서
난 것이다 — 즉 신규 6번째 항목 자체는 두 번 다 정상 동작했다. 이후 재시도 3회는 모두 성공했다(§2 표는 그 중 3회차).
이 레이스는 `bench_mode3_onchain.mjs`가 스스로 만든 하트비트 환경과 명시적 게시 호출 사이의 타이밍 문제로 보이며, 이
작업(Task 9)의 범위(측정·문서·spec 정정)에서는 스크립트나 `cia.js`를 고치지 않았다 — 별도 수정 작업이 필요하면 후속
과제로 남긴다.

## 4. 원본 stdout (성공한 3회차 실행)

```
$ node scripts/bench_pi_cred.mjs pot21_final.ptau
## pi_cred 실측

| 항목 | 값 |
|---|--:|
| 증명 시간 (중앙값, 10회) | 831.8 ms |
| 검증 시간 (중앙값, 10회) | 10.3 ms |
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

$ node scripts/bench_mode3_onchain.mjs   # 3회차(성공)
## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1057 (1048–4768) |
| ├ 체인 동기화 syncMs | 25 (24–249) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 1899 ms, 이후 재사용) | 0 (0–1899) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 124 (119–247) |
| ├ 증명 proveMs (pi_cred V6) | 865 (853–1535) |
| 서비스 verifyLogin (Groth16 + σ + root) | 35 (33–309) |
| 재검증 왕복(캐시 π) | 27 (26–31) |
| 재검증 verifyLogin | 33 (32–34) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 162 (159–167) |
| execute gas (mask=0, 캐시 π, N회) | 416047 (416003–416059) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 433147 |
| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | 1047 (1023–1238) |
| execute gas (mask=1 + set, 새 π + claim, N회) | 455142 (455118–455186) |
| execute gas (집합만, mask=0 + set, to=dEaD, N회) | 421472 (421416–421484) |
| 계정 배포 gas (factory.deploy, CREATE2) | 908220 |
| PiCredVerifier 배포 gas | 873724 |
| Mode3WalletFactory 배포 gas | 1483752 |
| RevocationLog 게시 gas (리프 1) | 43868 |
| RevocationLog 하트비트 gas (리프 0) | 40305, 40273, 40285, 40305, 40273, 40285, 40273, 40285 |
| zkey 크기 | 16405887 bytes |
| 공개 입력 수 | 25 |
```

`pi_cred`의 콘솔 출력에 있는 "pi_cred V6" 문자열(로그인 하위 항목)은 `bench_mode3_onchain.mjs`의 하드코딩된 라벨 텍스트다
(회로가 V6이라는 뜻이 아니라 이 스크립트가 아직 항목 라벨을 V7로 갱신하지 않았다 — 이번 작업에서 바꾸라는 지시를 받은
줄은 머리 주석과 "공개 입력 수" 행뿐이라 이 라벨은 그대로 뒀다).

## 5. 남은 것

- §1에서 V7의 witness/prove 분리 시간을 못 실었다(스크립트 출력 형식 차이) — 필요하면 `bench_zkp_inventory.mjs` 계열
  스크립트로 다시 잴 것.
- §2의 gas 증가분 분해(호출 데이터 꼬리 vs 회로 검증자 공개 입력 처리 vs `AttrGate` claim 로직)는 하지 않았다.
- §3의 하트비트/명시적 게시 레이스는 재현 가능하지만(2/5) 근본 수정은 이 작업 범위 밖이다.
