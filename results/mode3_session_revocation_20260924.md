# Mode 3 세션 폐기(V8, RCL 세션 리프 + 비멤버십 2개) 실측 — 2026-09-24

설계: `docs/superpowers/specs/2026-09-24-mode3-session-revocation-design.md`. V7(집합 소속 술어,
`results/mode3_predicates_20260923.md`) 대비 회로 V8(세션 리프 `Poseidon(5, Cf_s)` 의 두 번째 비멤버십 ④′ 추가, **공개 입력은
25개 그대로**)의 비용을 잰다.

측정 환경: AMD Ryzen 9 5950X(16코어), Node v22.20.0, snarkjs(Groth16, BN254), hardhat 로컬 노드(:8545, 이 작업 세션에서
기동·측정 후 종료). N=10, 중앙값 (최소–최대). 명령:

```
node scripts/bench_pi_cred.mjs pot21_final.ptau
npx snarkjs r1cs info build/mode3/pi_cred.r1cs      # 제약·공개 입력 수 확인용(bench_pi_cred.mjs 는 제약 수를 안 찍음)
node scripts/bench_mode3_onchain.mjs
```

`build/mode3/pi_cred_final.zkey` 는 이미 V8 회로로 만들어져 있었다(Task 2 에서 `scripts/build_mode3_circuit.sh` 로 재생성,
2026-09-24 16:43) — `bench_pi_cred.mjs` 는 zkey 가 있으면 재사용만 하고(셋업은 없을 때만), 이 측정에서 새로 만들지 않았다.
이 작업에서 `scripts/build_mode3_circuit.sh` 나 `npm run zk:*` 는 실행하지 않았다.

아래 §1·§2 의 숫자는 모두 **같은 실행 1회**(§3 의 원본 stdout)에서 그대로 옮긴 값이다. V7 열은
`results/mode3_predicates_20260923.md` §1·§2 에서 옮겼다.

## 1. 회로 제약·ZKP 시간 (pi_cred / π_rp)

| 항목 | V7 (2026-09-23) | V8 (2026-09-24, 이번 실측) |
|---|--:|--:|
| R1CS 제약 | 27,329 | **37,130** (`npx snarkjs r1cs info`, +9,801) |
| 공개 입력 수 | 25 | **25** (불변 — 서비스·컨트랙트 인터페이스 무변경) |
| Wires | 27,356 | **37,184** |
| Private Inputs | 88 | **155** (+67 — 세션 비멤버십 증인 `s_*`: `s_lowValue`·`s_lowNextIndex`·`s_lowNextValue` + `s_pathElements[32]`·`s_pathIndices[32]`) |
| 증명 시간 (중앙값, N=10, witness+prove) | 832.8 ms | **1,191.7 ms** (+358.9 ms, ×1.43) |
| 검증 시간 (중앙값, N=10) | 10.0 ms | **10.0 ms** (불변 — 공개 입력 수가 같다) |
| zkey 크기 | 16,405,887 bytes | **23,442,451 bytes** |

제약이 +9,801 인 것은 `IMTNonMembershipV2(32)` 한 벌(경로 32단 Poseidon + 비교)과 세션 리프용 `Poseidon(2)` 가 통째로 더
들어갔기 때문이다. 검증 시간·검증자 가스가 그대로인 것은 Groth16 검증 비용이 **공개 입력 수**에만 달려 있고 그 수가 25로
불변이기 때문이다(아래 §2).

## 2. 온체인 실측 (N=10, `bench_mode3_onchain.mjs`)

| 항목 | V7 (2026-09-23) | V8 (2026-09-24, 이번 실측) |
|---|--:|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1,059 (1,046–4,726) ms | **1,475 (1,434–5,221) ms** |
| ├ 체인 동기화 syncMs | 25 (24–246) | **25 (23–254)** |
| ├ 사용자 자격증명 발급 userCredMs (π_u, 첫 로그인만) | 0 (0–1,914) | **0 (0–1,911)** |
| ├ CIA 세션 발급 issueMs | 125 (120–248) | **127 (124–249)** |
| ├ 증명 proveMs (pi_cred) | 863 (848–1,468) | **1,237 (1,199–1,911)** |
| 서비스 verifyLogin (Groth16 + σ + root) | 36 (33–323) | **36 (32–349)** |
| 재검증 왕복(캐시 π) | 27 (26–31) | **27 (26–31)** |
| 재검증 verifyLogin | 34 (32–34) | **33 (32–35)** |
| /wallet/tx 왕복(mask=0, 캐시 π) | 163 (160–164) | **162 (160–165)** |
| **execute gas (공개 0: mask=0, 캐시 π, N회)** | 415,991 (415,991–416,035) | **416,015 (416,003–416,059)** |
| **execute gas (첫 tx, 계정 배포 별도)** | 433,067 | **433,135** |
| /wallet/tx 왕복(mask=1 + set, 새 π + `AttrGate.claim`) | 1,038 (1,028–1,245) | **1,398 (1,383–1,589)** |
| **execute gas (범위+집합: 새 π + claim, N회)** | 455,138 (455,094–455,174) | **455,162 (455,142–455,174)** |
| **execute gas (범위만: mask=1, set 없음, to=dEaD, N회)** | 421,052 (420,996–421,076) | **421,076 (421,020–421,100)** |
| **execute gas (집합만: mask=0 + set, to=dEaD, N회)** | 421,436 (421,388–421,460) | **421,428 (421,368–421,484)** |
| 계정 배포 gas (factory.deploy, CREATE2) | 908,232 | **908,232** |
| PiCredVerifier 배포 gas | 873,724 | **874,396** |
| Mode3WalletFactory 배포 gas | 1,483,728 | **1,483,740** |
| RevocationLog 게시 gas (리프 1) | 43,900 | **43,880** |
| RevocationLog 하트비트 gas (리프 0) | 40,305, 40,285, … (10회) | **40,305, 40,305, 40,285, 40,285, 40,285, 40,285, 40,293, 40,293, 40,293, 40,293** |
| zkey 크기 | 16,405,887 bytes | **23,442,451 bytes** |
| 공개 입력 수 | 25 | **25** |

**읽는 법.**

- **가스는 사실상 불변이다.** `execute` 네 변형 모두 V7 대비 −8 ~ +24 gas 로, 같은 판을 여러 번 잰 잡음 범위(V7 판에서도
  mask=0 실행값이 415,979~416,059 사이로 흔들렸다)와 구분되지 않는다. 회로 제약이 36% 늘었어도 Groth16 검증자 코드는
  공개 입력 25개에 대한 같은 페어링 검사라 온체인 비용이 안 오른다 — 세션 폐기를 위해 서비스·컨트랙트가 치르는 가스는 없다.
  `PiCredVerifier` 배포 gas 가 +672 인 것은 검증자 컨트랙트의 상수(검증키 원소)가 바뀐 것뿐이다.
- **비용은 증명자(지갑)가 낸다.** 증명 시간이 832.8 → 1,191.7 ms(+43%)이고, 로그인 왕복도 1,059 → 1,475 ms 로 그만큼
  늘었다(다른 하위 항목 syncMs·issueMs·verifyLogin 은 그대로). 캐시 π 를 쓰는 재검증(27 ms)·`/wallet/tx`(162 ms)는
  증명을 새로 만들지 않으므로 V7 과 같다.
- zkey 가 16.4 → 23.4 MB 로 커졌다 — 지갑이 들고 있어야 할 파일 크기이고, 배포·복사할 `build/mode3/` 가 그만큼 커진다.
- `RevocationLog` 게시 gas 의 ±20 차이는 리프 값(바이트 0 의 개수)에 따른 calldata 비용 차이다. 하트비트(리프 0) gas 가
  40,273~40,305 사이에서 흔들리는 것도 같은 이유(epoch 값의 바이트)이고 V7 판과 같은 범위다.

## 3. 원본 stdout (§1·§2 표와 같은 실행 1회)

```
$ node scripts/bench_pi_cred.mjs pot21_final.ptau

## pi_cred 실측

| 항목 | 값 |
|---|--:|
| 증명 시간 (중앙값, 10회) | 1191.7 ms |
| 검증 시간 (중앙값, 10회) | 10.0 ms |
| zkey 크기 | 23.4 MB |
| 공개 입력 수 | 25 |

$ npx snarkjs r1cs info build/mode3/pi_cred.r1cs
[INFO]  snarkJS: Curve: bn-128
[INFO]  snarkJS: # of Wires: 37184
[INFO]  snarkJS: # of Constraints: 37130
[INFO]  snarkJS: # of Private Inputs: 155
[INFO]  snarkJS: # of Public Inputs: 25
[INFO]  snarkJS: # of Labels: 181530
[INFO]  snarkJS: # of Outputs: 0

$ node scripts/bench_mode3_onchain.mjs

## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1475 (1434–5221) |
| ├ 체인 동기화 syncMs | 25 (23–254) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 1911 ms, 이후 재사용) | 0 (0–1911) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 127 (124–249) |
| ├ 증명 proveMs (pi_cred V7) | 1237 (1199–1911) |
| 서비스 verifyLogin (Groth16 + σ + root) | 36 (32–349) |
| 재검증 왕복(캐시 π) | 27 (26–31) |
| 재검증 verifyLogin | 33 (32–35) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 162 (160–165) |
| execute gas (mask=0, 캐시 π, N회) | 416015 (416003–416059) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 433135 |
| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | 1398 (1383–1589) |
| execute gas (mask=1 + set, 새 π + claim, N회) | 455162 (455142–455174) |
| execute gas (범위만, mask=1, to=dEaD, N회) | 421076 (421020–421100) |
| execute gas (집합만, mask=0 + set, to=dEaD, N회) | 421428 (421368–421484) |
| 계정 배포 gas (factory.deploy, CREATE2) | 908232 |
| PiCredVerifier 배포 gas | 874396 |
| Mode3WalletFactory 배포 gas | 1483740 |
| RevocationLog 게시 gas (리프 1) | 43880 |
| RevocationLog 하트비트 gas (리프 0) | 40305, 40305, 40285, 40285, 40285, 40285, 40293, 40293, 40293, 40293 |
| zkey 크기 | 23442451 bytes |
| 공개 입력 수 | 25 |
```

출력의 "pi_cred V7" 라벨은 `bench_mode3_onchain.mjs` 의 하드코딩된 항목 이름이다(회로가 V7 이라는 뜻이 아니다 — V7 판
측정에서 "V6" 라벨이 남아 있던 것과 같은 자리다. 이번 작업에서도 스크립트는 고치지 않았다).

## 4. 남은 것 / 재현성 메모

- 이번 실행은 V7 판 §3 에 적힌 하트비트·명시적 게시 레이스(`publish already in progress`) 없이 **첫 시도에 성공**했다
  (1/1). 그 레이스는 여전히 스크립트에 남아 있다 — 재현되면 재실행한다.
- 세션 폐기 자체의 비용(`POST /cia/revoke scope=session` 처리, 리프 1개 추가 게시)은 따로 재지 않았다. 게시 tx 는 리프
  개수에 비례하고 그 단가는 위 "RevocationLog 게시 gas (리프 1)" 43,880 이다 — 세션 리프도 사용자 리프와 같은 트리·같은
  형식이라 단가가 같다.
- `bench_pi_cred.mjs` 는 witness 생성과 prove 를 나눠 찍지 않는다(V7 판과 같은 한계) — 표의 증명 시간은 합산값이다.
- 트리 성장: 폐기된 세션 리프는 만료 뒤에도 트리에 남는다(append-only). 재기준화는 후속이라 이번 측정에는 그 영향이 없다
  (설계 §6, `docs/MODE3_DEMO.md` "세션 폐기 (V8)" 한계).
