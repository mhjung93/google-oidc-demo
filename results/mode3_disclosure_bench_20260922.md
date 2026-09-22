# Mode 3 선택 공개(V6) 실측 — 2026-09-22

설계: `docs/superpowers/specs/2026-09-22-mode3-selective-disclosure-design.md`. V5(자격증명 이중 구조, `results/zkp_inventory_20260921.md`)
대비 회로 V6(선택 공개: `disc_mask`·`disc_lo[4]`·`disc_hi[4]` 공개 입력 9개 추가, π_u V2: 속성 4개가 AA 기록값으로 공개)의 비용을 잰다.

측정 환경: AMD Ryzen 9 5950X(16코어), Node v22.20.0, snarkjs(Groth16, BN254), hardhat 인프로세스/로컬 노드(:8545). N=10, 중앙값
(최소–최대). 스크립트: `node scripts/bench_zkp_inventory.mjs 10`, `node scripts/bench_mode3_onchain.mjs 10`(격리 CIA·지갑 에이전트
스택, `tests/helpers/isolated_mode3_stack.mjs`).

## 1. 회로 제약과 ZKP 시간

| 항목 | V5 (2026-09-21) | V6 (2026-09-22, 이번 실측) |
|---|--:|--:|
| pi_cred(π_rp) R1CS 제약 | 26,601 | **25,369** (`npx snarkjs r1cs info build/mode3/pi_cred.r1cs`) |
| pi_cred 공개 입력 | 14 | **23** |
| pi_cred witness+prove (ms, 중앙값) | 859.6 (840.3–1,280.3) | **809.0 (798.6–1,209.9)** |
| pi_cred verify (ms, 중앙값) | 11.5 (10.5–16.6) | **10.7 (7.1–12.6)** |
| π_u prove (ms, 중앙값) | 121.9 (120.1–333.8) | **79.7 (79.1–295.0)** (V2, 공개 입력 uid+attrs4+C_u_pt+cm_u) |
| π_u verify (ms, 중앙값) | 140.5 (138.2–144.4) | **98.7 (97.5–100.2)** |

V6 은 제약이 오히려 **줄었다**(26,601 → 25,369, −1,232). 선택 공개 검사(범위 8개 + Num2Bits(64)×4) 가 늘었지만, 이번 회로 정리에서
다른 부분이 더 줄어든 결과다(정확한 항목별 증감은 회로 diff 로 추적하지 않았음 — 총량만 확인). π_u V2 는 prove/verify 모두 V5 보다
빠르다(스펙 §3.5 예상대로 지수승이 줄어든 효과 — attrs 항이 AA 쪽에서 빠지므로 지갑 쪽 스칼라곱이 감소).

## 2. 로그인·공개 트랜잭션 왕복 (지갑 HTTP, N=10)

| 항목 | V5 (2026-09-21, 참고) | V6 (2026-09-22, 이번 실측) |
|---|--:|--:|
| 로그인 전체 왕복(발급+증명) | 1,073 ms | **1,054 (1,023–4,710) ms** |
| CIA 세션 발급 issueMs | 124 ms | **124 (120–247) ms** |
| /wallet/tx 왕복, mask=0(캐시 π) | — | **151 (149–154) ms** |
| /wallet/tx 왕복, mask=3(새 π + `AttrGate.claim`) | — | **1,000 (979–1,043) ms** — 새 π 생성(pi_cred ≈ 0.8 s)이 대부분 |

로그인 왕복의 최댓값(4,710 ms)은 N 회 중 첫 회에서 사용자 자격증명(π_u, 발급 ≈ 1.9 s)까지 새로 받은 경우다(이후 재사용, `userCredMs=0`).
mask=3 왕복은 반복마다 disclosure(discKey)를 바꿔(슬롯 0 의 상한을 1990→1999 로 증가) 캐시를 피하고 매번 새 π 를 만들게 했다 —
`AttrGate.claimed` 매핑이 지갑 주소당 한 번뿐이라 반복마다 새 `AttrGate` 도 배포했다(그 배포 가스는 표에 넣지 않는다).

## 3. 온체인 가스 (N=10)

| 항목 | V5 (2026-09-21, 참고) | V6 (2026-09-22, 이번 실측) |
|---|--:|--:|
| `execute` gas, 캐시 π (mask=0) | 339,321 | **402,079 (402,035–402,091)** |
| `execute` gas, 첫 tx(계정 배포 별도) | 356,453 | **419,135** |
| `execute` gas, mask=3(새 π) + `AttrGate.claim` | — | **444,973 (444,881–444,997)** |
| `RevocationLog` 게시(리프 1) | 43,888 | 43,888 (동일 — 회로 변경과 무관) |
| `RevocationLog` 하트비트(리프 0) | 40,305 | 40,285–40,305 (동일) |

**검증자 gas 차이(공개 입력 14 → 23).** mask=0 캐시 π 기준 402,079 − 339,321 = **+62,758 gas**. 별도로 컨트랙트 단위 테스트
(`npx hardhat test test/Mode3Wallet.test.mjs`, mask=0, 이번 실행 실측)에서도 450,675 − 387,961 = **+62,714 gas** 로 거의 같은
증가폭이 나온다(두 측정의 절대값 차이는 `to`·`value` 등 시나리오 차이 때문이지만, 공개 입력 9개 추가에 따른 증가분은 두 갈래
측정이 일치한다. 컨트랙트 테스트 gas 는 π 바이트 크기에 따라 실행마다 수십 gas 잡음이 있다 — 다른 실행에서 450,631 관측).

mask=3(선택 공개 + `AttrGate.claim`) 오버헤드는 mask=0 대비 444,973 − 402,079 = **+42,894 gas**(호출 데이터 꼬리 9워드 부착,
`Disclosure` 이벤트, `AttrGate.claim` 자체의 `SSTORE`·`require` 를 합친 값이며 항목별로 분해하지는 않았다).

## 4. 원본 stdout

```
$ node scripts/bench_zkp_inventory.mjs 10
## ZKP 실측 (N=10, ms 중앙값 (최소–최대), AMD Ryzen 9 5950X, Node v22.20.0, snarkjs)

| 증명 | witness | prove | witness+prove | verify | 증명 크기(JSON B) | 공개 입력 | zkey(B) | vkey(B) | wasm(B) |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| π_u V2 (Σ, Mode 3 사용자 자격증명, 속성 공개) | - | 79.7 (79.1–295.0) | 79.7 (79.1–295.0) | 98.7 (97.5–100.2) | 691 | 7 | - | - | - |
| pi_cred (Mode 3 V6) | 202.9 (196.8–216.8) | 608.6 (594.4–993.1) | 809.0 (798.6–1209.9) | 10.7 (7.1–12.6) | 722 | 23 | 15433687 | 6948 | 4712692 |

(pi_ins_sess·pi_ins_acct·pi_uid 행은 Mode 2 몫이라 이 문서에서 생략 — 전체는 스크립트 재실행 참고)

$ node scripts/bench_mode3_onchain.mjs 10
## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1054 (1023–4710) |
| ├ 체인 동기화 syncMs | 29 (28–213) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 1897 ms, 이후 재사용) | 0 (0–1897) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 124 (120–247) |
| ├ 증명 proveMs (pi_cred V6) | 856 (826–1519) |
| 서비스 verifyLogin (Groth16 + σ + root) | 35 (32–328) |
| 재검증 왕복(캐시 π) | 31 (29–35) |
| 재검증 verifyLogin | 32 (31–33) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 151 (149–154) |
| execute gas (mask=0, 캐시 π, N회) | 402079 (402035–402091) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 419135 |
| /wallet/tx 왕복(mask=3, 새 π + AttrGate.claim, N회) | 1000 (979–1043) |
| execute gas (mask=3, 새 π + claim, N회) | 444973 (444881–444997) |
| 계정 배포 gas (factory.deploy, CREATE2) | 861813 |
| PiCredVerifier 배포 gas | 833149 |
| Mode3WalletFactory 배포 gas | 1434080 |
| RevocationLog 게시 gas (리프 1) | 43888 |
| RevocationLog 하트비트 gas (리프 0) | 40285, 40305, 40305, 40305, 40305 |
| zkey 크기 | 15433687 bytes |
| 공개 입력 수 | 23 |
```

## 5. 남은 것

- π_rp 제약이 V5 → V6 에서 줄어든 정확한 원인(선택 공개 검사 추가분을 상쇄한 다른 감소)은 회로 diff 로 추적하지 않았다 — 논문에
  싣기 전에 항목별 제약 분해가 필요하면 별도로 확인할 것.
- mask=3 오버헤드(+42,894 gas)를 "호출 데이터 꼬리 전달" vs "`AttrGate.claim` 자체 로직"으로 분해하지 않았다.
