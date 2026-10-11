# Mode 3 온체인 실측 — V9 등록부(등록부 소속 조건) (2026-10-02)

설계: `docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md`. Task 1–15 로 회로·컨트랙트(`Mode3Log`)·CIA·지갑
에이전트·RP 가 V9 로 이행을 마친 뒤, 이 실측(Task 16)이 제약·증명/검증 시간·온체인 gas·로그인 지연을 다시 잰다.

V9 의 핵심 변화: pi_cred 회로에 **등록부 소속 조건**(`RegistrationCommit()` + `MerkleInclusion(20)`)이 더해지고, 기존
**사용자 자격증명 비멤버십**(`IMTNonMembershipV2(32)`, Cf_u 쪽)은 삭제됐다(세션 Cf_s 쪽 비멤버십은 그대로 남는다). 공개
입력은 25 → 30(`REG_ROOT` 추가, `attrs` 4 → 6 슬롯). `Mode3Log` 컨트랙트가 폐기 트리 root 와 등록부 root 를 한 tx 로
같이 게시한다(`Revoked` + `SlotUpdated` 이벤트, `contracts/Mode3Log.sol`).

**V8 비교값 출처**: 제약·증명/검증 시간은 `results/mode3_session_revocation_20260924.md`(V7→V8 실측), execute·배포·게시
gas 는 `results/mode3_review_fixes_20260925.md`(같은 V8 회로 위에서 컨트랙트 리뷰 수정 반영판, 커밋 `4aa5589`) — 이
저장소에 실제로 남아 있는 가장 가까운 V8 실측이다. 둘 다 이번 작업에서 재실행하지 않았다(기존 결과 파일은 덮어쓰지 않는다).

## 측정 조건

- CPU: AMD Ryzen 9 5950X(16 코어) · Node v22.20.0 · snarkjs(Groth16, BN254)
- 커밋: `c5575a7` · 측정 일시: 2026-10-02 02:07 KST
- hardhat 로컬 노드(:8545, 이 작업을 시작하기 전부터 떠 있던 것 — 새로 띄우거나 끄지 않았다). 온체인 벤치는 그 위에 격리
  CIA + 지갑 에이전트(임시 포트, 임시 상태 파일)를 띄운다 — 개발용 :4100/:5100/:3100 은 건드리지 않는다.
- N=10, 중앙값 (최소–최대). 스크립트: `scripts/bench_pi_cred.mjs pot21_final.ptau`(zkey 는 `build/mode3/pi_cred_final.zkey`
  기존 것을 재사용 — 새로 만들지 않았다), `npx snarkjs r1cs info build/mode3/pi_cred.r1cs`, `node scripts/bench_mode3_onchain.mjs 10`.
- 중앙값은 두 스크립트 모두 `med(a) = [...a].sort((x,y)=>x-y)[Math.floor(a.length/2)]` 로 계산한다 — 짝수 N(=10)에서는
  가운데 두 값 중 **큰 쪽**(upper-middle)을 쓴다. V8 쪽 결과 파일들도 같은 스크립트의 같은 함수로 냈으므로 같은 기준으로
  비교된다.

**측정 방법 메모(재현성)**: 처음에 `bench_pi_cred.mjs` 와 `bench_mode3_onchain.mjs 10` 을 서로 겹쳐(병렬로) 돌렸더니
`bench_pi_cred.mjs` 의 증명 시간이 1,673.0 ms 로 나와 V8(1,191.7 ms) 대비 +40% 로 튀었다 — 두 프로세스가 같은 머신에서
동시에 Groth16 증명을 돌려 CPU 를 다퉜을 가능성이 커서(snarkjs 증명은 코어를 많이 쓴다) 그 측정은 버리고, 두 스크립트를
**겹치지 않게 순차로** 다시 돌렸다. 아래 숫자는 전부 그 격리 재실행 값이다. gas 는 EVM 실행 비용이라 CPU 경합과 무관해서
두 번의 `bench_mode3_onchain.mjs` 실행에서 사실상 같았다(예: execute gas mask=0 캐시 455,971 vs 455,939 — 0.007% 차이,
잡음 범위).

## 1. 회로 — 제약·공개 입력·증명/검증 시간

| 항목 | V8 (2026-09-24) | V9 (이번 실측) | 차이 |
|---|--:|--:|--:|
| R1CS 제약(비선형) | 37,130 | **34,934** | −2,196 |
| Wires | 37,184 | 34,966 | −2,218 |
| Private Inputs | 155 | 131 | −24 |
| 공개 입력 수 | 25 | **30** | +5 |
| 증명 시간(중앙값, N=10) | 1,191.7 ms | **1,271.3 ms** | +79.6 ms (+6.7%) |
| 검증 시간(중앙값, N=10) | 10.0 ms | 11.3 ms | +1.3 ms |
| zkey 크기 | 23,442,451 B | 22,316,319 B | −1,126,132 B |

## 2. execute() gas — 네 가지 공개 변형

| 변형 | V8 (리뷰 수정판, 09-25) | V9 (이번 실측) | 차이 |
|---|--:|--:|--:|
| mask=0, 캐시 π | 417,533 | **455,939** | +38,406 (+9.2%) |
| 범위만(mask=1) | 422,366 | **462,283** | +39,917 (+9.5%) |
| 집합만(mask=0+set) | 422,982 | **462,931** | +39,949 (+9.4%) |
| 범위+집합+claim(새 π) | 456,439 | **497,385** | +40,946 (+9.0%) |
| 첫 tx(mask=0, 계정 배포 tx 는 별도) | 434,665 | 473,027 | +38,362 (+8.8%) |

참고치(이 작업의 브리프가 제공한 값, 이번 실측에서 재확인하지 않음): Task 6 의 hardhat 테스트가 직접 잰 `execute()` gas
504,535 — mask=0 변형의 정합성 참고용. 측정 경로(hardhat 테스트가 컨트랙트를 직접 호출 vs 이 벤치가 지갑 에이전트의 HTTP
경로를 거침)가 달라 위 표와 나란히 놓지 않는다.

## 3. 배포·게시 gas

| 항목 | V8 (리뷰 수정판, 09-25) | V9 (이번 실측) | 차이 |
|---|--:|--:|--:|
| 계정 배포(factory.deploy, CREATE2) | 939,808 | **995,731** | +55,923 (+6.0%) |
| PiCredVerifier 배포 | 874,396 | **976,980** | +102,584 (+11.7%) |
| Mode3WalletFactory 배포 | 1,517,288 | **1,577,919** | +60,631 (+4.0%) |
| Mode3Log 배포¹ | 측정한 적 없음(V8 의 `RevocationLog` 배포 gas 도 어느 결과 파일에도 없다) | **1,104,315** | — |
| 폐기 리프 게시(리프 1개) | 43,856 | **49,771** | +5,915 (+13.5%) |
| 등록부 슬롯 게시(슬롯 1개, `SlotUpdated` 1건) | 해당 없음(V8 에는 등록부가 없다) | **52,480** | V9 신규 |
| 하트비트 게시(리프 0, 슬롯 0) | 40,273–40,305(그 실행에서 9건 관측) | **46,176**(1건 관측) | +5,871(40,305 기준, +14.6%) |

¹ `node scripts/bench_mode3_onchain.mjs 1`(N=1) 로 별도 검증·측정했다 — 배포 gas 는 생성자 인자 값(ciaAddress·빈
root 둘)에 분기하지 않아 결정적이므로 N=10 으로 다시 돌릴 필요가 없다. `lib/mode3_onchain.js` 의 `deployLog()`(벤치
전용 — 실제 스택·테스트는 `tests/helpers/mode3_chain.mjs` 의 `deployMode3Log()` 를 쓴다)로 측정 전용 더미를 하나
배포했고, 빈 폐기 root·빈 등록부 root 는 스택이 `cia.logAddress` 를 처음 띄울 때와 같은 방법(`createRevocationTree().getRoot()`,
`createRegistryTree().root()`)으로 만들었다. 이 더미 주소는 스택 어디에도 연결하지 않았다(§6.3b).

## 4. 로그인 지연 (N=10, 중앙값 (최소–최대), ms)

| 항목 | V9 (이번 실측) |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1,626 (1,580–4,901) |
| ├ 첫 로그인(사용자 자격증명 신규 발급 + 등록부 게시 대기 포함) | **4,901** |
| ├ 체인 동기화 syncMs | 56 (54–510) |
| ├ 사용자 자격증명 발급 userCredMs(첫 로그인 775, 이후 재사용) | 0 (0–775) |
| ├ CIA 세션 발급 issueMs(ZKP 없음, sig_u 검증 + 서명) | 134 (123–260) |
| ├ 증명 proveMs(pi_cred V9, 온체인 벤치 내부) | 1,343 (1,303–2,075) |
| 서비스 verifyLogin(Groth16 + σ + root) | 36 (35–354) |
| 재검증 왕복(캐시 π) | 58 (55–63) |
| 재검증 verifyLogin | 37 (34–40) |

V8 쪽 "첫 로그인" 비교값: `mode3_review_fixes_20260925.md` 의 로그인 전체 왕복 최대값 5,212 ms(그 실행의 userCredMs
최대 1,895 ms + proveMs 포함). V8 에는 등록부가 없어 그 느림은 전부 π_u(사용자 자격증명) 발급 때문이고, V9 의
4,901 ms 는 π_u 발급(775 ms)에 더해 **등록부 게시가 체인에 반영될 때까지 기다리는 구간**이 새로 들어간 것이다
(`mode3_wallet_agent.js` `/wallet/login` 의 `uc.fresh` 분기 — 새 사용자 자격증명을 받으면 그 슬롯이 등록부에 게시될
때까지 최대 30초 폴링한다, 설계 2026-10-01 §8.3). 두 버전은 느린 원인이 구조적으로 달라 표로 나란히 놓지 않고 각주로만
비교한다.

## 5. 해석

- **제약이 준 이유(37,130 → 34,934, −2,196)**: V9 는 `circuits/pi_cred.circom` 에서 사용자 자격증명 Cf_u 의
  비멤버십 증명(`IMTNonMembershipV2(32)`, 깊이 32 트리)을 지운다 — 설계 문서 §5.2 조건 4′의 "사용자 리프 비멤버십은
  삭제"라는 기술과, 실제 회로에 그 컴포넌트 인스턴스가 더는 없고(비멤버십은 세션 쪽 `nmS` 하나만 남음) 일치한다. 대신
  **등록부 소속 조건**(§5.2 조건 9)이 들어간다: `RegistrationCommit()`(`cm = s_u·G_SU + r_u·H` 재계산) +
  `Poseidon(3)` 리프 해시 + `MerkleInclusion(regDepth=20)`(깊이 20 포함 증명). 32단 비멤버십 하나를 20단 포함 증명
  하나와 작은 커밋 재계산으로 바꾼 셈이라 순 제약은 줄었다. `attrs` 가 4 → 6 슬롯으로 늘어난 몫(커밋 항 2개, 범위 술어
  슬롯 2개)은 이미 이 순감소치에 반영돼 있다 — 항목별로 갈라 따로 재지는 않았다. 설계 문서 §5.5 의 "V8 ± 1천" 추정은
  방향(소폭 변화)만 맞혔고 크기(실측 −2,196 vs 추정 거의 0)는 빗나갔다 — 이 실측으로 추정을 대체한다.
- **execute gas 가 느는 이유(mask=0 기준 +38,406, +9.2%)**: 네 변형 모두 비슷한 절대량(+38.4천 ~ +41.0천)이 늘어
  술어 종류와 무관한 **고정 오버헤드**로 보인다. 공개 입력이 25 → 30(+5) 이 된 것이 Groth16 검증자 쪽 비용 대부분을
  설명한다 — EVM 의 `ecMul` 프리컴파일 1회가 6,000 gas, `ecAdd` 1회가 150 gas(EIP-1108)이므로, 공개 입력 5개가
  늘면 선형결합 `vk_x += pub[i]·IC[i]` 항이 5개 늘어 대략 5 × 6,150 ≈ 30,750 gas — 관측된 증가분의 대부분을
  대략 설명한다(정확한 재구성은 아니다). 나머지(약 7천~1만)는 `_checkStatement` 가 `log.regRoot()` 외부 조회를
  하나 더 하는 것(새 저장 슬롯 1개 읽기)과, 서명 꼬리가 10워드(V8, 슬롯 4×2 + mask + set 2)에서 15워드(V9, 슬롯
  6×2 + mask + set 2)로 넓어져 다이제스트 계산·calldata 읽기가 커진 몫으로 보이나, 그 둘을 갈라 따로 재지는 않았다.
- **배포 gas 가 전부 오르는 이유**: `Mode3Wallet`·`Mode3WalletFactory`·`PiCredVerifier` 세 컨트랙트 모두 바이트코드가
  커졌다 — `PiCredVerifier.sol` 은 공개 입력 30개용으로 재생성됐고(IC 포인트 5개 추가), `Mode3Wallet.sol` 은 `regRoot`
  필드·`StaleRegistryRoot` 검사·6슬롯 디스클로저 검사가 늘었다(설계 §6). 팩토리는 `creationCode` 를 품고 있어 같이 오른다.
  `Mode3Log` 자체의 배포 gas(1,104,315)는 네 컨트랙트 중 가장 크다 — root 두 개(`revRoot`·`regRoot`)를 저장하고
  `publish()` 안에서 이벤트 두 종류(`Revoked`·`SlotUpdated`)를 내는 분기까지 포함하는 코드이기 때문으로 보인다. V8 의
  `RevocationLog`(root 하나, 이벤트 하나)와 나란히 둘 값이 없다 — 이번이 이 저장소에서 로그 컨트랙트 배포 gas 를 처음
  잰 것이다(§3 각주 1).
- **등록부 슬롯 게시(52,480 gas)는 V9 신규 항목**이다 — `Mode3Log.publish()` 가 같은 tx 에서 `SlotUpdated` 이벤트를
  하나 더 내는 비용(스토리지 쓰기 1회 + 이벤트 로그)이 더해진 값이고, V8 에는 등록부 자체가 없어 비교 대상이 없다.
  폐기 리프 게시(+13.5%)·하트비트(+14.6%)가 함께 오른 것은 `publish()` 서명이 `regRoot`·`slotIdx`·`slotLeaves` 세
  인자를 더 받게 돼(§4) 모든 게시 tx 의 calldata·다이제스트 계산이 커졌기 때문으로 보인다(항목별 분해는 하지 않았다).

## 6. 측정 방법 — 원본 출력

### 6.1 `npx snarkjs r1cs info build/mode3/pi_cred.r1cs`

```
[INFO]  snarkJS: Curve: bn-128
[INFO]  snarkJS: # of Wires: 34966
[INFO]  snarkJS: # of Constraints: 34934
[INFO]  snarkJS: # of Private Inputs: 131
[INFO]  snarkJS: # of Public Inputs: 30
[INFO]  snarkJS: # of Labels: 194678
[INFO]  snarkJS: # of Outputs: 0
```

### 6.2 `node scripts/bench_pi_cred.mjs pot21_final.ptau` (격리 재실행)

zkey 는 `build/mode3/pi_cred_final.zkey`(2026-10-01 14:14 생성)를 그대로 썼다 — "… zkey 생성" 로그가 찍히지 않아
새로 만들지 않았음을 확인했다.

```
## pi_cred 실측

| 항목 | 값 |
|---|--:|
| 증명 시간 (중앙값, 10회) | 1271.3 ms |
| 검증 시간 (중앙값, 10회) | 11.3 ms |
| zkey 크기 | 22.3 MB |
| 공개 입력 수 | 30 |
```

### 6.3 `node scripts/bench_mode3_onchain.mjs 10` (격리 재실행)

```
## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1626 (1580–4901) |
| ├ 첫 로그인(사용자 자격증명 신규 발급 + 등록부 게시 대기 포함) | 4901 ms |
| ├ 체인 동기화 syncMs | 56 (54–510) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 775 ms, 이후 재사용) | 0 (0–775) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 134 (123–260) |
| ├ 증명 proveMs (pi_cred V9) | 1343 (1303–2075) |
| 서비스 verifyLogin (Groth16 + σ + root) | 36 (35–354) |
| 재검증 왕복(캐시 π) | 58 (55–63) |
| 재검증 verifyLogin | 37 (34–40) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 197 (193–261) |
| execute gas (mask=0, 캐시 π, N회) | 455939 (455915–455983) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 473027 |
| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | 1572 (1522–1763) |
| execute gas (mask=1 + set, 새 π + claim, N회) | 497385 (497349–497417) |
| execute gas (범위만, mask=1, to=dEaD, N회) | 462283 (462239–462319) |
| execute gas (집합만, mask=0 + set, to=dEaD, N회) | 462931 (462887–462943) |
| 계정 배포 gas (factory.deploy, CREATE2) | 995731 |
| PiCredVerifier 배포 gas | 976980 |
| Mode3WalletFactory 배포 gas | 1577919 |
| Mode3Log 등록부 슬롯 게시 gas (슬롯 1개, SlotUpdated 1건) | 52480 |
| Mode3Log 폐기 리프 게시 gas (리프 1개) | 49771 |
| Mode3Log 하트비트 게시 gas (리프 0, 슬롯 0) | 46176 |
| zkey 크기 | 22316319 bytes |
| 공개 입력 수 | 30 |
```

실행 뒤 `ps aux` 로 `cia.js`·`mode3_wallet_agent.js` 잔여 프로세스가 없음을 확인했고, hardhat 노드(:8545)는 이
작업을 시작하기 전과 같은 프로세스로 계속 떠 있다(블록 번호만 진행했다 — 이 작업이 새로 띄우거나 끈 적 없다).

### 6.3b `node scripts/bench_mode3_onchain.mjs 1` (N=1, Mode3Log 배포 gas 전용 검증 — 리뷰 Important 수정)

Mode3Log 배포 gas 행(§3)을 추가하려고 스크립트에 측정 전용 더미 배포를 넣은 뒤(스택의 `cia.logAddress` 는 건드리지
않는다) N=1 로 한 번 더 돌려 확인했다. 다른 행은 N=10 재실행 없이 §6.3 의 값을 그대로 쓴다(배포 gas 는 결정적이라
N=1 과 N=10 에서 같은 값이어야 하고, 실제로 아래 값들이 §6.3 의 N=10 값과 잡음 범위 안에서 일치한다).

```
| 계정 배포 gas (factory.deploy, CREATE2) | 995731 |
| PiCredVerifier 배포 gas | 976980 |
| Mode3WalletFactory 배포 gas | 1577919 |
| Mode3Log 배포 gas | 1104315 |
| Mode3Log 등록부 슬롯 게시 gas (슬롯 1개, SlotUpdated 1건) | 52480 |
| Mode3Log 폐기 리프 게시 gas (리프 1개) | 49763 |
| Mode3Log 하트비트 게시 gas (리프 0, 슬롯 0) | 46156 |
```

실행 뒤 `ps aux` 로 `cia.js`·`mode3_wallet_agent.js` 잔여 프로세스가 없음을, hardhat 노드(:8545)는 이 작업 시작 전과
같은 프로세스로 계속 떠 있음을(블록 번호만 진행) 다시 확인했다.

### 6.4 버려진 1차(병렬) 실행값 — 참고용, 위 표에는 쓰지 않음

| 항목 | 1차(병렬, 버림) | 2차(격리, 채택) |
|---|--:|--:|
| `bench_pi_cred.mjs` 증명 시간(중앙값) | 1673.0 ms | 1271.3 ms |
| `bench_pi_cred.mjs` 검증 시간(중앙값) | 13.0 ms | 11.3 ms |
| 로그인 전체 왕복 | 2002 (1589–4896) | 1626 (1580–4901) |
| 첫 로그인 | 4896 ms | 4901 ms |
| 온체인 벤치 내부 proveMs(중앙값) | 1655 (1328–2027) | 1343 (1303–2075) |
| execute gas (mask=0, 캐시 π) | 455971 | 455939 |

gas 값은 두 실행에서 사실상 같고(결정적 EVM 비용이라 CPU 경합과 무관), 지갑 프로세스 안에서 재는 시간값(증명 시간·
proveMs·로그인 전체 왕복)만 1차가 전반적으로 더 높게 나왔다 — "첫 로그인" 한 값만은 공교롭게 비슷했다(두 컨트랙트
배포가 선행돼 시간이 흐른 뒤라 오염 구간을 비켜 간 것으로 보인다).
