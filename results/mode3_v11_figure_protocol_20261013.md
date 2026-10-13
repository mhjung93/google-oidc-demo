# Mode 3 V11 실측 — 그림(2026-10-12 Overall Flow) 프로토콜 판 올리기

설계: `docs/superpowers/specs/2026-10-12-mode3-v11-figure-protocol-design.md` §8(비용). 이 파일이 그 표의 "V11 실측" 열의 근거다.

## 측정 조건

- CPU: AMD Ryzen 9 5950X(16 코어) · Node v22.20.0 · snarkjs(Groth16, BN254) — `/proc/cpuinfo`·`node -v` 로 확인.
- 커밋(작업 시작): `6ec83b7`. 작업 트리는 Task 1~11(V11 구현)이 이미 반영된 상태이고 아직 커밋되지 않았다 — 실측은
  이 커밋 로그에는 없는, 작업 트리의 현재 코드를 대상으로 했다.
- 측정 일시: 2026-10-13 03:42~04:10 KST(각 스크립트 실행 시각, `date` 실행값 — 아래 각 절에 적는다).
- hardhat 로컬 노드(:8545, 이 작업을 시작하기 전부터 떠 있던 것 — 새로 띄우거나 끄지 않았다). 온체인 벤치는 그 위에
  격리 CIA + 지갑 에이전트(임시 포트, 임시 상태 파일)를 띄운다 — 개발용 :4100/:5100/:3100 은 건드리지 않는다.
- `build/mode3/`의 `pi_cred_final.zkey`·`pi_idp_final.zkey` 등은 이미 만들어져 있던 산출물을 그대로 썼다(이 작업에서
  `scripts/build_mode3_circuit.sh`·`npm run zk:*` 를 실행하지 않았다).
- 회로 제약·공개 입력 수는 `npx snarkjs r1cs info build/mode3/{pi_cred,pi_idp}.r1cs` 로도 독립 확인했다(아래 표와 정확히 일치).

## 1. 회로 실측

측정: `date +%Y-%m-%d\ %H:%M:%S` → 2026-10-13 03:28 KST 시작(`node scripts/bench_pi_idp.mjs`), 03:42 KST(`node scripts/bench_pi_cred.mjs pot21_final.ptau`).

| 항목 | V10(기준) | V11 추정(스펙 §8) | V11 실측 | 비고 |
|---|---|---|---|---|
| pi_cred 비선형 제약 | 34,934 | 35,000 ± 1,500 | **33,909** | `r1cs info` 로 확인. 추정 범위 하단(−1,025) |
| pi_cred 공개 입력 | 30 | 33 | **33** | `[30] auid_s [31] arid_s [32] r_s`(D12) |
| pi_cred 증명 시간(중앙값, 10회) | 1,271 ms | ≈ 1,300 ms | **1,168.2 ms** | `node scripts/bench_pi_cred.mjs pot21_final.ptau` |
| pi_cred 검증 시간(중앙값, 10회) | 11.3 ms | ≈ 12 ms | **9.3 ms** | 위와 같음 |
| pi_cred zkey 크기 | 22.3 MB | ≈ 22.5 MB | **22.1 MB**(22,072,043 bytes) | — |
| pi_idp 비선형 제약 | (없음 — V10 은 π_u 시그마) | ≈ 13,000(스펙 §4) | **6,325** | `r1cs info` 로 확인. CommitUser(3,537) + CommitSessionV11(2,236) + Poseidon(auid·auid_s) — 추정의 절반 |
| pi_idp 공개 입력 | — | 8 | **8** | `uid, auid, auid_s, C_u_x, C_u_y, C_s_x, C_s_y, max_height` |
| pi_idp 증명 시간(중앙값, 10회) | 80 ms(π_u 시그마) | ≈ 450 ms | **292.0 ms** | `node scripts/bench_pi_idp.mjs` |
| pi_idp 검증 시간(중앙값, 10회) | 99 ms(π_u 시그마) | ≈ 10 ms | **13.2 ms** | 위와 같음 |
| pi_idp zkey 크기 | — | ≈ 8 MB | **4.0 MB**(3,963,739 bytes) | 제약 수가 추정의 절반인 것과 같은 비율 |

## 2. 온체인 실측 (`node scripts/bench_mode3_onchain.mjs`, N=10, :8545)

측정: 2026-10-13 03:42 KST 시작, 03:45 KST 종료(약 3분).

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP, 중앙값(최소–최대)) | 1,837 ms (1,808–7,087) |
| ├ 첫 로그인(사용자 자격증명 신규 발급 + 등록부 게시 대기 포함) | 7,087 ms |
| ├ 체인 동기화 syncMs | 79 ms (77–505) |
| ├ 사용자 자격증명 발급 userCredMs(첫 로그인 1,582 ms, 이후 재사용) | 0 ms (0–1,582) |
| ├ CIA 세션 발급 issueMs(π_IdP 생성(지갑, ≈292ms) + `/cia/issue` 왕복: sig_u·π_IdP 검증 + 서명) | 467 ms (448–1,582) |
| ├ 증명 proveMs(pi_cred V11) | 1,201 ms (1,190–1,504) |
| 서비스 verifyLogin(Groth16 + σ + root) | 36 ms (33–510) |
| 재검증 왕복(캐시 π) | 81 ms (78–86) |
| 재검증 verifyLogin | 34 ms (33–35) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 216 ms (209–281) |
| **execute gas(mask=0, 캐시 π, N회)** | **477,220 (477,164–477,220)** |
| execute gas(첫 tx, 계정 배포 tx 는 별도) | 494,308 |
| execute gas(mask=1+set, 새 π + AttrGate.claim, N회) | 518,644 (518,600–518,680) |
| execute gas(범위만, mask=1, to=dEaD, N회) | 483,514 (483,478–483,570) |
| execute gas(집합만, mask=0+set, to=dEaD, N회) | 484,170 (484,102–484,206) |
| 계정 배포 gas(factory.deploy, CREATE2) | 995,731 |
| PiCredVerifier 배포 gas | 1,038,520 |
| Mode3WalletFactory 배포 gas | 1,577,103 |
| Mode3Log 배포 gas | 1,688,767 |
| Mode3Log 등록부 슬롯 게시 gas(슬롯 1개) | 57,820 |
| Mode3Log 폐기 리프 게시 gas(리프 1개) | 52,502 |
| Mode3Log 하트비트 게시 gas | 48,871 |
| Mode3Mirror 배포 gas | 874,921 |
| Mode3Mirror 갱신 gas(강제 릴레이, N회) | 45,121 (45,101–47,877) |
| Mode3Log requestRevocation gas(접수증 제출, N=5) | 100,912 (81,008–100,932) |
| Mode3Log 강제 publish gas(pending 슬롯 1개, N=5) | 76,020 (76,000–77,996) |
| zkey 크기(pi_cred) | 22,072,043 bytes |
| 공개 입력 수 | 33 |

`issueMs` 는 `issueSession` 호출 전체(지갑 쪽 π_IdP 증명 생성 ≈292ms 포함)를 지갑이 잰 값이다 — V10 기준 134ms(네트워크 왕복 +
sig_u 검증 + 서명) + π_IdP 증명 292ms + π_IdP 검증 13ms ≈ 440ms 로 실측 467ms 가 거의 설명된다. **첫 로그인의 `userCredMs` 는
`issueMs` 와 같은 값(부분집합)이다 — 두 행을 더하지 않는다.**

이 스크립트는 애초에 공개 입력 30개 시절(V9)에 쓰였고, 이번에 33개로 바뀌면서 두 가지가 깨졌다 — `scripts/bench_mode3_onchain.mjs`
자체를 고쳤다(브리프가 허용한 범위):
- 머리 주석의 "공개 입력 30개" 표기와 표 끝의 `console.log`(`| 공개 입력 수 | 30 |`)를 33으로.
- `/wallet/login`·검증(`rp.verifyLogin`)이 이제 RP 챌린지 `r_rp`(D6)를 요구한다 — 스크립트의 `login()`·`verify()` 헬퍼가
  `r_s` 만 받던 것을 `r_rp` 도 받아 넘기도록 고쳤다(세 호출부: 로그인 N회 루프, 재검증 루프의 재검증, 접수증 사이클의 재로그인).
  고치지 않았으면 모든 로그인이 400(`r_s, r_rp 필요`)으로 실패했을 것이다.

## 3. execute gas 증가 분석 (스펙 §8 "비고" 참고 — 애디펌의 원 기록과 다른 값이 나온 이유)

컨트롤러의 작업 장부(브리프 보충 메모)에는 이 작업 전에 "Mode3Wallet.execute gas: 455,947 → **525,679**(+69,732), 공개 입력 +3로는
1/3 만 설명됨"이라는 기록이 있었다. 이번에 직접 두 경로로 다시 측정한 결과, **같은 조건으로 비교하면 거의 전부 설명된다** —
장부의 525,679 는 **다른 조건**을 비교한 값이었다.

- **같은 스크립트·같은 조건(이 파일의 정본 비교)**: `scripts/bench_mode3_onchain.mjs` 의 "execute gas(mask=0, 캐시 π, N회)" 행은
  V10 결과 파일(`results/mode3_v10_revocation_chain_20261002.md` 69행·218행)의 같은 행과 정확히 같은 조건(선택 공개 없음,
  캐시된 증명, `to` 임의 EOA, **value=0**)이다. V10 455,947 → V11 **477,220**, **+21,273(+4.67%)**. 공개 입력이 30→33으로
  3개 늘어난 몫 — Groth16 검증자의 pairing/스칼라곱 비용(대략 20,000)과 `_checkStatement`·마스크 위생 루프가 calldata 를
  더 읽는 비용(대략 1,500)을 더하면 ≈ 21,500 으로, 실측 +21,273 과 거의 정확히 맞는다. **미설명분은 사실상 없다(≈ −200,
  측정 잡음 수준).**
- **장부의 525,679 가 어디서 왔는지**: `bash scripts/run_tests.sh contract` 로 `test/Mode3Wallet.test.mjs` 를 실제로 돌려
  "정상 실행" 케이스의 `console.log('      execute() gas: …')` 를 확인했다 — **525,655**(장부의 525,679 와 24 gas 차이,
  같은 테스트 케이스의 다른 실행으로 보인다). 이 테스트는 **다른 조건**이다: (1) 갓 배포한 지갑의 **첫** `execute()`
  (nonce 0→1, 계정 배포와 별도 tx) — 이 자체가 이 결과 파일의 "execute gas(첫 tx)" 행(494,308)과 같은 범주이고,
  (2) `value: ethers.parseEther('0.1')` 를 **한 번도 손대지 않은 랜덤 EOA**로 보낸다 — EVM 은 잔액이 0 이고 존재한 적
  없는 계정에 값을 보내면 "새 계정 생성" 비용(대략 25,000, EIP-2929 cold-access 포함)을 추가로 물린다. 494,308(이 파일의
  "첫 tx", value=0) 과 525,655(`test/Mode3Wallet.test.mjs`, value=0.1 ETH·새 계정)의 차이(≈31,347)가 그 설명과 크기가
  맞는다. 즉 장부의 "+69,732"는 **V10 의 value=0 조건(455,947)과 V11 의 value=0.1·새 계정 조건(525,679)을 비교한 것**이라
  애초에 서로 다른 측정이었다 — V11 프로토콜 변경이 설명해야 할 몫이 아니다.
- **결론**: 공개 입력 3개 증가가 설명해야 하는 gas 증가는 +21,273(+4.67%) 이고, 이는 "검증자 ≈20k + calldata ≈1.5k" 추정과
  거의 정확히 일치한다. 결함으로 분류하지 않는다. (참고로 `test/Mode3Wallet.test.mjs` 자체는 이 작업에서 수정하지 않았다 —
  Task 12 의 손댈 파일 목록 밖이다.)

## 4. 로그인 왕복 — 지갑 에이전트 타이밍(`tests/test_mode3_wallet_agent.mjs` 와 같은 코드 경로)

측정: 2026-10-13 03:48~03:49 KST, `node tests/test_mode3_wallet_agent.mjs`(격리 스택, :8545) — 48개 단언 전부 통과(실패 0).
이 테스트 자체는 숫자를 stdout 에 내지 않는다(통과/실패만) — "로그인 왕복" 행의 실제 숫자는 **같은 `/wallet/login` 라우트와
같은 `timings{syncMs,userCredMs,issueMs,proveMs}` 필드**를 쓰는 §2 의 `bench_mode3_onchain.mjs` 로그인 루프에서 그대로
가져왔다(교차 확인: `tests/test_mode3_wallet_agent.mjs` 자신의 `tx` 케이스가 찍는 "execute gas 494356" 이 §2·§3 의
"execute gas(첫 tx)" 494,308 과 48 gas 차이로 거의 같다 — 같은 조건임을 뒷받침한다). 이 머신의 단일 실행 값이다 — 다른
머신·다른 부하에서는 달라질 수 있다.

## 5. 전체 테스트 실행

브리프·애디펌 순서(벤치 먼저 → `npm test` → `contract` → `chain` → `snap` → `browser`)대로 돌렸다. 각 그룹의 명령·결과·
소요 시간은 Task 12 보고서(`.superpowers/sdd/2026-10-12-mode3-v11-figure-protocol/task-12-report.md`)에 정리했다 — 이
결과 파일은 벤치·gas 분석만 다룬다(스펙 §11 의 범위).

## 6. 참고

- 스펙: `docs/superpowers/specs/2026-10-12-mode3-v11-figure-protocol-design.md` §8(이 파일로 "V11 실측" 열을 채웠다).
- V10 비교 기준: `results/mode3_v10_revocation_chain_20261002.md`.
- 덱·그림(`documents/261012.pptx` 등) 반영은 스펙 §12 — 코드 밖이라 이 작업에서 다루지 않았다.
