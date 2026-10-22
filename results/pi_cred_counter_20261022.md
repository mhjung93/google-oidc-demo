# pi_cred counter(34번째 공개 입력) 추가 — 제약·증명/검증 시간 실측

2026-10-22 설계 §6.5(세션키별 온체인 상한)로 `circuits/pi_cred.circom` 에 34번째 공개 입력 `counter`와
구간 비멤버십(IMTRangeNonMembershipV2)이 붙었다(Task 3: 회로·빌드, Task 4: 계정 컨트랙트·픽스처·테스트).
이 문서는 그 변경이 회로 제약·증명/검증 시간에 미친 영향을 실측한다.

## 측정 조건

- CPU: AMD Ryzen 9 5950X(16 코어) · 메모리 31GB(`free -g`) — `lscpu`·`free -g` 로 확인.
- Node v22.20.0 · hardhat 2.28.0 · snarkjs 0.7.5 · ethers 6.16.0 · circomlibjs 0.1.7.
- 명령: `node scripts/bench_pi_cred.mjs pot21_final.ptau` (`build/mode3/pi_cred_final.zkey` 가 이미
  있어 zkey 재생성 없이 증명·검증만 실측했다. 입력은 `tests/helpers/mode3_fixture.mjs` 의
  `buildValidInput()` 기본값 — counter 는 기본 `LOGIN_COUNTER`(2^32−1)).
- 제약·공개 입력 수는 `npx snarkjs r1cs info build/mode3/pi_cred.r1cs` 로도 독립 확인했다(아래 표와 일치).
- 측정 일시: 2026-10-23 05:09 KST(`date` 실행값).
- **측정 환경 — 데모 스택이 함께 돌아가는 머신, 참고치**: 측정 시점에 Mode 3 데모 스택(포트 5100·8082·8547·8548)이
  이 머신에서 함께 실행 중이었다(건드리지 않았다). `results/mode3_v11_figure_protocol_20261013.md`·
  `results/baselines_20261013.md` 와는 측정 시점의 백그라운드 부하가 다를 수 있어, 아래 수치는 절대값보다
  "이전 대비 변화량" 쪽을 더 신뢰할 수 있는 참고치로 읽는다.

## 결과

| 항목 | 이전(V11, 공개 입력 33) | 측정(이번, 공개 입력 34 — counter 추가) | 비고 |
|:--|--:|--:|:--|
| 비선형 제약 | 33,909 | **34,445** (+536) | `r1cs info` 로 확인. 구간 비멤버십 가젯(IMTRangeNonMembershipV2) 추가분 |
| 공개 입력 | 33 | **34** | `[33] counter`(2026-10-22 §6.5) |
| 증명 시간(중앙값, 10회) | 1,168.2 ms | **1,208.3 ms** | `node scripts/bench_pi_cred.mjs pot21_final.ptau` |
| 검증 시간(중앙값, 10회) | 9.3 ms | **7.9 ms** | 위와 같음. Groth16 검증 비용은 공개 입력 수에 선형이라 미세한 차이는 측정 잡음(§ 위 "참고치") |
| zkey 크기 | 22,072,043 bytes (22.1 MB) | **22,356,311 bytes (22.4 MB)** | 제약 증가(+1.6%)와 비슷한 비율로 커졌다 |

- "이전" 열은 `results/mode3_v11_figure_protocol_20261013.md` 의 V11(공개 입력 33) 실측값을 그대로 인용했다
  (재측정하지 않음 — 그 문서는 이 변경 전의 바닥값이다).
- 제약 수 증가(+536, 약 +1.6%)는 세션 리프를 단일 비멤버십(`Poseidon(5,Cf_s)` 하나)에서 구간 비멤버십
  (`[H'·2^32, H'·2^32+counter]`)으로 바꾼 데 따른 것이다. Task 2 검토가 확인한 분해는 `+536 = Num2Bits(32)
  32 + lo·hi 범위 검사 Num2Bits(252)×2 = 504`. 전체 제약(34,445)은 Mode 2(13,905)의 약 2.5배,
  V3(25,505)의 약 1.35배다.
- 증명 시간은 측정 잡음 범위 안(1,168→1,208ms, +3.4%)이고, 검증 시간은 오히려 줄었다(9.3→7.9ms) — 둘 다
  공개 입력 1개·비선형 제약 536개 증가로 설명되는 크기가 아니라, 위 "참고치" 각주대로 백그라운드 부하 차이로
  보는 것이 합리적이다.

## 참고

- 이 결과는 `tests/test_pi_cred_witness.mjs` 가 보고하는 "비선형 제약 34,445"(2026-10-22 추가된 witness
  테스트 실행분)와 일치한다.
- 비교 대상인 V11(공개 입력 33) 바닥값은 `results/mode3_v11_figure_protocol_20261013.md` 를 인용했다.
