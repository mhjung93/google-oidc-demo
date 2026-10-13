# zk-Delegation(Mode 3) 바닥값(floor) 기준선 실측

`scripts/bench_baselines.cjs` 실행 결과. zk 증명도 외부 IdP 도 쓰지 않는 평범한 연산들의 비용을 Mode 3 비용과
나란히 두기 위한 기준선이다.

## 측정 조건

- CPU: AMD Ryzen 9 5950X(16 코어) · 메모리 31GB(`free -g`) — `lscpu`·`free -g` 로 확인.
- Node v22.20.0 · hardhat 2.28.0 · snarkjs 0.7.5 · ethers 6.16.0 · circomlibjs 0.1.7.
- 명령: `npx hardhat run scripts/bench_baselines.cjs` (인프로세스 hardhat 네트워크 — `--network` 없음, :8545 미사용).
- 측정 일시: 2026-10-13 12:02 KST(`date` 실행값).
- (B)는 `contracts/test/AcceptAllPiCredVerifier.sol`("무엇이든 통과시키는" 검증자)로 Groth16 pairing 비용을
  제거한 조건이라 `build/mode3` 의 zkey·wasm·snarkjs 증명 생성이 전혀 필요 없었다.

## 결과

### (A) EOA → EOA 값 전송 gas

| 조건 | gas |
|:--|---:|
| 1차(cold) | 21,000 |
| 2차(warm) | 21,000 |

### (B) Mode3Wallet.execute gas — AcceptAllPiCredVerifier(검증 비용 제거, AA 오버헤드만)

| 조건 | gas |
|:--|---:|
| 첫 호출(to=새 EOA, value=0, mask=0) | 85,138 |
| mask=0·캐시 π 와 같은 모양(N=5, 중앙값(최소–최대)) | 68,038 (68,026–68,094) |
| value=0.1 ETH → 손대지 않은 주소(test/Mode3Wallet.test.mjs "정상 실행" 조건 재현) | 116,942 |

### (C) 평범한 서명 검증 시간(Node crypto, N=1,000)

| 방식 | 시간 |
|:--|:--|
| RS256(RSA-2048) | 중앙값 16.7 µs / 평균 17.1 µs (최소 16.5–최대 56.8) |
| Ed25519 | 중앙값 80.7 µs / 평균 81.7 µs (최소 79.6–최대 115.6) |
| ECDSA secp256k1 복구(ethers.recoverAddress) | 중앙값 1,456.7 µs / 평균 1,525.5 µs (최소 1,396.5–최대 4,267.2) |

### (D) EdDSA-Poseidon(Baby Jubjub) 검증 시간(circomlibjs, N=200)

| 방식 | 시간 |
|:--|:--|
| EdDSA-Poseidon verify | 중앙값 20,174.5 µs / 평균 20,163.5 µs (최소 19,713.7–최대 21,339.5) |

## 해석

- **AA 오버헤드** = AcceptAll execute(mask=0, 캐시 π 조건, 68,038) − EOA 전송 기준선(21,000) = **47,038 gas**.
  이것이 계정 추상화(서명 복구·`_checkStatement`·이벤트 3개)만의 순수 비용이다.
- **Groth16 검증 비용** = 실 검증기 execute(`results/mode3_v11_figure_protocol_20261013.md` 의 477,220) −
  AcceptAll execute(68,038) = **409,182 gas**. 즉 execute 총 gas 의 약 86%가 Groth16 pairing·스칼라곱이고,
  나머지 14%가 평범한 계정 추상화 로직이다.
- 교차 검증: "첫 호출 − 캐시 호출" 차이는 AcceptAll(85,138−68,038=17,100)과 실 검증기(494,308−477,220=17,088)
  가 거의 같다 — 이 차이는 nonce 슬롯이 0→1 로 바뀌는 SSTORE(zero→nonzero, ≈20,000)와 1→2(nonzero→nonzero,
  ≈5,000)의 차이에서 오는 것이라 검증자와 무관하다. 마찬가지로 "value=0.1 ETH·새 계정" 조건의 추가 비용도
  AcceptAll(116,942−85,138=31,804)과 실 검증기(525,655−494,308=31,347)가 거의 같다 — 두 조건 모두 Groth16
  과 무관한 비용이 정확히 같은 크기로 얹힌다는 뜻이고, 이는 (B)의 분해가 조건을 맞춰 비교한 결과라는 근거다.
- 오프체인 서명 검증은 RS256(16.7µs) < Ed25519(80.7µs) ≪ ethers 의 순수 JS ECDSA 복구(1,457µs, 네이티브
  바인딩 없이 @noble/curves 를 쓰기 때문)다. EdDSA-Poseidon(circomlibjs, 20,175µs)은 이보다 1,000배 이상
  느리지만, 이는 **회로 안에서 검증하는 비용이 아니라** circomlibjs 의 순수 JS 필드 연산 구현의 오프체인 비용이다
  — 실제 회로 안 검증 비용은 pi_cred 증명 시간(1,168ms, V11 결과 파일)에 이미 포함돼 따로 더해지지 않는다.

## 참고

- V11 실 검증기 execute gas(477,220)·pi_cred 증명 시간(1,168.2ms) 등은 `results/mode3_v11_figure_protocol_20261013.md`
  에서 그대로 인용했다(재측정하지 않음).
- `scripts/bench_baselines.cjs`.
