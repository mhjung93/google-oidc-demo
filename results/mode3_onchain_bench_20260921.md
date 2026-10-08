# Mode 3 온체인 실행 실측 (2026-09-21, 자격증명 이중 구조 V5)

측정: `node scripts/bench_mode3_onchain.mjs 10`, 격리 스택(CIA + 지갑 에이전트), hardhat :8545, AMD Ryzen 9 5950X, Node v22.20.0. 2026-09-18 판은 `results/mode3_onchain_bench_20260918.md`.
userCredMs 는 첫 로그인(사용자 자격증명 π_u 발급) 만 > 0 이고 이후 로그인은 재사용이라 0 — 첫 로그인 값에는 지갑 프로세스의 circomlibjs(Baby Jubjub·Poseidon WASM) 첫 초기화가 섞여 있는 것으로 보인다(warm π_u 생성+검증은 `results/zkp_inventory_20260921.md` 의 ≈ 122 + 140 ms). 로그인 전체 왕복의 최대값 4,762 ms 도 그 첫 로그인이다(2026-09-18 판도 첫 로그인 4,874 ms).
issueMs 는 지갑이 재는 세션 발급 구간 전체다: 세션키 생성, chainId RPC, 세션 커밋 C_s·sig_u 계산, CIA 왕복(sig_u 검증·부분군 검사·chainAlive RPC·서명), PPID 계산·상태 저장. CIA 안의 계산(부분군 검사 + credMessageV5 + EdDSA-Poseidon 서명)만 따로 재면 중앙값 29.6 ms(N=20, 이 프로세스 안에서 직접 호출) 다 — 나머지는 RPC 두 번·HTTP·키 생성·상태 저장이다.

## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1073 (1048–4762) |
| ├ 체인 동기화 syncMs | 29 (27–213) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 1962 ms, 이후 재사용) | 0 (0–1962) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 124 (120–245) |
| ├ 증명 proveMs (pi_cred V5) | 870 (845–1502) |
| 서비스 verifyLogin (Groth16 + σ + root) | 38 (36–344) |
| 재검증 왕복(캐시 π) | 31 (30–37) |
| 재검증 verifyLogin | 36 (35–37) |
| /wallet/tx 왕복(캐시 π, 서명+제출+채굴) | 151 (150–153) |
| execute gas (캐시 π, N회) | 339321 (339321–339365) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 356453 |
| 계정 배포 gas (factory.deploy, CREATE2) | 713542 |
| PiCredVerifier 배포 gas | 648923 |
| Mode3WalletFactory 배포 gas | 1269478 |
| RevocationLog 게시 gas (리프 1) | 43888 |
| RevocationLog 하트비트 gas (리프 0) | 40305, 40305 |
| zkey 크기 | 16022463 bytes |
| 공개 입력 수 | 14 |
