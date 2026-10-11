
## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1394 (1363–4874) |
| ├ 체인 동기화 syncMs | 31 (29–220) |
| ├ CIA 발급 issueMs (π_issue 포함) | 422 (412–1984) |
| ├ 증명 proveMs (pi_cred) | 898 (862–1595) |
| 서비스 verifyLogin (Groth16 + σ + root) | 39 (37–352) |
| 재검증 왕복(캐시 π) | 33 (32–39) |
| 재검증 verifyLogin | 36 (35–40) |
| /wallet/tx 왕복(캐시 π, 서명+제출+채굴) | 157 (154–159) |
| execute gas (캐시 π, N회) | 339341 (339297–339353) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 356441 |
| 계정 배포 gas (factory.deploy, CREATE2) | 713542 |
| PiCredVerifier 배포 gas | 648683 |
| Mode3WalletFactory 배포 gas | 1269466 |
| RevocationLog 게시 gas (리프 10) | 50968 |
| RevocationLog 하트비트 gas (리프 0) | 40261, 40305 |
| zkey 크기 | 15459179 bytes |
| 공개 입력 수 | 14 |
