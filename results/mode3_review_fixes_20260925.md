# Mode 3 온체인 실측 — 2026-09-25 리뷰 수정 반영판

측정 시각 2026-09-25 15:58 KST, `node scripts/bench_mode3_onchain.mjs 10` (N=10). 회로·zkey·`PiCredVerifier.sol` 은 V8(2026-09-24)에서
바뀌지 않았다. 바뀐 것은 컨트랙트 두 개(`Mode3Wallet.sol`, `Mode3WalletFactory.sol`)와 서명 다이제스트다 — 커밋 `4aa5589`:
마스크 밖 슬롯 거절(`BadDisclosure`)과 σ_tx 다이제스트에 `max_height`·`allowAgent`·태그 3워드 추가.

**이 파일은 `results/mode3_session_revocation_20260924.md` 를 대체하지 않는다.** 그 파일은 V7→V8 회로 비교 기록이고
여기는 같은 V8 회로 위에서 컨트랙트만 바뀐 뒤의 재측정이다.

## 이전 측정과의 차이 (V8 2026-09-24 → 이 판)

| 항목 | V8 (09-24) | 이 판 (09-25) | 차이 |
|---|--:|--:|--:|
| execute gas (mask=0, 캐시 π) | 416,015 | 417,533 | **+1,518** |
| execute gas (첫 tx) | 433,135 | 434,665 | **+1,530** |
| execute gas (범위만) | 421,076 | 422,366 | **+1,290** |
| execute gas (집합만) | 421,428 | 422,982 | **+1,554** |
| execute gas (범위+집합+claim) | 455,162 | 456,439 | **+1,277** |
| 계정 배포 gas (CREATE2) | 908,232 | 939,808 | **+31,576** |
| `Mode3WalletFactory` 배포 gas | 1,483,740 | 1,517,288 | **+33,548** |
| `PiCredVerifier` 배포 gas | 874,396 | 874,396 | **0** |
| `RevocationLog` 게시 gas (리프 1) | 43,880 | 43,856 | −24 |

읽는 법:

- **execute 는 실행당 1,300~1,550 gas(+0.31~0.37%) 늘었다.** 다이제스트가 5워드 더 넓어져 `abi.encode` 와 keccak 입력이
  160바이트 커진 것, 그리고 마스크 위생 루프의 calldata 읽기 8회가 합쳐진 값이다. 공개 입력 수(25)는 그대로라 Groth16
  검증 비용은 바뀌지 않았다.
- **배포 gas 가 3만대 오른 것은 `Mode3Wallet` 바이트코드가 커졌기 때문이다.** 팩토리는 `creationCode` 를 품고 있어 같이 오른다.
- **`PiCredVerifier` 가 정확히 0 차이인 것이 생성 파일을 건드리지 않았다는 증거다.**
- `RevocationLog` 의 −24 는 리프 값의 0바이트 개수에 따른 calldata 비용 차이로, 이전 판에서도 ±20 수준으로 흔들리던 항목이다.

## 원본 출력

## Mode 3 온체인 실행 실측 (N=10, 중앙값 (최소–최대), ms)

| 항목 | 값 |
|---|--:|
| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | 1497 (1483–5212) |
| ├ 체인 동기화 syncMs | 25 (24–251) |
| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 1895 ms, 이후 재사용) | 0 (0–1895) |
| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | 127 (114–253) |
| ├ 증명 proveMs (pi_cred V7) | 1258 (1245–1918) |
| 서비스 verifyLogin (Groth16 + σ + root) | 35 (34–379) |
| 재검증 왕복(캐시 π) | 29 (27–32) |
| 재검증 verifyLogin | 34 (33–36) |
| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | 164 (161–166) |
| execute gas (mask=0, 캐시 π, N회) | 417533 (417509–417577) |
| execute gas (첫 tx, 계정 배포 tx 는 별도) | 434665 |
| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | 1446 (1403–1615) |
| execute gas (mask=1 + set, 새 π + claim, N회) | 456439 (456383–456463) |
| execute gas (범위만, mask=1, to=dEaD, N회) | 422366 (422298–422378) |
| execute gas (집합만, mask=0 + set, to=dEaD, N회) | 422982 (422946–423026) |
| 계정 배포 gas (factory.deploy, CREATE2) | 939808 |
| PiCredVerifier 배포 gas | 874396 |
| Mode3WalletFactory 배포 gas | 1517288 |
| RevocationLog 게시 gas (리프 1) | 43856 |
| RevocationLog 하트비트 gas (리프 0) | 40305, 40305, 40285, 40273, 40281, 40285, 40285, 40285, 40281 |
| zkey 크기 | 23442451 bytes |
| 공개 입력 수 | 25 |
