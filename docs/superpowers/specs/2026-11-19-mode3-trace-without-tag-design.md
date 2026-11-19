# Mode 3 — trace tag 없는 개봉: zkIdP 의 auid_s 기록으로 uid 를 찾는다 (설계, 2026-11-19)

- 상태: **구현됨(2026-11-19, 사용자 결정·회로 재빌드 승인 뒤).** 재빌드·테스트 결과와 남은 것은 §5.
- 사용자 결정(2026-11-19 데모 시나리오 9·10 과 이어진 답): "지금 개봉하는 것 그대로 하되, 트랜잭션에 trace tag 빼고 ZKP 에도 public input 에서 제거",
  "tag 를 여는 게 아니라 해당 PPID 로 로그인한 가장 최신의 auid_s 를 IdP 에 제공하면 그걸 보고 uid 를 반환", "IdP 는 기록을 갖고 있는 형태", "회로 재빌드 승인".
- 한 줄: π_cred 와 거래에서 trace tag(ElGamal 암호문)를 뺀다. 개봉은 서비스가 그 PPID 의 가장 최신 `auid_s` 를 zkIdP 에 내고, zkIdP 가 **발급 때 남긴 `auid_s → uid` 기록**에서 uid 를 찾아 돌려준다.
- 비범위: 등록·발급·폐기 규칙, π_IdP, 서비스 등록의 조합 키(`pk_trace`·`X_svc`·`x_AA`) 자체의 삭제(§1 T5 — 쓰지 않게 될 뿐 지우지 않는다), 다른 세션의 스펙
  `2026-11-16-mode3-trace-tag-compress-design.md`(같은 회로의 tag 를 다루는 문서 — 이 변경이 tag 를 없애므로 그 작업과는 양립하지 않는다. 사용자 조율 필요).

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| T1 | π_cred 에서 **tag 세 값(c1.x·c1.y·c2)과 그 계산(TraceTag·ρ ≠ 0)을 뺀다.** | 사용자 결정. |
| T2 | **`pk_trace` 두 값도 공개 입력에서 뺀다**(요청은 tag 만이었다 — 구현상 필요). | tag 가 없으면 회로 안에서 `pk_trace` 를 쓰는 제약이 없다. 제약 없는 공개 입력은 Groth16 에서 아무 값이나 통과해 "검증자가 자기 키와 견준다" 는 검사가 빈 껍데기가 된다. |
| T3 | 공개 입력은 **34 → 29개**: `[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8,9] pk_CIA [10] disc_mask [11..16] disc_lo [17..22] disc_hi [23] set_sel [24] set_root [25] auid_s [26] arid_s [27] r_s [28] counter`. | 앞 10개는 그대로, 뒤는 5칸씩 당겨진다. 색인은 `lib/mode3_onchain.js` 의 `PUB_INDEX` 가 정본이다. |
| T4 | 거래(`Mode3Wallet.execute`): 공개 입력 배열 `uint[29]`, **세션키 서명의 다이제스트와 `Mode3Auth` 이벤트에서 tag 를 뺀다**, `BadTag`·`pkTrace` 대조를 뺀다. | "트랜잭션에 trace tag 빼고". 다이제스트가 바뀌므로 지갑 쪽 서명 대상도 같이 바뀐다. |
| T5 | 지갑·팩토리 컨트랙트의 **생성자 인자(`pkTraceX`·`pkTraceY`)와 서비스 등록·인증서의 `pk_trace` 는 남겨 둔다** — 값은 저장되지만 검사에 쓰이지 않는다. | 인자를 빼면 팩토리·배포 스크립트·계정 주소 계산·Blockscout 검증·RP 인증서 형식까지 바뀐다. 이번 범위를 회로·거래·개봉으로 좁힌다. 대가: 쓰이지 않는 값이 남는다(후속 정리). |
| T6 | zkIdP 는 발급 때마다 **`auid_s → { uid, at }` 기록**을 남긴다(상태 파일, 계정마다 5,000개 — `CIA_AUID_S_LOG_MAX`). **오래된 것을 밀어내지 않는다 — 차면 그 계정의 발급을 `auid_log_full`(409)로 거절한다**(리뷰 I-1, §5). 연결 해제·계정 폐기에도 지우지 않는다(추적의 근거다). 관리자의 계정 **삭제**는 기록도 함께 지운다(그 뒤의 개봉은 `resolved: false`). | 사용자 결정("IdP 는 기록을 갖고 있는 형태"). 지금까지의 "auid_s 는 남기지 않는다"(D1 — 최신 하나만 예외)를 뒤집는다. **대가: auid_s 는 거래의 공개 입력이라 체인에 보인다 — zkIdP 는 서비스의 협조 없이도 그 기록으로 거래의 주인을 안다.** 지금까지는 조합 키의 서비스 쪽 조각이 있어야 열렸다. |
| T7 | 개봉 요청(`POST /cia/open/request`): 서비스가 `{ arid, publicSignals[29], proof, ts, sig }` 를 낸다 — **그 PPID 의 가장 최신 로그인의 증명 한 벌**이다(공개 입력 안에 PPID·arid·auid_s 가 함께 있다). `D_svc`(부분 복호)는 없다. 서명 메시지는 `{ arid, PPID, auid_s, ts }`. | "지금 개봉하는 것 그대로": 서비스 관리자 요청 → zkIdP 가 증명·서명·arid 를 확인해 대기 목록에 → zkIdP 관리자 승인 → 결과. 증명을 함께 받으므로 서비스가 남의 `auid_s` 를 지어내 물을 수 없다. |
| T8 | 승인(`POST /cia/openings/:id/approve`): 기록에서 그 `auid_s` 의 uid 를 찾는다. 있으면 `resolved: true` + uid, 없으면 `resolved: false`(기록에 없음 — 기록 상한 밖이거나 이 zkIdP 가 낸 값이 아니다). | 복호·전수 대입이 없다. |
| T9 | 거래 해시로 여는 길(`txHash`)은 그대로 둔다 — 거래의 공개 입력에 `auid_s` 가 있다. | 지금 화면의 "이 거래를 누가 보냈나" 가 그대로 된다. |
| T10 | 화면: 서비스·zkIdP 관리자의 개봉 화면에서 tag 표기(c1·c2)를 `auid_s` 로 바꾼다. 지갑의 "영지식 증명" 카드에서 tag·pk_trace 묶음을 뺀다. | 보이는 값이 실제와 같게. |

## 2. 바뀌는 곳

- 회로: `circuits/pi_cred.circom`(입력 `r`·`pk_trace_*`·`tag_*`, ⑧ 블록, `main` 의 공개 목록). `bash scripts/build_mode3_circuit.sh pi_cred` 로 zkey·vkey·wasm·`contracts/PiCredVerifier.sol` 을 한 세트로 다시 만든다
  (스크립트의 "34개" 검사를 29로). **지금까지의 증명 키·배포된 검증자·지갑은 모두 무효다 — 데모는 리셋(재배포)해야 한다.**
- 컨트랙트: `contracts/Mode3Wallet.sol`(T4), `contracts/AttrGate.sol`(공개 입력 수를 쓰면). `npx hardhat compile`.
- 라이브러리: `lib/mode3_onchain.js`(`PUB_INDEX`·다이제스트·calldata·영수증 해석), `lib/mode3_wallet.js`(증명 입력에서 tag·`pk_trace`), `lib/mode3_rp.js`(검증에서 tag·`pk_trace` 대조), `lib/mode3_trace.js`(개봉 서명 메시지).
- 서버: `cia.js`(T6~T8), `mode3_rp.js`(T7·T9), `mode3_wallet_agent.js`(에이전트 모드의 증명 입력 — 같은 lib 를 쓴다).
- 화면: `mode3/user/ui.js`(공개 입력 묶음), `mode3/rp_admin.html`·`mode3/cia_admin.html`(개봉), `mode3/common/strings.js`.
- 테스트·문서.

## 3. 보안 메모

- **조건부 익명성의 모양이 바뀐다**(T6): "서비스와 zkIdP 가 함께해야 열린다" 에서 "zkIdP 의 기록으로 열린다" 로. 절차(서비스의 요청 + zkIdP 관리자의 승인)는 남지만 암호학적 강제는 없다 — zkIdP 가 기록을 가진 이상
  체인의 `auid_s` 를 혼자 대조할 수 있다. 사용자 결정이며, 논문의 서술과 맞춰야 한다.
- **zkIdP 쪽 서비스 은닉이 온체인 사용자에게는 깨진다**(리뷰 I-2): 거래의 공개 입력에는 `auid_s` 만이 아니라 `arid`(평문)와 `PPID` 도 함께 있다. 그래서 zkIdP 는 기록 한 줄로 "이 uid 가 **그 서비스**(arid)의
  **그 계정**(PPID)을 쓴다" 를 알고, 같은 PPID 지갑의 다른 거래(다른 `auid_s`)도 그 uid 의 것으로 잇는다. 발급 때는 여전히 `arid_s` 만 보지만(어느 서비스인지 모른다), 그 로그인이 거래로 이어지는 순간 체인이 나머지를 알려 준다.
  거래를 보내지 않는 로그인(서비스에만 증명을 내는 경우)은 서비스가 증명을 넘기지 않는 한 zkIdP 가 잇지 못한다. T6 의 대가이며 논문의 "IdP 는 RP 를 모른다" 서술과 함께 정리해야 한다.
- 서비스는 자기에게 온 증명만 낼 수 있다(공개 입력의 arid 가 자기 것이어야 하고 서명이 자기 서비스 키여야 한다) — 다른 서비스의 `auid_s` 는 열지 못한다.
- `auid_s` 는 로그인마다 다르다 — 한 번의 개봉이 그 사용자의 다른 로그인·다른 서비스의 가명을 드러내지 않는다(zkIdP 가 돌려주는 것은 uid 다).

## 4. 테스트

- 단위: 산출물 대조(`tests/test_mode3_artifacts.mjs` — 공개 입력 29개·순서), `PUB_INDEX`·다이제스트, 스크립트 검사.
- 컨트랙트(`test/Mode3Wallet.test.mjs`): 29개 배열·다이제스트·이벤트.
- 체인: `tests/test_cia_opening.mjs`(요청·승인·기록에 없음·남의 arid·위조 서명), 웹 코어.
- 브라우저(passkey-web): 로그인·출금이 새 회로로 돌고, 개봉이 uid 를 돌려준다.
- 사용자 지시(2026-11-19)로 스냅·에이전트 모드의 브라우저 테스트는 돌리지 않는다 — 같은 lib 를 쓰므로 함께 바뀌지만 미검증으로 남는다.

## 5. 구현 결과(2026-11-19)

- 회로 재빌드: `bash scripts/build_mode3_circuit.sh pi_cred` — 공개 입력 29개, 비선형 제약 30,866개(전에는 34,9xx). 새 `pi_cred_final.zkey`·vkey·wasm·`contracts/PiCredVerifier.sol`. **옛 키와 검증기는
  `build/mode3_backup_20261119_tag/` 에 복사해 뒀다**(git 밖). `npx hardhat compile` 완료.
- 통과(지시대로 passkey-web 관련과 바꾼 부분의 전용 테스트만): 단위 40/40, 회로 증인 46, 산출물 대조 12, 지갑 lib 19, 서비스 검증 35, 개봉 13(다시 씀), 웹 코어 28·26, 지갑 컨트랙트 51, AttrGate·참조 코드 8,
  passkey-web 브라우저 17·30(로그인·출금·개봉 포함).
- **돌리지 않은 것**: 스냅·에이전트 모드의 테스트(`test_mode3_browser.mjs`·`test_mode3_wallet_agent.mjs`·`test_mode3_e2e.mjs`·`test_mode3_demo_stack.mjs`·`test_mode3_rp_relay.mjs` 등). 색인이 눈에 보이는 줄은
  고쳤지만(e2e·wallet_agent·demo_stack) 실행해 확인하지 않았다 — 같은 lib 를 쓰므로 동작은 함께 바뀌었다.
- **고치지 않은 것**: `scripts/bench_baselines.cjs`(없어진 `PUB_INDEX.PK_TRACE_*`·`TAG_*` 를 쓴다 — 벤치를 돌리려면 손봐야 한다), 용어 사전의 `tag` 항목과 서비스 승인 화면의 "추적 조각" 문구(조합 키는 등록에 남아 있다),
  `lib/mode3_trace.js`·`circuits/lib/mode3_trace_tag.circom`(쓰이지 않지만 지우지 않았다).
- **분리 데모는 리셋(재배포)해야 한다**: 호스트 PC 의 지갑 페이지는 `build/mode3` 의 새 증명 키를 바로 내지만, VM 의 서비스·zkIdP 와 체인의 검증자·지갑은 옛 회로 것이다 — 재배포 전에는 로그인이 `bad_proof` 로 실패한다.

### 리뷰(2026-11-19, Opus — Critical 0·Important 2·Minor 10) 뒤 바꾼 것

- 색인·세션키 다이제스트·회로 제약은 어긋난 곳이 없었다(회로 `main` ↔ `PUB_INDEX` ↔ 컨트랙트 ↔ 서비스 검증 ↔ 개봉 ↔ 화면의 29칸).
- **I-1 발급 기록을 밀어내지 않는다**: 계정당 500개를 넘으면 오래된 것부터 버리던 것을, 5,000개(`CIA_AUID_S_LOG_MAX`)에서 **발급을 거절**하게 바꿨다(`auid_log_full`). 밀어내면 사용자가 발급을 되풀이해
  지난 거래의 기록을 스스로 지울 수 있었다(`key` 정책에서는 1회용 코드도 필요 없다). 대가: 그 수만큼 로그인한 계정은 더 발급받지 못한다 — 운영이라면 계정과 따로 둔 append-only 저장소가 맞다.
- **I-2 대가를 적었다**(§3 둘째 항목, `cia.js` 의 주석).
- M-6 서비스 관리자 화면이 `resolved: false` 를 "실패 — approved" 로 보이던 것을 "zkIdP 의 발급 기록에 없다" 로. M-7 재빌드 전(공개 입력 34개)의 로그인 로그 줄은 개봉에 쓰지 않는다.
  M-8 승인 경로의 `resolved: false`·상한 거절 테스트를 더했다(`tests/test_cia_opening.mjs`).
- **고치지 않은 것**: 계정 삭제가 기록도 지운다(M-1 — T6 에 적었다), 같은 `auid_s` 가 두 계정에 기록되면 첫 계정만 돌려준다(M-2 — 연결 해제 뒤 같은 비밀을 다른 계정에 등록하고 서비스가 `r_rp` 를 되풀이한 경우),
  세션키 다이제스트가 `auid_s` 를 덮지 않는다(M-3 — 세션마다 `pk_i` 가 새로 생겨 지금은 성립하지 않는다), 거절·미해결 뒤의 재요청과 대기 목록에 상한이 없다(M-4), `auidSLog` 가 상태 이행 검사에 없다(M-5),
  남은 옛 표기(M-9 — ABI 의 `BadTag`, `pub[30..33]` 주석 등), 개봉 요청 서명이 증명 자체를 덮지 않는다(M-10).

