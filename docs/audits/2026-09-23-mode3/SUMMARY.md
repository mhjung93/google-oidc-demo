# Mode 3 전체 코드 점검 — 종합 (2026-09-23, HEAD 725f010 기준, 읽기 전용)

점검자 4명(A CIA / B 지갑·Snap·페이지 / C RP·회로 / D 컨트랙트·커버리지). 상세 보고서: A-cia.md, B-wallet.md, C-rp-circuit.md, D-contracts.md.
제외: lib/mode3_rcl_sync.js·tests/test_mode3_rcl_sync.mjs(진행 중 SDD), 문서에 이미 "한계"로 적힌 데모 동작.

## 판정
- **Critical 0** — 폐기 우회·비밀 유출·서명/증명 검증 우회·자금 손실 경로 없음.
- **Important 8**(A2·B1·C2·D3) — 코드 5, 문서-코드 불일치 3.
- Minor 33.

## Important (수정 후보)
| # | 위치 | 결함 | 실패 시나리오 | 방향 |
|---|---|---|---|---|
| A-I1 | cia.js:633 | 개봉 중복 판정 키가 (arid, c1)뿐 — c2·PPID 빠짐 | 지갑이 tag 난수 r 을 재사용하면 두 트랜스크립트가 같은 키 → 서비스가 B 세션 개봉을 요청해도 A 의 승인 항목 id 가 돌아와 A 의 uid·PPID 가 나감(책임 추적 오귀속) | dup 키에 c2·PPID 추가 |
| A-I2 | cia.js:420-432 (+lib/mode3_credential.js:66-77) | 관리자 POST /cia/accounts/:uid/attrs 가 본문 없음/짧은 배열을 0 패딩 | 본문 없는 요청 한 번에 속성 4칸이 0 이 되고 옛 C_u 리프가 append-only 트리로 게시돼 되돌릴 수 없음 | 이 엔드포인트만 길이 4 배열 필수(패딩은 발급 경로에 필요하니 유지) |
| B-I1 | mode3_wallet_agent.js /wallet/session/witness · mode3/wallet.html 재승인 분기 | 재승인 동의 창의 allowAgent 가 RP 요청 본문에서 오고 세션 실제 값과 대조 없음 | allowAgent=1 세션을 '0' 으로 재승인 요청 → 사용자는 "아니오"를 읽고 승인, 세션은 그대로 1 (동의 창 스푸핑; RP 쪽은 지난 SDD 에서 고쳤으나 지갑 쪽이 안 막음) | 팝업이 세션 실제 값을 쓰고 /wallet/session/witness 가 불일치 시 409 |
| C-1 | lib/mode3_rp.js:55-57 | RP 오프체인 로그인이 RevocationLog.lastPublishedBlock(root 나이)을 안 봄 | CIA 게시가 멈추면 온체인 execute 는 100블록 뒤 RootTooOld 로 멈추는데 오프체인 로그인은 계속 통과 — 하트비트 도입(2026-09-18)으로 스펙 §8.5 전제가 깨짐 | **정책 결정**: RP 도 root 나이 상한(컨트랙트와 같은 상수)으로 fail-closed 할지 |
| C-2 | lib/mode3_rp.js:53,79 → mode3_rp.js:240-244,342 → mode3/rp.html:117,215 | 회로는 mask 비트 0 슬롯의 lo/hi 에 제약 없음(정상)인데 RP 가 9워드를 mask 로 거르지 않고 세션·로그·API·화면에 실음 | mask=1 만 켜고 lo[1]=hi[1]=410 을 끼우면 화면·로그에 "국가 410 공개"처럼 보임(온체인 AttrGate 는 mask 확인 → 안전, RP 표시·기록 한정) | 기록·표시 전에 mask 로 lo/hi 마스킹 |
| D-I1 | docs/MODE3_DEMO.md:62 | 팩토리 initcode 가 생성자 9인자 전부(maxLifetime 포함)를 덮는데 주소 변경 경고엔 MODE3_MAX_ROOT_AGE 만 | 경고를 지킨 채 MODE3_MAX_LIFETIME_BLOCKS 만 바꿔도 PPID 계정 주소 전부 변경 → 잔액 접근 불가 | 문서 한 줄 |
| D-I2 | mode3_rp.js:121-128,146 | ensureFactory() 가 factoryAddress 있으면 조기 리턴 | 팩토리 배포 후 MODE3_MAX_LIFETIME_BLOCKS 를 바꾸면 온체인 immutable 과 오프체인 검증기 상한이 갈라짐 — "로그인은 되는데 execute 만 TooFarExpiry" | 기동 시 팩토리의 maxLifetime·maxRootAge 를 읽어 env 와 대조, 다르면 경고/거부(B M-7 과 같은 건) |
| D-I3 | scripts/run_tests.sh:13 · docs | contract 그룹이 build/mode3 zkey·wasm 을 전제(Mode3Wallet.test.mjs:17 before 훅) | 문서는 "hardhat 인프로세스만"이라 깨끗한 체크아웃에서 그룹 전체 실패 이유를 모름 | 문서 한 줄(+CLAUDE.md) |

## 주목할 Minor (운영 사고·잠복 함정)
- B M-1 pruneSessions 가 ProofCache 를 안 비움 → 같은 r_s 재로그인 시 옛 π 재사용으로 로그인이 조용히 깨짐(폐기 우회 아님).
- B 복구 불가 창: /wallet/register 201 직후 Snap storeRegistration 실패 → 영구 registration_incomplete/already_registered, 출구는 재시연 세트뿐인데 UI·문서 어디에도 없음.
- A: imt_v2.rebaseline 은 정렬 순서라 이벤트 재생 모델과 비호환(현재 미사용, 잠복 함정); docs/MODE3_DEMO.md:146-147 vs :226 "속성 변경 직후 publish" 지침 모순; 개봉 승인이 rps 항목 재검증 없이 x_AA null 이면 500·영구 pending.
- D: publishRoot leaves 무제한 + cia.js:530 청크 없음 → 큰 게시가 가스로 실패하면 전원 fail-closed; transcriptFromTx 주석("성공한 execute 만")이 사실과 다름(ok=false 에도 emit).
- B M-8: CSRF 방어가 express.json() 하나에 걸려 있고 Host 미검사(DNS 리바인딩 시 CORS 무력) — 데모 범위.
- C: /api/mode3/open txHash 경로 지역 arid·팩토리 미검사(CIA 검사에만 의존); challenges/sessions/logins 무제한 증가; revalidate 가 max_height·allowAgent 미갱신.
- B M-4/M-5: Snap 트랜잭션 동의 창이 data(호출 함수)를 안 보여 주고 serviceName 을 호출자 문자열 그대로 씀.
- D 커버리지 구멍: digest 의 chainid·to/value/data 변조, recovered==address(0), 팩토리 재배포 시 주소 변화, AttrGate no-disclosure 경로, 재진입 시나리오.

## 강점(재점검 불필요)
비밀 경계(persist replacer·stripSecrets·팝업 결과·로그 전부 확인) / 오리진 4겹 일관 / 회로 무제약 대입 0·공개 입력 23개 다섯 곳 일치(.sym·vkey 실증) / 컨트랙트 §5.3 순서 그대로·재진입·서명 가변성·꼬리 위조·교차 로그 재생 차단 / JS↔Solidity digest 독립 구현 대조 / 발급 원자성·게시 digest·크래시 복구 fail-closed.

## 결정 (2026-09-23, 사용자 "추천대로")
- **C-1 정책**: RP 오프체인 로그인도 컨트랙트와 같은 상한(`MODE3_MAX_ROOT_AGE`, 기본 100블록)으로 root 나이를 검사해 fail-closed 로 간다. 온체인과 오프체인의 폐기 보장을 같게 맞추고, 하트비트가 있어 정상 운영에선 영향이 없다.
- **수정 범위**: Important 8 + 주목 Minor(pruneSessions/ProofCache, 등록 직후 Snap 저장 실패 복구 창 문서화, 문서 내 publish 지침 모순) + RCL 증분 동기화 최종 리뷰 잔여 N1·N2·N4 를 한 묶음으로 계획 → SDD. 나머지 Minor 는 이 문서에 기록으로 남긴다.
- 이 점검은 HEAD `725f010` 기준이며, 이후 RCL 증분 동기화 커밋(`76bae84..cf3ff0c`)은 별도 최종 리뷰를 거쳤다(`lib/mode3_rcl_sync.js` 는 점검 제외 대상이었음).
