# Mode 3 전체 코드 리뷰 — 2026-11-03 (Fable 5.1, 5영역)

기준: `feat/mode3-v11` HEAD 7e9eb25. 영역별 리뷰어(Claude Fable 5.1) 5명이 읽기 전용으로 점검했고, Important 전부는 컨트롤러가 코드로 재확인했다. 영역별 상세는 같은 폴더의 `A-idp.md`, `B-wallet-agent.md`, `C-rp.md`, `D-contracts-circuits.md`, `E-pages-snap.md`.

| 영역 | 범위 | Critical | Important | Minor |
|---|---|---|---|---|
| A | IdP 서버 `cia.js` + lib(state·issuance·registry·revocation·log·trace·attr_schema·imt_v2) | 0 | 3 | 12 |
| B | 지갑 에이전트 `mode3_wallet_agent.js` + lib(wallet·onchain·credential·rcl_sync) | 0 | 0 | 12 |
| C | RP `mode3_rp.js`·`lib/mode3_rp.js`·`rp.html`·`rp_admin.html` | 0 | 2 | 9 |
| D | 컨트랙트(Mode3Wallet·Factory·Log·Mirror·RootHistory·AttrGate) + 회로 pi_cred | 0 | 1 | 7 |
| E | 페이지(wallet·cia_*)·demo.js·gsi.js·Snap | 0 | 2 | 11 |
| 합계 | | **0** | **8** | **51** |

## Important (8건, 컨트롤러 재확인)

| # | 영역 | 내용 | 확인 |
|---|---|---|---|
| 1 | A | **기동 자동 게시가 거울 초기화보다 먼저 돈다** (`cia.js:355` → `publishNow` → `:1274 pruneMirroredBounds`, `initMirrors` 는 `:1687`). `MIRRORS.length===0` 판정으로 그 게시에 실린 (pk_i, c) 가 거울에 닿기 전에 `pendingBounds` 에서 지워진다. `lastPublication` 으로 한 번은 중계되므로, 중계가 실패하거나 그 전에 다른 게시가 끼면 거울 상한이 영영 빠진다 → 창 G 동안 폐기 세션 거래 통과(10-25 §2.2 위반). | 확인(조건부) |
| 2 | A | **무인증 `/cia/register_rp` 로 origin 선점** (`cia.js:593` `service_key_mismatch` 409 가 status 무관). denied 뒤에도 복구 경로 없음 → 진짜 RP 영구 잠금, `rps` 무제한 증가. 기존 테스트는 409 를 정상으로 단언. | 확인 |
| 3 | A | **무인증 경로의 동기 scrypt(~26 ms) + 요청마다 전체 persist** (signup·login·auth/code). 이벤트 루프 포화 → 하트비트 기아 → `RootTooOld` 로 전원 fail-closed. 로그인 무차별 대입 제한 없음. | 확인(설계 §10 은 루프 차단만 수용) |
| 4 | C | **재검증이 `REQUIRE_DISCLOSURE` 정책을 다시 보지 않음** (`mode3_rp.js:456-460` 이 새 증명의 disclosure·max_height 로 덮어씀; 정책 게이트는 로그인 `:409` 에만). 지갑 재검증 π 는 disclosure=null 이라 zkTWO 세션이 속성 변경 뒤에도 재검증만으로 무기한 유지. | 확인 |
| 5 | C | **RP 개봉·관리자 API 무인증** (`/api/mode3/open`, `/open/:id`, `/logins`, `/txs`, `/sessions`) + 분리 데모 `MODE3_BIND_HOST=0.0.0.0` → LAN 누구나 개봉 요청·전 세션 PPID·pk_i 열람. 문서화된 데모 한계. | 확인(운영 전 필수) |
| 6 | D | **`Mode3Log._enforceRevocationQueue` 중첩 루프 + 무제한 `pendingList`** → 접수증 비축으로 publish 가스 초과·영구 차단 → maxRootAge 뒤 전원 `RootTooOld`. **2026-10-26 리뷰 Important 7·8 과 같은 주제** — 사용자가 10-27 에 "하지 않기로" 결정한 항목. | 확인(결정 유지 여부만) |
| 7 | E | **`CIA_ADMIN_OPEN=1` 에서 `requireAdmin` 이 헤더 존재조차 안 봄** (`cia.js:404-405`) → 본문 없는 승인 라우트(`/cia/rps/:arid/approve·deny`, `/cia/publish`)가 교차 사이트 폼 POST(CSRF) 로 눌린다. 공격자가 `register_rp` 로 올린 RP 를 관리자 브라우저로 승인 위조. A 도 Minor 로 같은 지적. | 확인 |
| 8 | E | **관리자 페이지의 되돌릴 수 없는 조작 3개가 확인창 없음** (`cia_admin.html:422-424, 470-472` RP 거절·개봉 승인·개봉 거절). 개봉 승인은 uid 영구 기록 = 조건부 프라이버시 해제. | 확인 |

## 조치(2026-11-03, 같은 날)

| # | 조치 |
|---|---|
| 1 | `cia.js`: `mirrorsReady` 플래그 — `initMirrors()` 전에는 "거울 없음" 정리를 하지 않고, 초기화 뒤 거울이 정말 없을 때 정리한다. |
| 2 | `cia.js`: 승인 전(pending·denied) 항목은 운영자 키(`rp_key`, 이름 일치)로 다시 등록해 pending 으로 되돌린다(arid 유지, 묶였던 슬롯 해제). 승인된 항목은 그대로 409. 미승인 항목 상한 `CIA_MAX_UNAPPROVED_RPS`(기본 200) 초과 시 새 origin 은 429. 테스트 `test_cia_accounts`. |
| 3 | 미조치(운영 전 결정): 비동기 scrypt·레이트리밋·persist 디바운스. |
| 4 | `mode3_rp.js`: 술어 검사를 `requiredPredicateReason` 으로 빼 로그인·재검증이 같이 쓴다. `mode3_wallet_agent.js`: 로그인 때의 `disclose`·`set` 을 세션에 남겨 재검증 π 에 다시 싣는다. 테스트 `test_mode3_user_core`(술어 없는 재검증 π → `predicate_unmet`). |
| 5 | 미조치(데모 한계 문서화 유지). |
| 6 | 미조치 — 2026-10-27 결정(게시 백로그 재설계 안 함) 유지. |
| 7 | `cia.js requireAdmin`: `CIA_ADMIN_OPEN=1` 에서도 GET 이외 요청은 `X-CIA-Admin-Secret` 헤더가 있어야 한다. 테스트 `test_cia_admin_open`. |
| 8 | `cia_admin.html`: RP 거절·개봉 승인·개봉 거절에 `confirmDanger`(문구 3개 추가). |

### Minor 조치(같은 날, 바로 고칠 수 있는 것만)

- B-M1 `/wallet/tx/record`: 대기 항목의 account 가 세션 계정과 다르면 `bound_wrong_account`; `clearAppliedBounds` 도 같은 계정의 항목만 지운다.
- E-M7 세 서버(IdP·RP·지갑 에이전트)에 `X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors 'none'`.
- E-M1·E-M2 지갑 승인 팝업: 여는 창(opener)의 메시지만 받고, 제목(서비스명)도 오리진 대조 뒤에 그린다. E-M3 popup_blocked 주석 정정.
- A-Minor 프로토타입 키 아이디(`constructor`·`__proto__`): 아이디 색인·운영자 맵을 자기 속성으로만 본다.
- C-M8 `MODE3_WALLET_AGENT_ORIGIN` 을 `new URL().origin` 으로 정규화(끝 '/' 함정).
- E-M9 사유 사전에 코드 8개 추가(`not_snap_mode`·`precheck_failed`·`session_witness_failed`·`registration_incomplete`·`oidc_cancelled`·`snap_empty`·`login_failed`·`secrets_mismatch`), `wallet_gsi_origin` 문구를 코드(hostname 만 검사)와 맞춤, 지갑 페이지의 사유 리터럴 전수 대조 테스트.
- 미조치 Minor: B-M2(RP 오리진의 `skipSync`)는 데모의 stale_root 시연이 RP 페이지에서 그 옵션을 쓰므로 유지. 나머지는 영역 보고서 참조.

## 권고 묶음

- **지금 고칠 것(작고 명확)**: 1(기동 게시를 `initMirrors()` 뒤로, 또는 기동 시 `pruneMirroredBounds` 보류), 2(denied·pending 에서 같은 origin 재등록 허용 + rp_key 검사, `rps` 상한), 4(재검증에 로그인과 같은 정책 게이트 적용), 7(open 모드에도 헤더 존재 요구 — 관리자 페이지는 이미 `open` 을 보냄), 8(`confirmDanger` 3곳).
- **운영 전 결정**: 3(scrypt 를 비동기 `scrypt` 로 + 로그인 레이트리밋 + persist 디바운스), 5(RP 관리자·개봉 API 에 시크릿 또는 로컬 바인드), 6(접수증 대기열 재설계 — 10-27 결정 재확인).

## Minor 묶음(51건, 상세는 영역 보고서)

- A: 프로토타입 키 아이디 409, `revokeSessionMessage` 범위, 세션 maxAge 없음, approve/deny 경합, `e.message` 노출, 무제한 묶음 게시(기존), 개봉 x_AA null 500(기존), 폐기 세션 기록 만료 정리로 사라짐, 1회용 코드 평문, 주석 불일치, 시드 alicepw 7자.
- B: tx/record 의 pendingBoundId 계정 미대조, RP 오리진의 `skipSync`, maxLifetime 대역 vs TTL+GRID, 레이트리밋·프로버 합치기 없음, session/witness 증인 미대조, 500 매핑 누락, 이벤트 정렬 가정, 동시 요청 경합, demoOverride 교차 소비, revoke 비대칭, 상태 파일 잔존, 소항목 7.
- C: 로그 전 세션 생성, σ 재전송, 로그인/세션 fail 기준 불일치, 릴레이 자원·동시 배포·RPC 프록시, open txHash 지역 검사, 무제한 배열, `e.message`, CORS 정규화, 국가 슬롯 하드코딩.
- D: 거울 root 나이 기준, 접수증 만료·epoch 결속, counter 32비트·LOGIN_COUNTER 겹침(문서화), rootWindow>maxRootAge 정책, 이월 2건, pk_trace 부분군 전제 위치. 회로: `<--` 무제약 신호 없음, 비교자 폭 넘침 없음, 미사용 공개 입력 없음, 검증기 34 입력 일치(IC↔zkey 짝은 확인 필요).
- E: 팝업 onMessage source 미대조·선점, 오리진 대조 전 서비스명 표시, popup_blocked 주석, Snap predicateLines 미검증 표시, reauth 표시, consentLogin 순서, X-Frame-Options 없음, wallet 비교 철자(확인 필요), reason 사전 누락 8개, snap.manifest allowedOrigins(확인 필요), registerBtn 클로저.

## 테스트 공백(요약)

기동+거울+pendingBounds, origin 선점 복구, 무인증 부하, approve/deny 경합, 큰 묶음 게시(가스), 재검증 정책 게이트, RP 노출면, 다른 계정 record/pendingBoundId, RP skipSync, maxLifetime 회귀, 동시성, 비정렬 로그, 컨트랙트 서명 길이·chainid 변조·UntrustedKeys·재진입, 회로 counter≥2^32·비불리언 경로·범위, 페이지 postMessage source·CSRF·confirmDanger.
