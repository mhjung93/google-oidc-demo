# Area C — Mode 3 RP(zkONE/zkTWO) 코드 리뷰 (feat/mode3-v11, HEAD 7e9eb25, 읽기 전용)

대상: `mode3_rp.js`(643줄) · `lib/mode3_rp.js`(210줄) · `mode3/rp.html`(906줄) · `mode3/rp_admin.html`(269줄) · `mode3/common/rp.css`(151줄).
대조: `docs/MODE3_DEMO.md`(RP·env·각본), 스펙 2026-10-25(root 창·counter) · 2026-10-22(폐기 counter 상한) · 2026-10-16(OIDC 래퍼), 전 감사 `docs/audits/2026-09-23-mode3/SUMMARY.md`, 수정 커밋 `c35b000`(E1·E2) · `3d26000`(uniqueMembers). `.env`·등록 파일·키 파일·상태 파일은 열지 않았다.

## 1. 한 줄 총평

성명(34개 공개 입력)·root·세션 바인딩·릴레이 calldata 검사는 전 감사와 10-26 수정 이후 빈틈 없이 닫혀 있고 Critical 은 없다. 남은 것은 **"로그인 때만 확인하고 세션 수명 동안은 다시 보지 않는" 정책 술어(REQUIRE_DISCLOSURE)와, 문서상 "데모용 인증 없음"으로 남겨 둔 관리자·개봉 API 가 VM 분리 데모(0.0.0.0 바인드)에서 그대로 LAN 에 열리는 점**이다.

## 2. 발견 사항 (심각도 순)

### C-I1 (Important) — 재검증이 정책 술어를 다시 보지 않아 zkTWO 세션이 속성 변경 뒤에도 무기한 유지된다

- 위치: `mode3_rp.js:442-463` (`/api/mode3/revalidate`), 특히 `:456-460`; 술어 검사는 `:415-428` 로그인 경로에만 있다.
- 문제: `REQUIRE_DISCLOSURE=1`(zkTWO) RP 는 로그인에서 `countrySet`·`minAge` 를 서버가 강제한다(`:409`). 그러나 재검증은 `verifyLogin` 만 통과하면 **`s.disclosure = discOf(v.disclosure)` 로 세션의 공개 조건을 새 증명의 것으로 덮어쓰고(`:458`), `s.max_height` 도 새 값으로 바꾸며(`:459`) 술어를 다시 요구하지 않는다**. 지갑 양쪽(`mode3_wallet_agent.js:1109` `proveSession(rsKey, synced, timings, null, src)`, `mode3/user/core/user_core.js:745` 같은 호출)은 재검증 증명을 항상 `disclosure = null`(mask 0, set 없음) 로 만든다. 따라서 정상 지갑으로도 zkTWO 세션은 첫 재검증 이후 `disclosure: {mask:'0', set:null}` 이 되고, 로그인 정책 "만 19세 이상, 허용 국가만" 은 세션 생성 순간 한 번만 보증된다.
- 실패 시나리오: (1) 사용자 A 가 zkTWO 에 술어를 만족해 로그인한다. (2) IdP 관리자가 A 의 country 를 허용 집합 밖으로 바꾼다(또는 등록부 갱신·재발급) → regRoot 가 바뀌어 `/api/mode3/request` 가 `revalidate_required`(`:481`). (3) A 의 지갑이 새 자격증명으로 **술어 없는** π 를 만들어 재검증 → RP `ok`. (4) A 는 zkTWO 를 계속 쓴다. 재검증이 `max_height` 를 새 증명의 값으로 재바인딩하므로(`:459`) 재검증을 반복하면 세션은 로그인 시점의 만료와 무관하게 무기한 산다 — 즉 **정책 재평가 지점이 영원히 오지 않는다**. 지갑을 고친 사용자라면 속성 변경 전에 세션을 열어 두는 것만으로 정책을 영구 우회한다.
- 최소 수정(택1 또는 조합): (a) `REQUIRE_DISCLOSURE` 이면 재검증에도 로그인과 같은 술어 검사를 적용(검사 블록을 함수로 빼서 두 경로에서 호출) — 이 경우 지갑 재검증이 세션의 원래 `disclose/set` 을 다시 실어야 하므로 지갑 변경이 따라온다(스펙 결정 필요). (b) 지갑 변경 없이 가려면 재검증에서 `s.disclosure` 는 덮어쓰지 않고(세션 생성 때 보증한 값 유지), `max_height` 재바인딩을 로그인 때의 상한(`min(new, 로그인 시 max_height)`)으로 제한해 세션 수명을 로그인 성명이 정하게 한다. 어느 쪽이든 C-4(2026-09-25) 의 "마지막 증명에 다시 묶는다" 결정과 충돌하는 부분을 스펙에 명시해야 한다.
- 테스트: 없음. `tests/test_mode3_demo_full.mjs:172-180`(막 3a) 은 로그인 직후 `disclosure.set.root` 만 본다; 재검증 뒤 세션 `disclosure`·정책 재평가를 보는 케이스가 어디에도 없다. `tests/test_mode3_user_core.mjs:216` 은 `REQUIRE_DISCLOSURE` 의 로그인 거절만 본다.

### C-I2 (Important) — 관리자·개봉 API 가 무인증이고, VM 분리 데모는 0.0.0.0 에 바인드한다 (문서화된 데모 한계 — 운영 전 필수)

- 위치: `mode3_rp.js:575`(`POST /api/mode3/open`), `:597`(`GET /api/mode3/open/:id`), `:608-609`(`/logins`·`/txs`), `:630`(`/sessions`), `:613`(`/logout`); 바인드 `:29` `MODE3_BIND_HOST`, `scripts/demo_split_start.sh:119` `MODE3_BIND_HOST=0.0.0.0`.
- 문제: 설계의 개봉 통제는 "RP 운영자 요청 + IdP 관리자 승인" 두 당사자다(`rp_admin.html:46` 문구, 설계 §6). 코드에서는 RP 쪽 당사자가 없다 — `/api/mode3/open` 은 누구나 호출하고, RP 는 `x_svc` 로 부분 복호(`D_svc`)를 만들고 `sk_service` 로 서명해 IdP 에 보낸다(`:586-590`). 응답의 `id`(IdP 가 만든 32바이트 난수) 를 받은 그 호출자가 `GET /api/mode3/open/:id` 로 승인 뒤 **uid 를 그대로 받는다**(IdP `cia.js:1670` 이 `uid` 를 돌려주고 RP 가 그대로 중계, `:603`). 또 `/api/mode3/sessions`·`/logins`·`/txs` 는 전 사용자의 PPID·pk_i·계정 주소·공개 조건을 익명에게 준다.
- 실패 시나리오: 분리 데모(IdP·zkONE·zkTWO VM, `.10/.11/.12`)에서 같은 LAN 의 임의 호스트가 `POST http://zkONE:3100/api/mode3/open {PPID}` → `id` 수신 → IdP 관리자가 "RP 운영자가 냈다" 고 믿고 승인 → 공격자가 `GET /api/mode3/open/:id` 로 uid 획득. 피해자 PPID 는 `/api/mode3/sessions` 로 전부 열람 가능하다. 운영자 승인은 거쳤지만 **RP 의 동의 없이** 열린다. 로컬(127.0.0.1) 바인드에서는 같은 머신 사용자만 가능.
- 최소 수정: `/admin` 페이지와 `/api/mode3/{open,open/:id,logins,txs,sessions}` 에 공유 비밀 헤더(IdP 의 `X-CIA-Admin-Secret` 과 같은 방식, `MODE3_RP_ADMIN_SECRET`) 를 요구하고 `rp_admin.html` 이 sessionStorage 에 넣어 보내게 한다. `rp.html` 이 자기 세션 생존 확인에 쓰는 `/api/mode3/sessions`(`rp.html:343·360·374`) 는 `/api/mode3/sessions/check` 로 바꾸면 전체 목록 공개가 없어진다(이미 지갑용으로 있다, `:623`). 바인드가 0.0.0.0 일 때 비밀이 없으면 기동 경고 또는 거부.
- 테스트: `tests/test_rp_server_exposure.js` 는 Mode 2 RP(:3000) 전용이다. Mode 3 RP 노출면(어느 라우트가 무인증인가) 테스트가 없다.

### C-M1 (Minor) — 로그인 트랜스크립트 기록 전에 세션이 만들어진다 (책임 추적 공백)

- 위치: `mode3_rp.js:431`(sessions.set) → `:437`(appendFileSync).
- 문제: 로그 쓰기가 실패하면(디스크·권한) 500 이 나가지만 세션·`logins` 는 이미 만들어졌다. 그 세션은 쓸 수 있는데 개봉 재료(트랜스크립트)가 없다 — `lastTranscriptOf` 가 이전 로그인을 돌려주거나 `no_transcript`.
- 수정: appendFileSync 를 `sessions.set` 앞으로 옮기고 실패 시 세션을 만들지 않는다(fail-closed).
- 테스트: 없음.

### C-M2 (Minor) — 재검증·세션 요청의 σ 가 재전송 가능하다 (현재 피해 없음)

- 위치: `lib/mode3_rp.js:125-127`(σ 는 `r_s` 위), `:207-209`(`${r_s}:${body}`), `mode3_rp.js:486`.
- 문제: 메시지에 nonce·시각이 없고 RFC6979 서명은 결정적이라 같은 세션의 같은 요청(`balance`)·같은 재검증 트랜스크립트는 바이트까지 같다. 관찰자가 재전송하면 `/request` 는 같은 답을 돌려주고, `/revalidate` 는 같은 root 가 최신인 동안 세션을 그 증명으로 다시 묶는다(실질 변화 없음). 설계 §8.4 의 "요청마다 새 σ" 는 body 가 다를 때만 성립한다. 지금의 RP 요청은 읽기(`balance`) 뿐이라 피해가 없지만, 상태를 바꾸는 요청을 붙이는 순간 재전송이 문제가 된다.
- 수정: 요청 메시지에 서버 발행 nonce 또는 `ts` 를 넣고 RP 가 최근 nonce 집합을 유지(지갑 `signSessionRequest` 규약 변경 수반). 지금 범위에서는 문서에 "세션 요청은 멱등 읽기만" 을 명시.
- 테스트: 재전송 케이스 없음.

### C-M3 (Minor) — 로그인은 RPC 장애 시 10분 캐시 뷰로 검증하지만 세션 요청은 fail-closed — 두 경로의 신선도 기준이 다르다

- 위치: `lib/mode3_rp.js:55-62`(`chainView` 캐시 폴백) vs `mode3_rp.js:477-479`(`refreshChainView().catch(() => null)` → 503).
- 문제: RPC 가 끊긴 10분 동안 새 로그인·재검증은 옛 head·root 로 통과(그 사이 폐기 미반영, `v.head` 가 멈춰 `expired`·`root_too_old` 가 발동하지 않음)하고, 같은 세션의 요청은 `chain_unavailable` 로 막힌다. 의도된 결정(테스트 `test_mode3_rp.mjs:347`)이지만 보수적 경로와 관대한 경로가 뒤바뀌어 있다 — 로그인(세션 생성)이 더 엄격해야 자연스럽다. **확인 필요**: 10분 캐시가 여전히 원하는 정책인지.
- 수정: `headMaxAgeMs` 를 블록 기준으로 낮추거나(예: maxRootAge 의 일부), 로그인도 `refreshChainView` 실패 시 503.

### C-M4 (Minor) — 릴레이: 속도 제한 이전의 무인증 CPU·RPC 소모, 동시 배포 경합

- 위치: `mode3_rp.js:518`(`computeAddress` RPC), `:520`(Groth16 검증), `:522`(속도 제한), `:527`(deploy).
- 문제: (1) 형식만 맞는 calldata 를 보내면 요청마다 RPC 1회 + Groth16 검증(수십 ms CPU) 을 속도 제한 전에 소비한다 — 설계 의도("틀린 증명이 남의 몫을 깎지 않게") 의 대가다. 전역 제한이 없어 단일 공격자가 CPU 를 점유할 수 있다. (2) 같은 미배포 계정에 동시 요청 둘이 오면 둘 다 `getCode === '0x'` 를 보고 `deploy` 를 호출 → 두 번째는 CREATE2 충돌로 revert, 릴레이어 가스 소모 + 500. (3) `/api/mode3/relay/:txHash`(`:544`) 는 임의 해시의 영수증을 중계하는 열린 RPC 프록시다.
- 수정: 전역(IP 또는 전체) 토큰 버킷을 Groth16 앞에, 배포 중인 PPID 집합(`deploying: Set`) 으로 중복 배포 차단, `relay/:txHash` 는 `relayedTxs` 에 있는 해시만.
- 테스트: 속도 제한(계정별)·bad proof 는 있음(`test_mode3_rp_relay.mjs:33·108`); 동시 배포·전역 제한은 없음.

### C-M5 (Minor) — `/api/mode3/open` txHash 경로가 지역 검사(arid·팩토리 계정) 없이 IdP 에만 의존 (전 감사 Minor 유지)

- 위치: `mode3_rp.js:565-573·583-590`.
- 문제: 임의 체인 트랜잭션(다른 RP 의 execute) 으로도 RP 가 `D_svc = x_svc·c1` 을 만들어 서명·전송한다. IdP 가 `wrong_arid`(`cia.js:1602`) 로 거절하므로 결과는 403 이지만, RP 가 자기 조각으로 임의 `c1` 의 부분 복호를 계산해 외부로 내보내는 경로가 무인증으로 열려 있다(수신자는 IdP 뿐이라 현재 실질 유출은 없다).
- 수정: `d.pub[PUB_INDEX.ARID] === String(reg.arid)` 와 `tx.to === factory.computeAddress(pub[0])` 를 릴레이와 같은 규칙으로 먼저 검사.
- 테스트: 없음(`test_mode3_demo_stack.mjs:210` 은 없는 해시 404 만).

### C-M6 (Minor) — 비제한 메모리: challenges·sessions·logins·relayedTxs·로그인 로그 전체 읽기

- 위치: `mode3_rp.js:306·312·337·339`, `lastTranscriptOf`(`:555`, 파일 전체 파싱).
- 문제: `/api/mode3/challenge` 는 무인증·무제한(TTL 120초 안에서 누적), `sessions` 는 `/request` 가 만료를 볼 때만 비워진다(요청이 없으면 영구), `logins`·`relayedTxs` 는 절대 줄지 않는다, 개봉마다 로그 파일 전체를 읽는다. 데모 규모에서는 무해.
- 수정: 세션 sweep(head 를 읽는 자리에서 `max_height` 지난 것 제거), logins/relayedTxs 상한, 챌린지 발급 IP 제한.

### C-M7 (Minor) — 오류 응답이 내부 메시지를 그대로 낸다

- 위치: `mode3_rp.js:439·462·491·530·542·551·595·605·637` (`detail: e.message`), `revertName` 의 `e.message` 폴백(`:506`).
- 문제: RPC URL·파일 경로·ethers 내부 문구가 익명 호출자에게 간다. 데모 디버그 편의 vs 정보 노출.
- 수정: 로그에만 남기고 응답은 `reason` 코드만(IdP 의 S4 원칙과 같게).

### C-M8 (Minor) — 릴레이 CORS 허용 오리진이 정규화 없이 문자열 비교

- 위치: `mode3_rp.js:502` `origin === WALLET_ORIGIN` vs `:373` `originList(...)` 정규화.
- 문제: `MODE3_WALLET_AGENT_ORIGIN` 끝에 `/` 가 있으면 health 는 되고 relay/logout/sessions/check CORS 만 조용히 깨진다(health 주석이 바로 이 함정을 적어 두었다).
- 수정: `toOrigin(WALLET_ORIGIN)` 과 비교.

### C-M9 (Minor) — `rp.html` 의 국가 집합 슬롯이 `1` 로 박혀 있다

- 위치: `mode3/rp.html:612` `set: { slot: 1, ... }` vs 서버 `COUNTRY_SLOT = slotIndexOf(schema, 'country')`(`mode3_rp.js:77`).
- 문제: 스키마가 달라지면(IdP 커스텀 스키마) 페이지는 슬롯 1 로 요청하고 서버는 `COUNTRY_SLOT+1` 을 요구해 `predicate_unmet`. `ensureAttrGate` 는 같은 전제를 명시적으로 검사하고 건너뛰지만 페이지는 안 한다.
- 수정: `rp_info.predicates.attrSchema` 에서 country 슬롯을 찾아 쓰거나 서버가 `countrySlot` 을 rp_info 에 싣는다.
- 테스트: `test_mode3_custom_schema.mjs` 는 country 없는 스키마만 본다.

## 3. 확인했고 건전한 것

- **공개 입력 34개 전부 결속·검사**(`lib/mode3_rp.js:82-118`): [0] PPID 출력, [1] arid, [2] pk_i(σ), [3] max_height(head ≤ · ≤ head+L), [4] chainid, [5] allowAgent ≤ 1, [6]/[7] rev/regRoot = 거울 최신(같은 블록 스냅샷, `:49-52`), [8-11] pk_CIA·pk_trace 고정, [12-13] c1 ≠ 항등원, [15] mask < 64, [16-27] mask 로 지움(C-2), [28-29] sel ≤ 6·sel 0 이면 root 0·정책 root 일치(I-2), [31] arid_s = Poseidon(arid, r_rp), [32] r_s = 소비한 챌린지, [33] = LOGIN_COUNTER. [14] c2·[30] auid_s 는 출력값(회로가 C_s 에 결속). 정규 10진 강제(C-1) → 정책 검사와 groth16 이 같은 값. 전부 Groth16 **앞**에서 걸러 CPU 를 아낀다.
- **proof 정규형**(E1, `canonicalProof`): 길이 선검사 뒤 BigInt, q 미만, 사영 좌표 고정, 모르는 키 폐기 — 로그인·기록·릴레이·개봉 재료가 같은 객체.
- **root 수락**: RP 는 N=1(최신만) — 2026-10-25 창(G) 설계가 "RP 경로 변경 없음" 으로 명시(§5), 컨트랙트보다 엄격. b′ root 나이(maxRootAge) 를 로그인·재검증·세션 요청 세 곳에서 같은 상한으로(C-1 반영). 팩토리 immutable 을 채택해 env 와 어긋나면 온체인 값, 조회 실패면 검증기 자체를 만들지 않는 fail-closed(D-I2·I-1 반영).
- **세션 바인딩·고정 방지**: r_s 는 서버 난수·검증 전 1회 소비(`:411`), pub[32]·σ 둘 다 r_s 위, arid_s 가 r_rp(IdP 미공개) 를 요구해 타 RP·타 챌린지 토큰 차단. 재검증은 PPID·pk_i 일치 요구(`session_mismatch`). 로그아웃·만료·대체는 묘비(removedSessions) 로 "지움/모름" 을 구분. 같은 PPID 세션 1개.
- **릴레이 calldata**: `value` 0 고정, `to` = `computeAddress(pub[0])`, 셀렉터 execute·pub 34·pub[1]=arid, 배포 **전** Groth16(E2), 계정별 속도 제한, `estimateGas ≤ cap` 뒤 전송(gasLimit ≤ cap), 영수증의 `Executed.success` 로 상태 — 릴레이어는 자기 팩토리의 계정 `execute` 만 부른다. 계정 안 서명 digest 가 chainid·address(this)·to/value/data/nonce·max_height·allowAgent·태그를 덮고 `pub[33] == payload.nonce`(CounterMismatch) 라 릴레이어가 payload 를 바꿀 수 없다. 재전송은 NonceMismatch 로 estimateGas 에서 400(가스 미소모).
- **개봉 요청 무결성**(RP 측 서명): `ts` 포함 EIP-191, c1·D_svc·PPID·arid 가 메시지에 결속; `cert_s`·IdP 조각 PoK(rogue key) 를 기동·등록 때 검증.
- **postMessage**(`rp.html:491-497`): `ev.origin === walletOrigin && ev.source === popup`, 결과의 `r_s` 대조, 송신은 `walletOrigin` 명시, 창 이름을 종류·r_s 로 분리. 팝업 쪽(`popup.js:121-144`) 도 `ev.source === window.opener`·cert 오리진 대조.
- **XSS**: 두 페이지 모두 서버·지갑·팝업 문자열은 `textContent`/`title`/`dataset` 만. `demo.js renderVerdict` 의 `innerHTML = ''` 은 비우기 용도이고 값은 전부 `textContent`. 브랜드는 `/^zk/i` 로 걸러 텍스트로만. `?ppid=` 는 숫자만.
- **CORS/CSRF**: 세션 라우트는 CORS 없음(동일 오리진), 지갑 오리진에만 relay/logout/sessions/check, health 는 정규화된 allowlist + `Vary: Origin`. `express.json` 만 받으므로 교차 사이트 폼 POST 는 `malformed`. 본문 256kb(IdP 와 동일).
- **비밀 경계**: 응답·`/api/mode3/logins`·`/sessions` 에 r_s 전문·auid_s 전문·sk_service·x_svc 없음(rsShort). 로그인 로그 0600. rp_info 에 실리는 cert_s·pk_trace·arid 는 지갑이 필요로 하는 공개값. health 에 PPID·arid 없음.
- **OIDC 래퍼 RP 부분**: `rp_info.oidc` 는 IdP `public_keys.oidc` 중계(enabled·provider 만 사용), Google 버튼은 `oidc.enabled && WEB()` 일 때만 같은 zk 로그인을 `provider:'google'` 로 열고 RP 는 토큰·Google 신원을 보지 않는다(스펙 §3.2 대로).
- 전 감사·10-26 수정 재확인: C-1(root 나이)·C-2(mask)·D-I2(팩토리 상수)·E1·E2·uniqueMembers·C-4(재검증 max_height·allowAgent 재바인딩) 모두 코드에 있고 테스트가 있다. 전 감사 Minor "revalidate 가 max_height·allowAgent 미갱신" 은 해소됐고, "txHash 경로 지역 검사"·"무제한 증가" 는 그대로다(C-M5·C-M6).

## 4. 테스트 공백

1. **재검증 뒤 정책**(C-I1): `REQUIRE_DISCLOSURE=1` RP 에서 로그인 → 재검증 → `/api/mode3/sessions` 의 `disclosure` 가 유지/재검증되는지, 속성 변경 뒤 재검증이 거절되는지.
2. **Mode 3 RP 노출면**(C-I2): 어떤 라우트가 무인증인지 고정하는 테스트(Mode 2 의 `test_rp_server_exposure.js` 대응물). 비밀을 넣으면 그 테스트가 회귀 방어가 된다.
3. 로그인 로그 쓰기 실패 시 세션 미생성(C-M1).
4. 세션 요청·재검증 트랜스크립트 재전송 거동(C-M2) — 지금은 "같은 답" 이 기대값이므로 최소한 문서화.
5. 릴레이 동시 요청(같은 미배포 PPID 2건) 과 전역 폭주(C-M4).
6. `/api/mode3/open { txHash }` 에 다른 RP 의 execute 해시 → 지역 거절(C-M5, 지금은 IdP 403 에만 의존).
7. 세션 만료 sweep·`removedSessions` 1000개 회전·챌린지 폭주(C-M6).
8. `MODE3_WALLET_AGENT_ORIGIN` 끝 `/` 일 때 relay CORS(C-M8).
9. 커스텀 스키마에서 country 슬롯 ≠ 1 인 경우 페이지 로그인(C-M9) — `test_mode3_custom_schema.mjs` 는 country 없는 스키마만.
10. `/api/mode3/request` 의 `expired` 분기(head > max_height 로 세션이 지워지는 것) 는 `verifyLogin` 수준(E-6) 에만 있고 라우트 수준 테스트가 없다 — **확인 필요**(grep 으로 `'expired'` 가 라우트 테스트에서 안 잡혔다).
