# 리뷰 E — Mode 3 브라우저 페이지 + MetaMask Snap (feat/mode3-v11, HEAD 7e9eb25, 2026-11-03, 읽기 전용)

대상: `mode3/wallet.html`(1660줄) · `mode3/cia_user.html` · `mode3/cia_login.html` · `mode3/cia_rp.html` · `mode3/cia_admin.html` · `mode3/cia_account.html` · `mode3/common/demo.js` · `mode3/common/gsi.js` · `mode3/common/strings.js`(참조 키·문구 대조만) · `snap-mode3/src/index.js`(271줄) · `snap-mode3/src/crypto.js` · `snap-mode3/snap.manifest.json` · `snap-mode3/test/rpc.test.mjs`.
대조한 서버 코드(주장 검증용, 수정 대상 아님): `mode3_wallet_agent.js`(D2 미들웨어 :430-460, `/wallet/config`·`/wallet/secrets/salt`·`/wallet/oidc/nonce`·`/wallet/register`·`/wallet/register/resume`·`/wallet/authorize/precheck`·`/wallet/login` 오리진 대조·`/wallet/self_revoke`), `cia.js`(`requireAdmin` :404, `/cia/auth/code` :800, `issueCode/peekCode/consumeCode` :489-512, 승인 라우트 :643/:658/:1287/:1635/:1653), `lib/mode3_wallet.js`(`normalizeDisclosure`·`normalizeSet`), `mode3/rp.html`(popupCall :478-508, authorizeRequest :512). 지난 점검 `docs/audits/2026-09-23-mode3/SUMMARY.md`·`B-wallet.md` 의 B-I1·M-1·M-5 수정은 코드로 확인했고 다시 적지 않는다(M-4 `data` 미표시·M-8 CSRF 는 "기록으로 남김" 항목이라 재보고하지 않되, 아래 I-1 은 M-8 과 다른 서버·다른 전제다).

## (1) 한 줄 총평

비밀 경계(s_u·sk_u 는 Snap 에만, 페이지는 통과만)·postMessage 오리진 대조·IdP 인증 창의 nonce+wallet 결속·GSI nonce 결속·관리자 시크릿 비노출은 모두 코드로 확인되며 **Critical 없음**; 남은 것은 데모 기본 설정(`CIA_ADMIN_OPEN=1`)에서 본문 없는 관리자 승인 라우트가 교차 사이트 폼 POST 로 눌리는 점(I-1)과 되돌릴 수 없는 관리자 조작(RP 거절·개봉 승인)이 `confirmDanger` 없이 한 번 클릭인 점(I-2), 그리고 Snap 동의 창의 공개 술어 값 미검증 등 Minor 11건이다.

## (2) 발견 사항 (심각도순)

### Critical — 없음

### Important

**I-1. `CIA_ADMIN_OPEN=1`(데모 스크립트 기본) 이면 본문 없는 관리자 승인 라우트가 교차 사이트 폼 POST(CSRF) 로 눌린다** — 교차 영역(cia.js), 관리자 페이지 흐름에 직결
- 위치: `cia.js:404-405` (`requireAdmin`: `if (ADMIN_OPEN) return next();` — 헤더 존재조차 보지 않음), `cia.js:643`(`/cia/rps/:arid/approve`)·`:658`(deny)·`:1287`(`/cia/publish`) — 세 라우트 모두 본문을 읽지 않는다. `mode3/cia_admin.html:131` 은 open 모드에서도 `X-CIA-Admin-Secret: open` 을 보낸다. `scripts/demo_web_reset.sh:79`·`scripts/demo_split_start.sh:127`·`scripts/new_rp.sh:107` 이 `CIA_ADMIN_OPEN=${ADMIN_OPEN:-1}` 로 기본 켠다. `cia.js` 전체에 `Sec-Fetch-Site`/`Origin` 검사 없음(grep), `express.urlencoded` 없음.
- 무엇이 틀렸나: 지갑 에이전트는 D2(`mode3_wallet_agent.js:430-460`)로 Origin/Sec-Fetch-Site 를 막았지만 IdP 는 그런 층이 없고, open 모드의 `requireAdmin` 은 커스텀 헤더도 요구하지 않는다. JSON 본문이 필요한 라우트(`/cia/revoke` 등)는 `express.json()` 때문에 폼 POST 가 400 으로 막히지만(지난 점검 B M-8 의 논리), **본문이 없어도 동작하는 승인·거절·게시 라우트는 그 방어가 없다.** `/cia/register_rp`(`:572`)는 인증 없이 누구나 부를 수 있어 공격자는 자기 RP 의 `arid` 를 안다. 개봉(`/cia/openings/:id/*`)의 id 는 32바이트 난수(`:1628`)라 추측 불가 — 이 라우트는 영향 없음.
- 실패 시나리오: 데모 기본 설정으로 IdP(:4100) 가 떠 있는 기계의 브라우저에서 관리자가 아무 외부 사이트를 연다. 그 사이트가 `<form method=POST action="http://127.0.0.1:4100/cia/rps/<공격자 arid>/approve">` 를 자동 제출(또는 `fetch(..., {mode:'no-cors'})`) → 응답은 못 읽어도 요청은 실행돼 공격자 RP 가 **관리자 승인 없이 approved** 되고 인증서(`cert_s`)·추적 조각을 받는다. 같은 방식으로 정당한 pending RP 를 `deny`(되돌릴 수 없음)하거나 `/cia/publish` 를 임의 시점에 누를 수 있다. `cia.js:1705` 의 경고("이 IdP 에 닿는 누구나")는 네트워크 도달을 전제한 문장이고, 브라우저 CSRF 는 그 범위를 "그 기계에서 열린 모든 웹 페이지"로 넓힌다.
- 최소 수정: `requireAdmin` 의 open 분기를 `/cia/revoke`(`cia.js:1039`)와 같은 규칙으로 — `ADMIN_OPEN` 이면 **헤더가 문자열로 존재할 때만** 통과(`typeof req.get('X-CIA-Admin-Secret') === 'string'`). 커스텀 헤더는 preflight 를 강제하므로 CORS 없는 IdP 에서 폼·no-cors POST 가 막힌다. 관리자 페이지는 이미 `'open'` 을 보내 동작 변화 없음. 더 넓게는 지갑의 D2 와 같은 Origin/Sec-Fetch-Site 미들웨어를 IdP 에도 두는 것.
- 테스트: 없음. `tests/test_mode3_cia_state.js`·`test_mode3_demo_stack.mjs` 에 "ADMIN_OPEN=1 에서 헤더 없는 POST /cia/rps/:arid/approve 는 401/403" 단언 추가.

**I-2. 되돌릴 수 없거나 프라이버시를 해제하는 관리자 조작이 `confirmDanger` 없이 한 번 클릭이다**
- 위치: `mode3/cia_admin.html:422-424`(`decideRp(e,'approve'|'deny')`), `:470-472`(`decideOpening(o,'approve'|'deny')`), `:438-444`, `:486-500`. 비교: 계정 폐기 `:386`, 세션 폐기 `:376`, tamper `:310`, 게시 `:623` 은 모두 `Demo.confirmDanger(...)` 를 거친다.
- 무엇이 틀렸나: 보안 목표 "confirmDanger must gate destructive actions" 에 어긋난다. 같은 페이지의 설명문(`admin_rps_desc` "거절은 되돌릴 수 없습니다", `admin_openings_desc` "승인하면 … uid 를 기록합니다")이 되돌릴 수 없음을 말하면서 버튼은 즉시 실행한다. 특히 **개봉 승인은 사용자의 uid 를 영구 기록하는 조건부 프라이버시 해제 결정**인데 표 안의 작은 버튼 하나다.
- 실패 시나리오: 관리자가 "RP" 표에서 승인을 누르려다 바로 옆 "거절" 을 누르면(두 버튼이 공백 하나 사이) 그 RP 는 영구 거절되고 운영자는 다시 만들어 재승인을 받아야 한다. 개봉 요청 표에서 오클릭 한 번으로 요청 대상 사용자의 uid 가 IdP 기록에 남는다. 오클릭이 아니라도 I-1·M-7 과 결합하면 사용자 확인 단계가 없다는 점이 공격 면을 키운다.
- 최소 수정: `decideRp` 의 `deny`, `decideOpening` 의 `approve`·`deny` 앞에 `if (!Demo.confirmDanger('confirm_rp_deny'|'confirm_open_approve'|'confirm_open_deny')) return;` 와 사전 키 3개(`strings.js` ui) 추가. 승인(approve RP) 은 되돌릴 수 있는지(거절 가능) 확인 뒤 결정.
- 테스트: `tests/test_mode3_browser.mjs` 는 관리자 승인을 API 로 직접 한다(페이지 경로 없음). 페이지 경로에 `page.on('dialog')` 로 confirm 이 뜨는지 단언 추가.

### Minor

**M-1. 지갑 팝업 `onMessage` 가 `ev.source === window.opener` 를 보지 않고, 오리진 대조 전에 `handled = true` 로 잠근다**
- 위치: `mode3/wallet.html:673-699`(`handled = true; removeEventListener` 가 `ev.origin !== req.origin` 검사보다 앞), `:579`(등록 응답은 `ev.source` 로 보내지만 수신 쪽 검사는 없음). 비교: `cia_user.html:208`, `rp.html:492` 는 `ev.source === popup` 을 본다.
- 시나리오: RP 페이지 안의 제3자 iframe(광고 등)이 같은 브라우징 컨텍스트 그룹에서 `window.open('', '<RP 가 쓴 창 이름>')` 으로 팝업 핸들을 얻어 아무 `mode3-authorize` 를 먼저 보내면, 팝업은 `origin_mismatch` 로 끝나며 리스너를 떼고 3초 뒤 닫힌다 → 정당한 RP 요청이 매번 실패(DoS). 비밀 유출은 없다(응답은 `window.opener` 로, 대상 오리진은 `ev.origin`).
- 수정: `if (ev.source !== window.opener) return;` 를 맨 앞에 두고, `handled` 는 오리진 대조를 통과한 뒤 설정.
- 테스트: `test_mode3_browser.mjs:407` 은 오리진 불일치만 본다. opener 가 아닌 창의 선점 시나리오 없음.

**M-2. 오리진 대조 전에 RP 가 보낸 서비스 이름이 제목에 그려진다**
- 위치: `mode3/wallet.html:693-694`(`lastAuthReq = req; renderAuthTitle();`) 가 `:695` 의 `ev.origin !== req.origin` 보다 앞. `:700` 주석("요약은 오리진 대조를 통과한 뒤에만")은 요약(`renderAuthSummary`)에만 적용된다.
- 시나리오: 임의 페이지가 팝업을 열어 `serviceName:'국민은행'` 을 보내면 3초간 "국민은행의 요청을 승인하는 중" 제목이 보인다(위생은 거침, 동의 창은 뜨지 않음). 영향은 표시뿐.
- 수정: `lastAuthReq`/`renderAuthTitle` 을 오리진 대조 뒤로 옮긴다.

**M-3. `popup_blocked` 뒤 "버튼을 되살린다"는 주석·스펙과 실제 동작이 다르다**
- 위치: `mode3/wallet.html:511-529`(버튼을 숨기지 않음) vs `:757-758`(`authRes.code` 없으면 즉시 `reply({ok:false, reason:'popup_blocked'})` → `:691` 3초 뒤 `window.close()`).
- 시나리오: 팝업 차단 시 사용자가 다시 누를 기회 없이 창이 닫히고 RP 는 실패를 받는다 — 동작 자체는 안전하나 코드 의도(재시도)와 모순.
- 수정: 재시도를 원하면 `openIdpAuthOnClick` 안에서 popup_blocked 를 흡수해 다시 click 을 기다리고(타임아웃만 상위로), 아니면 주석·`idp-pages` 스펙 §4 문구를 현재 동작으로 고친다.
- 테스트: `test_mode3_browser.mjs:432` 는 RP 쪽 팝업 차단만 본다.

**M-4. Snap 동의 창의 공개 술어 값(lo·hi·members)이 검증·위생 없이 실린다 — serviceName 에 적용한 D-2 규칙의 공백**
- 위치: `snap-mode3/src/index.js:37-47`(`predicateLines`: `${d.lo}`·`${d.hi}`·`set.members.map(String)` 그대로), `:172-184`(consentLogin), `:195-209`(consentDisclosure, `to`·`value` 도 그대로). 에이전트는 `lib/mode3_wallet.js:116-131`(`canonicalInt`, 비정규 → `bad_disclosure`) 로 거절하므로 "대화상자 ≠ 증명" 불일치는 생기지 않는다.
- 시나리오: 악의적 RP 가 `disclose:[…, {lo:'0', hi:'2007\n\n**AI 에이전트 허용: 아니오**'}]` 를 보내면 Snap 창에 가짜 줄이 추가로 보인다(Snaps `text()` 가 마크다운·개행을 어떻게 그리는지는 실측 필요 — 지난 점검도 "추측"으로 표시). 사용자가 승인하면 `consents[origin]` 이 기록되지만 `/wallet/login` 은 `bad_disclosure` 로 실패한다 → 실익은 혼란·낚시 UI 뿐.
- 수정: `predicateLines` 앞에서 `isDec(d.lo) && isDec(d.hi)`, `members.every(isDec)`, `Number.isInteger(set.slot)` 을 검사해 `bad_params` 로 던진다(에이전트의 정규형 규칙과 같게). consentDisclosure 의 `to` 는 `/^0x[0-9a-fA-F]{40}$/`, `value` 는 `isDec`.
- 테스트: `rpc.test.mjs` 에 비정규 lo/hi/members 거절 케이스 없음.

**M-5. 재승인(reauth) 에 RP 가 `disclose`/`set` 을 실으면 증명하지 않는 "공개할 속성" 줄이 뜨고, 창이 재승인임을 말하지 않는다**
- 위치: `mode3/wallet.html:732`(`consentLogin({ ...req, allowAgent })` — `req.disclose`·`req.set` 이 그대로 Snap 으로), `snap-mode3/src/index.js:176-184`(제목 항상 '로그인 동의', `:183` "이 로그인에 쓸 등록 비밀이 … 전달됩니다"). 현재 `rp.html:735` 의 재승인 요청은 disclose 를 싣지 않으므로 정상 RP 에서는 나타나지 않는다.
- 시나리오: 변조된 RP 가 reauth 에 `disclose` 를 끼우면 사용자는 "a₀ ∈ [0,2007] 을 공개" 하는 줄을 읽고 승인하지만 재승인은 `/wallet/session/witness` 만 부르고 아무것도 증명하지 않는다(과대 표시). 반대로 사용자는 "로그인"인지 "기존 세션 재승인"인지 구분할 수 없다.
- 수정: reauth 분기에서 `disclose:null, set:null` 로 넘기고, Snap `consentLogin` 에 `reauth` 플래그를 받아 제목·안내문을 '세션 재승인' 으로 바꾼다.

**M-6. `consentLogin` 이 대화상자를 띄운 뒤에 등록 완전성(`buildWitness`)을 검사한다**
- 위치: `snap-mode3/src/index.js:171`(requireRegistered — uid 만 봄) → `:176` confirm → `:186` buildWitness(sk_u 64자 hex·attrs 배열 검사). `rpc.test.mjs:182-188` 이 그래서 `answers.push(true)` 를 먼저 해야 한다.
- 시나리오: `storeRegistration` 이 끝나지 않은(attrs=null) 상태에서 사용자가 동의 창을 승인한 뒤 `registration_incomplete` 를 받는다 — 사용자는 "승인했는데 왜 실패" 를 겪고, `consents[origin]` 기록 직전에 던지므로 기록은 남지 않는다.
- 수정: `buildWitness` 의 형식 검사를 별도 함수로 떼어 confirm 전에 부른다.

**M-7. 세 서버 어느 HTML 응답에도 `X-Frame-Options`/`frame-ancestors` 가 없다**
- 위치: `mode3_wallet_agent.js`·`cia.js`·`mode3_rp.js`·`lib/*.js` 에 해당 헤더 설정 없음(grep). 영향 범위: IdP `/user`·`/rp` 는 쿠키 세션(SameSite 기본 Lax → 교차 사이트 iframe 에서 쿠키 미전송)이고 관리자 "기억" 은 `sessionStorage`(최상위 사이트별 분할)라 프레임 안에서는 대체로 무력하지만, **`CIA_ADMIN_OPEN=1` 관리자 페이지와 file 모드 지갑 페이지는 프레임 안에서 그대로 동작**한다(D2 는 iframe 자신의 same-origin fetch 를 통과시킨다). `?authorize=1` 팝업은 `window.opener` 가 없으면 멈추므로 프레이밍 불가.
- 시나리오: 외부 페이지가 `/admin` 을 투명 iframe 으로 덮어 "개봉 승인"(I-2 와 결합: 확인창 없음) 또는 "RP 승인/거절" 위치에 클릭을 유도. file 모드 지갑에서는 "보내기"(기본값 사망 주소·0 wei 라 실익 작음).
- 수정: 세 서버의 HTML 라우트(또는 전역)에 `res.set('X-Frame-Options','DENY')` + `Content-Security-Policy: frame-ancestors 'none'`. 팝업은 최상위 창이라 영향 없음.

**M-8. IdP 인증 창의 `wallet` 쿼리 엄격 비교 ↔ Snap 두 철자 허용 ↔ GSI `localhost` 전용의 조합** — 확인 필요
- 위치: `mode3/cia_login.html:317`(`walletQuery !== walletOrigin`, 글자 그대로), `cia.js:72`(기본 `http://127.0.0.1:5100`), `snap-mode3/src/index.js:16-19`(두 철자 허용), `mode3/common/gsi.js:452`(`hostname === 'localhost'`), `strings.js:262`(`wallet_gsi_origin` "http://localhost:5100 에서만").
- 시나리오: Google 등록을 위해 지갑을 `localhost:5100` 으로 연 사용자가 같은 브라우저에서 **데모 계정** 으로 RP 로그인하면 인증 창이 `idp_auth_bad_wallet` 로 폼을 막는다(IdP 가 아는 지갑은 `127.0.0.1:5100`). 보안상 올바른 거절이지만 데모 혼선 — `docs/MODE3_DEMO.md:203` 은 127.0.0.1 로, Google 안내는 localhost 로 열라고 한다. 분리 VM 구성은 `MODE3_WALLET_AGENT_ORIGIN` 으로 맞출 수 있으므로 설정 문제일 수 있다(확인 필요).
- 수정: 런북에 "한 브라우저에서 두 경로를 섞으려면 `MODE3_WALLET_AGENT_ORIGIN`·`MODE3_WALLET_PUBLIC_ORIGIN` 을 localhost 로 통일" 한 줄, 또는 IdP 가 두 철자를 허용 목록으로 받기.

**M-9. 사전(strings.js) — RP 로 돌려보내는 사유 코드 8개가 `reasons` 에 없고, 문구 하나가 코드와 어긋난다**
- 없는 코드(스크립트 대조): `not_snap_mode`(wallet.html:590,702), `precheck_failed`(:721), `session_witness_failed`(:735), `registration_incomplete`(:793), `oidc_cancelled`(:543), `snap_empty`(:623), `login_failed`(:776), `secrets_mismatch`(에이전트 `/wallet/register/resume` → :614). `Demo.reason()` 이 null 을 돌려 RP·IdP 화면에 코드만 보인다(동작 문제 아님).
- 문구: `wallet_gsi_origin` "http://localhost:5100 에서만" 은 포트까지 고정하지만 `gsi.js:452` 는 hostname 만 본다(다른 포트의 localhost 도 허용). `ui`·`verdicts`·`terms` 참조 키는 전부 존재(data-i18n·tt·tte·confirmDanger 전수 대조).
- 테스트: `tests/test_mode3_demo_strings.js` 가 이 코드들을 잡지 못했다 — 페이지 소스에서 `reason: '…'` 리터럴을 뽑아 `reasons` 와 대조하는 단언 추가.

**M-10. Snap 매니페스트가 플랫폼 수준 오리진 제한(`endowment:rpc.allowedOrigins`)을 쓰지 않는다** — 확인 필요
- 위치: `snap-mode3/snap.manifest.json:12-14`(`"endowment:rpc": { "dapps": true }`), `package.json:13`(`@metamask/snaps-sdk ^1.4.0`). 오리진 검사는 `index.js:94-96` 코드 한 겹이다(테스트 `rpc.test.mjs:61-74` 로 모든 RPC 에 대해 검증됨).
- 수정: 플랫폼이 지원하는 버전이면 `"allowedOrigins": ["http://127.0.0.1:5100","http://localhost:5100"]` 를 추가해 두 겹으로. SDK 1.4.0 에서 지원되는지 실측 필요.

**M-11. `registerBtn` 결과 카드 생성기가 응답 `b` 를 붙잡는다 — 주석과 어긋남(비밀은 없음)**
- 위치: `mode3/wallet.html:1222-1226` 주석("카드가 들고 있는 인자에도 남기지 않는다 … 먼저 꺼내 둔다") vs `:1236` `() => ({ summary: tt(..., { uid, attrs: profileText(b.profile) }), detail })` 가 `b` 를 클로저로 잡는다. `/wallet/register` 201 응답(`mode3_wallet_agent.js:703`)은 `{uid, slot, auid, attrs, profile, provider}` 로 비밀이 없어 실제 유출은 없다.
- 수정: `const profile = b.profile;` 로 먼저 꺼내 쓰거나 주석을 고친다.

## (3) 점검했고 문제 없음 (구체 항목)

- **비밀 경계(페이지)**: `wallet.html:324` `safeDetail` 이 `sk_u·s_u·pwd·witness·userCredIssued·attrsChanged` 를 모든 '자세히' 에서 제거; `:782` RP 로 돌려주기 전 `userCredIssued·attrsChanged` 구조분해 제거; `:1597-1599` 자기 폐기 응답 `r`(pwd 포함)은 `uid` 만 꺼내 쓰고 카드 생성기에 넘기지 않음; `:1162-1182` salt 는 `console.warn` 에 값 없이 실패만, 5초 뒤 자동 가림(`SALT_REVEAL_MS`), 등록 소멸 시 즉시 가림(`:907`); `/wallet/status`(`mode3_wallet_agent.js:557-580`)는 `s_u·sk_u·witness` 를 싣지 않음(`$('status')` 원문 표시 안전).
- **Snap 비밀 경계**: `getPublicInfo` 가 비밀을 싣지 않음(`index.js:161-167`, 테스트 `:165-178` 키 집합 고정); `showSalt` 대화상자에 값 미표시(`:135`); `selfRevoke` pwd 미저장(`:236-238`, 테스트 `:300-307`); `reset` 뒤 비밀 잔존 없음(테스트 `:343-354`); `prepareRegister` 재호출이 같은 비밀을 돌려 nonce 결속 유지(`:123-124`).
- **Snap 오리진 검사**: `index.js:94-96` 이 switch 앞에 있어 거절 호출은 상태도 대화상자도 만들지 않음(테스트 `:61-74` 가 소스에서 RPC 목록을 뽑아 전수 검사).
- **Snap 동의 창 = 증명 값**: `consentLogin` 의 `allowAgent` 정규화('1'/'0')가 대화상자 표시와 기록·`/wallet/login` 본문(`wallet.html:765`)에서 일치; 재승인은 `precheck` 가 돌려준 세션 실제값만 쓰고(`wallet.html:727-734`) 없으면 동의 창 전에 중단(B-I1 수정 확인); `consentRevokeSession` 의 `bound` 가 입력칸 → 대화상자 → `/wallet/session/revoke` 본문까지 같은 문자열(`wallet.html:1127-1140`); `consentDisclosure` 는 `sanitizeDisclose()` 뒤의 `f` 를 그대로 `/wallet/tx/prepare` 에 보냄(`:1405-1412`); `cleanServiceName` 이 Snap·페이지 양쪽 동일(`index.js:28-34`, `wallet.html:441-447`, 테스트 `:223-238`).
- **postMessage 흐름**: 팝업 → RP 응답은 `window.opener` + 대상 오리진 `req.origin`(일치 시)·`ev.origin`(불일치 시)로만(`wallet.html:687-689`), ready 신호 `'*'` 에는 비밀 없음; 등록 응답은 `ev.source`+`ev.origin`(`:579`); `cia_user.html:206-216` 은 `ev.origin === walletOrigin0 && ev.source === popup` 두 겹 + 요청 시점 오리진 고정(`:192`), 등록 코드는 지갑 오리진으로만(`:209`); `rp.html:489-497` 도 같은 두 겹 + `r_s` 대조. 지갑은 메시지의 `ciaUrl` 을 쓰지 않고 `cfg.ciaUrl`(같은 오리진 `/wallet/config`)로 IdP 오리진을 정한다(`wallet.html:584`).
- **IdP 인증 창 결속**: 지갑이 16바이트 난수 nonce 를 만들고(`wallet.html:495`) `wallet=location.origin` 을 붙여 열며, 수신은 `ev.origin === ciaOrigin && nonce 일치` 둘 다(`:503`), 60초·창 닫힘 처리; `cia_login.html:312-317` 은 nonce·wallet 둘 다 있어야 하고 `wallet` 이 자기 `/mode3/health.walletOrigin` 과 글자 그대로 같을 때만 폼을 열고, 코드·오류는 그 검증된 오리진 하나로만 `postMessage`(`:323,:340`, `'*'` 없음); `:283` 비동기 초기화 전 Enter 제출 차단; 쿼리의 `wallet` 로 탐색·리다이렉트하지 않음(오픈 리다이렉트 없음). 서버는 코드를 `{uid, purpose, auid}` 에 묶고 1회 소진(`cia.js:489-512`, `:980`).
- **GSI nonce 결속**: `oidcToken` 이 `/wallet/oidc/nonce`(same-origin 전용) 결과를 그대로 `Mode3Gsi.render({nonce})`(`gsi.js:471`) 에 넣고 토큰을 `/wallet/register`·`/wallet/login`·`/wallet/self_revoke` 로만 넘김(변수·DOM·저장소 잔존 없음, `googleToken` 완료 시 `box.replaceChildren()`); 에이전트는 `reg:H(pk_u)`·`issue:H(pk_u|arid_s)` 를 계산하고 IdP 가 대조(`cia.js:825,:922,:934`); `gsiPrecheck` 가 Snap 보류 등록을 만들기 전에 실행(`wallet.html:630`).
- **관리자 시크릿**: 요청 헤더로만(`cia_admin.html:151,:158`), `#out` 은 메서드·경로·응답만(`:154`), `safeDetail` 로 `secret·pwd·sig_u` 제거(`:162`), URL 미사용, 기억은 옵트인 sessionStorage 로 안내문과 일치(`:28-31,:124-126`).
- **XSS**: 여섯 페이지·demo.js 의 서버/사용자/Snap 문자열은 모두 `textContent`·`createElement`·`replaceChildren`(`renderVerdict` `demo.js:72-83`, 표 생성 `cia_admin.html:192-231`, `shortCode`·`kvRow` `wallet.html:827-841`). `innerHTML` 은 비우기(`''`)와 고정 틀(`demo.js:26,:45,:134,:256`, 값은 숫자 `i+1`)뿐. `a.href` 에 들어가는 URL 은 전부 자기 서버 health/config 값(`cia_user.html:103`, `wallet.html:1626`, `cia_account.html:802`).
- **confirmDanger 적용 확인**: 지갑 세션 폐기·자기 폐기·Snap 초기화(`wallet.html:1123,:1582,:1606`), IdP 사용자 계정 폐기(`cia_user.html:174`), 계정 페이지 두 경로(`cia_account.html:787,:822`), 관리자 계정 폐기·세션 폐기·tamper·게시(`cia_admin.html:386,:376,:310,:623`); 폴백 `Demo` 에도 사전을 읽는 `confirmDanger` 있음.
- **반쯤 된 등록 복구**: `/wallet/register/resume` 이 Snap 의 보류 비밀로 `pk_u`·`auid` 를 재계산해 대조하고 상태를 바꾸지 않음(`mode3_wallet_agent.js:709-725`); 페이지는 `getPublicInfo.pending` 일 때만 이 경로(`wallet.html:609`).
- **D2 미들웨어와 페이지의 전제 일치**: 페이지가 부르는 비공개 라우트(`/wallet/login`·`/wallet/tx/prepare`·`/wallet/secrets/salt`·`/wallet/demo/override`·`/wallet/self_revoke` 등)는 모두 same-origin 전용이고 `/wallet/config`·`/wallet/attr_schema`·`/common/*`·`/` 만 공개 GET(`mode3_wallet_agent.js:440`).
- **cia_rp.html**: RP 키는 응답 직후 메모리(`justCreated`)에만, 로그아웃·세션 소멸 시 비움(`:493,:527`); 표는 textContent.

## (4) 테스트 공백

1. Snap(`rpc.test.mjs`): 비정규 `lo/hi/members`·비주소 `to` 거절(M-4); reauth 요청의 disclose 표시(M-5); `consentLogin` 이 불완전 등록을 **대화상자 전에** 거절하는지(M-6, 현재 테스트가 answers 를 먼저 넣어야 하는 것이 그 증거); `consentDisclosure` 가 미등록 상태에서도 뜨는 것이 의도인지 명시 단언 없음.
2. 브라우저(`test_mode3_browser.mjs`): opener 가 아닌 창의 `mode3-authorize` 선점·`ev.source` 검사(M-1); `popup_blocked` 뒤 지갑 팝업 쪽 재시도 동작(M-3); 관리자 페이지 경로의 confirm 게이트(I-2 — 지금은 API 로 승인); `CIA_ADMIN_OPEN=1` 에서 헤더 없는 교차 사이트 POST `/cia/rps/:arid/approve` 거부(I-1); 프레임 헤더(M-7); `localhost`·`127.0.0.1` 혼합 구성(M-8); snap 모드 "보기" 뒤 5초 자동 가림과 그 동안 콘솔·저장소에 s_u 가 없는지(`:238` 은 버튼 존재만 보는 것으로 읽힘 — 확인 필요).
3. 사전(`test_mode3_demo_strings.js`): 페이지가 RP 에 내는 `reason` 코드 전수가 `reasons` 에 있는지(M-9 의 8개가 빠져 있었다).
4. 관리자 페이지: `sessionStorage` 기억이 "이 창에서만" 인지(새 탭에서 비어 있는지) 단언 없음; `#out` 에 헤더 값이 섞이지 않는지의 자동 검사 없음(코드로는 안전).
