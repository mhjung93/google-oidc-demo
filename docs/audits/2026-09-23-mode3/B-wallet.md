# 점검자 B — 지갑 에이전트 · Snap · 브라우저 페이지 (읽기 전용, HEAD `64cf579`, `feat/mode3-cia`)

> **점검 중 워킹트리 변경 있음**: `mode3_wallet_agent.js` 가 점검 도중 디스크에서 바뀌었다 — 폐기 트리 동기화가 `lib/mode3_wallet.js` 의 `syncRevocationTree` 에서 (점검 제외 대상인) `lib/mode3_rcl_sync.js` 의 `createRevocationSync(...).sync()` 로 갈아끼워졌고, `proveSession` 이 π 를 `cached.revRoot` 와 `synced.root` 두 키로 캐시한다. 아래 줄번호는 **바뀌기 전 판**을 가리키지만 라우트·검증 구조는 그대로라 I-1·M-1~M-10 의 판정은 유효하다(M-11 만 문구를 조정했다). 새 동기화 모듈 자체는 공통 지침대로 점검하지 않았다.

## 1. 판정 요약

1. **비밀 경계는 튼튼하다.** `persist()` 의 replacer 가 `witness` 를 깊이 무관하게 빼고, snap 모드에서 상태 파일에 남는 것은 `uid·cm_u·attrs·Cf_u·leaf` 뿐이며(테스트가 문자열 단위로 못 박음), 로그·`/wallet/status`·`/wallet/config`·RP 로 가는 팝업 결과 어디에도 `s_u·r_u·sk_u·blind_u·blind_s·sessionPrivKey·비밀번호`가 실리지 않는다. Critical 없음.
2. **오리진 4겹(Snap `WALLET_ORIGINS` ↔ 에이전트 CORS ↔ 팝업 `ev.origin===req.origin`+precheck ↔ RP 의 `ev.origin`+`ev.source`)은 일관되고 서로를 보강한다.** 공격자 페이지 하나가 브라우저에서 할 수 있는 최대치는 "팝업을 띄워 `origin_mismatch` 를 받는 것"과 "항상 400 이 나는 비-preflight POST" 뿐이다(§4).
3. 남은 결함은 **재승인(`/wallet/session/witness`) 동의 문구가 세션의 실제 `allowAgent` 와 어긋날 수 있다는 Important 하나**와, 캐시·검증 일관성·복구 불가 조합에 관한 Minor 몇 개다.

---

## 2. 발견 목록

### Critical
없음.

### Important

**I-1. 재승인 동의 창의 `allowAgent` 를 에이전트가 세션과 대조하지 않는다 — 서비스가 부른 대로 보여 준다 (동의 창 스푸핑)**
- `mode3_wallet_agent.js:386-409` (`/wallet/session/witness`, 특히 :398 은 `Cf_u` 만 본다) · `mode3/wallet.html:197-205` (`consentLogin(req)` 에 RP 가 보낸 `req` 를 그대로 넘긴다) · `snap-mode3/src/index.js:119-127`
- **확인.** 재승인 경로에서 Snap 대화상자가 보여 주는 `AI 에이전트 허용: 예/아니오` 는 **팝업 요청 본문의 `allowAgent`** 에서 온다. 팝업은 precheck(인증서·팩토리)만 거치고 그 값이 `r_s` 세션의 `state.sessions[r_s].allowAgent` 와 같은지 확인하지 않으며, `/wallet/session/witness` 도 `allowAgent` 를 전혀 보지 않는다(`Cf_u` 일치만 본다).
- **실패 시나리오**: `allowAgent='1'` 로 로그인한 뒤 에이전트를 재시작 → 다음 재검증이 `needs_consent`. 이때 RP 페이지(또는 그 페이지의 XSS)가 재승인 팝업 요청에 `allowAgent: '0'` 을 실으면, 사용자는 **"AI 에이전트 허용: 아니오"** 를 읽고 승인한다. 그러나 세션의 σ_AA·π 의 공개 입력은 그대로 `allowAgent=1` 이고 컨트랙트도 1 로 통과시킨다 — 사용자가 거절했다고 믿은 권한이 그대로 살아난다. (`mode3/rp.html:53-56,244-251` 은 *RP 페이지 스스로* 이 위험을 알고 자기 값을 쓰지만, 이는 RP 의 선의에 기댄 방어다.)
- **고치는 방향**: 팝업이 `r_s` 세션의 실제 `allowAgent`(와 `arid`)를 에이전트에서 받아 동의 창에 쓰고, `/wallet/session/witness` 가 요청의 `allowAgent` 와 세션 값이 다르면 409 로 거절한다.

### Minor

**M-1. `pruneSessions` 가 `ProofCache` 를 비우지 않아 같은 `r_s` 재사용 시 옛 π 가 되돌아온다**
- `mode3_wallet_agent.js:75-79`(prune, `cache.clear()` 없음) vs `:111`(`replaceUserCred` 는 비운다) · `:420-436`(캐시 히트면 `Cf_u` 일치·`tree.has` 검사를 건너뛴다)
- **확인.** 만료로 세션이 prune 된 뒤 같은 `r_s` 로 다시 로그인하면 `duplicate_session` 검사를 통과해 **새** 세션(새 `pk_i`·`max_height`)이 만들어지지만, root 가 그대로면 `cache.get(root, r_s, '0')` 이 **옛 세션의 π** 를 돌려준다. 응답의 `sig`·`pk_i` 는 새 세션 것이라 RP 가 거절하고, 사용자에겐 원인 불명의 로그인 실패로 보인다. 폐기 우회는 아니다 — root 가 바뀌면 캐시 키가 달라져 `tree.has` 재검사가 반드시 돈다(§3 강점).
- 실제 `r_s` 는 `mode3_rp.js:191` 의 250비트 난수라 정상 운용에서는 닿지 않는다. 그래서 Minor.
- **고치는 방향**: `pruneSessions` 에서 지운 `r_s` 의 캐시 항목도 지우거나, 캐시 키에 세션의 `pk_i` 를 넣는다.

**M-2. 선택 공개 만족 검사가 `attrs` 없이도 조용히 통과한다**
- `lib/mode3_wallet.js:78` (`if (attrs[k] < l || attrs[k] > h)`)
- **확인**(`node -e` 로 실측): `normalizeDisclosure([{lo:'1',hi:'2'},null,null,null], [])` 는 `disclosure_unsatisfiable` 을 던지지 않고 `mask=1` 을 돌려준다 — `undefined < 1n` 이 false 이기 때문이다. `mode3_wallet_agent.js:553` 은 `state.registration.attrs ?? []` 를 넘기므로, `attrs` 가 아직 `null` 인 등록(버전 이행 직후 등)에서는 "400 disclosure_unsatisfiable" 대신 수 초 뒤 증명 생성 실패 → `500 {error:…}` 가 난다.
- **고치는 방향**: `normalizeDisclosure` 앞에서 `normalizeAttrs(attrs)` 를 강제하거나 `attrs.length !== 4` 면 `bad_disclosure`.

**M-3. 공개 검사와 증명이 서로 다른 `attrs` 를 본다 (snap 모드)**
- `mode3_wallet_agent.js:553` 은 파일의 `state.registration.attrs`, `:430` 의 `proveSession` 은 `src.registration().attrs`(= 세션 메모리 증인의 값).
- **확인.** 두 값이 어긋나면(Snap 의 `syncAttrs` 가 실패했거나 세션 증인이 옛 속성으로 채워진 경우) `/wallet/tx/prepare` 는 범위 검사를 통과시킨 뒤 회로 제약 불만족으로 500 을 낸다. 보안 문제는 아니고 진단이 나쁘다.
- **고치는 방향**: `buildExecute` 도 `secretSourceFor` 로 얻은 `src.registration().attrs` 를 쓴다(순서만 바꾸면 된다).

**M-4. `consentDisclosure` 대화상자가 `data`(호출할 함수)를 보여 주지 않는다**
- `snap-mode3/src/index.js:137-158` · `mode3/wallet.html:398`
- **확인.** 동의 창은 `대상 주소`·`금액`·공개할 슬롯만 보여 준다. `execute` 의 `payload.data`(예: `0x4e71d92d` = `claim()`)는 어디에도 나오지 않는다. 사용자는 "0 wei 를 이 주소로" 만 보고 임의의 컨트랙트 호출에 서명하는 셈이다(계정 배포 트랜잭션도 별도 동의 없이 MetaMask 확인창만 거친다).
- **고치는 방향**: 대화상자에 `data` 의 셀렉터(가능하면 알려진 함수명)와 길이를 줄로 추가한다.

**M-5. Snap 동의 창의 `serviceName` 이 호출자 문자열 그대로다**
- `snap-mode3/src/index.js:117-127` (`서비스: ${serviceName || rpOrigin}`) · `mode3/wallet.html:135-140`
- **확인**(문자열 전달 경로) / **추측**(MetaMask 가 `text()` 를 마크다운·개행으로 렌더한다는 부분). precheck 를 통과한(=CIA 가 승인한) 서비스만 여기 닿으므로 임의 페이지의 스푸핑은 아니다. 다만 승인된 서비스 하나가 `serviceName` 에 개행/마크다운을 넣어 아래 `오리진:` 줄을 흉내 낼 수 있다.
- **고치는 방향**: Snap 쪽에서 길이 제한 + 개행·마크다운 문자 제거(또는 `serviceName` 을 아예 쓰지 않고 오리진만 보여 준다).

**M-6. `file` → `snap` 모드 전환 시 옛 비밀이 상태 파일에 그대로 남는다**
- `mode3_wallet_agent.js:63-73`(버전 이행은 `registration` 을 통째로 보존) · `lib/mode3_secret_source.js:12-16`(`stripSecrets` 는 `/wallet/register` 에서만 불린다)
- **확인.** file 모드로 등록한 파일을 그대로 두고 `MODE3_WALLET_SECRETS=snap` 으로 띄우면, `state.registration` 의 `s_u·r_u·sk_u` 가 그대로 남고 이후 `persist()` 마다 다시 쓰인다. 문서(`docs/MODE3_DEMO.md:188`)의 "에이전트 파일에는 공개 부분만" 과 어긋난다. 이 상태에서는 Snap 의 새 `cm_u` 가 파일 값과 달라 `bad_witness` 로 막히므로 **기능적으로는 fail-closed**이고, `MODE3_DEMO.md:208-209` 가 재시연 세트로 풀라고 안내한다.
- **고치는 방향**: snap 모드 기동 시 `state.registration` 에 비밀 키가 있으면 `stripSecrets` 후 즉시 `persist()` 하고 경고를 남긴다.

**M-7. 팩토리 검증이 `maxLifetime`·`maxRootAge` 를 보지 않아 실패가 `TooFarExpiry` 로만 드러난다**
- `mode3_wallet_agent.js:192-207`(`arid`·`log`·`pkCIA`·`pkTrace` 만 대조) · `lib/mode3_wallet.js:44-48` + `mode3_wallet_agent.js:44-46`
- **확인.** `chooseMaxHeight` 의 최악값은 `head+399`(실측)라 기본 `L=400` 과는 딱 맞지만, 서비스가 `MODE3_MAX_LIFETIME_BLOCKS` 를 낮춰 팩토리를 배포하거나 지갑이 `MODE3_TTL_BLOCKS`/`MODE3_HEIGHT_GRID` 를 올리면 로그인은 성공하고 **모든 `execute` 가 `TooFarExpiry` 로 revert** 한다. 에이전트는 기동 시에도 precheck 에서도 이를 알아채지 못한다(문서 `docs/MODE3_DEMO.md:65` 에만 "TTL+GRID 이상이어야" 라고 적혀 있다).
- **고치는 방향**: `checkService` 가 `f.maxLifetime()` 을 읽어 `TTL_BLOCKS + HEIGHT_GRID` 보다 작으면 `bad_factory` 로 거절한다. (`verifier()` 미대조는 설계 스펙 `2026-09-18-…-onchain-execution-design.md:395` 에 잔존 위험으로 이미 적혀 있어 재발견하지 않는다.)

**M-8. CSRF 방어가 `express.json()` 하나에만 걸려 있다는 주석이 `/wallet/self_revoke` 에만 있다**
- `mode3_wallet_agent.js:501-504`(주석) · `:211`(`app.use(express.json(...))`)
- **확인.** 같은 논거가 `/wallet/register`·`/wallet/login`(snap)·`/wallet/tx`·`/wallet/tx/prepare`·`/wallet/attrs/sync`·`/wallet/session/witness` 전부에 똑같이 적용된다. 특히 `/wallet/tx`(file 모드, 릴레이어가 가스를 내고 바로 전송)와 `/wallet/attrs/sync`(옛 C_u·전 세션 폐기)는 되돌리기 어렵다. 또한 에이전트는 `Host` 헤더를 확인하지 않아 DNS 리바인딩으로 `127.0.0.1:5100` 이 공격자 오리진의 동일 오리진이 되면 CORS 방어가 통째로 무력해진다(브라우저의 로컬 네트워크 차단에만 기댄다).
- **고치는 방향**: 전역 미들웨어로 `Origin` 헤더 화이트리스트(없거나 지갑/RP 오리진일 때만 통과) + `Host` 가 `127.0.0.1:PORT`/`localhost:PORT` 인지 검사.

**M-9. `wallet.html` 이 `innerHTML` 에 서버 응답값을 보간한다 (rp.html 의 규칙과 불일치)**
- `mode3/wallet.html:367, 405, 430`(`${b.reason ?? status}` 등) — `mode3/rp.html:66-74` 는 같은 이유로 `setVerdict()` + `textContent` 만 쓴다고 명시.
- **확인.** 현재 `reason` 은 전부 에이전트가 만든 리터럴이라 실제 XSS 경로는 없다. 규칙이 한쪽에만 지켜져 있어 나중에 서버가 자유 문자열을 `reason` 에 담으면 깨진다.
- **고치는 방향**: `rp.html` 의 `setVerdict` 와 같은 헬퍼로 통일.

**M-10. 상태 파일 파손·버전 다운그레이드 처리**
- `lib/mode3_state.js:8-11`(`JSON.parse` 예외를 잡지 않음) · `mode3_wallet_agent.js:66`(`!==` 비교)
- **확인.** 파일이 깨지면 에이전트가 import 시점에 던져 기동하지 않는다(원인 안내 없음). 또 파일 버전이 `WALLET_STATE_VERSION` 보다 **높아도** "옛 형식" 으로 보고 세션과 `userCred` 를 비운다.
- **고치는 방향**: `readJson` 에서 파싱 실패를 잡아 경로·이유를 알리고, 버전 비교는 `<` 로.

**M-11. 서비스 오리진이 `/wallet/revalidate` 로 동기화를 무제한 유발할 수 있다**
- `mode3_wallet_agent.js:441-479`
- **확인.** 동기화는 호출마다 돈다(점검 중 배선이 `createRevocationSync` 로 바뀌어 창세기 재생 비용은 체크포인트로 줄었으나, 레이트 리밋은 여전히 없다). RP 오리진(또는 그 XSS)이 루프를 돌리면 에이전트 CPU·RPC 를 점유한다(π 자체는 캐시된다). 또 `/wallet/revalidate`·`/wallet/request` 는 `r_s` 가 **부르는 서비스의 arid 에 속한 세션인지** 확인하지 않는다 — 지금은 허용 오리진이 하나뿐이고 `r_s` 가 250비트 난수라 무해하나, 다중 RP 로 확장하면 곧바로 교차 서비스 문제가 된다.
- **고치는 방향**: 간단한 레이트 리밋 + 세션의 `arid` 를 호출 오리진의 인증서와 대조.

---

## 3. 강점 (다시 볼 필요 없는 것)

- **비밀 경계**: `persist()` 의 replacer(`mode3_wallet_agent.js:65`)는 중첩 깊이와 무관하게 `witness` 를 뺀다. `stripSecrets`/`createSecretSource`(`lib/mode3_secret_source.js`)의 snap 분기는 `setUserCred` 에서 공개 3필드만 파일에 쓰고 `blind_u` 는 `pending`(HTTP 응답, 같은 오리진) 으로만 내보내며, 팝업이 RP 로 넘기기 전에 `userCredIssued`·`attrsChanged` 를 구조분해로 제거한다(`wallet.html:216`). 테스트가 상태 파일 문자열을 직접 검사한다(`tests/test_mode3_wallet_snap.mjs:62,119,172`). 소스 전체에 비밀을 찍는 `console.*` 이 없다.
- **세션 경로의 증인 출처 고정**: `secretSourceFor(req, rsKey)`(`:173-187`)는 세션 라우트에서 본문 `witness` 를 아예 보지 않고, 공개 `userCred` 가 없으면 세션을 지우는 대신 `needs_consent` 로 떨어뜨린다. 악의적 본문 증인이 세션을 지우지 못한다는 것을 테스트가 확인한다(`test_mode3_wallet_snap.mjs:147-149`).
- **폐기 fail-closed**: `syncRevocationTree`(`lib/mode3_wallet.js:138-157`)는 재구성 root 와 온체인 root 가 다르면 던지고, `buildCredentialProof` 는 증인이 계산한 root 로 공개 입력을 고정한다(`:171-175`). `ProofCache` 키에 root 가 들어 있어 **폐기 게시로 root 가 바뀌면 캐시가 반드시 미스** → `Cf_u` 일치·`tree.has` 재검사가 돈다. IMT 중복 삽입은 조용히 무시되므로(`lib/imt_v2.js:197`) CIA 의 중복 리프가 지갑 동기화를 죽이지 않는다.
- **서명 도메인 분리**: `signChallenge`/`signSessionRequest` 는 EIP-191(`\x19Ethereum Signed Message:…`), `signPayload` 는 `keccak256(abi.encode(uint256 chainId, address wallet, …))` 원시 다이제스트다(`lib/mode3_onchain.js:70-80`). 전자의 프리이미지는 `0x19`·'E' 로, 후자는 32바이트 `chainId` 워드로 시작해 교차 사용이 불가능하다. `/wallet/request` 가 서명하는 `${r_s}:${body}` 는 항상 `:` 를 포함해 `signChallenge` 의 10진 `r_s` 와도 겹치지 않는다. `payloadDigest` 는 선택 공개 9워드 전부를 덮는다.
- **오리진 검사 4겹이 모두 실제로 동작**: Snap 의 `WALLET_ORIGINS`(`index.js:16-19,68`), 에이전트의 함수형 CORS(요청 Origin 이 일치할 때만 헤더를 붙인다, `:216-222`, OPTIONS 응답 헤더를 테스트가 라우트별로 검사 `test_mode3_wallet_snap.mjs:84-87`), 팝업의 `ev.origin === req.origin` + **동의 창 전에** 돌리는 `/wallet/authorize/precheck`(`wallet.html:165-196`), RP 의 `ev.origin && ev.source === popup` + 지정 오리진 `postMessage`(`rp.html:147-148`). `cert_s` 가 `(arid, origin, pk_trace)` 를 모두 덮으므로(`lib/mode3_rp_cert.js:34-39`) 피싱 페이지가 남의 인증서를 끼워 넣을 수 없다.
- **`chooseMaxHeight` 격자·TTL 은 문서·상한과 맞는다**: 기본값에서 `max_height - head` 의 최댓값이 정확히 **399**(실측)로 `L = 400` 미만이며, 같은 100블록 창의 발급이 같은 값을 갖는다. `snap-mode3/src/crypto.js` 의 손수 구현 Baby Jubjub 은 항등원 `[0,1]`·스칼라 0 을 올바르게 처리하고(덧셈식을 대입해 확인), `randomScalar` 의 250비트 마스킹이 `lib/mode3_credential.js:58-63` 과 같다. `snap.manifest.json` 의 `shasum` 은 현재 `dist/bundle.js` 와 일치한다(`getSnapChecksum` 으로 재계산해 확인).

### 공격자 페이지 하나가 할 수 있는 최대치 (§2 지시 2에 대한 답)

- **RP 오리진이 아닌 임의 페이지**: 사실상 없음. 모든 라우트가 (a) `Origin === RP_ORIGIN` CORS 이거나 (b) CORS 없음이고, 본문은 `application/json` 이어야 하므로 항상 preflight 가 필요해 차단된다. 폼/`text/plain` 으로 보내면 `express.json()` 이 파싱하지 않아 `req.body` 가 비어 400. 지갑 팝업을 직접 열어 `postMessage` 는 할 수 있으나 `ev.origin === req.origin` + CIA 서명 인증서를 함께 만족시킬 수 없어 `origin_mismatch`/`bad_rp_cert` 에서 멈춘다. **동의 창 스푸핑·세션 삭제·재검증 유도·트랜잭션 유도 모두 불가.** (단 M-8 의 DNS 리바인딩 가정이 성립하면 전부 가능해진다.)
- **RP 오리진 자신(또는 그 XSS)**: `/wallet/revalidate`(임의 `r_s`, 폐기 시 그 세션 삭제 유발, 동기화 DoS), `/wallet/request`(임의 body 에 세션키 서명), `/wallet/config` 읽기, 팝업 구동. **`/wallet/tx*`·`/wallet/self_revoke`·`/wallet/attrs/sync`·`/wallet/status`·`/wallet/register` 는 불가**, snap 모드에서는 `/wallet/login` 도 불가(팝업 + Snap 동의 필수). 여기에 **I-1** 로 재승인 동의 문구의 `allowAgent` 를 속일 수 있다.
- **file 모드**에서는 `/wallet/login` 이 RP 오리진에 열려 있어 RP 가 사용자 상호작용 없이 로그인을 개시할 수 있다 — 설계상 "자동 테스트·헤드리스 데모" 용이라 한계로만 적는다.

### 상태 기계 — 복구 불가 조합 (§2 지시 3)

`/wallet/register` 가 201 을 돌려준 뒤 페이지의 `invokeSnap('storeRegistration')` 이 실패하면(탭 닫힘·MetaMask 거절), Snap 의 등록은 `sk_u:null, attrs:null` 로 남아 `buildWitness` 가 영구히 `registration_incomplete` 를 던지고 `register` 는 `already_registered` 로 막힌다. Snap 만 초기화해도 새 `cm_u` 가 CIA 등록과 달라 CIA 가 409 를 낸다 — **CIA·에이전트·Snap 세 보관소를 모두 비우는 재시연 세트가 유일한 출구**다. `mode3/wallet.html:302-311` 의 안내문과 `docs/MODE3_DEMO.md:208-209` 는 에이전트 파일 쪽만 다루고 이 창(register 201 ↔ storeRegistration 사이)은 언급하지 않는다. 그 밖의 조합(`userCred:null`, Snap C_u 스테일, 속성 변경, 자기 폐기, reset)은 모두 다음 로그인이 자가 치유하거나 `user_cred_mismatch`/`needs_consent` 로 fail-closed 된다.

---

## 4. 점검하지 못한 것과 이유

- **컨트랙트와의 바이트 일치**(`payloadDigest` ↔ `Mode3Wallet.execute`, `pub[14..22]` 꼬리 인코딩, `Disclosure` 이벤트) — 범위상 점검자 D. 여기서는 JS 쪽 인코딩이 자기 정합적이라는 것까지만 봤다.
- **CIA(`cia.js`)·서비스(`mode3_rp.js`, `lib/mode3_rp.js`)·회로** — 점검자 C·D·E 범위. `verifyRpCert`·`normalizeAttrs` 처럼 지갑이 직접 부르는 것만 읽었다.
- **실행 검증 전무**: 공통 지침에 따라 서버 기동·테스트 실행을 하지 않았다(순수 함수 `chooseMaxHeight`·`normalizeDisclosure`·`getSnapChecksum` 만 `node -e` 로 불러 봤다). 따라서 I-1·M-1 의 재현은 코드 독해 기반이며 런타임으로 확인하지 않았다.
- **실제 MetaMask 환경** — Snap 대화상자의 마크다운/개행 렌더링(M-5), `endowment` 없이 `crypto.getRandomValues` 가 SES 안에서 제공되는지, MetaMask 의 로컬 네트워크 접근 차단이 M-8 을 얼마나 막아 주는지는 브라우저 실측이 필요해 추측으로 표시했다.
- **`lib/mode3_rcl_sync.js`·`tests/test_mode3_rcl_sync.mjs`** — 공통 지침에서 점검 제외(진행 중).
- **상태 파일 실물**(`mode3_wallet_state.json` 등) — 읽기 금지 항목이라 열지 않았다. 파일 권한은 `writeJsonAtomic(…, 0o600)` 코드로만 확인했다(일반 umask 에서 0600 유지).
