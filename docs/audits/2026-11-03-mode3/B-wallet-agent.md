# 영역 B — Mode 3 지갑 에이전트 독립 코드 리뷰 (읽기 전용)

- 대상: `mode3_wallet_agent.js`(1549줄), `lib/mode3_wallet.js`, `lib/mode3_onchain.js`, `lib/mode3_credential.js`, `lib/mode3_rcl_sync.js`, `lib/mode3_revocation.js`, `lib/imt_v2.js`, 보조로 `lib/mode3_secret_source.js`, `lib/mode3_registry_sync.js`, `lib/mode3_registry.js`, `lib/mode3_rp_cert.js`, `lib/mode3_set_tree.js`, `lib/mode3_health.js`, `lib/mode3_state.js`, `contracts/Mode3Wallet.sol`(counter·bound 의미 대조), `mode3/wallet.html`(팝업·라우트 호출부만).
- 기준: `feat/mode3-v11` HEAD `7e9eb25`. 서버·테스트 실행 없음, 상태 파일·키 파일·`.env` 열지 않음. 줄번호는 모두 현재 워킹트리 기준.
- 이전 점검(`docs/audits/2026-09-23-mode3/SUMMARY.md`, B-wallet.md)에서 고친 항목(B-I1, M-1, M-8 의 Host/Origin)은 현재 코드로 **고쳐졌음을 확인**했고 다시 보고하지 않는다. 당시 "기록으로만 남긴" Minor 중 아직 그대로인 것은 §2 끝에 한 줄씩만 적었다.

## 1. 한 줄 총평

비밀 경계·오리진 정책(D2)·증명 바인딩(root/counter/disclosure)·폐기 트리 fail-closed 는 코드가 주석의 주장대로 동작하며 **Critical·Important 결함은 찾지 못했다**; 남은 것은 같은-오리진 전용 라우트 사이의 일관성 구멍, 시연용 스위치(`skipSync`·override)의 노출 범위, 레이트 리밋 부재, 그리고 진단만 나쁘게 만드는 Minor 들이다.

## 2. 발견 목록 (심각도 순)

### Critical — 없음
### Important — 없음

아래는 모두 **Minor** 다. 번호는 우선순위 순(먼저 고칠 가치가 있는 것부터).

---

**M-1. `/wallet/tx/record` 의 `pendingBoundId` 판정이 대기 항목의 `account` 와 세션 계정을 대조하지 않는다 (`/wallet/bounds/apply` 와 비대칭)**
- `mode3_wallet_agent.js:1517-1528` (record 의 pendingBoundId 분기), 비교 대상 `:1461-1462` (apply 는 `bound_wrong_account` 로 막는다), `:1377-1392` (`clearAppliedBounds` 도 `(pk_i, bound)` 만 본다).
- 무엇이 틀렸나: record 는 `p = pendingBounds.find(id)` 뒤 곧바로 `boundApplyVerdict(receipt, walletAddr, p)` 를 부른다. `walletAddr` 은 **요청 `r_s` 세션의 계정**이고 `p.account` 는 확인하지 않는다. `boundApplyVerdict` 는 `walletAt(walletAddr).sessionBound(p.pk_i)` 를 읽어 `onchainBound <= reqBound` 면 `applied(alreadyLower)` 로 보고, 호출자가 pending 을 지운다.
- 실패 시나리오(자해 한정): 같은 사용자가 계정 A 의 세션으로 `execute(to=A, setSessionBound(pk_i_B, 0))` 를 보낸다(S1 "상한 다툼", 스펙 2026-10-22 §7 에 적힌 가능성). 그 영수증을 `/wallet/tx/record { r_s: A세션, txHash, pendingBoundId: B계정의 대기항목 }` 로 넘기면 A 의 `sessionBound(pk_i_B)=1 → onchainBound 0 ≤ reqBound` 라 **B 계정에는 아무 것도 반영되지 않았는데 B 의 대기 항목이 지워진다**. `clearAppliedBounds` 도 같은 영수증의 `SessionBound(pk_i_B, 0)` 로그로 같은 일을 한다. 남이 할 수는 없다(같은 오리진·같은 지갑 사용자) — 그래서 Minor.
- 최소 수정: record 의 분기에 apply 와 같은 `if (p.account.toLowerCase() !== walletAddr.toLowerCase()) boundResult = { applied:false, reason:'bound_wrong_account' }` 를 넣고, `clearAppliedBounds` 의 필터에 `x.account.toLowerCase() === walletAddr.toLowerCase()` 를 추가한다.
- 테스트: 없음. `tests/test_mode3_wallet_agent.mjs:773`(F-14) 는 맞는 계정만 다룬다. "다른 계정 세션의 r_s 로 record" 케이스 추가.

**M-2. `/wallet/revalidate` 의 `skipSync` 가 RP 오리진에 열려 있어 지갑의 캐노니컬 사전 확인·만료 정리를 건너뛴다**
- `mode3_wallet_agent.js:1091-1097`. 라우트는 `loginCors`(RP 오리진 CORS) 이고 `skipSync` 는 본문 플래그다.
- 무엇이 틀렸나: 정상 경로는 `syncAll → pruneSessions → proveSession` 이 **캐노니컬 최신**으로 등록부·세션 구간을 확인해 IdP 가 받아들였지만 거울에 아직 안 실린 폐기도 `revoked/revoked_session` 으로 거절한다(`:997-1016`). `skipSync` 경로는 `lastSync` 의 캐시 π 에 새 σ 만 붙여 돌려주며 이 확인과 `pruneSessions` 를 모두 건너뛴다. RP(또는 RP 페이지의 XSS)가 임의로 켤 수 있다.
- 실패 시나리오: 관리자가 세션 S 를 IdP 에서 폐기(`/cia/revoke scope=session`)했고 다음 게시까지 ≤50블록 남은 상태. RP 가 `skipSync:true` 로 재검증하면 지갑은 거절하지 않고 S 의 π·σ 를 낸다. RP 검증기(`lib/mode3_rp.js`)는 root 가 아직 거울 최신이므로 통과시킨다 — 지갑이 이미 "알 수 있었던" 폐기를 RP 가 원하면 게시 전까지 무시할 수 있다. 영향은 "RP 측 로그인 상태가 게시까지 조금 더 산다" 뿐이고 온체인 경로(`/wallet/tx*`)에는 skipSync 가 없어 자산에는 닿지 않는다.
- 최소 수정: `skipSync` 는 요청 `Origin` 이 지갑 자신(또는 없음)일 때만 받거나(`req.get('Origin')` 이 RP 오리진이면 400), `MODE3_DEMO_SWITCHES=1` 같은 env 로 게이트한다. 또는 skipSync 경로에서도 `pruneSessions` + 캐노니컬 `registryCheck`/구간 확인(싼 해시 몇 번)은 수행한다.
- 테스트: `:286`(skipSync → RP stale_registry_root) 만 있고 "RP 오리진에서 skipSync 로 폐기 직후 세션이 살아 돌아온다" 는 케이스는 없다.

**M-3. 팩토리 `maxLifetime` 대역 검사가 지갑의 `TTL_BLOCKS + HEIGHT_GRID` 와 비교하지 않는다 — 로그인은 되는데 `execute` 가 한동안 `TooFarExpiry`**
- `mode3_wallet_agent.js:400`, `lib/mode3_onchain.js:34` (`FACTORY_MAX_LIFETIME_BAND = 1..1600`), `lib/mode3_wallet.js:75-79` (`chooseMaxHeight` 최악 `head+399`), `contracts/Mode3Wallet.sol` `_checkStatement` (`pub[3] > block.number + maxLifetime → TooFarExpiry`).
- 무엇이 틀렸나: 2026-09-23 점검 B M-7 의 "maxLifetime 이 TTL+GRID 보다 작으면 bad_factory" 는 I-3 수정에서 **대역(1..1600)** 검사로 들어갔다. 대역 안의 값 1..399 는 통과하지만 지갑이 정하는 `max_height` 가 `head+300..399` 라 발급 직후 `execute` 는 모두 revert 한다(블록이 `max_height − maxLifetime` 까지 진행한 뒤에야 짧은 창에서 통과).
- 실패 시나리오: RP 가 `MODE3_MAX_LIFETIME_BLOCKS=100` 으로 팩토리를 배포. 로그인 200 → 사용자가 PPID 계정에 입금 → "보내기" 는 매번 409 `execute_reverted TooFarExpiry`. 자동 블록 생성이 없는 데모 체인에서는 체감상 "영구" 다. 복구는 가능(지갑 TTL env 를 낮춰 재로그인)하므로 Minor.
- 최소 수정: `checkService` 에 `if (BigInt(flt) < TTL_BLOCKS + HEIGHT_GRID) return bad_factory 'maxLifetime below wallet TTL+grid'`.
- 테스트: `:501` 은 `2^40`(상한 밖)만 검사한다. `maxLifetime: 100n` 케이스 추가.

**M-4. RP 오리진이 부를 수 있는 비용 큰 경로에 레이트 리밋·진행중 합치기가 없다 (이전 M-11 잔존, 범위 확대)**
- `/wallet/revalidate`(`:1081`) → `syncAll()`(`:162`, 등록부는 **매번 창세기부터 전체 재생** `lib/mode3_registry_sync.js:12-20`) → 캐시 미스면 Groth16 `fullProve`. file 모드 `/wallet/login`(`:774`) 은 RP 오리진에서 사용자 상호작용 없이 π_IdP + π_cred 두 증명을 만든다.
- 무엇이 틀렸나: `rcl.sync()` 는 `inFlight` 로 합쳐지지만(`lib/mode3_rcl_sync.js:145-157`) 등록부 재생·`proveSession` 은 요청마다 독립이다. 같은 `r_s` 에 동시 요청 N 개가 와도 N 개의 snarkjs 프로버가 병렬로 돈다.
- 실패 시나리오: 승인된 RP 의 페이지 XSS 가 자기 세션 `r_s` 로 `/wallet/revalidate` 를 게시 직후(캐시 미스) 수십 건 동시에 쏜다 → 에이전트 메모리·CPU 점유, 사용자의 지갑 페이지 작업이 멎는다. 파괴적 효과는 없다(세션·상태 불변).
- 최소 수정: `proveSession` 에 `(rootKey, rsKey, discKey)` 별 진행중 Promise 맵(ProofCache 와 나란히) + 세션별 동시 1건; `syncRegistryTree` 에도 `createRevocationSync` 와 같은 inFlight 합치기. 레이트 리밋은 선택.
- 테스트: 동시성·부하 테스트 없음. `test_mode3_rcl_sync.mjs:225` 는 rcl 만 다룬다.

**M-5. `/wallet/session/witness` 가 증인의 `attrs`·`sk_u` 를 파일 `attrs`·`pk_u` 와 대조하지 않아, 뒤의 tx/prepare·revoke 가 분류 안 된 500/400 으로 실패한다 (이전 M-3 의 잔존 경로)**
- `mode3_wallet_agent.js:947-974`(Cf_u·allowAgent 만 대조), `:1255-1283`(`buildExecute` 는 **파일** `attrs` 로 술어를 정규화) vs `:1027-1028`(증명은 `src.registration().attrs` = 세션 증인의 값). `/wallet/login`(`:832-836`) 에는 자가 치유가 있지만 재승인 경로에는 없다.
- 실패 시나리오: `PUT /wallet/profile` 뒤 페이지가 Snap `syncAttrs` 를 놓쳤고 에이전트가 재시작됐다. 재승인으로 들어온 증인은 옛 attrs 다(Cf_u 는 세션 발급 당시 C_u 와 맞으므로 통과). 이후 `/wallet/tx/prepare` 는 파일 attrs 로 `disclosure_unsatisfiable` 판정을 하고 회로는 증인 attrs 로 C_u 를 재계산해 실패 → 500 `{error:'Assert Failed …'}`. 보안 영향 없음(fail-closed).
- 최소 수정: witness 라우트에서 `JSON.stringify(witness.attrs.map(String)) !== JSON.stringify(state.registration.attrs)` 면 409 `attrs_mismatch`(+ 응답에 `attrsChanged` 를 실어 페이지가 Snap 을 맞추게), `eddsaPubOf(witness.sk_u)` ≠ `registration.pk_u` 면 400 `bad_witness`.
- 테스트: `test_mode3_wallet_snap.mjs:182,222` 는 정상 증인만. attrs 불일치 증인 재승인 케이스 없음.

**M-6. `/wallet/login` 이 `proveSession` 의 `revoked`·`revoked_session` 을 매핑하지 않아 500 이 되고 세션이 남는다**
- `mode3_wallet_agent.js:917-925`(처리 목록에 두 사유 없음 → `throw e` → `:935` 500 `{error:'revoked'}`). 같은 사유를 `/wallet/revalidate:1117-1119`·`buildExecute:1300-1303` 은 세션 삭제 + 403 으로 처리한다.
- 도달 가능성: 발급 직후라 거의 닿지 않는다 — fresh 가 아닌 경로에서 `chooseUserCred` 와 `proveSession` 이 같은 `synced` 를 보므로 결과가 같다. 닿는 경우는 `syncAll` 재호출(`:906`, fresh 대기 루프) 뒤 관리자가 그 사이 슬롯을 바꿔치기한 때. 그때 응답은 500 이고 **방금 persist 한 세션은 삭제되지 않은 채 남아** 다음 재검증에서야 지워진다(그 사이 `/wallet/status` 에 살아 있는 세션으로 보임).
- 최소 수정: 두 사유를 revalidate 와 같은 분기(세션 삭제·캐시 삭제·persist·403)로 추가.
- 테스트: 없음(재현이 어렵다 — 등록부 바꿔치기 관리자 API 로 가능).

**M-7. `rcl_sync`/`syncRevocationTree` 는 이벤트 순서를 정렬하지 않는다 — IMT root 는 삽입 순서에 의존한다**
- `lib/mode3_wallet.js:223-231`(`queryFilter` 결과를 그대로 순회), `lib/mode3_rcl_sync.js:108-115`(델타도 그대로). 등록부 쪽 `lib/mode3_registry_sync.js:19` 는 명시적으로 `(blockNumber, index)` 정렬한다.
- 무엇이 틀렸나: `imt_v2.insert` 는 물리 위치를 삽입 순서로 정하므로(`lib/imt_v2.js:395-401` 주석) 같은 블록 안 두 `Revoked` 이벤트가 뒤바뀌어 오면 root 가 달라 **fail-closed throw**(`:235`) 가 난다 — 틀린 트리는 안 만들지만 그 RPC 를 쓰는 동안 로그인·재검증·tx 가 전부 503 이다. hardhat·geth 는 정렬해 돌려주므로 현재 데모에선 안 보인다. (**확인 필요**: 실제 운영 RPC 중 비정렬 반환 사례가 있는지는 확인하지 않았다.)
- 최소 수정: 두 곳에 `events.sort((a,b)=>(a.blockNumber-b.blockNumber)||(a.index-b.index))` 한 줄.
- 테스트: 비정렬 입력 케이스 없음(`test_mode3_rcl_sync.mjs` 는 provider 가 정렬해 준다고 가정).

**M-8. 동시 요청 경합으로 상태가 중복/이중 처리될 수 있다 (같은 오리진 한정)**
- (a) `/wallet/session/revoke`(`:1171-1221`): 같은 `r_s` 로 두 요청이 겹치면 둘 다 `s` 를 읽고 IdP 로 가고(멱등 200), 둘 다 `pendingBounds.push` → **같은 (account, pk_i, bound) 대기 항목이 두 개**. 하나를 반영하면 `clearAppliedBounds` 가 둘 다 지우긴 하지만 상태 화면에 두 줄로 보인다.
- (b) `/wallet/register`(`:655-703`): `if (state.registration)` 검사(`:676`) 뒤 `await` 가 여럿이라 동시 두 등록이 모두 IdP 로 간다. IdP 가 둘째를 409 로 막으면 무해하고, 막지 못하면 둘째가 `state.registration` 을 덮어 Snap 과 어긋난다(**확인 필요**: IdP 가 같은 uid 의 2차 등록을 거절하는지는 A 영역).
- (c) `/wallet/login` 의 `duplicate_session`(`:799`) 도 같은 패턴 — 같은 `r_s` 두 요청이 모두 발급돼 IdP 에 세션 기록이 둘 남는다.
- 최소 수정: 라우트 진입 시 `inFlightByKey(rsKey|'register')` 로 두 번째를 409 `busy` 로 돌려보낸다.
- 테스트: 없음.

**M-9. 시연 덮어쓰기(`demoOverride`)가 소비 시점을 고르지 못해 **무관한 다음 요청**(RP 가 유발한 재검증 포함)에 걸린다**
- `mode3_wallet_agent.js:616`(`takeOverride`), `:1023`(`prove` 는 **캐시 미스일 때만** 소비), `:1111`(revalidate 의 `fake_sig`), `:1076`(`fake_proof`).
- 무엇이 틀렸나: 설정은 같은 오리진만 할 수 있어(미들웨어, 테스트 `:228` 확인) 공격면은 아니다. 그러나 `prove` 스코프는 캐시 히트 동안 남아 있다가 다음 게시 뒤 RP 의 일상 재검증(캐시 미스)에서 터져 `demo_proof_failed` 로 그 RP 세션이 실패하고, `fake_sig`/`fake_proof` 는 사용자가 "다음 로그인에서 보이려고" 켰는데 RP 폴링 재검증이 먼저 소비한다.
- 최소 수정: override 에 `r_s`(또는 라우트 이름)를 함께 받아 그 요청에서만 소비하거나, 재검증 경로에서는 override 를 보지 않는다.
- 테스트: `:924-995` 는 설정 직후 바로 쓰는 경로만.

**M-10. `/wallet/session/revoke` 가 `account` 를 못 구하면(RPC 실패) 대기 항목 없이 성공으로 끝난다**
- `:1187`(`accountAddressOf` 는 실패를 null 로 삼킨다) → `:1211`(`if (account)` 만 push). 응답에 `pendingBoundId:null` 이 실리지만 페이지는 "반영 대기 없음" 으로 읽는다.
- 영향: 2026-10-25 설계 뒤 거울 counter(`sig_i`) 가 정본이라 차단 자체는 된다. 다만 사용자가 "지금 반영" 으로 올릴 수 있던 자기 호출 상한이 영구히 빠진다. 또 `bound===null` 기본값 경로는 체인 읽기 실패를 503 으로 돌려주는데(`:1192-1193`) `account` 계산 실패는 조용히 지나간다 — 같은 체인 문제를 두 가지로 다룬다.
- 최소 수정: `s.factoryAddress` 가 있는데 `account` 가 null 이면 503 `chain_unavailable` 로 끝낸다(IdP 를 부르기 전).
- 테스트: 없음.

**M-11. 상태 파일 — 이전 점검 Minor 잔존 두 건**
- (a) `:112`(`state.version !== WALLET_STATE_VERSION`): **더 높은** 버전 파일도 "옛 형식" 으로 보고 세션·userCred 를 비운다(이전 M-10). `>` 비교 시 기동 거부가 맞다.
- (b) file 모드로 등록한 파일을 그대로 두고 `MODE3_WALLET_SECRETS=snap` 으로 띄우면 `s_u·sk_u` 가 파일에 남고 매 `persist()` 에 다시 쓰인다(이전 M-6, 기동 시 `stripSecrets` 없음). 기능적으로는 `bad_witness` 로 fail-closed.
- (c) `lib/mode3_state.js:8-11` `readJson` 이 JSON 파손을 잡지 않아 기동 시 원인 안내 없이 죽는다(이전 M-10).
- 테스트: `:1132` 는 8→10 상향만.

**M-12. 작은 것들(한 줄씩)**
- `:452` `same` 판정이 `http://${host}` 를 늘 허용한다 — `MODE3_WALLET_PUBLIC_ORIGIN` 이 https 일 때 http 오리진도 "같은 오리진" 이 된다(**확인 필요**: 데모에선 https 구성이 없다).
- `:1163` `/wallet/self_revoke` 는 모든 예외를 502 `cia_unavailable` 로 뭉갠다(F3 의 원칙과 어긋남 — 지역 오류도 IdP 장애로 보임).
- `:278` `ciaPost` 에 타임아웃이 없다(`pollRpOrigins`·`oidcConfig`·`fetchAttrSchema` 는 있다) — IdP 가 응답을 물고 있으면 로그인·폐기 요청이 undici 기본(수 분)까지 매달린다.
- `:1534` `/wallet/tx/record` 는 `execute` 가 아닌 트랜잭션(지갑으로의 단순 입금)도 `countTx` 로 센다 → health 의 `txs` 가 부풀어 체험 모드 판정이 앞당겨질 수 있다. `dec` 가 null 이면 세지 않는 게 맞다.
- `:641` `/wallet/oidc/nonce purpose=issue` 는 `arid·r_rp ≥ 2^250` 을 `aridSOf` 가 throw 해 500 으로 낸다(400 이 맞다); `:1257-1259` `buildExecute` 의 `value` 도 uint256 초과를 ethers 인코딩 단계에서 500 으로 낸다.
- `:1024-1043` `validateWitness` 가 `sk_u` 는 형식만 본다 — 잘못된 sk_u 는 IdP 의 `bad user signature`(400) 로만 드러나 "Snap 상태가 낡았다" 는 진단이 어렵다(`/wallet/register/resume:718` 은 pk_u 대조를 한다 — 같은 한 줄을 `validateWitness` 에도).
- `:109` `persist()` 의 replacer 는 **어느 깊이든** `witness` 라는 키를 지운다 — 사용자 `profile` 필드명이 `witness` 면 사라진다(스키마가 정하므로 현재는 불가능).

---

## 3. 점검했고 건전한 것 (짧게)

- **Host/Origin 미들웨어(`:436-459`) 완전성**: 모든 라우트 앞(`express.json` 보다 앞)에서 (a) Host 허용 목록 421, (b) 공개 GET 5종(`/`, `/wallet/config`, `/mode3/health`, `/wallet/attr_schema`, `/common*`) 과 OPTIONS 만 면제, (c) Origin 이 있으면 지갑 자신 또는 `RP_CORS_PATHS`×허용 RP, 없으면 `Sec-Fetch-Site ∈ {same-origin, none}` 만. `Origin: null` 은 403. 경로 정규화(소문자·끝 '/')는 Express 5 라우터(`router/lib/layer.js` `loosen` + 대소문자 무시, 리터럴은 raw path 대조)와 같은 동치류라 "미들웨어는 공개로 보고 라우터는 다른 핸들러로" 가는 틈이 없다(퍼센트 인코딩은 미들웨어 쪽이 더 엄격해지는 방향으로만 어긋난다). `RP_CORS_PATHS` 와 실제 `loginCors` 부착 라우트(`:465-469`)가 일치하고 snap 모드에서 `/wallet/login` 이 둘 다에서 빠진다. 테스트 `test_mode3_wallet_agent.mjs:214-262` 가 라우트별로 못 박았다.
- **CORS**: `cors()` 함수형 origin(일치할 때만 ACAO), credentials 미사용, `methods: ['POST']`, preflight 는 세 라우트만 `app.options`. `/wallet/config` 는 GET 전용 configCors, health 는 수동 헤더 + `Vary: Origin`.
- **비밀 경계**: `persist()` 가 `witness` 를 뺀다; snap 등록은 `stripSecrets`; `/wallet/status`·`/mode3/health`·`/wallet/config` 응답과 `pendingBounds` 전개(`...p`)에 비밀 필드 없음; `/wallet/login` 의 `userCredIssued(blind_u)` 는 같은 오리진 팝업까지만 가고 팝업이 RP 로 넘기기 전에 구조분해로 제거(`wallet.html:783`); `console.*` 에 값 출력 없음; 500 의 `e.message` 에 비밀값이 실리는 경로 없음(snarkjs 오류는 신호 이름만). `sessionPrivKey` 가 파일에 남는 것은 두 모드 공통의 설계(세션키는 에이전트 소유)이며 0o600.
- **서명 도메인 분리**: `signChallenge`(EIP-191, 10진 r_s)·`signSessionRequest`(EIP-191, `${r_s}:${body}` — 항상 ':' 포함)·`signRevokeBind`(EIP-191, `MODE3_REVOKE_BIND_V1|…`)·`signPayload`(raw keccak digest) 네 가지가 서로 변환되지 않는다. 특히 RP 오리진이 `/wallet/request` 로 얻는 서명은 어떤 메시지로도 revoke-bind 나 execute 다이제스트가 될 수 없다.
- **증명 바인딩**: 캐시 키 `(chainId, revRoot, regRoot) | r_s | discKey#n<nonce>`; `proveSession` 이 `cached.revRoot/regRoot` 를 거울 쌍과 대조하고 어긋나면 `syncAt` 격리 트리로 1회 재증명 후 `sync_unstable`(fail-closed); tx 는 `accountNonceOf` 를 **먼저** 읽고 `counter=nonce` 로 증명(컨트랙트 `pub[33]==payload.nonce` 와 일치); 로그인은 `LOGIN_COUNTER` 로 "리프 하나라도 있으면 실패"; σ 의 다섯 성명 필드는 `statementDigestFields(proved.publicSignals)` 에서 가져온다; `normalizeDisclosure/normalizeSet` 은 정규형 10진·중복 거절·root 를 members 로부터 재계산(RP root 불신); `pk_trace` 는 cert 에서만.
- **폐기 사전 확인(V10)**: 캐시 히트에도 캐노니컬 최신 `registryCheck` + `sessionLeafRange` 구간 비멤버십을 다시 본다(`:997-1016`); "is a member" 문구만 `revoked_session` 으로 바꾸고 다른 오류는 그대로 올려 세션을 잘못 지우지 않는다.
- **rcl_sync**: 델타 root ≠ 온체인 root → 전체 재생 1회 → 그래도 다르면 throw(캐시는 정확성에 무관); head 되감김(재시작·리셋) 양쪽 분기; 캐시 리프 유효성·root 재검증; 중복 리프는 `insert→false` 로 무해; 한 틱 삽입으로 중간 root 노출 방지; `inFlight` 합치기; `reset()` 지연 처리; `syncAt` 은 체크포인트 불변. `untilEpoch` 프리픽스 재생은 거울이 epoch 를 건너뛰어도 옳다(≤ 비교). 반쪽 리오그(같은 높이, 다른 블록)도 root 대조가 잡아 bootstrap 으로 간다.
- **세션 라우트 RP 대조**: `sessionMatchesRequester` 가 Origin·arid 를 모두 보고 "없는 세션" 으로 다룬다; `precheck(r_s)` 는 cert 검증 뒤에만 `sessionAllowAgent` 를 내고 arid 를 대조한다(B-I1 수정 확인).
- **tx/prepare→record**: calldata 는 nonce 에 묶여 1회용; record 는 `receipt.to == computeAddress(PPID)` 만 받고 배포 tx·남의 tx 를 거절; `boundApplyVerdict` 가 `Executed.success` 와 `sessionBound` 재조회를 **둘 다** 보고, pending 삭제는 판정 뒤에만.
- **반쯤 된 상태의 자가 치유**: `issueSession` 이 `replaceUserCred`(persist) → 세션 저장(persist) 순서라 중간 크래시는 다음 로그인의 `chooseUserCred` 가 등록부로 바로잡는다; snap 의 `src.pending` 은 실패 응답에도 실린다(S3); `/wallet/session/witness` 가 파일의 공개 userCred 를 되살린다; `cred_revoked` 재시도는 1회.
- **데모 override 표면**: `/wallet/demo/override` 는 `RP_CORS_PATHS` 밖이라 RP·외부 오리진은 403(`test_mode3_wallet_agent.mjs:228`); 폼 전송은 Origin/Sec-Fetch 검사와 JSON 전용 파서 두 겹에 막힌다; 효과는 메모리·1회성.
- **`/wallet/rcl/reset`·`/wallet/self_revoke`**: 같은 오리진 + `confirm:true`/JSON 전용으로 폼 CSRF 불가; self_revoke 는 등록 uid 와 대조해 임의 uid·pwd 통로가 아니다.

## 4. 테스트 공백

1. `/wallet/tx/record` + `pendingBoundId` 에서 **세션 계정 ≠ 대기 항목 계정**(M-1) 과 `clearAppliedBounds` 의 다른 계정 영수증.
2. RP 오리진의 `skipSync` 가 캐노니컬 폐기(게시 전) 세션을 되살리는지(M-2) — 지금은 "stale_registry_root 를 보인다" 만 있다.
3. 팩토리 `maxLifetime ∈ [1, TTL+GRID)`(예 100) 로 로그인 뒤 execute 가 `TooFarExpiry` 인 회귀(M-3).
4. 동시성: 같은 `r_s` 재검증 N 건 동시(프로버 중복), 같은 `r_s` 폐기 2건(pending 중복), 등록 2건 동시(M-4·M-8).
5. 재승인 증인의 attrs/sk_u 불일치(M-5) — 현재는 정상 증인과 Cf_u/allowAgent 불일치만.
6. `/wallet/login` 중 등록부 바꿔치기로 `proveSession` 이 `revoked` 를 던지는 경로의 응답 코드·세션 잔존(M-6).
7. rcl/registry 재생에 비정렬 로그를 주입했을 때의 동작(M-7) — mock provider 로 가능.
8. 미들웨어 경계값: `Origin: null`, https `MODE3_WALLET_PUBLIC_ORIGIN` 과 http Origin, `/Wallet/Revalidate/`(대소문자·끝 '/') 를 RP 오리진이 부를 때 CORS 헤더가 붙는지, 비-RP 오리진의 OPTIONS 에 ACAO 가 없는지(헤더 단언은 `:175` 가 일부).
9. `demoOverride` 가 설정 뒤 **다른** 요청(RP 재검증)에 소비되는 것을 잡는 테스트(M-9).
10. `/wallet/session/revoke` 에서 `accountAddressOf` 실패 시의 응답(M-10) — RPC 실패 주입.
11. 상태 파일: 더 높은 version·JSON 파손·file→snap 전환 기동(M-11).
12. `/wallet/tx/record` 가 비-execute 입금 tx 를 세는지(M-12), `/wallet/oidc/nonce` 범위 밖 arid 의 400.

## 5. 점검하지 못한 것

- 실행 검증 없음(지침). 모든 판정은 코드 독해이며 M-2·M-6·M-7 의 재현은 런타임으로 확인하지 않았다.
- IdP(`cia.js`)·RP(`mode3_rp.js`, `lib/mode3_rp.js`)·회로·Snap 번들은 지갑이 직접 호출하는 지점(`/cia/revoke` 의 `sig_i`·`bound` 처리, RP 검증기의 `bad_counter`·만료 검사)만 대조했다.
- `MODE3_WALLET_ALLOWED_HOSTS`·`MODE3_WALLET_PUBLIC_ORIGIN` 의 실제 분리 데모 설정값은 `.env` 를 열지 않아 보지 못했다.
