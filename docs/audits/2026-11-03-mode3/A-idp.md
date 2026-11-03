# A — Mode 3 IdP(CIA) 서버 코드 점검 (feat/mode3-v11, HEAD 7e9eb25, 읽기 전용)

대상: `cia.js`(1707줄) + `lib/mode3_cia_state.js`, `lib/mode3_issuance.js`, `lib/mode3_registry.js`, `lib/mode3_revocation.js`, `lib/mode3_log.js`, `lib/mode3_trace.js`, `lib/mode3_attr_schema.js`, `lib/imt_v2.js`. 보조로 `lib/mode3_oidc.js`, `lib/mode3_oidc_nonce.js`, `lib/mode3_state.js` 를 읽었다(OIDC·persist 판단에 필요). 상태 파일·키 파일·.env 는 열지 않았다. 서버·테스트는 돌리지 않았고, `scryptSync` 비용 1회 측정(독립 one-liner)만 했다.
2026-09-23 점검(SUMMARY.md)에서 수정된 항목(A-I1 개봉 dup 키, A-I2 속성 0 패딩)은 현재 코드에서 반영 확인했고 다시 적지 않는다. 그때 "기록으로 남김" 한 Minor 중 아직 남아 있는 것은 §2 끝에 짧게만 표시한다.

## 1. 한 줄 총평

인증·서명·증명·nonce 결속·게시 잠금·크래시 복구 같은 핵심 불변식은 전부 코드로 지켜지고 있어 **Critical 은 없다**. 다만 (1) 기동 시 자동 게시가 거울 초기화보다 먼저 돌아 **거울 공개 세션 counter 대기열을 조기 폐기**하는 순서 결함, (2) 무인증 `/cia/register_rp` 로 **RP origin 을 선점하면 되돌릴 길이 없는** 가용성 결함, (3) 무인증 경로의 동기 scrypt + 전체 상태 persist 가 **하트비트까지 굶겨 전원 fail-closed** 로 이어질 수 있는 DoS 경로 — 셋이 Important 다. 나머지는 Minor.

## 2. 발견 사항 (심각도 순)

### Critical — 없음

### Important

#### I-1. 기동 자동 게시가 `initMirrors()` 보다 먼저 돌아 `pendingBounds` 를 거울이 받기 전에 버린다
- 위치: `cia.js:355`(loadState 안 `publishNow()`), `cia.js:1274`(`if (MIRRORS.length === 0) pruneMirroredBounds()`), `cia.js:1185-1195`(pruneMirroredBounds — `MIRRORS.length === 0` 이면 `floor = state.epoch`), `cia.js:1686-1687`(`await loadState(); initMirrors();` 순서).
- 무엇이 잘못됐나: `pruneMirroredBounds` 는 `MIRRORS.length === 0` 을 "거울이 없다" 로 해석하지만, 기동 중 `loadState()` 가 백로그(pending 리프·pendingSlots)를 보고 `publishNow()` 를 부르는 시점에는 `MIRRORS` 가 아직 `[]` 다(`initMirrors()` 는 그 뒤 1687행). 그래서 이 게시에 실린 `(pk_i, bound)` 항목은 `epoch = E` 를 받은 직후 `E > E` 가 거짓이라 **전부 삭제**된다. 스펙 2026-10-25 §2.2·§4 의 "모든 거울이 그 항목이 실린 epoch 이상을 받을 때까지 매 게시에 다시 싣는다" 가 기동 경로에서 깨진다.
- 실패 시나리오: 사용자가 `pk_i·sig_i` 를 실어 세션을 폐기(`/cia/revoke scope=session`, 리프 push + `pendingBounds` 에 `{pk_i, c, epoch:null}`) → 게시 전에 IdP 가 죽음 → 재기동: `state.pending.length > 0` 이라 353행 조건 참 → `publishNow()` 가 리프와 bound 를 epoch E 로 캐노니컬에 올림 → 1274행에서 bound 항목 삭제 → `scheduleRelayAfterPublish()`(1693행)가 `lastPublication(E)` 를 거울에 보내려 하지만 **(a)** `CIA_MIRROR_RELAY_ON_PUBLISH=0`(런북의 "거울 지연을 눈으로 보이는 시연용" 설정)이거나 **(b)** 그 순간 거울 체인 RPC 가 안 떠 있으면 중계가 안 되고, 다음 하트비트(50블록)가 E+1 을 bound 없이 올리면 `lastPublication` 이 E+1 로 바뀌어 **그 거울의 `sessionBoundOf[pk_i]` 는 영영 설정되지 않는다**(컨트랙트는 payload 로만 갱신). 결과: root 유효 창 G 블록 동안 폐기된 세션키의 `nonce ≥ c` 거래가 응용 체인에서 통과 — 10-25 설계가 닫으려던 바로 그 노출이 다시 열린다(창이 닫힌 뒤에는 RCL 리프가 막으므로 영구 우회는 아니다).
- 최소 수정: `pruneMirroredBounds` 와 1274행의 판정을 `MIRRORS.length === 0` 대신 `MIRROR_SPECS.length === 0`(설정 기준) 으로 바꾸고, `MIRRORS` 가 아직 비어 있으면(초기화 전) 정리하지 않는다. 또는 `initMirrors()` 를 `loadState()` 의 자동 게시 앞으로 옮긴다(`selfChainId` 가 345행에서 정해지므로 자동 게시 직전에 호출하면 된다).
- 테스트: 없음. `tests/test_cia_startup.mjs` 는 pending 리프 복구만 보고 bound 를 다루지 않는다. `tests/test_cia_revoke_bound.mjs` 는 재기동 없이 `/cia/admin/relay` 로 중계한다. 격리 하네스는 `CIA_MIRROR_HEARTBEAT_BLOCKS='0'` 이라 기동 직후 자동 중계 경로 자체를 밟지 않는다.

#### I-2. 무인증 `/cia/register_rp` 로 origin 을 선점하면 진짜 RP 가 영구히 잠긴다(삭제·교체 경로 없음)
- 위치: `cia.js:572-611`(등록), `cia.js:583`(origin 으로 기존 엔트리 조회), `cia.js:593-595`(키 다르면 409 `service_key_mismatch` — status 와 무관), `cia.js:637-664`(관리자 라우트는 `GET /cia/rps`·`approve`·`deny` 셋뿐).
- 무엇이 잘못됐나: `register_rp` 는 인증이 없고(설계상 zkONE·zkTWO 자동 등록용으로 의도된 것은 맞다) origin 소유 확인도 없다. origin 당 엔트리는 하나이며, 한 번 생기면 **어떤 상태(pending·denied·approved)여도** 다른 `pk_service`/`X_svc` 로 온 요청은 409 다. `deny` 는 status 만 바꾸고 엔트리를 지우거나 키를 비우지 않으므로 관리자가 거절해도 그 origin 은 영원히 그 공격자 키에 묶인다. 운영자 슬롯 경로(`rp_key`)도 `if (!e)` 분기 안에서만 보므로, 선점된 origin 에는 키가 맞아도 닿지 못한다.
- 실패 시나리오: 공격자가 `POST /cia/register_rp { name:'zkTHREE', origin:'http://192.168.226.12:3001', pk_service:<자기 주소>, X_svc:<자기 점> }` 를 먼저 보냄 → 202 pending. 운영자가 `/cia/rp/create` 로 만든 `rp_key` 를 넣어 `new_rp.sh` 로 띄운 진짜 zkTHREE 가 같은 origin 으로 등록 요청 → 583행에서 선점 엔트리를 찾고 593행에서 **409 `service_key_mismatch`** → RP 가 영원히 등록 폴링에서 멈춤. 관리자가 `deny` 해도 다음 요청은 여전히 409(`e.status === 'denied'` 분기는 593행 뒤에 있다). 상태 파일을 손으로 고치는 것 말고 복구가 없다. 부수적으로 origin 문자열만 바꿔 가며 무제한으로 `state.rps` 를 불릴 수 있다(각 요청이 `persist()` 로 전체 상태를 다시 쓴다).
- 최소 수정: (a) `denied` 엔트리는 재등록 시 **새 키로 교체**(pending 으로 되돌림)를 허용하거나, 관리자 `DELETE /cia/rps/:arid`(또는 `reset`)를 추가한다. (b) 운영자 슬롯 경로를 강화: `rp_key` 가 맞으면 기존 선점 엔트리(approved 가 아닌 것)를 그 슬롯의 키로 덮어쓰게 한다 — 키를 아는 쪽이 운영자이므로 선점보다 우선권이 있다. (c) `rps` 수 상한 또는 origin 당 미승인 엔트리 TTL.
- 테스트: `tests/test_cia_register_issue.mjs:138-146` 이 "같은 origin 다른 키 → 409", "deny 뒤 403" 을 **의도된 동작으로** 단언한다. 선점·복구 시나리오(denied 뒤 정당한 키로 재등록, rp_key 로 선점 돌파)는 없다.

#### I-3. 무인증 경로의 동기 scrypt·전체 상태 persist 가 하트비트까지 굶겨 전원 fail-closed 를 부를 수 있다(+ 무차별 대입 제한 없음)
- 위치: `cia.js:386-390`(`hashPw`/`newPw`/`pwOk` — `scryptSync` N=16384), `cia.js:750-764`(`/cia/signup`: 무인증, scrypt + 계정 생성 + `persist()`), `cia.js:702-710`(`/cia/rp/signup` 동일), `cia.js:765-774`·`800-809`·`711-715`(로그인·인증 코드: 존재하는 uid/id 에 대해 scrypt), `cia.js:206`(`persist()` = 전체 상태 `JSON.stringify` + fsync + rename), `cia.js:1689`(하트비트가 같은 이벤트 루프의 `setInterval`).
- 무엇이 잘못됐나: 스펙 2026-10-22 §10 은 "동기 scrypt 가 이벤트 루프를 잠깐 막는 점은 데모 수준에서 수용" 이라고 적었다. 그러나 수용 범위에 **하트비트 기아**는 들어 있지 않다. 이 머신에서 `scryptSync` 1회 = **약 26 ms**(측정값). 단일 스레드라 초당 ~40 요청으로 루프가 포화되고, `/cia/signup` 은 인증 없이 그 비용 + 계정 하나 + 전체 상태 파일 재작성(계정 수에 비례)을 유발한다. 하트비트 틱(`heartbeatTick`)·거울 릴레이·`/cia/issue` 가 전부 같은 루프라, 포화가 `MAX_ROOT_AGE`(100블록) 이상 이어지면 캐노니컬·거울 root 가 늙어 **모든 사용자의 로그인·거래가 `RootTooOld` 로 fail-closed** 된다 — 공격자는 계정도 비밀도 필요 없다. 또 `/cia/user/login`·`/cia/auth/code`·`/cia/rp/login` 에 시도 제한·지연이 없어 8자 비밀번호(시드 `alicepw` 는 7자) 무차별 대입이 가능하다(코드 주석 768행은 응답 시간 차이만 데모 범위로 언급).
- 실패 시나리오: 공격자가 `POST /cia/signup {id:'x<n>', pwd:'aaaaaaaa'}` 를 초당 50회 보냄 → 이벤트 루프 상시 점유 → `heartbeatTick` 지연 → 공개 체인(12 s 블록)이라면 20분 뒤 `lastPublishedBlock` 이 100블록 넘게 늙음 → RP 오프체인 검증(`MODE3_MAX_ROOT_AGE`)·컨트랙트 `RootTooOld` 로 전원 거절. 부수로 `cia_state.json` 이 계정 수만큼 커지고 `/cia/accounts` 관리자 화면이 무거워진다.
- 최소 수정: (a) `scrypt`(비동기, libuv 스레드풀) 로 바꾸고 `pwOk` 를 async 로(호출 7곳 모두 이미 async 라우트 안이거나 async 로 바꿀 수 있다). (b) 무인증 쓰기 라우트(`/cia/signup`, `/cia/rp/signup`, `/cia/register_rp`, `/cia/auth/code`, 로그인)에 IP 당 토큰 버킷 또는 실패 횟수 기반 지연. (c) `persist()` 를 디바운스하거나 최소한 signup 류는 즉시 fsync 를 피한다. (d) 하트비트를 별도 타이머가 아닌 "게시 지연 감시" 로 두어 포화 중에도 최우선으로 돌게 하는 것은 과하므로 (a)(b) 로 충분.
- 테스트: 없음(`rate|lock|429` 관련 단언 없음). 데모 수용 사항이므로 **정책 재확인 필요** — 하트비트 기아 결과까지 수용할지 사용자가 정할 문제다.

### Minor

#### M-1. 프로토타입 키와 겹치는 아이디(`constructor`, `__proto__`)가 잘못된 409 로 막힌다
- 위치: `cia.js:403`(`state.loginIds[loginIdKey(id)] ?? null`), `cia.js:706`(`state.operators[id]`), `cia.js:755`.
- `state.loginIds`·`state.operators` 는 프로토타입이 있는 보통 객체라 `['constructor']` 가 `Object` 함수(truthy)를 돌려준다. 가입은 `id_taken`(409) 으로 거절되고(메시지가 틀림), 로그인은 `pwOk(state.accounts[<function>])` → 401 로 안전하게 끝난다. `__proto__` 는 LOGIN_ID_RE 가 선행 `_` 를 막지만 OPERATOR_ID_RE(`[a-z0-9_-]{3,32}`)는 통과 → `state.operators['__proto__']` 가 `Object.prototype`(truthy) → 409. 쓰기는 일어나지 않아 오염은 없다.
- 수정: 조회·존재 검사를 `Object.hasOwn(...)` 으로(코드 저장소 `peekCode` 는 이미 그렇게 한다), 또는 `loginIds`/`operators` 를 `Object.create(null)` 로.
- 테스트: 없음.

#### M-2. `revokeSessionMessage` 가 uid·Cf_s·nonce 의 필드 범위를 검사하지 않는다(다른 메시지와 불일치)
- 위치: `lib/mode3_issuance.js:67-71`(bound 만 검사), 비교: `issueRequestMessageV11`·`registerMessage` 는 `isField`/`isScalar`.
- `Cf_s + p` 같은 별칭은 Poseidon 안에서 같은 해시라 서명은 통과하지만 1067행의 `rec` 조회가 정규 문자열 비교라 404 로 끝난다 — 보안 결과는 없고 일관성 문제. `verifyRevokeBind` 도 `BigInt(Cf_s)` 로 정규화한다. 수정: 세 인자에 `isField`/`isScalar` 추가.
- 테스트: `tests/test_mode3_issuance.js` 에 범위 단언이 다른 메시지에만 있다(확인 필요).

#### M-3. 사용자 세션 MemoryStore 가 만료 없이 자란다
- 위치: `cia.js:521`(`cookie: { httpOnly, sameSite:'lax' }` — `maxAge` 없음, `saveUninitialized:false`).
- express-session MemoryStore 는 `cookie.expires` 가 없으면 서버 쪽 항목을 지우지 않는다. 로그인마다 `regenerate` 로 새 sid 가 생기고 옛 것은 지워지지만, 로그아웃하지 않은 클라이언트 수만큼 메모리에 남는다. 가입이 무인증이라(I-3) 공격자가 계정 하나로 반복 로그인해도 regenerate 가 이전 sid 를 지우므로 성장은 "다른 쿠키 저장소 수" 에 묶인다 — 데모에서 실질 위험은 낮다. 수정: `cookie.maxAge`(예: 12h) 지정.

#### M-4. `CIA_ADMIN_OPEN=1` 에서 본문 없는 관리자 POST 는 다른 사이트에서 CSRF 로 호출할 수 있다
- 위치: `cia.js:404-405`(ADMIN_OPEN 이면 헤더 검사 없음), `/cia/publish`(1287), `/cia/rps/:arid/approve|deny`(643·658), `/cia/openings/:id/approve|deny`(1635·1653) — 모두 본문 없이 동작.
- 문서(69행 주석·런북)는 "이 IdP 에 닿는 누구나" 를 경고하지만, 폼 POST(`text/plain`)는 CORS 프리플라이트가 없어 **피해자의 브라우저를 거쳐** LAN 밖에서도 닿는다(응답은 못 읽지만 효과는 남는다). `express.json` 이 본문을 안 파싱해도 위 라우트는 본문이 필요 없다. 데모 전용 모드이므로 Minor. 수정: ADMIN_OPEN 이어도 `X-CIA-Admin-Secret` 헤더의 **존재**(값 무관)는 요구한다 — `/cia/revoke` 1039행은 이미 그렇게 한다(`typeof hdr === 'string'`); `requireAdmin` 만 다르다.

#### M-5. RP 승인과 거절이 경합하면 denied 가 approved 로 덮인다
- 위치: `cia.js:643-657`(approve: `await makeShare` 뒤에 `e.status = 'approved'`), `cia.js:658-664`(deny: 동기).
- approve 가 `makeShare` 를 기다리는 사이 deny 가 들어오면 deny 는 `pending` 을 보고 `denied` 로 바꾸고, 재개한 approve 가 상태 재확인 없이 `approved` 로 덮는다. 관리자 전용·수 ms 창이라 Minor. 수정: `await makeShare` 뒤 `if (e.status !== 'pending') return 409`.
- 테스트: 없음.

#### M-6. 라우트 catch 가 `err.message` 를 그대로 응답한다
- 위치: `cia.js:620, 656, 889, 1007, 1115, 1289, 1436, 1528, 1540, 1568, 1632, 1651` 등.
- snarkjs·ethers·fs 오류 메시지가 그대로 클라이언트(지갑 → RP 페이지)로 간다. S4(2026-10-13) 로 vkey 경로는 막았지만 일반 경로는 남아 있다. 비밀값이 메시지에 들어가는 경로는 찾지 못했다(서명·토큰·비밀번호는 로그·응답 어디에도 없음). 수정: 알려진 `status` 가 있는 오류만 메시지를 내고 나머지는 `'internal'`.

#### M-7. 기동 시 전 칸 재발행·무제한 리프 묶음이 가스 상한을 넘으면 게시가 영구 실패한다(기존 기록 잔존)
- 위치: `cia.js:265-267`(fullRegistryRebuild/epochDiverged 때 `0..next-1` 전부), `cia.js:1250-1252`(pending·pendingSlots 전부 한 tx).
- 2026-09-23 "기록으로 남김" 과 같은 건. 가입자가 수천 명이면 한 tx 가 블록 가스를 넘어 모든 게시가 revert → 하트비트 실패 → root 늙음. 수정: 청크 게시(epoch 를 여러 개 써도 컨트랙트는 증가만 본다).

#### M-8. 개봉 승인에서 `x_AA` 가 null 인 RP 면 500·영구 pending(기존 기록 잔존)
- 위치: `cia.js:1641`(`BigInt(e.x_AA)`). 정직한 런타임에선 승인된 RP 만 개봉을 요청할 수 있어(1596행) 도달이 어렵다. 그대로 기록.

#### M-9. 폐기된 세션 기록이 만료 정리에 함께 지워져 관리자 "세션 폐기 목록" 에서 사라진다
- 위치: `cia.js:999`(`/cia/issue` 가 같은 체인의 만료 기록을 revokedAt 유무와 무관하게 filter), `cia.js:1454-1473`(pruneExpiredSessions 동일), `cia.js:1503-1516`(revoked_sessions 는 기록에서만 모은다).
- 리프는 `state.revoked` 에 남아 안전에는 영향이 없다. 표시·감사 용도의 문제. `pendingBounds` 에 남은 `pk_i` 와 대응되는 기록이 사라져 관리자 화면에서 bound 를 추적할 수 없게 되는 점도 같다.

#### M-10. 1회용 코드가 상태 파일에 평문으로 남는다
- 위치: `cia.js:489-496`(`state.codes[code] = {...}; persist()`).
- 파일은 0600·TTL 5분이고 코드만으로는 발급이 안 되므로(sk_u·π_IdP 필요) 영향은 작다. 수정하려면 `sha256(code)` 를 키로 저장.

#### M-11. 주석과 코드 불일치 두 곳(동작 무해)
- `cia.js:1103-1106`: "rec 은 버려진 객체" — `filter` 는 객체 참조를 유지하므로 `rec` 자체는 살아 있다. 재조회는 "그 사이 만료로 지워졌는가" 확인으로는 여전히 의미가 있어 코드는 그대로 두면 된다.
- `cia.js:1275`: 반환의 `heartbeat` 플래그가 `noNewBounds` 스냅샷을 쓴다 — 게시 중 새 bound 가 들어오면 값이 틀릴 수 있다(로그 문구만 영향).

#### M-12. 시드 계정 `alicepw` 는 가입 규칙(8자) 미달
- 위치: `cia.js:147-150`. 의도된 데모 계정이므로 수정 대상이 아니라 기록만(`CIA_DEMO_ACCOUNTS=1` 때만 존재).

## 3. 점검했으나 건전한 것(요약)

- **서명 입력 파싱(S1)**: `parseEddsaSig` 가 R8·S 범위를 걸러 `mulPointEscalar(-1n)` 무한 루프를 막는다. 네 라우트 모두 사용(857·882·955·1072).
- **1회용 코드**: 32B 난수, `Object.hasOwn` 조회, TTL, `{uid, purpose, auid}` 결속(register 는 auid null 강제, issue 는 정확 일치), **peek → 모든 검증 통과 → 상태 변경 직전 consume** 순서(840·864, 942·980·993). 동시 요청은 동기 구간에서 하나만 통과함을 확인. TTL 만료 테스트 있음(`test_cia_accounts.mjs:121`).
- **아이디 해석**: 숫자만인 아이디 금지(`LOGIN_ID_RE`)로 uid/아이디 이름공간이 겹치지 않고, `loginIds` 는 기동마다 accounts 에서 다시 만들어 손상 항목이 남지 않는다. 대소문자 색인 일관.
- **등록**: `registerAccount` 가 auid 필드 범위·pk_u 부분군·sig_reg 를 검증하고 await 뒤 409 를 재확인. OIDC 첫 로그인은 **등록 전** `registration.pk_u` 로 nonce 결속(리뷰 C1 반영, 922행).
- **발급**: 형식 → 필드 범위 → 계정·disabled → 체인 허용 → 부분군 → sig_u(`Cf_u·Cf_s` 를 IdP 가 점에서 유도) → π_IdP(공개 입력 IdP 조립) → 체인 생존 → disabled 재확인 → 물린 C_u 거절 → 게시 뒤 활성 cred 재확인(S2). `auid_s·arid_s` 는 저장하지 않는다(D1).
- **OIDC 검증기**: RS256 고정, iss 두 형태, aud=clientId, exp·iat·sub 필수, clockTolerance 60 s, 오류 분류(invalid 401 / unavailable 502), nonce 접두어 검사 → 라우트가 `reg:H(pk_u)`·`issue:H(pk_u|arid_s)`·`revoke:` 로 완전 대조. 토큰 재사용은 같은 (pk_u, arid_s) 안에서만 가능하고 sk_u 없이는 무용.
- **세션 폐기**: 서명 검증을 기록 조회보다 먼저(1068) → Cf_s 존재 오라클 없음. `verifyRevokeBind` 로 pk_i 를 sk_i 서명에 묶어 남의 세션키 상한 낮추기 차단. 만료 세션(head > max_height) 리프 삽입 거절(append-only 비대 방지). 낮추기만 새 리프, 올리기는 멱등. 관리자가 먼저 폐기한 세션에 사용자가 pk_i 를 붙이는 경로(1095).
- **게시**: `withPublishLock` 원자 획득·소유자 해제, `signedEpochMax` 를 **서명 전** 저장, revRoot·leaves·regRoot·slots 를 같은 동기 구간에서 스냅샷(게시 중 들어온 revoke/setSlot 은 뒤에 남음), 접수증 대기열·은퇴 슬롯 선처리, 게시 뒤 prefix 만 걷어냄. 다이제스트는 `lib/mode3_log.js` 한 곳.
- **크래시 복구**: tx 성공 뒤 persist 전에 죽어도 `reconcileWithChain` 이 pending 접두사·epoch·등록부를 체인 기준으로 맞춘다. `writeJsonAtomic` 은 tmp+fsync+rename.
- **상태 변경 순서**: `revokeAccount` 는 disabled·슬롯 0·slotRetired 를 persist 한 뒤에야 체인(접수증·게시)에 간다. `/cia/revoke session` 은 insert → push → 기록 → persist 가 동기.
- **IMT v2**: remove 없음(append-only 자료구조 강제), anchor·zeros 설계, 구간 비멤버십 증인(`low.value < lo`, `low.nextValue > hi || 0`) 논리 정확. 세션 리프 `H'·2^32 + c < 2^252`.
- **등록부**: 경로 규약(산술 연산, pathIndices)이 회로 주석과 일치. `set(0)` 멱등.
- **세션 쿠키**: httpOnly·lax, 로그인·로그아웃마다 `regenerate`(고정 방지), 두 역할 공존 로직 정확.
- **CORS**: 함수형 origin(정확 일치), 관리자 헤더는 허용 목록 밖, 5개 POST 프리플라이트.
- **개봉**: RP 서명 → arid·pk_CIA·pk_trace·chain·allowAgent·r≠0 → Groth16 순서(서명이 증명보다 앞이라 무인증 증명 검증 DoS 없음). dup 키 (arid, c1, c2, PPID). 결정 뒤 복호 재료 삭제.
- **로그·응답의 비밀**: 비밀번호·해시·코드·토큰·서명·x_AA·eddsa 키가 로그·응답에 나가는 경로를 찾지 못했다. `/cia/public_keys` 의 clientId·ethAddress 는 공개값.
- **프라이버시**: IdP 가 RP 를 알게 되는 경로는 설계된 개봉(approve)만. 발급 요청에 arid 원문 없음.

## 4. 테스트 공백

1. **기동 자동 게시 + 거울 + pendingBounds**(I-1): 폐기(pk_i) → 게시 전 종료 → 재기동 → 거울 `sessionBoundOf` 가 결국 설정되는지. `startIsolatedCia` 의 `CIA_MIRROR_HEARTBEAT_BLOCKS='0'` 기본 때문에 기동 직후 자동 중계 경로가 어느 테스트에서도 돌지 않는다 — 한 테스트만 `'1'` 로 띄울 것.
2. **RP origin 선점·복구**(I-2): denied 뒤 정당한 키로 재등록, `rp_key` 가 맞는 요청이 선점 엔트리를 넘는지. 현재 테스트는 409 를 정상으로 단언한다.
3. **무인증 쓰기 라우트의 부하·제한**(I-3): 최소한 "signup 100회 뒤 상태 파일 크기·응답 시간" 류의 smoke 또는 레이트 리밋 도입 뒤 429 단언.
4. 프로토타입 키 아이디(`constructor` 가입·로그인, 운영자 `__proto__`) — M-1.
5. approve/deny 경합 — M-5(게이트 프록시 기법은 `test_cia_issue_race.mjs` 에 이미 있다 — `makeShare` 는 체인을 안 타므로 createShare 를 지연시키는 훅이 필요, 확인 필요).
6. 큰 묶음 게시(수백 슬롯·리프) 가 가스 상한에서 어떻게 되는지 — M-7.
7. `revokeSessionMessage` 인자 범위 — M-2.
8. `/cia/admin/revoked_sessions` 가 만료 정리 뒤에도 폐기 목록을 보여야 한다면 그 기대를 테스트로 — M-9(기대 자체가 정책 결정).

---
근거는 전부 위 파일:행 번호로 직접 확인했다. 실행하지 않은 것: 서버·테스트 전부(`scryptSync` 비용 측정 one-liner 1회만). "확인 필요" 로 표시한 두 곳(M-2 의 issuance 테스트 범위, 테스트 공백 5 의 훅 가능성)은 코드로 확정하지 않았다.
