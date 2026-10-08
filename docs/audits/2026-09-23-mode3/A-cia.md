# 점검자 A — CIA(AA) 서버·발급·폐기·개봉

브랜치 `feat/mode3-cia` HEAD 기준, 읽기 전용. 대상: `cia.js`, `lib/mode3_cia_state.js`, `lib/mode3_issuance.js`,
`lib/mode3_credential.js`, `lib/mode3_revocation.js`, `lib/imt_v2.js`, `lib/imt.js`, `lib/mode3_trace.js`,
`lib/mode3_opening.js`, `lib/mode3_log.js`, `lib/mode3_rp_cert.js`, `lib/mode3_state.js` + 관련 테스트.

## 1. 판정 요약

- 과제로 지목된 일곱 항목(발급 검사 순서·원자성, π_u V2 의 속성 출처, 폐기의 pending→publish 완전성, max_height/chainAlive,
  개봉 검증, 비밀 취급, IMT v2 불변식) 중 **여섯은 코드에서 확인한 대로 설계·스펙과 일치**했고, 발급 경로에서 폐기된 C_u·비활성
  계정으로 σ_AA 가 나갈 틈은 찾지 못했다(유일한 실제 I/O 양보점 `chainAlive` 뒤에 재확인이 있다).
- **Critical 없음.** Important 2건은 (a) 개봉 중복 판정 키에 `c2`·`PPID` 가 빠져 tag 난수 r 이 겹치면 감사 기록이 다른 세션의
  uid 를 돌려주는 것, (b) 관리자 속성 변경이 본문 없는 요청에서 속성 4칸을 조용히 0 으로 만들고 활성 C_u 를 되돌릴 수 없게
  물리는 것이다.
- 나머지는 Minor 12건(오류 경로의 부분 변이, 무인증 `/cia/state` 노출, 정규화 규칙 불일치, `rebaseline` 잠복 함정, 문서
  내부 모순 등)이다. 게시·크래시 복구·상태 이행 경로는 fail-closed 로 잘 짜여 있고 테스트가 두텁다.

## 2. 발견 목록

### Critical
없음.

### Important

**I1. 개봉 중복 판정 키가 `(arid, c1)` 뿐이다 — 다른 세션의 uid·메타데이터가 감사 기록으로 돌아온다**
`cia.js:633`
```js
const dup = state.openings.find((o) => o.arid === arid && o.c1.x === c1x && o.c1.y === c1y &&
  (o.status === 'pending' || (o.status === 'approved' && o.resolved !== false)));
if (dup) return res.status(200).json({ id: dup.id, status: dup.status });
```
- 결함: 같은 `(arid, c1)` 이면 `c2`·`PPID`·`max_height`·`allowAgent` 가 전혀 달라도 **앞선 개봉 항목의 id** 를 돌려준다.
  `c1 = r·B8` 이므로 태그 난수 `r` 이 겹치는 두 트랜스크립트는 서로 다른 uid 를 담고도 같은 키를 갖는다.
- 실패 시나리오(확인 — 코드): 지갑 W 가 사용자 A 의 로그인에서 쓴 `r` 을 사용자 B 의 로그인에 재사용한다(`lib/mode3_wallet.js:176`
  의 정직한 경로는 매번 새 난수를 쓰므로 이 경로에 서지 않지만, r 은 지갑이 고르는 값이라 강제되지 않는다). 서비스가 A 의 세션
  개봉을 요청해 승인받은 뒤, **B 의 트랜스크립트로 다시 요청**하면 CIA 는 증명을 통과시키고도 `dup` 으로 A 의 id 를 준다.
  서비스는 `/cia/open/:id` 에서 A 의 `uid`·`PPID`·`max_height`·`chainid`·`allowAgent` 를 받아 B 의 트랜잭션을 A 에게 귀속시킨다.
  (개봉 = 조건부 프라이버시의 책임 추적 장치이므로, 잘못된 귀속은 그 장치의 목적을 깬다.)
- 고치는 방향: `dup` 키에 `o.c2 === c2 && o.PPID === PPID` 를 더한다(같은 트랜스크립트만 멱등으로 취급).

**I2. 관리자 속성 변경이 본문 없는 요청에서 속성을 전부 0 으로 만들고 활성 C_u 를 되돌릴 수 없이 물린다**
`cia.js:420-432` (`normalizeAttrs` 는 `lib/mode3_credential.js:66-77`)
```js
try { attrs = normalizeAttrs(req.body?.attrs).map(String); } catch (e) { return res.status(400)... }
acct.attrs = attrs;
const inserted = await retireActiveCred(uid);
```
- 결함: `normalizeAttrs(undefined)` 는 throw 하지 않고 `[0,0,0,0]` 을 돌려준다(짧은 배열도 0 으로 채운다). 즉 `attrs` 를
  빠뜨린 관리자 요청 한 번이 "속성 전부 0 + 활성 자격증명 폐기" 로 성공(200)한다.
- 실패 시나리오(확인 — 코드): 관리자 페이지/스크립트가 `POST /cia/accounts/12345/attrs` 를 본문 없이(또는 `{attrs:[1990]}`
  처럼 일부만) 보내면 `acct.attrs = ['0','0','0','0']` 이 되고 `retireActiveCred` 가 리프를 `pending` 에 넣는다. 폐기 트리는
  append-only 라 되돌릴 수 없고(`lib/imt_v2.js:294`), 사용자는 이후 출생연도·국가·등급이 전부 0 인 C_u 만 받는다. AttrGate
  같은 속성 게이트는 그 계정을 영구히 거절한다.
- 고치는 방향: 이 엔드포인트에서만 "길이 4 의 배열 필수" 를 강제한다(`Array.isArray(req.body?.attrs) && length === 4` 아니면 400).
  `normalizeAttrs` 의 패딩 동작은 발급 경로에 필요하므로 그대로 둔다.

### Minor

**m1.** `cia.js:298` — `/cia/register_rp` 안에서 `const S = (o) => ...` 가 모듈 최상단의 `S`(`cia.js:196`)를 가린다. 지금은
299행에서만 쓰여 TDZ 에 걸리지 않지만, 이 핸들러 앞쪽에 `S(ciaPub)` 류를 한 줄 넣는 순간 `ReferenceError` 가 된다(확인 — 코드).
→ 지역 이름을 `pt` 등으로 바꾼다.

**m2.** `cia.js:642-657` — `/cia/openings/:id/approve` 가 `state.rps[o.arid]` 를 재검증하지 않는다. `/cia/register_rp`
(무인증)는 v3 이행으로 `pk_service === null` 인 항목을 만나면 `x_AA = null; pk_trace = null; status='pending'` 으로 되돌린다
(`cia.js:276-283`). 그 arid 에 pending 개봉이 남아 있으면 승인 시 `BigInt(e.x_AA)` → TypeError → 500 이고 항목은 영구히
pending 이다(확인 — 코드). → 승인 앞에 `e?.status === 'approved' && e.x_AA` 를 확인해 409 로 돌려준다.

**m3.** `cia.js:236-244`, `478-485`, `427-429` — 오류 경로의 부분 변이. `retireActiveCred` 는 `c.revoked = true` 를 먼저 쓰고
`tree.insert` 를 부르므로, insert 가 throw 하면 "revoked 로 표시됐지만 리프가 `revoked`·`pending` 어디에도 없는" 상태가
메모리에 남고 다른 요청의 `persist()` 가 그대로 파일에 쓴다 — 그 C_u 는 영영 폐기 트리에 들어가지 않는다(이미 발급된 σ_AA 는
`max_height` 까지 산다). 마찬가지로 `revokeAccount` 의 `acct.disabled = true`, 속성 변경의 `acct.attrs = attrs` 도 persist 전
변이다. insert 가 throw 하는 조건은 용량 소진(2^32)·값 0·값 ≥ 2^252 뿐이라 **사실상 도달 불가**(추측 아님, `lib/imt_v2.js:161-168`
확인). → 상태 변이를 insert 성공 뒤로 미루거나, 실패 시 롤백한다.

**m4.** `cia.js:342` — `/cia/register` 는 `acct.password !== pwd` 로 평문 비교하고, `/cia/account/self_revoke`(`cia.js:581`)
는 `secretMatches`(timingSafeEqual)를 쓴다. 같은 데모 비밀번호에 규칙이 둘이다(확인). 데모라 실질 위험은 없지만 한쪽으로 통일이 낫다.

**m5.** `cia.js:48` — `HEARTBEAT_POLL_MS = Number(process.env.CIA_HEARTBEAT_POLL_MS) || 5000`. 바로 위 `cia.js:37-41` 이
"빈 문자열/0 이 조용히 기본값으로 떨어지는" 함정을 길게 설명하고 `envBig` 로 고쳤는데, poll 쪽은 같은 함정이 남아 있다
(`'0'` 을 주면 5000 이 된다, 확인). → `envBig` 과 같은 방식으로 맞춘다.

**m6.** `cia.js:604-615, 636` — `publicSignals` 는 `BigInt(v).toString()` 으로 정규화해 쓰는데(2026-09-18 점검 1 반영),
`D_svc` 는 요청 원문을 그대로 서명 메시지(`openRequestMessage`)와 `state.openings` 에 쓴다. 앞자리 0 이 붙은 `D_svc` 는 통과하고
저장되지만 다른 클라이언트가 정규형으로 재현하면 서명이 어긋난다(확인 — 코드). 기능 영향은 서비스 자신에게만 있으나 규칙이 갈린다.
→ `D_svc` 도 `pointFromStrings` → `toString()` 으로 정규화한 뒤 메시지·저장에 쓴다.

**m7.** `cia.js:679-684` — `/cia/state` 는 무인증으로 `credCount`(활성 사용자 자격증명 수)·`leafCount`·`pendingCount` 를
낸다. 루프백 바인딩이라 노출 범위는 좁지만, CIA 를 조회 경로에서 빼겠다는 설계 취지(§9.9)와는 결이 다르다(확인).

**m8.** `cia.js:105` + 호출처 전부 — `persist()` 는 매 변이마다 상태 **전체**를 `JSON.stringify` + `fsync` 로 동기 기록한다
(`lib/mode3_state.js:13-31`). `state.openings` 는 상한이 없고 승인된 서비스가 트랜스크립트마다 한 항목씩 늘릴 수 있으므로,
장기 운영에서 요청당 O(전체 상태) 동기 I/O 로 이벤트 루프가 막힌다(확인 — 코드; 데모 규모에서는 문제 없음).

**m9.** `lib/mode3_cia_state.js:56-61` — v6→v7 이행이 `state.revoked` 와 `state.pending` 을 **독립 조건**으로 push 한다.
어떤 이유로 리프가 이미 `revoked` 에 있고 `pending` 에는 없으면 pending 만 늘어 "pending 은 revoked 의 접미사" 불변식
(`cia.js:107-114` 의 `buildPublishedTree` 전제)이 깨지고, 기동 시 root 대조 실패 → `process.exit(1)` 로 복구가 로그 재배포밖에
없다(확인 — 코드; `/cia/user_cred` 의 409 가드 때문에 실제 도달은 어렵다). → 두 배열을 한 조건으로 함께 push 한다.

**m10.** `lib/imt_v2.js:314-318` — `rebaseline(liveValues)` 는 값을 **오름차순으로 정렬해** 새 트리를 쌓는다. Mode 3 지갑은
`Revoked` 이벤트를 **삽입 순서**로 재생해 트리를 만들므로(설계상 root 는 순서 의존), CIA 가 언젠가 rebaseline 을 쓰면 그 순간
모든 지갑이 root 불일치로 fail-closed 된다. 현재 Mode 3 호출처는 없다(확인 — grep). 잠복 함정으로만 기록한다.

**m11.** `docs/MODE3_DEMO.md:146-147` vs `docs/MODE3_DEMO.md:226` — 속성 변경 절은 "속성 변경 직후 `/cia/publish` 를 따로
부르지 말고 하트비트 게시에 묶이게 둔다"(익명 집합 때문)고 하는데, 시연 워크스루 S8′ 은 "속성 변경 → `/cia/publish`" 를
지시한다. 문서 내부 모순이다(확인). → 워크스루에 "시연 편의상 즉시 게시, 운영에서는 하지 말 것" 단서를 단다.

**m12.** `cia.js:403-417` + `lib/mode3_issuance.js:129` — `/cia/attrs` 는 nonce 의 신선도·재사용을 검사하지 않는다(스펙 §3.3
이 명시한 선택). 가로챈 `(uid, nonce, sig_u)` 한 벌로 언제든 그 계정의 속성을 다시 읽을 수 있고, `disabled` 도 보지 않는다.
문서대로이므로 결함이 아니라 한계로만 적는다(확인).

## 3. 강점 (다음 점검자가 다시 볼 필요 없는 것)

1. **발급 경로의 원자성**: `/cia/issue`(`cia.js:437-473`)·`/cia/user_cred`(`cia.js:359-400`) 안의 await 는 `chainAlive`
   하나를 빼면 전부 캐시된 WASM 약속에 대한 마이크로태스크라 핸들러가 다른 요청과 인터리브하지 않는다. 유일한 실제 양보점인
   `chainAlive` 뒤에 `acct.disabled || activeCred(uid)?.Cf_u !== cfu` 재확인이 있고 그 뒤는 전부 동기다. `user_cred` 는
   활성이 없어질 때까지 도는 루프와 마지막 동기 구간의 이중 재확인으로 "disabled 계정에 활성 자격증명" 을 막는다.
   `tests/test_cia_issue_race.mjs` 가 `eth_blockNumber` 게이트 프록시로 이 창을 결정적으로 재현해 세 경우(동시 user_cred,
   user_cred↔revoke, issue↔revoke)를 덮는다. **과제 1번은 코드·테스트 모두에서 통과.**
2. **π_u V2 의 속성 출처**: `cia.js:376` 이 `attrs: acct.attrs.map(BigInt)`, `cm_u: pointFromStrings(acct.cm_u)` 로 **서버 기록만**
   넘긴다. 요청 본문의 attrs 를 읽는 곳은 어디에도 없다(`/cia/register` 도 `DEMO_ACCOUNTS` 값을 쓴다). `verifyUserCred`
   (`lib/mode3_issuance.js:106-126`)는 네 점의 정규 인코딩·곡선·부분군, 네 스칼라의 `[0, r)` 범위, 챌린지 재계산을 모두 하고
   챌린지에 uid·attrs·C_u·cm_u 가 들어가 바꿔치기가 불가능하다. **과제 2번 통과 — Critical 없음.**
3. **게시와 크래시 복구**: `publicationDigest`(`lib/mode3_log.js:26-31`)가 `(DOMAIN, 로그 주소, root, epoch, keccak(leaves))`
   를 덮고 `contracts/RevocationLog.sol:42-46` 의 `digestFor` 와 바이트 단위로 같다(JS 는 `solidityPacked`, Solidity 는
   `abi.encodePacked` — 둘 다 bytes32 연결, 빈 배열도 일치). `publishing` 플래그로 게시가 직렬화되고, `leaves`/`root` 스냅샷은
   같은 동기 구간에서 잡히며, tx 성공 뒤 실은 앞부분만 pending 에서 잘라 그 사이 들어온 폐기를 잃지 않는다. `reconcileWithChain`
   의 접두사 walk 는 기동·게시 직전 양쪽에서 돌고 불일치면 기동 거부/503 으로 fail-closed 다. `tests/test_cia_startup.mjs` 가
   크래시 복구·epoch 따라잡기·로그 재배포 거부·상태 파일 유실 거부를 모두 덮는다. **과제 3번 통과**(폐기·자기 폐기·속성 변경이
   전부 `retireActiveCred` → `revoked`+`pending` → `persist()` 를 타고, 응답 전에 파일에 남는다).
4. **개봉 검증**: 공개 입력 23개의 인덱스 매핑이 `circuits/pi_cred.circom:192-196` 의 선언 순서와 정확히 일치하고
   (`cia.js:614`, `lib/mode3_rp.js:52`, `contracts/Mode3Wallet.sol:121-135` 셋 다 동일), 서비스 서명(`recoverSigner` vs
   `e.pk_service`)·`isFreshTs`·`wrong_arid`·`untrusted_cia`·`wrong_trace_key`·`wrong_chain`·`bad_tag`·Groth16 을 다 통과해야
   pending 이 되며, uid 는 운영자 승인 시점에야 계산된다. 조각 PoK 는 CIA 가 `proveShare` 로 내고 **서비스가**
   `mode3_rp.js:76-104` 의 `verifyCiaShare` 에서 `verifyShare` + `pk_trace == X_svc + X_AA` 를 둘 다 확인한다(등록 파일 재적재
   때도 재검증). `resolveTagPlaintext` 의 역조회는 `Poseidon(uid, arid)` 정확 일치라 오매칭 확률이 무시 가능하고, `D_svc` 를
   조작해 특정 uid 로 맞추려면 `x_AA` 를 모르는 채 `Poseidon(K)` 를 겨냥해야 해 실현 불가다. **과제 5번 통과.**
5. **IMT v2 불변식**: anchor 리프 `(0,0,0)` 은 절대 제거·재사용되지 않고, `zeros[0]` 이 리터럴 `0n` 이라 빈 슬롯이 anchor 와
   모양이 같아지는 위조 경로가 막혀 있다. `validateValue` 가 0 과 2^252 이상을 거부하고, `leafValue`/`has`/`getNonMembershipWitness`
   가 모두 `MASK_252` 로 같은 정규화를 거치며, 용량 소진은 조용한 오답 대신 throw 다. `remove()` 가 없어 append-only 가
   자료구조 수준에서 강제된다. **과제 7번은 `rebaseline` 잠복 함정(m10)을 빼면 통과.**
6. **max_height/chainAlive(과제 4번)**: CIA 는 `< 2^64` 만 보고(`cia.js:444`) 상한 L 은 검증자가 강제한다 —
   `lib/mode3_rp.js:58-59`(`head ≤ max_height ≤ head + 400`)와 `contracts/Mode3Wallet.sol:133-135`(`Expired`/`TooFarExpiry`)가
   같은 규칙이고, 지갑의 `chooseMaxHeight`(ttl 300 + grid 100)는 최댓값이 `head + 399` 라 L=400 안에 든다. 하트비트 기본 50 <
   `MAX_ROOT_AGE_DEFAULT` 100 도 문서(`lib/mode3_onchain.js:12-15`)와 일치한다. **문서와 코드가 어긋나지 않는다.**
7. **비밀 취급(과제 6번)**: `sk_u` 는 생성 후 응답에 한 번 실리고 상태에는 `pk_u` 만 남는다(`cia.js:350-354`). CIA 는 `s_u` 를
   구조적으로 볼 수 없다(π_u 가 숨긴다). `x_AA` 는 상태 파일에만 있고 `rpView`(`cia.js:316`)·`/cia/openings`·오류 메시지 어디에도
   나가지 않는다. 키·상태 파일은 `writeJsonAtomic(..., 0o600)` 으로 임시 파일 → fsync → rename 이다. `cia_keys.json` 파손 시
   조용히 새 키를 만들지 않고 parse 예외로 죽는다(Mode 2 의 키 회전 연쇄를 부르는 경로가 없다). 관리자 페이지는 시크릿을
   저장하지 않고 헤더로만 보낸다.

## 4. 점검하지 못한 것

- **실행 검증 없음.** COMMON.md 의 지시대로 서버 기동·테스트 실행을 하지 않았다. 모든 판정은 정적 읽기와 회로/컨트랙트
  선언과의 대조에 기반한다 — 특히 I1 은 코드 논리로만 확인했고 실제 재현은 하지 않았다.
- `cia_state.json`·`cia_keys.json` 의 실제 내용·파일 권한(읽기 금지). 코드상 0600 인 것만 확인했고, 이미 존재하는 파일의
  권한이 과거에 다른 모드로 만들어졌을 가능성은 확인할 수 없었다.
- `circuits/pi_cred.circom` 내부(비멤버십 v3 제약, TraceTag, 선택 공개 구간 술어)와 `build/mode3` vkey 가 그 회로에서 나온
  것인지 — 점검자 C 범위.
- 지갑·Snap 쪽 증인 구성과 `lib/mode3_rcl_sync.js`(범위 제외).
- 개봉 요청의 Groth16 검증이 실제로 23개 공개 입력을 요구하는지는 vkey 를 열지 않아 확인하지 못했다(snarkjs 가 길이 불일치를
  거르는지는 라이브러리 동작에 의존 — `cia.js:604` 의 `publicSignals.length !== 23` 선검사가 있어 실질 위험은 없다).
