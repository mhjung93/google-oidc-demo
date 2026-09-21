# Mode 3 — 자격증명 이중 구조 설계: 사용자 자격증명 C_u 와 세션 커밋 C_s

작성 2026-09-21. 기반: `2026-09-18-mode3-onchain-execution-design.md`(온체인 실행, max_height 지갑 결정판, HEAD 6181cda).
사용자 결정(2026-09-21): 속성을 **사용자 속성**(세션과 무관, 사용자가 관리)과 **AA 속성**(세션 관련: max_height, 세션 공개키,
nonce)으로 나눈다. AA 는 사용자 속성으로 만든 자격증명 하나를 사용자당 하나 관리하고, 폐기 요청이 오면 그 자격증명을 RCL 에 올려
그 사용자의 **모든 세션**을 무효화한다. 세션 속성은 여전히 AA 가 세션마다 확인·서명한다. 사용자 자격증명은 **사용자당 하나**다(서비스별 아님).

---

## 1. 무엇이 달라지는가

| 항목 | 지금(2026-09-18) | 이 설계 | 이유 |
|---|---|---|---|
| 커밋 | `C = Commit(uid, arid, s_u, pk_i, a₁..a₄; blind)` 세션마다 | `C_u = Commit(uid, s_u, a₁..a₄; blind_u)` 사용자당 하나 + `C_s = Commit(arid, pk_i; blind_s)` 세션마다 | 사용자 속성과 세션 속성 분리 |
| AA 서명 | `Sign(D_V4, C, max_height, chainid, allowAgent)` | `Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent)` | 세션 속성은 AA 가 확인·서명 |
| 폐기 리프 | `Poseidon(TAG=3, C)` 세션마다 | `Poseidon(TAG=4, Cf_u)` 사용자당 하나 | 리프 하나로 모든 세션 무효화 |
| 계정 폐기 | 미만료 세션 리프 전부 삽입 + disabled | 활성 C_u 리프 삽입 + disabled | 리프 N → 1 |
| 세션 발급의 ZKP | π_issue(시그마, C 의 uid·s_u 정합) | 없음 — C_u 조회 + sig_u 만 | uid·s_u 는 C_u 발급 때 이미 증명됨 |
| 사용자 자격증명 발급 | (없음 — 매 세션이 발급) | `POST /cia/user_cred`: π_u(시그마) + sig_u, 속성 바뀔 때만 | 드문 작업 |
| AA 의 세션 기록 | `issued[uid] = [{leaf, C, max_height, chainid}]` | 없음 | 폐기가 세션 기록에 의존하지 않는다 |
| 만료 정리 | `CIA_REVOKE_SKEW_BLOCKS`, 체인별 헤드로 정리 | 없음 | 지울 세션 기록이 없다 |
| 공개 입력 | 14개 | 14개 그대로 | 서비스·컨트랙트 검사 불변 |
| 회로 | 25,560 제약 | ≈ 27k(추정) | 커밋 항 9 → 10, Poseidon 압축 +1 |
| 세션 폐기(하나만) | 가능(`scope=credential`, C 지정) | 불가 — 계정 단위만 | 사용자 결정. §9 |

바뀌지 않는 것: PPID 유도, 트레이스 태그·개봉, RevocationLog·게시·하트비트, 서비스 검사 순서(§6.1 2026-09-18), Mode3Wallet
검사 순서(§5.3), max_height 를 지갑이 정하고 검증자가 L 로 막는 규칙, 온체인 공개성 불변식(§2).

---

## 2. 불변식 재확인: AA 가 본 값은 공개 입력에 없어야 한다

AA 가 이 설계에서 보는 값: `uid, C_u, C_s, chainid, allowAgent, max_height`. 온체인 공개 입력: `PPID, arid, pk_i, max_height, chainid,
allowAgent, root, pk_AA, pk_trace, tag`. 대조 가능한 값은 여전히 `(chainid, allowAgent, 양자화 max_height)` 뿐이다.

- **pk_i 는 C_s 안에 둔다.** 덱 12장은 세션 공개키를 AA 속성으로 평문에 두지만, 그러면 AA 가 온체인 pk_i 로 트랜잭션 ↔ uid 를
  바로 잇는다(2026-09-18 §9.4). AA 는 "커밋된 세션키가 있다"는 것만 확인하고 서명이 그것을 덮으므로 바꿔치기는 불가능하다.
- **C_u 는 어느 서비스에도 나가지 않는다.** π_rp 의 비공개 증인이고 리프도 비공개다. 서비스 간 연결(G3)은 지금처럼 PPID 의 arid 가
  갈라 주며, 두 서비스가 기록을 합쳐도 C_u 로 이을 값이 없다.
- **세션키 재사용은 C_s 의 arid 가 막는다.** 같은 세션 자격증명은 다른 arid 에서 열리지 않는다. 열린다 해도 PPID 가 공개 입력 arid
  를 쓰므로 트랜스크립트 재생은 arid 불일치로 거절된다.
- **폐기 시각 상관**: 리프 하나가 게시되면 그 사용자의 모든 서비스 세션이 같은 블록에 죽는다. 지금 계정 폐기(리프 전부 일괄 삽입)와
  같은 상관이며, 게시 한 번에 섞인 리프 수가 익명 집합이다. 리프 값은 Poseidon(4, Cf_u) 라 서비스가 대조할 수 없다.
- **AA 가 세션별로 갖는 기록이 사라진다.** 논문 V-D "AA 는 성명이 만료된 뒤 사용자를 로그인과 잇는 것을 아무것도 갖지 않는다"가
  "발급 직후부터 아무것도 갖지 않는다"로 강해진다.

---

## 3. 자격증명

### 3.1 사용자 자격증명 C_u

```
C_u_pt = uid·G_UID + s_u·G_SU + a₁·G_ATTR0 + a₂·G_ATTR1 + a₃·G_ATTR2 + a₄·G_ATTR3 + blind_u·H
Cf_u   = Poseidon(C_u_pt.x, C_u_pt.y)
```

생성원은 `lib/mode3_credential.js` `PEDERSEN_GENERATORS` 의 같은 점을 쓴다(G_ARID, G_PKI 만 안 쓴다). 스칼라는 전부 `[0, 2^250)`.
사용자당 **활성 C_u 는 하나**다. 속성을 바꾸면 새 C_u 를 발급받고, AA 는 옛 C_u 의 리프를 pending 에 넣는다(§4.2). 만료는 두지 않는다 —
세션에 max_height 가 있고 폐기는 RCL 이 하므로, C_u 의 수명은 "폐기될 때까지"다. (지갑 비밀 유출 시 노출은 지금과 같다: s_u 가 새면 새
세션을 계속 만들 수 있고, 막는 것은 폐기뿐이다.)

### 3.2 세션 커밋 C_s

```
C_s_pt = arid·G_ARID + pk_i·G_PKI + blind_s·H
Cf_s   = Poseidon(C_s_pt.x, C_s_pt.y)
```

로그인마다 새 blind_s. arid 를 넣는 이유는 §2(세션키 재사용 차단). AA 는 C_s 를 열지 못하고 열 필요도 없다.

### 3.3 AA 서명 메시지

```
m = Poseidon(DOMAIN_MODE3_CRED_V5, Cf_u, Cf_s, max_height, chainid, allowAgent)
DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149        // ASCII "MODE3CREDV5"
σ_AA = EdDSA-Poseidon.Sign(sk_AA, m)
```

Poseidon 인자 6개(V4 는 5개). max_height 는 지갑이 정한 값 그대로(2026-09-18 §3.2 갱신 유지).

### 3.4 요청 서명 sig_u

```
사용자 자격증명 요청:  Poseidon(DOMAIN_MODE3_USERCREDREQ, C_u_pt.x, C_u_pt.y)
                      DOMAIN_MODE3_USERCREDREQ = 102762131813745922824802108462542767441   // ASCII "MODE3USERCREDREQ"
세션 발급 요청:       Poseidon(DOMAIN_MODE3_ISSUEREQ_V4, Cf_u, C_s_pt.x, C_s_pt.y, chainid, allowAgent, max_height)
                      DOMAIN_MODE3_ISSUEREQ_V4 = 401414577397388343646241740924474932       // ASCII "MODE3ISSUEREQV4"
```

둘 다 등록 때 받은 sk_u 로 서명한다. 세션 요청 서명이 Cf_u 를 덮으므로 제3자가 남의 C_u 에 자기 C_s 를 붙여 달라고 할 수 없다.

### 3.5 사용자 자격증명 증명 π_u (시그마 프로토콜)

지금 `proveIssuance` 에서 arid·pk_i 항을 뺀 것이다.

```
PoK{ (s_u, a₁..a₄, blind_u, r_u) :
     C_u_pt = uid·G_UID + s_u·G_SU + Σ aₖ·G_ATTR(k-1) + blind_u·H   ∧   cm_u = s_u·G_SU + r_u·H }
공개: uid, C_u_pt, cm_u.   FS 도메인 DOMAIN_MODE3_USERCRED = 6125100363120193649816638735684   // ASCII "MODE3USERCRED"
```

응답 스칼라 7개(z_su, z_attr[4], z_blind, z_ru), 커밋 점 T1·T2. 검증은 `verifyIssuance` 와 같은 구조(부분군 검사, z < ℓ, 챌린지 재계산,
두 등식). 지금 155/164 ms 보다 조금 빠르다(지수승 2개 감소).

### 3.6 폐기 리프

```
leaf = Poseidon(TAG_MODE3_USER, Cf_u),   TAG_MODE3_USER = 4      // TAG_MODE3_CRED=3(V4 세션 리프)과 갈라 둔다
```

리프는 C_u 자체도, C_u 의 해시 하나도 아니다: 점 C_u 를 Cf_u 로 압축(필드 원소 하나, 서명 인자와 같은 값)하고 태그 4 를 앞에 붙여 다른 리프 종류
(Mode 2 의 1·2, V4 의 3)와 값이 겹치지 않게 한다. 회로는 증인에서 연 C_u 로부터 같은 식으로 리프를 계산하므로 증명자가 다른 리프를 제시할 수 없다.

---

## 4. CIA (`cia.js`)

### 4.1 `POST /cia/user_cred` — 사용자 자격증명 발급 (신규)

요청 `{uid, C_u_pt, proof, sig_u}`.
검사 순서: 형식 → 계정 존재·disabled 아님 → C_u_pt 부분군 점 → sig_u(§3.4) → π_u(§3.5).
효과: `accounts[uid].creds` 에 `{Cf_u, C_u_pt, leaf, issuedAt, revoked:false}` 추가. **이미 활성 C_u 가 있으면** 그 항목을
`revoked:true` 로 바꾸고 리프를 `pending` 에 넣는다(다음 게시에 나간다). 같은 Cf_u 재요청은 200 멱등.
응답 `201 {Cf_u, leaf}`. AA 서명은 없다 — 세션 서명(§3.3)이 Cf_u 를 덮는다.

### 4.2 `POST /cia/issue` — 세션 발급 (V5)

요청 `{uid, Cf_u, C_s_pt, chainid, allowAgent, max_height, sig_u}`.
검사 순서: 형식 → disabled → chainid 허용·체인 생존(`chainAlive`) → `max_height < 2^64` → `allowAgent ∈ {"0","1"}` → sig_u(§3.4)
→ **Cf_u 가 이 uid 의 활성 자격증명**(`creds` 에서 `revoked:false` 인 항목과 일치; 아니면 403 `no_user_cred`) → C_s_pt 부분군 점 → 서명.
응답 `{Cf_u, Cf_s, max_height, chainid, allowAgent, sig:{R8,S}}`.
**기록하지 않는다.** `issued` 맵, `pruneExpired`, `CIA_REVOKE_SKEW_BLOCKS` 는 삭제한다(env 는 경고 후 무시).
π_issue 검증이 사라지므로 발급 지연은 서명 비용(수 ms)이 된다.

### 4.3 폐기

- `POST /cia/revoke {uid, scope:'account'}`: 활성 C_u 의 리프를 pending 에 넣고(`revoked:true`), `disabled=true`. 활성 C_u 가 없으면
  disabled 만. 멱등.
- `POST /cia/revoke {uid, scope:'credential'}`: 활성 C_u 의 리프만 넣는다(계정은 살아 있음 → 사용자가 새 C_u 를 받아야 함). "속성 정정
  강제" 용도. `leaf`/`C` 인자는 없어진다(사용자당 하나이므로 지목할 것이 없다).
- 자기 폐기(`/cia/self_revoke`, pwd): `scope:'account'` 와 같다.
- `set_disabled false`(복구): 계정만 살린다. 옛 C_u 는 이미 트리에 있으므로 사용자는 새 C_u 를 발급받는다(지갑이 자동으로 한다, §6.1).
게시·하트비트는 그대로(2026-09-18 §4.5).

### 4.4 상태 v6

```
accounts[uid] = { pk_u, cm_u, disabled, creds: [ { Cf_u, C_u_pt:{x,y}, leaf, issuedAt, revoked } ] }
issued 삭제.  rps, openings, revoked, pending, epoch 는 그대로.
```

이행(v5 → v6): `issued` 를 버리고(경고 로그) 각 계정에 `creds: []` 를 넣는다. 옛 세션 자격증명은 서명 도메인이 달라 어차피 V5 회로에서
안 열린다. RevocationLog 는 리프 태그가 바뀌므로 새로 배포한다(`.env` `CIA_LOG_ADDRESS` 갱신).

### 4.5 개봉

변경 없음. 태그 평문 `Poseidon(uid, arid)` 역조회는 `accounts` 의 uid 목록으로 한다(지금도 `issued` 를 쓰지 않는다).
개봉 결과의 `allowAgent, max_height` 는 트랜스크립트 공개 입력에서 읽는다(지금과 같음).

### 4.6 `/cia/public_keys`

변경 없음(`pk_CIA, logAddress, chainIds, heartbeatBlocks`).

---

## 5. 회로 `pi_cred` V5 (`circuits/pi_cred.circom`)

비공개 입력: `uid, s_u, attrs[4], blind_u, blind_s, r, S, R8x, R8y, lowValue, lowNextIndex, lowNextValue, pathElements[32], pathIndices[32]`
(V4 의 `blind` 하나가 `blind_u, blind_s` 둘이 된다. arid 는 공개 입력에서 읽는다.)
공개 입력 14개, 순서 그대로: `PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2`.

조건:
1. `C_u_pt = CommitUser(uid, s_u, attrs, blind_u)`, `Cf_u = Poseidon(C_u_pt)` — `circuits/lib/mode3_commit.circom` 에 `CommitUser`(7항)
   와 `CommitSession`(3항) 템플릿을 추가한다. 생성원 상수는 기존 `CommitPedersen` 의 것을 글자 단위로 복사.
2. `C_s_pt = CommitSession(arid, pk_i, blind_s)`, `Cf_s = Poseidon(C_s_pt)`.
3. `EdDSA-Poseidon.Verify(pk_CIA, σ, Poseidon(DOMAIN_MODE3_CRED_V5, Cf_u, Cf_s, max_height, chainid, allowAgent))`.
4. `PPID = Poseidon(uid, s_u, chainid, arid)` — 변경 없음.
5. `Poseidon(TAG_MODE3_USER=4, Cf_u) ∉ Tree(revRoot)` — 리프 유도만 바뀐다.
6. 태그 `c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon((r·pk_trace).x, .y)` — 변경 없음.
7. `allowAgent·(allowAgent−1) = 0`, `pk_i < 2^160`, `max_height < 2^64`, 커밋 스칼라 250비트 — 변경 없음. **`r ≠ 0` 을 회로에 넣는다**
   (사용자 결정 2026-09-21; `IsZero(r).out === 0`, 제약 2개). 컨트랙트·서비스의 `c1 ≠ O` 검사는 방어선 중복으로 그대로 둔다.

제약 추정: 스칼라곱 +1(≈ +1.3k), Poseidon(2) +1(≈ +240), Poseidon 인자 5→6(≈ +60) → 약 27.2k. 실측은 빌드 후 §8 에 적는다.
빌드: `bash scripts/build_mode3_circuit.sh`(pot21). vkey·`PiCredVerifier.sol` 재생성 → 서비스가 검증자·팩토리를 재배포 → PPID 계정 주소가
전부 바뀐다(2026-09-18 과 같은 수용).

---

## 6. 지갑 (`mode3_wallet_agent.js`, `lib/mode3_wallet.js`)

### 6.1 상태 v6

```
registration = { uid, s_u, r_u, sk_u, cm_u, attrs[4],
                 userCred: { C_u_pt:{x,y}, Cf_u, blind_u, leaf, issuedAt } | null }
sessions[r_s] = { arid, PPID, chainid, allowAgent, factoryAddress, pk_trace,
                  C_s_pt, blind_s, sessionPrivKey, pk_i,
                  credential: { Cf_u, Cf_s, max_height, chainid, allowAgent, sig, pk_CIA }, issuedAt }
```

`userCred` 는 첫 로그인 때(또는 속성 변경 때) 만든다. 이행(v5 → v6): 세션과 userCred 를 비운다(옛 형식), 등록은 유지 — 지금 규칙과 같다.

### 6.2 로그인 흐름 (2026-09-15 §5 + 온체인 §6.3 위에서 바뀌는 부분만)

1. 인증서·오리진·pk_trace·팩토리 검증 — 그대로.
2. 체인 동기화 `synced = syncRevocationTree()` — 그대로.
3. **사용자 자격증명 확보**: `userCred` 가 없거나 `synced.tree.has(userCred.leaf)` 이면(폐기됨) 새로 만든다:
   blind_u 뽑기 → C_u_pt → π_u(§3.5) → sig_u → `POST /cia/user_cred`. 403(disabled)이면 `account_disabled` 로 끝.
   ※ 폐기된 뒤 `set_disabled false` 로 복구된 계정은 여기서 자동으로 새 C_u 를 받는다.
4. **세션 발급**: 세션키 생성, blind_s, C_s_pt, `max_height = chooseMaxHeight(head)`, sig_u → `POST /cia/issue`(§4.2).
5. 증명: 증인에 `blind_u, blind_s` 와 userCred 의 속성, 세션의 arid 등. 캐시 키 `(root, r_s)` 그대로.
6. 이후(σ, 세션 요청, 재검증, /wallet/tx) — 그대로.

재검증·트랜잭션의 폐기 확인: `synced.tree.has(userCred.leaf)` 이면 모든 세션이 `revoked`. 세션별 확인은 없어진다.

### 6.3 속성 변경 `POST /wallet/attrs {attrs}` (신규)

등록의 attrs 를 바꾸고 §6.2 3단계를 강제 실행한다(새 C_u). AA 가 옛 리프를 pending 에 넣으므로 다음 게시에 옛 C_u 의 세션이 죽는다 —
지갑은 기존 세션을 즉시 지우고 사용자에게 재로그인을 안내한다. 데모 페이지에 버튼 하나.

### 6.4 `/wallet/status`

`userCred: { Cf_u, issuedAt, revoked: bool }` 를 추가한다. 세션 목록의 `max_height` 등은 그대로.

---

## 7. 서비스·컨트랙트

- `lib/mode3_rp.js`, `mode3_rp.js`: vkey 경로만(빌드 산출물). 검사 순서·reason 코드 불변.
- `contracts/Mode3Wallet.sol`, `Mode3WalletFactory.sol`, `RevocationLog.sol`: **변경 없음**. `PiCredVerifier.sol` 은 snarkjs 가 재생성.
- 서비스 기동 시 검증자·팩토리 자동 재배포(등록 파일에 `factoryAddress` 가 있으면 경고 — 2026-09-18 최종 리뷰 규칙 그대로).

---

## 8. 성능·비용 (예상 → 실측으로 교체)

| 항목 | 지금 | 예상 |
|---|--:|--:|
| 세션 발급(AA) | 422 ms (π_issue 155 + 검증 164 + 서명) | ≈ 10 ms |
| 사용자 자격증명 발급 | — | ≈ 300 ms, 속성 변경 때만 |
| π_rp 증명 | 858 ms, 25,560 제약 | ≈ 900 ms, ≈ 27.2k 제약 |
| 로그인 왕복 | 1,394 ms | ≈ 950 ms (첫 로그인은 + 300 ms) |
| 계정 폐기 게시 | 리프 N개 ≈ 40k + 1.1k·N gas | 리프 1개 ≈ 41k gas |
| 공개 입력·execute gas | 14 / 339k–388k | 불변 |

---

## 9. 덱·논문과 다르게 한 것과 이유

1. **세션 공개키를 커밋 안에 둔다**(덱 12장은 AA 속성 평문). §2. AA 는 C_s 로만 확인한다.
2. **세션 단위 폐기를 없앤다.** 사용자 결정(2026-09-21): 폐기 = 사용자의 모든 세션. 필요해지면 `Poseidon(TAG_S, Cf_s)` 리프로 두 번째
   비멤버십을 넣는다(+≈8k 제약, 리프 관리 부활). 이 문서 범위 밖.
3. **사용자 자격증명은 사용자당 하나, 서비스별 아님.** 서비스별(C_{u,s})로 하면 서비스 단위 폐기가 가능하지만 속성 변경 시 서비스 수만큼
   재발급하고 AA 가 서비스 수를 안다. 프라이버시는 두 안이 같다(§2). 사용자 결정.
4. **C_u 만료 없음.** §3.1.
5. 2026-09-18 §9 의 결정들(nonce·H(C) 비공개, cm_u 유지, 태그 평문 arid, 트랜잭션마다 π 첨부)은 그대로.
6. **발급 요청 인증은 pwd 가 아니라 sk_u 서명**(덱 13장은 pwd). 2026-09-14 부터의 규칙이며 이 문서에서 명시한다. pwd 는 등록·자기 폐기에만.

---

## 10. 구현 범위와 순서

1. `lib/mode3_credential.js`: `userCommit`, `sessionCommit`, `credMessageV5`, 도메인·TAG 상수. `lib/mode3_issuance.js`: `proveUserCred`/
   `verifyUserCred`(π_u), `userCredRequestMessage`, `issueRequestMessageV4`. `lib/mode3_revocation.js`: `userLeaf`.
2. 회로 `circuits/lib/mode3_commit.circom`(CommitUser, CommitSession), `circuits/pi_cred.circom` V5 → `bash scripts/build_mode3_circuit.sh`
   → `tests/helpers/mode3_fixture.mjs` 갱신 → circuit 그룹 테스트.
3. CIA: `/cia/user_cred`, `/cia/issue` V5, 폐기 단순화, 상태 v6, `issued`·skew 제거.
4. 지갑: 상태 v6, 로그인 3~5단계, `/wallet/attrs`, status, 폐기 확인.
5. 서비스: vkey 경로 확인, 팩토리 재배포 경고 확인. 컨트랙트 테스트는 fixture 갱신만.
6. 테스트: `tests/test_mode3_issuance.js`(π_u, 메시지), `test_mode3_credential*`, `test_cia_register_issue.mjs`(user_cred 케이스, issue V5, 폐기
   = 리프 1개, 옛 C_u 자동 pending), `test_cia_startup.mjs`, `test_cia_issue_race.mjs`(π 없이 sig_u 경합), `test_cia_opening.mjs`,
   `test_mode3_wallet.mjs`, `test_mode3_rp.mjs`, `test_mode3_e2e.mjs`, `test_mode3_wallet_agent.mjs`(userCred 자동 발급·폐기·복구·속성 변경),
   `test_mode3_demo_stack.mjs`, `test/Mode3Wallet.test.mjs`(fixture 만).
7. 문서: `docs/MODE3_DEMO.md`(env 제거, 속성 변경 버튼), 이 문서 §8 실측, 논문 v3 반영 목록(§11).
8. 벤치: `scripts/bench_zkp_inventory.mjs`(π_u 추가, π_idp 세션 행 제거), `bench_mode3_onchain.mjs` 재실행.

---

## 11. 논문·형식 문서에 되돌아갈 것

- V-B 등록 뒤 "사용자 자격증명" 절 신설, V-D 를 세션 발급으로 축소(π_issue 이동), Table 2 관계(커밋 둘), VI-A 리프 정의, VI-D 폐기(리프 1개),
  VIII-B Table 3 실측, IX 한계(세션 단위 폐기 없음).
- `security_formal.md`: A2·A5·A8 갱신, 정리 9(폐기 효력)의 "미만료 성명 전부" → "활성 C_u 리프 하나", 대응표 재점검.
- `conditional_privacy_formal.md`: 성명 정의의 C → (C_u, C_s), 정리 3 의 W(T*) 정의는 그대로.
- 슬라이드 `260918_zkDelegation_ZKPs.pptx`·`260918_zkDelegation_flow.pptx`: π_idp → π_u(사용자 자격증명), 세션 발급에 ZKP 없음.
