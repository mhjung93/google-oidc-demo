# Mode 3 — 속성 credential 설계 (attribute privacy 1단계)

**상태: 설계 확정. 구현 전.**
작성 2026-09-14. 2026-09-14 설계 대화에서 정해진 내용을 옮긴다.

기반 문서: `2026-09-09-mode3-cia-revocation-design.md` (이하 "기반 설계"). 이 문서는 기반 설계의
**§4.1(credential 구성), §5(증명 π), §6.2(발급), §6.3(RP 로그인)** 을 대체한다. 등록(§6.1), 폐기(§6.5,
§6.5.1), 복구(§6.6), 폐기 자료구조와 체인(§7), 파라미터 중 게시 주기·fail-closed(§8.1~8.3, §8.5)는
그대로다. 컨트랙트(`RevocationLog`)는 바뀌지 않는다.

---

## 1. 무엇이 달라지는가

| | 기반 설계 | 이 문서 |
|---|---|---|
| 커밋 `C_pt` | `uid, arid, s_u, pk_i, blind` 5슬롯 | + `attr₀..attr₃` 4슬롯 = 9슬롯 |
| CIA 서명 메시지 | `Poseidon(DOMAIN, C, max_height)` | `Poseidon(DOMAIN_V2, C, exptime, chainid, nonce)` |
| 만료 | `max_height` (블록 높이) | `exptime` (Unix 초, 벽시계) |
| 발급 재생 방지 | `sk_u` 서명이 덮는 `height` 창 `[head−30, head+1]` | `sk_u` 서명이 덮는 사용자 nonce, CIA 가 `(uid, nonce)` 영구 보관 |
| 체인 식별 | 없음 | `chainid` — 사용자가 제시, CIA 허용 목록 대조, RP 가 자기 체인과 대조 |
| 회로 공개 입력 | `[PPID, arid, pk_i, max_height, revRoot, pk_CIA_x, pk_CIA_y]` | `[PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y]` |
| 가명 `PPID` | `Poseidon(uid, arid, s_u)` | `Poseidon(uid, s_u, chainid, arid)` — 체인 간 unlinkability (2026-09-15 추가) |

바뀌지 않는 것: 폐기 리프 `H(C)`, 트리·게시·root 검사, 등록 프로토콜, `sk_i` 로 RP
challenge 에 서명하는 세션 바인딩, credential 캐시·재사용 규칙(§8.4).

**목적.** 사용자가 CIA 에게 보이지 않는 속성을 credential 에 담아 두고, 다음 단계에서 RP 에 속성
술어(예: `attr₀ ≥ 임계값`)만 영지식으로 보여주기 위한 기반이다. **이 문서의 범위는 커밋·서명·검증
형식까지다.** 술어 증명 회로와 RP 측 술어 검증은 다음 단계다.

---

## 2. 가정과 신뢰 (기반 설계 §2 에 더하는 것)

- **CIA 는 속성 값을 모르고 검증하지 않는다.** 속성은 사용자가 고른다. 따라서 `σ_CIA` 가 보증하는 것은
  "인증된 `uid` 가 등록된 `s_u` 로 만든 커밋"까지이고 **속성의 진위는 보증하지 않는다.** 속성에 신뢰가
  필요한 용도는 이 설계로 충족되지 않는다 — CIA 가 속성을 공개 입력으로 대조하는 변형(기반 설계 §6.2 의
  `uid` 와 같은 방식)이 그 자리이며, 이번 대화에서 채택하지 않았다.
- `uid`·`s_u` 바인딩은 유지한다. `π_issue` 는 여전히 `C_pt` 에 CIA 가 아는 `uid` 가 있고 `s_u` 가 등록
  커밋 `cm_u` 와 같음을 증명한다. Sybil 방지(기반 설계 §6.1)와 PPID 의 소유권이 여기에 걸려 있다.
- 벽시계 만료는 CIA 와 RP 의 시계가 대체로 맞는다고 가정한다. 데모에서는 같은 기계다.

---

## 3. credential

```
C_pt = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + attr₀·G₅ + attr₁·G₆ + attr₂·G₇ + attr₃·G₈ + blind·H
C    = Poseidon(C_pt.x, C_pt.y)
credential = (C, exptime, chainid, nonce, σ_CIA)
σ_CIA = EdDSA-Poseidon.Sign(sk_CIA, Poseidon(DOMAIN_MODE3_CRED_V2, C, exptime, chainid, nonce))
폐기 리프 = mask₂₅₂(Poseidon(TAG_MODE3_CRED, C))                       ← 변경 없음
PPID = Poseidon(uid, s_u, chainid, arid)                               ← chainid 추가 (2026-09-15)
```

- 생성원 `G₁..G₈, H` 는 circomlib `pedersen.circom` 의 NUMS 점 `BASE[0..8]` 이다. 기존 다섯 개
  (`uid, arid, s_u, pk_i, blind` = `BASE[0..4]`)의 배정은 바꾸지 않고 `attr₀..₃` 에 `BASE[5..8]` 을 더한다.
  `BASE` 는 10개이므로 여유는 1개가 남는다.
- 모든 스칼라(`attr₀..₃` 포함)는 `[0, 2²⁵⁰)` 이다(기반 설계 §4.1 의 상한). 쓰지 않는 속성 슬롯은 0.
  `credCommit` 은 상한 밖이면 throw 하고, 회로는 `Num2Bits(250)` 으로 강제한다.
- `DOMAIN_MODE3_CRED_V2` 는 기존 `DOMAIN_MODE3_CRED` 와 다른 값이다. 옛 형식의 서명을 새 회로에, 새 서명을
  옛 회로에 재생할 수 없게 한다.
- `exptime` 은 Unix 초. `chainid` 는 폐기 체인(`RevocationLog` 가 있는 체인)의 chain id. `nonce` 는 사용자
  무작위 `[0, 2²⁵⁰)`.
- **`PPID` 가 `chainid` 를 덮는다(2026-09-15).** 같은 사용자가 같은 RP 에 다른 체인으로 로그인하면 가명이 달라야
  한다 — 그렇지 않으면 두 체인의 RP 로그를 맞대어 동일인임을 특정할 수 있다(발표 자료 6장의 `H(ID, salt, chain, rid)`;
  인자 순서도 그 표기를 글자 단위로 따른다). `chainid` 는 이미 서명 메시지와 회로 공개 입력에 있으므로 비용은 Poseidon
  입력 1개다. 서명과 가명이 같은 `chainid` 신호를 쓰므로 둘이 어긋날 수 없다. 이로써 Mode 2 의 `Poseidon(uid, rid, salt)`
  와 같은 구조라는 기반 설계 §4.1 의 서술은 더 이상 성립하지 않는다.
- **`exptime`·`chainid`·`nonce` 는 `C` 밖에서 서명된다.** 셋 다 CIA 가 값을 확인해야 하는 것들이라
  커밋 안에 숨기면 안 된다(기반 설계 §4.1 의 `max_height` 논거와 같다).

---

## 4. 발급 (기반 설계 §6.2 대체)

```
1. 사용자: (pk_i, sk_i) 생성, blind·nonce 무작위, attr₀..₃ 선택(기본 0)
           C_pt = Commit(uid, arid, s_u, pk_i, attr₀..₃, blind)
           chainid = 지갑이 보는 폐기 체인의 chain id

2. 사용자 → CIA:
     uid, C_pt, chainid, nonce
     π_issue : PoK { 공개 (uid, cm_u, C_pt),  witness (arid, s_u, pk_i, attr₀..₃, blind, r_u) :
                 C_pt = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + attr₀·G₅ + attr₁·G₆ + attr₂·G₇ + attr₃·G₈ + blind·H
               ∧ cm_u = s_u·G₃ + r_u·H }
     sig_u = Sign(sk_u, Poseidon(C_pt.x, C_pt.y, chainid, nonce))

3. CIA (이 순서로):
     형식 검사(uid·chainid·nonce 10진, C_pt 점, proof, sig_u)
     disabled == false
     chainid ∈ 허용 목록                      ← CIA_CHAIN_IDS. 미설정이면 CIA 의 RPC chainId 하나
     (uid, nonce) 미사용                       ← 사용됐으면 409
     sig_u 검증 (등록된 pk_u)
     π_issue 검증                              ← arid·pk_i·attr·blind 는 여전히 모른다
     같은 C 미발급                              ← 409 (기존과 같다)
     disabled 재확인 (기록 직전, 기존과 같다)

4. CIA: exptime = now + CIA_TTL_SECONDS
        C = Poseidon(C_pt.x, C_pt.y)             ← 사용자에게서 받지 않는다 (기존과 같다)
        σ_CIA = Sign(sk_CIA, Poseidon(DOMAIN_MODE3_CRED_V2, C, exptime, chainid, nonce))
        기록: issued[uid] += {leaf: H(C), C, exptime};  nonces[uid] += nonce

5. CIA → 사용자: (exptime, chainid, nonce, σ_CIA, pk_CIA)
```

**`height` 창 검사는 없앤다.** 그 검사가 막던 것은 "만료된 발급 요청 본문을 그대로 다시 내서 같은 `C` 에
새 `max_height` 를 받는 TTL 연장" 이었다. 이제 `sig_u` 가 `nonce` 를 덮고 CIA 가 쓴 nonce 를 거절하므로
같은 본문은 두 번 통과하지 못한다. 대신 **`(uid, nonce)` 는 영구 보관한다.** 발급 기록(`issued`)처럼
만료 뒤 지우면, 기록이 사라진 뒤 옛 본문을 다시 내는 경로가 정확히 되살아난다. uid 당 32바이트씩
늘어나는 비용은 감수한다(§7 한계).

**`exptime` 은 사용자 서명에 넣지 않는다.** CIA 가 정하는 값이라 사용자가 서명할 시점에 없다. 사용자가
`exptime` 을 제안하고 CIA 가 상한만 검사하는 변형은 채택하지 않았다.

**`chainid` 는 사용자가 제시하고 CIA 가 허용 목록과 대조한다.** CIA 가 자기 RPC 값을 일방적으로 넣는
변형보다 다중 체인(기반 설계 §6.5 의 CREATE2 논거)에 맞고, 사용자가 임의 값을 넣는 변형보다 안전하다.
데모의 허용 목록은 `31337` 하나다.

**`π_issue` 확장.** 시그마 프로토콜의 표현 증명을 생성원 9개로 늘린다. Fiat-Shamir 챌린지는 기존대로
`(DOMAIN_MODE3_ISSUE, uid, C_pt, cm_u, T1, T2)` 를 덮는다 — `chainid`·`nonce` 는 `sig_u` 가 덮으므로
챌린지에 넣지 않는다.

---

## 5. 증명 π (기반 설계 §5 대체)

```
공개 입력   PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y   ← 이 순서
비공개 입력 uid, s_u, blind, attr₀..₃, nonce, σ_CIA(S, R8x, R8y), 비멤버십 witness
             (C 는 회로가 계산한다 — 증명자가 고를 수 없다)

증명 내용
  ① EdDSA-Poseidon.Verify(pk_CIA, Poseidon(DOMAIN_MODE3_CRED_V2, C, exptime, chainid, nonce), σ_CIA) = 1
  ② C_pt = Commit(uid, arid, s_u, pk_i, attr₀..₃, blind)      ← 개봉. arid·pk_i 는 공개 입력과 일치
  ③ PPID = Poseidon(uid, s_u, chainid, arid)                      ← chainid 는 ① 과 같은 공개 입력
  ④ mask₂₅₂(Poseidon(TAG_MODE3_CRED, C)) ∉ IMT(revRoot)
```

**`nonce` 는 비공개다.** 공개 입력으로 두면 RP 가 credential 마다 고유한 값을 보게 되고, RP 로그가
유출되면 CIA 의 `(uid, nonce)` 기록과 맞춰 `uid ↔ RP` 가 이어진다. `pk_i` 를 `C` 안에 둔 것(기반 설계
§4.1 의 심층 방어)과 같은 논거다. `nonce` 가 회로 안에 있어야 하는 이유는 서명 메시지에 들어 있기
때문이지, RP 가 볼 필요가 있어서가 아니다.

**`attr₀..₃` 도 비공개다.** 이 단계에서 회로는 속성을 커밋 개봉에만 쓴다. 다음 단계의 술어 회로는
이 witness 위에 제약을 더한다.

검증자의 의무(`pk_CIA_x/y` 를 설정된 키와 대조)와 "π 는 root 가 바뀔 때까지 재사용" 규칙은 기반 설계
그대로다.

---

## 6. RP 로그인 (기반 설계 §6.3 대체)

```
1. RP → 지갑:  challenge
2. 지갑:       revRoot 가 최신이 아니거나 exptime 이 임박하면 π 재생성(또는 재발급)
               σ = Sign(sk_i, challenge)
3. 지갑 → RP:  (π, 공개입력, σ)
4. RP:
     a. L1 헤드를 최근 10분 안에 읽었는가?   아니면 거부      ← 그대로
     b. π.revRoot == 방금 읽은 root ?        아니면 거부      ← 그대로
     c. now ≤ exptime ?                      아니면 거부      ← 벽시계. 블록 높이 비교를 대체
     c'. chainid == RP 가 읽는 체인의 id ?    아니면 거부      ← 신규. RP 는 기동 시 RPC 에서 읽어 고정
     d. Groth16 검증
     e. 서명 검증 (pk_i, challenge, σ)
     f. PPID 로 사용자 식별
```

`c'` 가 막는 것: 다른 체인의 `RevocationLog` 기준으로 발급된 credential 을 이 RP 에 내는 것. root 검사
`b` 만으로는 두 체인의 트리가 우연히(초기 빈 트리처럼) 같은 root 일 때 구별하지 못한다.

---

## 7. 지갑·CIA 상태와 만료

- **지갑**: 등록 요청에 `attrs`(10진 문자열 4개, 생략 시 전부 0)를 받아 상태 파일에 저장한다. 발급마다
  `nonce` 를 새로 뽑고 `chainid` 는 RPC 의 `chainId` 로 채운다. credential 재사용 판단은
  `now + EXPIRY_MARGIN_SECONDS < exptime` (기본 여유 30초, 기존 3블록에 상응).
- **CIA**: `issued[uid]` 항목은 `{leaf, C, exptime}`. 만료 정리와 계정 폐기 대상 선별(기반 설계 §6.5 의
  "미만료 리프")은 `exptime + CIA_REVOKE_SKEW_SECONDS(기본 300) ≥ now` 로 한다 — 여유의 이유는 §8 3번.
  `nonces[uid]` 는 문자열 배열, 정리하지 않는다. 상태 파일
  스키마 버전을 올리고, 옛 스키마(`max_height` 항목)는 **읽지 않고 기동을 거부한다** — 옛 credential 은
  어차피 새 회로에서 검증되지 않으므로 마이그레이션할 가치가 없다. 데모 재시연 세트(hardhat 재시작 →
  재배포 → 상태 파일 삭제 → 재기동)가 그 경로다.
- **TTL 기본값**: `CIA_TTL_SECONDS = 3600`. 기존 300블록 × 12초에 상응한다. 발급 창과 TTL 의 관계
  검사(`TTL > 창 + 1`)는 창이 사라졌으므로 함께 사라진다.
- 폐기 트리는 영향을 받지 않는다. 리프는 만료하지 않고 제거되지 않는다(기반 설계 §7.1, append-only).
  "만료"는 발급 기록과 credential 쪽 개념이고, 이 문서는 그 시계를 블록에서 벽시계로 바꿀 뿐이다.

---

## 8. 알려진 한계

1. **속성 진위 미보증** (§2). 서명은 커밋 제출자가 인증된 uid 임만 말한다.
2. **nonce 영구 보관.** uid 당 발급 1회에 32바이트. 데모 규모에서 무시할 수 있다. 운영이라면 만료
   시점을 사용자 서명에 넣는 설계(사용자 제안 `exptime`)로 바꿔 정리 가능하게 해야 한다.
3. **벽시계 의존.** CIA·RP 시계가 어긋나면 만료 판정이 어긋난다. 특히 RP 가 뒤처지면 RP 는 CIA 기준으로 만료된
   credential 을 그 차이만큼 더 받아들이는데, CIA 가 그 사이 발급 기록을 버렸으면 계정 폐기가 그 리프를 넣지 못한다 —
   블록 높이 기준에서는 체인이 공용 시계라 없던 구멍이다. CIA 는 기록을 `CIA_REVOKE_SKEW_SECONDS`(기본 300초)만큼
   늦게 버려 그 창을 덮는다(§7). 시계 차이가 그보다 크면 여전히 구멍이 남는다.
4. **CIA 가 `chainid` 를 본다.** 허용 목록이 하나면 정보량이 0 이고, 여럿이면 사용자가 어느 체인을
   쓰는지 CIA 가 안다. 기반 설계 §2.3 의 "CIA 에게 숨기는 것" 목록에 chain 선택은 없으므로 감수한다.
5. **옛 credential·증명 전부 무효.** 회로가 바뀌므로 `build/mode3` 의 zkey·vkey 를 다시 만들어야 하고
   (`pot21_final.ptau`, 수 분), 다른 기계에 복사해 둔 `build/` 도 다시 옮겨야 한다.
6. **nonce 집합 비용.** `nonces[uid]` 는 발급마다 32바이트씩 무한히 늘고 조회가 O(n), 발급마다 상태 파일 전체를 다시 쓴다. 데모 규모에서 무시할 수 있다.

---

## 9. 구현 범위

변경: `circuits/lib/mode3_commit.circom`(9슬롯), `circuits/pi_cred.circom`(메시지 해시 `Poseidon(5)`,
공개 입력 순서, `attr`·`nonce` witness), `lib/mode3_credential.js`(생성원 4개, `credCommit` 9인자,
`credMessage(C, exptime, chainid, nonce)`, `DOMAIN_MODE3_CRED_V2`), `lib/mode3_issuance.js`(표현 증명
9생성원, `issueRequestMessage(C_pt, chainid, nonce)`), `lib/mode3_wallet.js`(입력·공개 입력 순서, 만료
여유), `lib/mode3_rp.js`(`c`·`c'`), `cia.js`(요청 형식, 검사 순서, nonce 집합, TTL 초, 스키마 버전),
`mode3_wallet_agent.js`(attrs·nonce·chainid), `mode3_rp.js`(chain id 고정), `mode3/wallet.html`(속성
입력 4칸), 테스트(`test_pi_cred_witness.mjs`, `test_mode3_issuance.js`, `test_cia_register_issue.mjs`,
`test_cia_startup.mjs`, `test_cia_issue_race.mjs`, `test_mode3_wallet.mjs`, `test_mode3_rp.mjs`,
`test_mode3_e2e.mjs`, `test_mode3_wallet_agent.mjs`, `test_mode3_demo_stack.mjs`, 격리 헬퍼),
`docs/MODE3_DEMO.md`, `build/mode3` 재생성.

변경 없음: 컨트랙트, `lib/mode3_revocation.js`, `lib/mode3_log.js`, 게시·폐기·복구 엔드포인트,
Mode 2 전부.

---

## 10. 다음 단계 (이 문서 밖)

- 속성 술어 증명: `attr₀ ≥ 공개 임계값` 같은 범위 증명을 `π` 에 더하고 RP 가 임계값을 공개 입력으로
  검증한다. 커밋 형식은 이 문서로 고정되어 있으므로 회로와 RP 검증만 더하면 된다.
- 속성 진위: CIA 가 계정 DB 의 속성을 `π_issue` 공개 입력으로 대조하는 변형.
