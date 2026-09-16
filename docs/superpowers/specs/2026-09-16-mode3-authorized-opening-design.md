# Mode 3 — 승인된 개봉(authorized opening) 설계: 2-of-2 트레이스 태그

**상태: 설계 확정. 구현 전.**
작성 2026-09-16. 2026-09-16 설계 대화에서 정해진 내용을 옮긴다. 같은 날 먼저 쓴 "r_s 기록 결합 + 보관 기간" 판은 이 판으로
대체됐다(§9 에 기각 이유).

기반 문서: `2026-09-15-mode3-session-statement-design.md`(이하 "세션 설계")와 그 기반인
`2026-09-14-mode3-attribute-credential-design.md`(이하 "속성 설계"), `2026-09-09-mode3-cia-revocation-design.md`(이하 "기반 설계").
이 문서는 세션 설계의 **§2(조건부 추적 가능성)·§3(서비스 등록·`cert_s` 메시지)·§4(인증 요구의 필드)·§6(증명 π 의 공개 입력)·
§8(CIA 상태의 `used_rs`)·§9 1번** 과 기반 설계의 **§2.2("CIA-RP 담합 — 범위 밖")·§11 "CIA-RP 담합을 위협 모형에 넣을지" 행** 을
대체한다. 커밋 `C_pt`·CIA 서명 메시지·가명·폐기·게시·자기 폐기·컨트랙트는 바뀌지 않는다.

---

## 1. 무엇이 달라지는가

| | 세션 설계 (2026-09-15) | 이 문서 |
|---|---|---|
| CIA-RP 담합 | 위협 모형 밖. "기록을 맞대면 uid↔PPID 가 이어진다"는 사실만 기록 | **승인된 개봉으로 모델에 넣는다.** 서비스 조각 + CIA 조각 + 운영자 승인이 있어야 세션 하나의 uid 가 열린다 |
| 연결 고리 | r_s (CIA 의 `used_rs` 와 RP 기록을 맞댐) | **트레이스 태그** `tag = Enc(pk_trace,s, uid)` — 로그인마다 지갑이 만들어 증명의 공개 입력에 넣고, 회로가 평문이 커밋 안의 uid 임을 증명 |
| CIA 의 `used_rs` | uid → [r_s], 영구 | **없앤다.** 재생 방지는 RP 의 r_s 소비가 맡는다(§4.4). CIA 는 로그인당 아무것도 저장하지 않는다 |
| 서비스 등록 | `{name, origin}` → 즉시 `arid, cert_s` (무허가) | `{name, origin, pk_service, pk_trace,svc}` → **pending** → 운영자 승인(CIA 조각 생성) → `arid, pk_trace, cert_s` |
| `cert_s` 메시지 | `(arid, H(origin))` | **`(arid, H(origin), pk_trace.x, pk_trace.y)`**, 도메인 V2. 지갑은 인증서에 실린 `pk_trace` 로만 암호화한다 |
| 증명 π 공개 입력 | 9개 | **14개**: + `pk_trace.x, pk_trace.y, tag.c1.x, tag.c1.y, tag.c2` |
| RP 의 로그인 기록 | 메모리. 조회 응답에 r_s 축약 | **파일에 영속화**(트랜스크립트 전체). 조회 응답의 축약은 그대로 |
| 개봉 절차 | 없음 | 서비스가 트랜스크립트 + 자기 부분 복호를 서명해 요청 → 운영자 승인 → CIA 가 자기 조각으로 마저 복호 → uid (§6) |

**목적.** 논문 III-B·VII-H 가 "담합은 범위 밖"이라 해놓고 설계는 r_s 라는 결합 손잡이를 남긴 모순을 없애고, 개봉을 절차가 아니라
암호로 보장한다: 태그가 올바르게 만들어졌음을 ZKP 가 보증하고(검증 가능 암호화), 두 조각이 모여야만 열린다(2-of-2 임계 복호).
EL PASSO 의 임계 복호 identity escrow 와 같은 자리다.

**바뀌지 않는 것.** `C_pt`·`C`·`σ_CIA = Sign(DOMAIN_MODE3_CRED_V3, C, exptime, chainid, r_s)`·`PPID`·발급 PoK·폐기 트리·게시·자기
폐기·`RevocationLog`.

---

## 2. 위협 모형 (세션 설계 §2, 기반 설계 §2.2 대체)

- **개봉은 세 당사자가 있어야 한다.** 요청하는 서비스(자기 조각으로 부분 복호, `pk_service` 로 서명), CIA(자기 조각으로 마저 복호),
  승인하는 CIA 운영자(`CIA_ADMIN_SECRET`). 운영자 승인은 "외부 승인 절차"의 자리이며, 실제 배포에서는 법적·조직적 절차가 들어간다 —
  PairCT 와 같은 경계다.
- **드러나는 것은 그 세션의 uid 하나다.** CIA 는 `s_u` 를 모르므로 uid 를 알아도 그 사용자의 다른 서비스 가명을 열거하지 못한다.
  같은 서비스의 다른 세션은 PPID 가 같으므로 서비스가 이미 잇고 있다.
- **서비스 기록이 새도 CIA 혼자서는 못 연다.** 로그에는 암호문뿐이고 CIA 조각만으로는 복호되지 않는다. 이것이 r_s 기록 결합 판을
  버린 첫째 이유다(§9).
- **CIA 와 서비스가 담합하면 운영자 승인 없이 그 서비스의 태그를 전부 연다.** 두 조각을 합치면 되기 때문이다. 기록 결합 판에서도
  로그를 맞대면 같았다 — 운영자 승인은 두 판 모두 CIA 내부 통제다. 이를 넘으려면 조각 하나를 제3의 감사자에게 주는 2-of-3 이
  필요하며, 태그 방식은 그 확장이 자연스럽다(§8 2번, 이 문서 범위 밖).
- **다른 서비스의 태그는 열리지 않는다.** 태그는 그 서비스의 조합 키로 암호화돼 있고, 개봉 요청의 트랜스크립트 `arid` 를 CIA 가
  요청자와 대조한다(§6).
- **서비스가 지갑에게 가짜 `pk_trace` 를 주는 공격.** 서비스가 전체 비밀을 아는 키를 주면 서비스 혼자 복호할 수 있다. 그래서
  `pk_trace` 는 `cert_s` 에 실려 CIA 서명으로 묶이고, 지갑은 인증서의 값만 쓴다(§3). CIA 는 승인 때 자기 조각을 더해 조합 키를
  만들므로 서비스 혼자 아는 키는 인증서에 실리지 않는다.
- honest-but-curious CIA, 지갑 신뢰, 능동적 CIA 부정(위조 root)·네트워크 관측은 기반 설계 그대로다.

---

## 3. 서비스 키와 등록 승인 (세션 설계 §3 대체)

서비스는 키를 **둘** 가진다. 용도가 달라 하나로 겸하지 않는다.

| 키 | 곡선 | 용도 |
|---|---|---|
| `(sk_service, pk_service)` | secp256k1, `pk_service` = 이더리움 주소 | 개봉 요청·결과 수령의 서명(EIP-191, `ethers.verifyMessage`). 세션 요청 서명과 같은 스킴 |
| `(x_svc, X_svc = x_svc·B8)` | Baby Jubjub, `x_svc < 2^250` | 트레이스 태그의 **서비스 조각** |

```
1. RP 기동:   등록 파일이 없으면 두 키쌍 생성. 비밀은 파일에(0600)
2. RP → CIA:  POST /cia/register_rp { name, origin, pk_service, X_svc }
3. CIA:       X_svc 가 곡선 위이고 소수 위수 부분군에 있는지 검사 (l·X_svc = O). 아니면 400
              origin 이 처음이면   arid ← randomScalar(),
                                  rps[arid] = { name, origin, pk_service, X_svc, status: "pending", requestedAt }   → 202 { arid, status }
              origin 이 있고 (pk_service, X_svc) 가 같으면 현재 상태를 돌려준다 (멱등 — 이 호출이 상태 조회를 겸한다):
                                  pending  → 202 { arid, status }
                                  approved → 200 { arid, origin, pk_trace, cert_s }
                                  denied   → 403 { arid, status }
              origin 이 있고 키가 다르면 → 409 service_key_mismatch (키 회전은 지원하지 않는다 — §8)
4. 운영자:    GET  /cia/rps                    (requireAdmin) — 전부: arid, name, origin, pk_service, X_svc, pk_trace, status, requestedAt, decidedAt
              POST /cia/rps/:arid/approve      (requireAdmin) →  x_AA,s ← randomScalar()  (CIA 조각. 서비스마다 하나, 영구, 밖으로 나가지 않는다)
                                                                  pk_trace = X_svc + x_AA,s·B8
                                                                  rps[arid] += { x_AA,s, pk_trace, status: "approved", decidedAt }
              POST /cia/rps/:arid/deny         (requireAdmin) → status "denied", decidedAt
              cia_admin.html 에 "등록된 서비스" 표와 승인/거절 버튼
5. CIA:       cert_s = EdDSA-Poseidon.Sign(sk_CIA, Poseidon(DOMAIN_MODE3_CERT_S_V2, arid, H(origin), pk_trace.x, pk_trace.y))
              승인된 서비스에게만. 결정적이라 저장하지 않고 조회 때 다시 서명한다
6. RP:        202 면 **등록 대기 상태로 기동**: 서버는 뜨되 /api/mode3/challenge·login·revalidate·request 는 503 registration_pending,
              rp_info 는 { arid, origin, status: "pending" }. 5초마다 2 를 다시 보내 200 이 오면 pk_trace·cert_s 를 파일에 쓰고 활성.
              403 이면 로그에 남기고 대기를 멈춘다. 파일에 cert_s 가 있으면 기동 시 pk_CIA 로 검증하고 바로 활성
7. RP 파일:   mode3_rp_registration.json = { arid, origin, pk_service, sk_service, X_svc, x_svc, status, pk_trace?, cert_s?, issuedAt? }  (0600)
```

- **`DOMAIN_MODE3_CERT_S_V2`** = ASCII "MODE3CERTS2" 빅엔디언. 옛 인증서(`pk_trace` 없음)가 새 지갑에서 통과하지 않게 한다.
- **`pk_trace` 가 인증서에 실리는 이유**는 §2 의 가짜 키 공격이다. `pk_service` 는 실리지 않는다 — 지갑이 쓸 일이 없고, 개봉 요청을
  검증하는 CIA 는 등록부를 갖고 있다.
- **CIA 조각 `x_AA,s` 는 승인 시점에 만든다.** 승인 전 서비스는 조합 키가 없으므로 지갑이 태그를 만들 수 없고, 따라서 로그인이 없다.
  조각은 `cia_state.json` 에 있다 — 잃으면 그 서비스의 과거 태그는 영원히 열 수 없다(§8 4번). `sk_CIA` 와 같은 급으로 다룬다.
- **승인이 `cert_s` 에 주는 의미.** 세션 설계 §9 3번("등록 무허가")은 사라진다. `cert_s` 는 "운영자가 이 origin 을 이 이름의 서비스로
  승인했고, 이 조합 키의 한 조각을 CIA 가 갖고 있다"를 뜻한다. 승인 기준(도메인 소유 확인 등)은 운영 절차이며 프로토콜이 검사하지
  않는다 — 데모의 운영자는 버튼을 누른다.
- **`arid` 는 요청 시점에 배정한다.** 거절된 origin 은 거절 상태로 남고 재요청은 403 이다(§8 5번).
- **데모 각본에 "0. 서비스 등록 승인" 행이 생긴다.** 격리 테스트·데모 스택 테스트는 헬퍼가 관리자 시크릿으로 승인을 대행한다.
- v3 상태 파일의 기존 `rps` 항목(키 없음)은 마이그레이션 때 `status: "approved"` 로 두되 조각이 없으므로, 그 서비스가 키를 내며
  재등록하면 그때 조각을 만들고 `pk_trace` 를 채운다(§7).

---

## 4. 트레이스 태그

### 4.1 구성

```
공개      pk_trace = (x_svc + x_AA,s)·B8            ← 서비스의 조합 키. cert_s 에 실림
지갑      r ← [1, 2^250)                              ← 로그인마다 새로
          c1 = r·B8
          K  = r·pk_trace
          c2 = uid + Poseidon(K.x, K.y)  (mod p)
          tag = (c1, c2)                              ← 공개 입력 3개 (c1.x, c1.y, c2)
복호      K = x_svc·c1 + x_AA,s·c1                    ← 두 조각의 부분 복호를 더한다. 어느 하나로는 K 가 안 나온다
          uid = c2 − Poseidon(K.x, K.y)
```

- **해시 ElGamal.** uid 를 점으로 인코딩해 곱셈군 ElGamal 을 하면 복호 뒤 이산로그를 풀어야 하고 회로에 점 덧셈이 더 든다. K 를
  Poseidon 으로 마스크로 바꾸면 회로는 스칼라 곱 둘과 Poseidon 하나이고, 복호는 뺄셈이다. 평문 uid 는 이미 회로 witness 다.
- **B8** 은 circomlib EdDSA 의 기저점(`eddsa.circom` 의 BASE8). `pk_CIA` 와 같은 부분군이다. `x_svc`, `x_AA,s`, `r` 은 모두 `[0, 2^250)`
  (기반 설계 §4.1 의 스칼라 상한 규약).
- **태그는 로그인마다 다르다**(r 이 새로). 같은 서비스 안에서 로그인들은 PPID 로 이미 이어지므로 태그의 무연결성은 서비스에 대해
  새로 지키는 성질이 아니다. 지키는 것은 **기밀성**이다 — 조각 하나로는 열리지 않는다.
- **CIA 는 태그를 보지 않는다.** 태그는 증명과 함께 서비스에게만 간다. 발급 요청에는 없다. 13장(CIA 는 서비스를 모른다)은 유지된다.

### 4.2 회로 (세션 설계 §6 대체)

```
공개 입력   PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y,        ← 기존 9개, 순서 그대로
            pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2                          ← 신규 5개. 총 14개
비공개 입력 uid, s_u, blind, attrs[4], σ_CIA(S, R8x, R8y), 비멤버십 witness, r          ← r 신규

증명 내용
  ①~④  세션 설계 §6 그대로 (CIA 서명, 커밋 개봉, PPID 유도, 비멤버십)
  ⑤    r < 2^250 (Num2Bits),  tag_c1 = r·B8 (EscalarMulFix),  K = r·pk_trace (EscalarMulAny),
       tag_c2 = uid + Poseidon(K.x, K.y)                                                  ← 평문이 ② 의 uid 와 같은 신호
```

- **검증자(서비스)의 의무**가 하나 는다: `pk_trace_x/y` 가 자기 등록 파일의 `pk_trace` 와 같은지 대조한다. `pk_CIA` 대조와 같은
  성격이다 — 대조하지 않으면 사용자가 아무 키로나 암호화한 태그를 낼 수 있다. `pk_trace` 를 공개 입력으로 두는 이유가 이것이다.
- `pk_trace` 의 곡선·부분군 검사는 회로에 넣지 않는다. 서비스가 자기 값과 같은지 대조하고, 그 값은 CIA 가 승인 때 검사한 `X_svc`
  에 자기 조각을 더해 만든 것이다.
- **예상 비용.** EscalarMulFix(250) + EscalarMulAny(250) + Poseidon(2) ≈ 5~7k 제약. 현재 22,224 → 약 28k, 증명 시간 0.8 초 → 약 1 초.
  실측은 구현 (c) 단계에서 하고 기반 설계 §11.1 표에 행을 더한다. zkey 는 `pot21_final.ptau` 로 재생성(수 분), 다른 기계의
  `build/mode3` 도 다시 옮긴다(속성 설계 §8 5번과 같은 비용).

### 4.3 인증 요구·로그인 (세션 설계 §4·§7 의 필드 변경)

```
RP → 지갑:  { arid, origin, cert_s, pk_trace, r_s }                       ← pk_trace 추가
지갑:       cert_s 를 pk_CIA 로 검증 — 메시지에 (arid, H(origin), pk_trace) 가 전부 들어간다. 요청의 Origin == cert 의 origin
            r 을 뽑아 tag 를 만들고 π 를 생성(공개 입력 14개)
지갑 → RP:  (π, 공개입력 14개, σ = Sign(sk_i, r_s))
RP:         세션 설계 §7 의 a~g 에 더해  d'. 공개 입력의 pk_trace == 등록 파일의 pk_trace   아니면 wrong_trace_key
            로그인 로그에 트랜스크립트 기록(§5)
재검증:     같은 성명으로 새 π 를 만들 때 r 도 새로 뽑는다 (태그가 바뀐다). RP 는 PPID·pk_i 만 세션과 대조하고 태그는 대조하지 않는다
```

- **`ProofCache` 키는 `(root, r_s)` 그대로.** 캐시된 π 를 재사용하면 태그도 같다 — 같은 세션 안이므로 무해하다.
- 지갑의 `credential`·`session` 상태에 `pk_trace` 가 들어간다(세션마다 인증서에서 읽은 값). 상태 파일 v4(v3 는 registration 유지,
  세션 비움 — 세션 설계 §8 과 같은 규칙).

### 4.4 `used_rs` 를 없애는 근거

`used_rs` 를 영구로 둔 이유(속성 설계 §4)는 "옛 발급 본문을 재생해 같은 `C` 에 새 만료를 받는 TTL 연장"이었다. 그 논거는 nonce 가
사용자 무작위·비공개였을 때 것이다. 지금 r_s 는 서비스가 발급하고 로그인 때 소비한다(세션 설계 §7 b). 옛 본문을 재생해 새 σ 를
받아도 그 r_s 는 서비스에서 이미 소비됐거나 잊혀서 `bad_challenge` 이고, 다른 서비스에서는 `arid` 가 공개 입력이라 `wrong_arid` 다.
따라서 CIA 의 r_s 집합은 재생 방지에 기여하지 않고, 추적은 이제 태그가 맡으므로 **CIA 는 로그인당 아무것도 저장하지 않는다.**
발급 검사에서 "(uid, r_s) 미사용" 단계와 409 `r_s already used` 는 사라진다. "같은 C 미발급" 409 는 그대로다.

---

## 5. 서비스의 로그인 기록 영속화

```
파일       MODE3_RP_LOGIN_LOG (기본 mode3_rp_logins.jsonl), 0600, JSON Lines 추가 쓰기
한 줄      { at, PPID, r_s, pk_i, exptime, root, publicSignals[14], proof }      ← r_s 전체, 트랜스크립트(태그 포함)
```

- 로그인 성공(`/api/mode3/login` ok)마다 한 줄. 재검증·세션 요청은 기록하지 않는다 — 개봉에 필요한 것은 태그가 든 트랜스크립트
  하나이며, 같은 PPID 의 어느 로그인 것이든 된다.
- 메모리의 `sessions`·`logins` 와 조회 응답(r_s 8자리 축약)은 그대로. 파일은 조회 API 로 내지 않는다.
- 로그가 새도 암호문뿐이다(§2). 그래도 0600 으로 두는 이유는 (PPID, 시각) 자체가 서비스의 사용자 활동 기록이기 때문이다.
- `.gitignore` 에 `mode3_rp_logins.jsonl` 추가.

---

## 6. 개봉 절차

```
① 요청   RP:        로그에서 그 PPID 의 트랜스크립트 하나를 고른다. c1 = (publicSignals[11], [12])
                    D_svc = x_svc·c1                                          ← 서비스의 부분 복호
                    sig = EIP-191.Sign(sk_service, "mode3-open:" + arid + ":" + r_s + ":" + PPID + ":" + D_svc.x + ":" + ts)
         RP → CIA:  POST /cia/open/request { arid, publicSignals[14], proof, D_svc, ts, sig }
         CIA (순서): 형식 (D_svc 곡선 위) → rps[arid] 존재·approved (404 unknown_service / 403 not_approved)
                    → |now − ts| ≤ 300 (401 stale)
                    → recover(sig) == rps[arid].pk_service (401 bad_signature)
                    → publicSignals[1] == arid (403 wrong_arid)
                    → publicSignals[7..8] == pk_CIA (403 untrusted_cia)
                    → publicSignals[9..10] == rps[arid].pk_trace (403 wrong_trace_key)   ← 이 서비스의 키로 만든 태그인가
                    → Groth16.Verify(vkey, publicSignals, proof) (403 bad_proof)          ← 태그가 잘 만들어졌음의 보증
                    → 같은 (arid, r_s) 로 pending 인 요청이 있으면 그 id 를 돌려준다 (200, 중복 생성 안 함)
                    → openings 에 추가: { id, arid, r_s, PPID, c1, c2, D_svc, status: "pending", requestedAt }   ← uid 는 아직 없다
         CIA → RP:  202 { id, status: "pending" }

② 승인   운영자:    GET  /cia/openings                 (requireAdmin)
                    POST /cia/openings/:id/approve     (requireAdmin) → K = D_svc + x_AA,s·c1,  uid = c2 − Poseidon(K.x, K.y)
                                                                         uid ∈ accounts 면 status "approved", uid 기록
                                                                         아니면 status "failed"  (D_svc 가 틀렸다 — 서비스 자신의 요청만 망친다)
                    POST /cia/openings/:id/deny        (requireAdmin) → status "denied"
                    cia_admin.html 에 목록과 승인/거절 버튼

③ 수령   RP → CIA:  GET /cia/open/:id?ts=…&sig=…       sig = EIP-191.Sign(sk_service, "mode3-open-result:" + id + ":" + ts)
         CIA:       ts 신선도·서명·openings[id].arid == 서명자의 arid
                    pending → 202   denied/failed → 403 { status }   approved → 200 { uid, PPID, r_s, decidedAt }
```

- **복호는 승인 시점에 한다.** 승인 전에는 uid 가 어디에도 계산되지 않는다 — pending 목록을 보는 운영자도 uid 를 모른다.
- **CIA 가 uid 를 알고 서비스에게 준다.** CIA 는 어차피 uid 전부를 안다. 반대로 CIA 가 `x_AA,s·c1` 만 돌려주고 서비스가 마저 복호하는
  변형은 CIA 감사 기록에 uid 가 남지 않는다는 차이만 있고, 분쟁 처리에서 CIA 운영자도 대상을 알아야 하므로 택하지 않았다.
- **`D_svc` 의 정당성은 증명하지 않는다.** 서비스가 틀린 `D_svc` 를 내면 uid 가 등록부에 없는 값이 나와 `failed` 다. 틀린 값으로
  얻을 수 있는 것이 없으므로(제3자의 uid 로 수렴하지 않는다) DLEQ 증명은 넣지 않는다.
- **왜 트랜스크립트를 검증하는가.** 태그가 이 서비스의 `pk_trace` 로 만들어졌고 평문이 진짜 uid 임은 회로가 보증한다. 검증 없이
  `(c1, c2)` 만 받으면 서비스가 임의의 암호문을 내 CIA 를 복호 오라클로 쓸 수 있다. 검증 비용은 14 ms 급이다(논문 VIII 실측).
- **왜 두 단계인가.** 요청과 결과를 한 호출로 돌려주면 승인 자리가 없다. **왜 `ts` 인가.** 가로챈 요청의 재전송을 막는다.
- **`openings` 는 영구**다 — 감사 기록이며 승인된 항목은 uid 를 담는다. **CIA 가 vkey 를 읽는다**(`MODE3_VKEY_PATH`, 기본
  `build/mode3/pi_cred_vkey.json`). 없으면 개봉 요청만 503.
- **RP 쪽 데모 경로.** `POST /api/mode3/open { PPID }` — 로그에서 그 PPID 의 최신 트랜스크립트로 ① 을 보낸다. `GET /api/mode3/open/:id`
  — ③. 둘 다 데모용이며 인증이 없다. `rp.html` 로그인 목록에 "개봉 요청" 버튼과 결과 표시.

---

## 7. 상태 요약

- **CIA (v4)**: `accounts`, `issued`, `rps`(arid → {name, origin, pk_service, X_svc, **x_AA,s**, pk_trace, status, requestedAt, decidedAt}),
  **`openings`**(영구), `revoked`, `pending`, `epoch`. `used_rs` 삭제. 새 env: `MODE3_VKEY_PATH`. **v3 → v4 마이그레이션**: `used_rs`
  버림, `rps` 항목은 `status: "approved"`·조각 없음, `openings = []`. v2 이하는 기동 거부(그대로).
- **RP**: `mode3_rp_registration.json` 에 `pk_service, sk_service, X_svc, x_svc, status, pk_trace` 추가(0600). 옛 등록 파일(키 없음)은
  기동 시 키를 만들어 재등록 → 승인된 항목이면 CIA 가 조각을 만들어 200. 새 파일 `mode3_rp_logins.jsonl`(0600). 새 env:
  `MODE3_RP_LOGIN_LOG`.
- **지갑 (v4)**: 세션에 `pk_trace` 저장. `cert_s` 검증 메시지 V2. 증명 입력에 `r`·`pk_trace`.
- **회로**: `pi_cred.circom` 공개 입력 14개, `circuits/lib/mode3_trace_tag.circom` 신규. `build/mode3` 재생성.

---

## 8. 알려진 한계

1. **CIA·서비스 담합은 운영자 승인을 우회한다**(§2). 기록 결합 판과 같다.
2. **2-of-3 은 범위 밖.** 조각 하나를 감사자에게 주면 CIA·서비스 담합에도 안전해지지만, 감사자 키 관리·부분 복호 프로토콜이 더
   든다. 태그 형식은 그대로 확장 가능하므로 다음 단계다.
3. **승인자가 운영자 한 명이다.** 승인 기준·분리된 감사자·다중 서명은 배포 정책이다.
4. **CIA 조각 유실 = 그 서비스의 과거 태그 영구 봉인.** `cia_state.json` 백업 정책이 곧 개봉 가능성이다.
5. **키 회전·재심사 없음.** 서비스 키가 바뀌면 같은 origin 으로 재등록할 수 없고(409), 거절된 origin 은 재요청할 수 없다(403).
   운영자가 항목을 지우거나 되돌리는 수단은 범위 밖이다.
6. **승인 기준은 프로토콜 밖이다.** 데모의 운영자는 버튼을 누른다.
7. **트랜스크립트 보관 비용.** 로그인당 약 1.7 KB(공개 입력 14개)가 서비스에 쌓인다. 서비스가 잘라내면 그 세션은 열 수 없다.
   PPID 당 하나만 남기면 충분하다.
8. **회로 비용.** 약 +25% 제약, zkey 재생성.
9. **태그는 사용자 프라이버시를 조각 둘의 비밀성에 건다.** 두 조각이 모두 새면 그 서비스의 모든 과거 로그인이 열린다. 전방 비밀성은
   없다.
10. 세션 설계 §9 의 나머지(CIA 가 로그인 경로에 있음, 속성 진위, 세션 요청 신선도)는 그대로다. "등록 무허가"는 사라진다.

---

## 9. 기각한 대안

- **r_s 기록 결합 + 보관 기간 W (같은 날 첫 판).** CIA 가 로그인당 (uid, r_s) 를 W 동안 보관하고 서비스 기록과 맞대는 방식. 회로
  변경이 없어 쌌지만 (i) 서비스 로그가 새면 CIA 혼자 연결할 수 있고, (ii) 보장이 절차적(기록이 남아 있어야)이며, (iii) W 밖 세션은
  못 열고, (iv) 2-of-3 으로 확장할 수 없다. 사용자 결정(2026-09-16)으로 태그 방식을 택했다.
- **uid 당 최신 r_s 하나만 보관.** CIA 는 서비스를 모르므로 마지막에 쓴 서비스만 열린다.
- **곱셈군 ElGamal(uid·B8 암호화).** 복호 뒤 이산로그가 필요하고 회로에 점 덧셈이 더 든다. 해시 ElGamal 로 대체(§4.1).
- **`pk_trace` 를 인증서 밖에 두기.** 서비스가 전체 비밀을 아는 키를 지갑에 줄 수 있다(§2).
- **서비스 키 하나로 서명과 조각을 겸하기.** 곡선이 다르고(secp256k1 vs Baby Jubjub) 키 분리 원칙에도 어긋난다.
- **CIA 가 부분 복호만 돌려주기.** §6 — 감사 기록에 uid 가 남지 않는다.
- **DLEQ 로 `D_svc` 증명.** §6 — 틀린 값으로 얻을 것이 없다.
- **개봉을 한 호출로.** 승인 자리가 없어진다.

---

## 10. 구현 범위

**(c) 회로 먼저** — 비용을 실측해 §4.2 의 예상을 확정한다. 그 뒤 **(a) 오프체인 전 구간.**

변경: `circuits/lib/mode3_trace_tag.circom`(신규), `circuits/pi_cred.circom`(공개 입력 14개, ⑤), `scripts/build_mode3_circuit.sh`
재실행, `lib/mode3_trace.js`(신규: 조각·조합 키·`encryptTag`·`partialDecrypt`·`combine`·부분군 검사), `lib/mode3_rp_cert.js`
(`DOMAIN_MODE3_CERT_S_V2`, `certSMessage(arid, origin, pk_trace)`), `lib/mode3_wallet.js`(`buildCredentialProof` 에 `pk_trace`·`r`,
공개 입력 14개), `lib/mode3_rp.js`(공개 입력 14개, `wrong_trace_key`), `lib/mode3_opening.js`(신규: 요청·결과 메시지, 서명·검증),
`cia.js`(상태 v4·마이그레이션, `used_rs` 제거, `register_rp` 의 두 키·pending/approved/denied·부분군 검사, `/cia/rps`,
`/cia/rps/:arid/approve|deny`(조각 생성), vkey 로드, `/cia/open/request`, `/cia/openings`, `/cia/openings/:id/approve|deny`(복호),
`/cia/open/:id`), `mode3_wallet_agent.js`(cert V2 검증, `pk_trace` 저장·전달, 상태 v4), `mode3_rp.js`(두 키 생성·등록 파일, 등록 대기
상태와 폴링, `pk_trace` 대조, 로그인 로그 jsonl, `/api/mode3/open`, `/api/mode3/open/:id`), `mode3/cia_admin.html`(등록된 서비스
표·승인·거절, 개봉 목록·승인·거절), `mode3/rp.html`(등록 대기 표시, 개봉 요청 버튼·결과), `tests/helpers/mode3_fixture.mjs`(태그 입력),
`isolated_cia.mjs`·`isolated_mode3_stack.mjs`(두 키·등록 승인 대행·vkey 경로), 테스트(circuit: `test_pi_cred_witness.mjs` — 태그
양성·평문 불일치·키 불일치 음성; unit: `test_mode3_trace.js` 신규 — 암복호 왕복·조각 하나로는 실패·부분군 검사, `test_mode3_rp_cert.js`
— V2 메시지; chain: `test_cia_register_issue.mjs` — pending/approve/deny/409/403, `used_rs` 제거, RP 대기→활성;
`test_cia_opening.mjs` 신규 — 정상 승인 경로, 거절, 틀린 `D_svc` → failed, 남의 arid 403, 남의 `pk_trace` 403, 잘못된 서명 401, 오래된
ts 401, v3 마이그레이션; `test_mode3_rp.mjs` — `wrong_trace_key`, 로그 줄 형식; `test_mode3_demo_stack.mjs` — 시나리오 0·9),
`docs/MODE3_DEMO.md`(시나리오 0 등록 승인, 시나리오 9 개봉, 상태 파일 v4, 새 파일·env), `.gitignore`(`mode3_rp_logins.jsonl`).

변경 없음: `lib/mode3_credential.js`·`lib/mode3_issuance.js`·`lib/mode3_revocation.js`·`lib/mode3_log.js`·컨트랙트·Mode 2 전부.

---

## 11. 논문·발표에 되돌아갈 것

- 논문 III-A 표 1: `pk_service`, `X_svc`/`x_AA,s`, `pk_trace`, `tag` 행. III-B: "AA–서비스 담합 범위 밖" → 승인된 개봉 모델(§2).
  III-C: G10 "conditional traceability: 두 조각 + 승인이 있어야 열리고, 그때만 그 세션의 uid 가 드러난다".
- 논문 V-B: 서비스 등록에 두 키와 운영자 승인, 조합 키 생성. V-C: 인증 요구에 `pk_trace`, 인증서가 그것을 덮는 이유. V-E: 표 2 에 조건
  ⑤(태그), 공개 입력 14개. V-F: `pk_trace` 대조, 로그인 기록 영속화.
- 논문 VII-E: 인증서의 의미("승인된 origin + 조합 키"). VII-H → "Authorized opening": 2-of-2 임계 복호, 검증 가능 암호화, 드러나는 범위,
  기록 결합 방식·escrow 단일 키 방식과의 비교(§9). VII-C 에 "AA 는 태그를 보지 않는다".
- 논문 VIII: 새 제약 수·증명 시간(실측 뒤), 개봉 시나리오 검증. 초록 A9 의 "about 22,000 constraints" 갱신.
- 논문 IX: "registration is unauthenticated" 삭제 → 승인 기준은 운영 절차. 조각 유실·담합 우회·2-of-3 미구현 추가. §8 1번(로그 유출)은
  삭제.
- 발표 자료: 13장 "AA 는 서비스를 모른다" 옆에 "단, 서비스·AA·운영자가 함께하면 세션 하나는 열 수 있다(2-of-2 태그)". 15장 증명 조건에
  ⑤ 추가.
