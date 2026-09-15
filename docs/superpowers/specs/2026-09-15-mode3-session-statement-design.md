# Mode 3 — 세션 성명과 서비스 인증서 설계 (AA 프로토콜 정렬)

**상태: 설계 확정. 구현 전.**
작성 2026-09-15. 발표 자료 `documents/260916_intro.pptx` 8·12·13장의 위임 인증(AA) 모델에 Mode 3 를 맞추기
위한 변경이다. 2026-09-15 설계 대화에서 정해진 내용을 옮긴다.

기반 문서: `2026-09-14-mode3-attribute-credential-design.md`(이하 "속성 설계")와 그 기반인
`2026-09-09-mode3-cia-revocation-design.md`(이하 "기반 설계"). 이 문서는 속성 설계의 **§3(서명 메시지), §4(발급),
§5(공개 입력), §6(RP 로그인), §7(지갑·CIA 상태)** 과 기반 설계의 **§2.2·§2.3(위협 모형 일부), §8.4(재증명 규칙)** 을
대체한다. 커밋 구성(속성 설계 §3 의 `C_pt`), 가명 유도, 등록(§6.1), 폐기·게시·자기 폐기(§6.5·§6.5.1·§7), 컨트랙트는
바뀌지 않는다.

---

## 1. 무엇이 달라지는가

| | 속성 설계 (2026-09-14) | 이 문서 |
|---|---|---|
| 서명 메시지의 요청별 값 | `nonce` — 사용자가 뽑고 CIA 가 (uid, nonce) 영구 보관 | `r_s` — **서비스가 뽑아** 사용자에게 주고, 사용자가 CIA 에 전달, CIA 가 (uid, r_s) 영구 보관 |
| `r_s`/`nonce` 의 회로 위치 | 비공개 witness | **공개 입력** (RP 가 자기가 준 값과 대조) |
| 성명의 단위 | RP(`arid`) 당 하나, 만료까지 어느 로그인에도 재사용 | **세션(`r_s`) 당 하나.** 로그인마다 새 발급, 세션 안에서만 재사용 |
| 요청 바인딩 | `sk_i` 로 RP challenge 에 서명 | **성명 안의 `r_s`** 가 로그인을 묶는다. `sk_i` 서명은 세션 안 후속 요청용 |
| 서비스 인증 | 없음 (RP 는 `arid` 를 env 로 고정) | RP 가 CIA 에 등록해 **`cert_s`** 를 받고, 지갑이 로그인 전에 로컬 검증 |
| CIA 가 로그인 경로에 있는가 | 아니오 (성명 재사용 시) | **예.** 로그인마다 발급 |
| CIA↔RP 연결 손잡이 | 없음 (`nonce` 비공개) | **`r_s` 가 연결 손잡이** — 의도된 조건부 추적 가능성(§2) |

**목적.** 발표 자료 8장의 흐름(서비스 → 사용자 → AA → 사용자 → 서비스, 성명에 서비스의 `r_s` 임베딩)과 12장(서비스
인증서)을 코드가 그대로 따르게 한다. 13장(AA 는 서비스를 모른다)은 `r_s` 가 무작위라 유지되고, 14·15장(가명·증명)은
변경 없다.

---

## 2. 위협 모형 변경 (기반 설계 §2 에 덧붙임)

- **CIA↔RP 조건부 추적 가능성을 명시한다.** CIA 는 발급마다 `(uid, r_s)` 를, RP 는 로그인마다 `(PPID, r_s)` 를
  기록한다. 두 기록을 맞대면 `uid ↔ PPID` 가 이어진다. 이는 PairCT(Mode 2)의 `r_token` 과 같은 자리이며, 감사자가
  분쟁 세션을 열 수 있는 근거가 된다. **단독** CIA 는 여전히 `arid`·`PPID`·속성을 모르고(커밋 안), 단독 RP 는 `uid` 를
  모른다. 담합·로그 결합을 위협 모형에 넣을지는 기반 설계 §11 의 미결 항목 그대로다 — 이 문서는 "결합하면 이어진다"는
  **사실**만 적는다. 따라서 RP 는 자기 (PPID, r_s) 기록을 공개하지 않는다 — 공개되면 단독 CIA 도 연결할 수 있다.
  데모 RP 의 조회 엔드포인트는 r_s 를 앞 8자리로 축약해 낸다.
- 속성 설계 §5 의 "`nonce` 는 비공개다" 논거는 폐기한다. 그 논거가 지키려던 성질(RP 로그 유출만으로 uid↔RP 연결
  불가)은 이 설계에서 **포기**한다 — 8장 그림을 따르기로 한 결정의 대가다.
- `cert_s` 는 CIA 에 보내지 않는다. 보내면 CIA 가 서비스를 알게 되어 13장이 깨진다. 지갑이 로컬에서 검증한다.

---

## 3. 서비스 등록과 `cert_s` (발표 12장)

```
1. RP → CIA:  POST /cia/register_rp { name, origin }
2. CIA:       arid ← randomScalar()  (< 2^250, CIA 가 배정 — Mode 2 의 rid 와 같은 방식)
              cert_s = EdDSA-Poseidon.Sign(sk_CIA, Poseidon(DOMAIN_MODE3_CERT_S, arid, H(origin)))
              기록: rps[arid] = { name, origin }
3. CIA → RP:  { arid, origin, cert_s }
4. RP:        파일에 영속화(mode3_rp_registration.json). 재기동 시 재사용. 기동 시 pk_CIA 로 검증
```

- `DOMAIN_MODE3_CERT_S` = ASCII "MODE3CERTS" 빅엔디언. `H(origin)` 은 `origin` 문자열의 `valueToField`(Mode 2 와 같은
  규약 — `sha256 → 250비트`). 서명 키는 `pk_CIA`(EdDSA-Poseidon) 그대로다.
- `origin` 을 서명에 넣는 이유는 Mode 2 `/register_rp` 와 같다 — 피싱 서비스가 진짜 서비스의 `arid` 를 자기 페이지에
  끼워 넣어도, 지갑은 요청을 보낸 오리진과 `cert_s` 의 오리진이 다르면 거절한다.
- **`arid` 는 더 이상 env 상수가 아니다.** RP 는 등록 응답의 `arid` 를 쓴다. 격리 테스트는 헬퍼가 등록을 대신 한다.
- 등록은 관리자 시크릿 없이 열어 둔다(데모). 실제라면 CIA 운영자의 승인 단계가 들어갈 자리다(§9 한계).

---

## 4. 인증 요구와 `r_s` (발표 8장 2단계)

```
RP → 지갑:  { arid, origin, cert_s, r_s }
    r_s ← randomScalar() (< 2^250). RP 가 (r_s → 미사용, 만료 시각) 으로 보관. TTL 2분(기존 challenge 와 같음)
지갑:       cert_s 를 pk_CIA 로 검증. 요청의 Origin 헤더 == cert_s 의 origin. 아니면 403 bad_rp_cert
```

- `r_s` 는 기존 `challenge`(32바이트 hex) 를 **대체**한다. 서명 메시지·회로에 들어가야 하므로 스칼라다. HTTP 에서는
  10진 문자열.
- 지갑 에이전트의 CORS 허용 오리진 검사는 그대로 두고, 그 위에 `cert_s.origin` 일치 검사가 더해진다.

---

## 5. 발급 (속성 설계 §4 대체)

```
1. 지갑: (pk_i, sk_i) 생성, blind 무작위, attrs 는 등록 때 저장한 값
         C_pt = Commit(uid, arid, s_u, pk_i, attrs; blind)                      ← 변경 없음
2. 지갑 → CIA: uid, C_pt, π_issue, chainid, r_s, sig_u = Sign(sk_u, Poseidon(C_pt.x, C_pt.y, chainid, r_s))
3. CIA (순서): 형식 → disabled → chainid 허용 → (uid, r_s) 미사용 (409) → sig_u → π_issue → 같은 C (409)
               → 체인 가용성 → disabled·(uid, r_s)·같은 C 재확인
4. CIA: exptime = now + CIA_TTL_SECONDS
        σ_CIA = Sign(sk_CIA, Poseidon(DOMAIN_MODE3_CRED_V3, C, exptime, chainid, r_s))
        기록: issued[uid] += {leaf, C, exptime};  used_rs[uid] += r_s
5. CIA → 지갑: exptime, chainid, r_s, σ_CIA, pk_CIA
```

- 속성 설계 §4 와의 차이는 `nonce → r_s` 뿐이다. 검사 순서·409·503·재확인 블록·영구 집합·TTL·skew 는 그대로.
- `DOMAIN_MODE3_CRED_V3` = ASCII "MODE3CREDV3" 빅엔디언. V2 서명(`nonce` 판)이 새 회로에서 재생되지 않게 한다.
- CIA 는 `r_s` 를 보지만 무작위값이라 서비스를 알 수 없다(13장). `cert_s`·`origin`·`arid` 는 CIA 에 가지 않는다.
- **로그인마다 발급된다.** CIA 가 멈추면 새 로그인은 막히고, 진행 중인 세션은 §7 의 재검증이 CIA 없이 되므로 계속
  동작한다 — 기반 설계 §2.1 "가용성은 별개 축"이 이 범위로 좁아진다.

---

## 6. 증명 π (속성 설계 §5 대체)

```
공개 입력   PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA_x, pk_CIA_y   ← 이 순서 (9개)
비공개 입력 uid, s_u, blind, attrs[4], σ_CIA(S, R8x, R8y), 비멤버십 witness

증명 내용
  ① EdDSA-Poseidon.Verify(pk_CIA, Poseidon(DOMAIN_MODE3_CRED_V3, C, exptime, chainid, r_s), σ_CIA) = 1
  ② C_pt = Commit(uid, arid, s_u, pk_i, attrs; blind)
  ③ PPID = Poseidon(uid, s_u, chainid, arid)
  ④ mask₂₅₂(Poseidon(TAG_MODE3_CRED, C)) ∉ IMT(revRoot)
```

`r_s` 가 공개 입력이 되면서 `Num2Bits(250)` 범위 검사는 그대로 둔다(스칼라 상한 규약). 나머지는 속성 설계 §5 와 같다.

---

## 7. RP 로그인·세션·재검증 (속성 설계 §6 대체)

```
로그인   지갑 → RP: (π, 공개입력, σ = Sign(sk_i, r_s))
         RP:
           b. π.r_s 가 내가 발급했고 아직 미사용인 r_s 인가?     아니면 bad_challenge   ← 소비한다
              `r_s` 는 검증 전에 소비한다 — 실패한 로그인도 같은 `r_s` 를 재사용하지 못하게
           a. L1 헤드를 최근 10분 안에 읽었는가?                아니면 chain_unavailable
           c. π.revRoot == 방금 읽은 root ?                     아니면 stale_root
           d. now ≤ exptime, chainid == 내 체인, pk_CIA 일치, arid == 내 arid
           e. Groth16
           f. σ 검증 (pk_i, r_s)
           g. 세션 생성: sessions[r_s] = { PPID, pk_i, exptime, root, at }

재검증   지갑 → RP: (π', 공개입력, σ' = Sign(sk_i, r_s))      ← root 가 바뀐 뒤 같은 성명으로 만든 새 π
         RP:
           b'. π'.r_s 가 **살아 있는 세션**인가?                 아니면 no_session
           c~f 동일. PPID·pk_i 가 세션과 같은지 확인
           g'. sessions[r_s].root 갱신

세션 요청 지갑 → RP: (r_s, body, σ = Sign(sk_i, r_s ‖ body))    ← 로그인 뒤 후속 요청 (pk_i 의 용도)
         RP: 세션 존재·미만료 → σ 검증 → 처리. 세션의 root 가 현재 root 와 다르면 `revalidate_required`
```

- **`r_s` 는 로그인 때 한 번 소비되고 그 뒤로는 세션 식별자다.** 같은 `r_s` 로 `/login` 을 다시 부르면
  `bad_challenge`, `/revalidate` 로 부르면 세션 재검증이다.
- 폐기가 효력을 갖는 지점은 재검증이다: root 가 바뀌면 RP 는 세션 요청을 `revalidate_required` 로 돌려보내고, 지갑은
  같은 성명으로 새 π 를 만든다. 성명이 폐기됐으면 지갑이 비멤버십 witness 를 만들지 못해(`is a member`) 재검증이 안
  되고, 새 로그인은 발급에서 `account_disabled` 다.
- 데모 시연용 "동기화 생략"은 재검증에 옛 π' 를 그대로 내는 것으로 옮긴다 → `stale_root`.

---

## 8. 지갑·RP·CIA 상태

- **지갑**: `credentials[arid]` → `sessions[r_s] = { arid, credential:{C, exptime, chainid, r_s, sigma, pk_CIA}, blind,
  sessionPrivKey, pk_i, issuedAt }`. 만료된 세션은 기동·로그인 때 걷어낸다. `ProofCache` 키는 `(root, r_s)`.
  등록값·`attrs` 는 그대로. 상태 파일 `version: 3`(옛 파일은 registration 유지, 세션 비움).
- **RP**: `mode3_rp_registration.json` = `{ arid, origin, cert_s, issuedAt }`(0600). 메모리: `challenges` (r_s → 만료),
  `sessions` (r_s → 세션). `rp_info` 가 `arid, origin, cert_s` 를 내준다.
- **CIA**: `rps[arid] = { name, origin }`; `nonces` → `used_rs`(이름만). 상태 파일 `version: 3`, 옛 버전 기동 거부(속성
  설계 §7 과 같은 규칙).

---

## 9. 알려진 한계

1. **조건부 추적 가능성** (§2). CIA 와 RP 의 기록을 맞대면 uid↔PPID 가 이어진다. 의도된 것이지만 담합 위협 모형은 미결.
2. **CIA 가 로그인 경로에 있다.** 로그인마다 발급이라 CIA 다운 = 새 로그인 불가. 진행 중 세션은 영향 없음.
3. **RP 등록에 승인 절차가 없다.** 아무나 `register_rp` 로 `cert_s` 를 받는다. 피싱 방어는 "오리진 일치"까지이며
   "이 서비스가 신뢰할 만하다"는 아니다.
4. 속성 설계 §8 의 한계(속성 진위 미보증, 벽시계, `used_rs` 무한 성장, 옛 credential 무효)는 그대로다.
5. **성명 재사용 규칙(기반 설계 §8.4)이 세션 안으로 좁아졌다.** "root 가 바뀔 때까지 재사용"은 여전히 맞지만 그
   대상이 RP 당 성명에서 세션 당 성명으로 바뀐다.
6. **세션 요청 서명에 신선도가 없다.** `Sign(sk_i, r_s ‖ body)` 는 root 가 바뀌거나 세션이 만료될 때까지 같은
   (r_s, body, sig) 를 재생할 수 있다. 데모의 echo 요청에서는 무해하며, 실제 요청에는 카운터나 시각을 메시지에
   넣어야 한다.

---

## 10. 구현 범위

변경: `circuits/pi_cred.circom`(`nonce` → 공개 `r_s`, 도메인 V3), `lib/mode3_credential.js`(`credMessage` 이름·도메인),
`lib/mode3_issuance.js`(`issueRequestMessage(C_pt, chainid, r_s)`, `certSMessage`), `lib/mode3_wallet.js`(`buildIssueRequest`
가 `r_s` 를 받음, `verifyRpCert`), `lib/mode3_rp.js`(공개 입력 9개, `r_s` 대조, 세션, 재검증), `cia.js`(`register_rp`,
`r_s`, 상태 v3), `mode3_wallet_agent.js`(cert 검증, 세션 상태, `/wallet/login`·`/wallet/revalidate`·`/wallet/request`),
`mode3_rp.js`(등록 파일, `rp_info`, `/api/mode3/login`·`/revalidate`·`/request`, 세션), `mode3/rp.html`·`wallet.html`,
테스트(circuit 1, unit 1, chain 6, 격리 헬퍼 2), `scripts/build_mode3_circuit.sh` 재실행, `docs/MODE3_DEMO.md`.

변경 없음: 컨트랙트, `lib/mode3_revocation.js`, `lib/mode3_log.js`, 폐기·게시·자기 폐기·복구 엔드포인트, Mode 2 전부.

---

## 11. 발표 자료에 되돌아갈 것 (코드 밖)

- 12·13장 도식: `(cert_s, r_s)` 가 User→AA 화살표에 있는 것을 `r_s` 만으로 고친다. `cert_s` 는 Service→User 화살표에.
- 8장 4단계 "인증 성명 전달" 옆에 "`r_s` 임베딩"을 표시.
- 1장 노트(초록): "증명은 폐기 상태가 바뀔 때까지 재사용" → "세션 안에서 재사용". "IdP 는 어느 서비스에 로그인하는지
  알 수 없고" 뒤에 "(IdP 와 서비스가 기록을 맞대면 세션을 열 수 있다 — 조건부 추적)" 을 넣을지는 담합 결정 뒤에.
- 9장 "커밋 밖" 항목의 `nonce` → `r_s`(서비스 발급).
