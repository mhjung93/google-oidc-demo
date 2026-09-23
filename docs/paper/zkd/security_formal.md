# zk-Delegation 보안 성질의 형식 정의와 증명

작성 2026-09-18. 대상은 논문 v3(`2026-09-18_v3_zk-Delegation_research_article.docx`)의 프로토콜과 브랜치 `feat/mode3-cia`(HEAD 4dd179a)의 구현이다. 논문 §III-C의 목표 G1–G10과 온체인 실행(§V-I)의 추가 성질을 게임 기반으로 정의하고 표준 가정으로 귀착시킨다. 조건부 프라이버시 문서(`2026-09-18_zkDelegation_conditional_privacy_formal`)의 정의 1–5·정리 1–5는 §4.10에 그대로 편입했다. 마지막 §6은 각 정리가 기대는 검사가 코드 어디에서 강제되는지의 대응표다. §7(만료를 지갑이 정함, 2026-09-18)과 §8(속성 선택 공개 V6, 2026-09-22)은 그 뒤의 갱신이며, §8 은 G5 의 정의 자체를 바꾼다 — 본문 §4.5·§6 의 해당 행은 §8 에 맞춰 고쳤다.

## 0. 요약과 읽는 법

| 목표 | 형식화 | 귀착 대상 | 결과 |
|---|---|---|---|
| G1 유일성 | 충돌 게임 | Poseidon 충돌 저항성 | 정리 1 |
| G2 불변성 | 두 번째 주소 게임 | Pedersen 결합성 + π_issue 특수 건전성 + Groth16 지식 건전성 + 250비트 범위 | 정리 2 |
| G3 비연결성 | 컨텍스트 간 구별 게임 | RO + 태그 익명성 + 영지식성 | 정리 3 |
| G4 서비스 비관측 | 발급 뷰 구별 게임(체인 없음) / 체인 포함 추측 게임 | Pedersen 은닉성 + 시그마 ZK / + 1/n | 정리 4·4′ |
| G5 속성 사용처 비관측(2026-09-22 재정의) | 검증자 측: 비공개 슬롯 구별 게임 / AA 측: 사용처 추측 게임 | Pedersen 은닉성 + Groth16 ZK / 정리 4′ 의 1/n (n = 술어 만족 집합) | 정리 5·5′ (§4.5, §8) |
| G6 서비스 인증 | 피싱 게임 | EdDSA EUF-CMA + F 충돌 저항성 + 브라우저 오리진 모델 | 정리 6 |
| G7 세션 바인딩·재생 | 오프체인 로그인·요청 위조 게임, 온체인 실행 위조·재생 게임 | ECDSA EUF-CMA + 상태기계 불변식 | 정리 7·8 |
| G8 폐기 건전성 | 폐기 뒤 수락 게임 | 인덱스드 트리 비회원 건전성(Poseidon) + Groth16 지식 건전성 + N=1 규칙 | 정리 9 |
| G9 라이브니스 독립 | 의존 그래프 명제 | (구조) | 명제 10 |
| G10 승인 개봉 | 태그 익명성·추적 가능성·국소성 | CDH(RO) + Groth16 + EdDSA | 정리 11–15 |
| 온체인 계정 | 주소 결정성·재진입·보류 상한 | keccak 충돌 저항성 + 상태기계 | 명제 16–18 |

정리의 상한은 모두 "표준 가정의 이점 + q·2^{−250}" 꼴이고, 예외는 정리 4′의 1/n 항이다. 형식화하지 않은 것은 §5에 모았다.

## 1. 시스템과 표기

- **군·체.** 𝔾 = ⟨B8⟩는 Baby Jubjub의 소수 위수 부분군, 위수 ℓ(2^250 < ℓ < 2^251). 𝔽는 BN254 스칼라체. 스칼라는 [0, 2^250)에서 뽑는다. H = Poseidon.
- **당사자.** 사용자 u(지갑 포함), AA, 서비스 s, 체인(로그 컨트랙트 L, 서비스별 팩토리 F_s, 계정 컨트랙트), 운영자.
- **등록.** 사용자: (uid_u, pk_u/sk_u), s_u, r_u ← [0, 2^250), cm_u = s_u·G₃ + r_u·H₀. AA는 (uid_u, pk_u, cm_u, disabled). 서비스: arid_s, pk_service, X_S = x_S·B8, x_A, pk_T = X_S + x_A·B8, cert_s = Sign_AA(H(D_cert, arid_s, F(origin_s), pk_T.x, pk_T.y)), F = 250비트로 자른 SHA-256.
- **성명.** C_pt = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + Σa_k·G_{4+k} + blind·H₀, C = H(C_pt.x, C_pt.y), σ_AA = Sign_AA(H(D_cred, C, max_height, chainid, allowAgent)). 속성 a = (a₁..a₄)는 **AA 계정 기록**이며 a_k ∈ [0, 2^64) (2026-09-22, §8; 그전에는 사용자 선택·250비트).
- **관계 R** (논문 Table 2): 공개 pub = (PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_A, pk_T, c1, c2, **disc_mask, disc_lo[4], disc_hi[4]**) — 23개, 증인 w = (uid, s_u, blind, a, σ_AA, r, path). 조건 1–6: 서명 검증, 커밋 재계산, PPID = H(uid, s_u, chainid, arid), leaf(C) ∉ Tree(root), 태그, 범위·불리언. **조건 7**(2026-09-22): disc_mask < 16, 비트 k 가 1 인 슬롯마다 disc_lo_k ≤ a_k ≤ disc_hi_k (lo·hi < 2^64); 비트가 0 인 슬롯은 무제약. 로그인 증명은 disc_mask = 0.
- **트랜스크립트** T = (pub, π). **검증** Vf_X(T) (X ∈ {서비스, 컨트랙트})는 Groth16.Verify(vk, pub, π)와 공개 입력 대조(pk_A·pk_T·arid·chainid 고정값, root = 현재 root, head/블록 ≤ max_height, allowAgent ≤ 1, disc_mask < 16, c1 ≠ O)의 논리곱이며, 서비스는 추가로 σ = Sign_{sk_i}(r_s)를, 컨트랙트는 nonce·payload 서명을 검사한다.
- **폐기 트리.** 깊이 32 인덱스드 머클 트리, 리프 leaf(C) = mask₂₅₂(H(3, C)), 비회원 증명 = 인접 리프 (v, v_next)와 경로. 로그 L은 (root, epoch, lastPublished)를 갖고 publishRoot(root′, epoch′, leaves, sig)로 갱신된다.
- **계정.** addr(PPID) = CREATE2(F_s, salt = PPID, initCode(PPID, arid, pk_A, pk_T, verifier, L, MAX_ROOT_AGE)). execute(payload, σ_tx, π, pub), σ_tx = Sign_{sk_i}(keccak(chainid, addr, to, value, data, nonce, disc_mask, disc_lo[4], disc_hi[4])) — 다이제스트가 π 의 공개 값 9워드를 덮는다(2026-09-22, §8). 컨트랙트는 π 검증 뒤 내부 호출 데이터 끝에 같은 9워드를 붙인다(payload.data 가 비어 있고 mask = 0 이면 예외).
- **오라클 표기.** 게임에서 정직한 당사자는 오라클로 나타난다: O_issue(요청) (AA), O_login·O_req·O_reval (서비스), O_exec (컨트랙트), O_publish (AA→L), O_open (개봉).

## 2. 가정

- **(A1) CDH** in 𝔾. **(A2)** H = Poseidon은 랜덤 오라클, 특히 충돌 저항. 질의 수 q_H. **(A3) Groth16**: 지식 건전성(추출기 Ext, 오차 ε_KS)과 영지식성(ε_ZK). **(A4) Pedersen**: 결합성(DL) 및 250비트 구간 블라인딩 아래 은닉성(구간 DL, 이점 Adv^{hide}). **(A5) EdDSA-Poseidon**(AA 서명·cert_s·sig_u) EUF-CMA. **(A6) ECDSA/secp256k1**(세션키·서비스 키·AA 게시 키) EUF-CMA, 서명 정규화(low-s) 가능. **(A7) π_issue**: 특수 건전성(두 수락 응답에서 표현 추출)과 특수 HVZK; Fiat–Shamir 아래 RO. 2026-09-22 부터 V2: 공개 입력에 AA 기록의 a 가 들어가고, 검증자가 Y = C_pt − uid·G₁ − Σa_k·G_{4+k} 를 계산한 뒤 Y 와 cm_u 에 대해 s_u 응답을 공유하는 두 Schnorr 등식을 검사한다(증인 (arid, s_u, pk_i, blind, r_u); 코드의 π_u V2 에 해당). **(A8) keccak256** 충돌 저항. **(A9) 브라우저 오리진 모델**: 페이지 스크립트는 자기 오리진과 다른 Origin 헤더로 지갑 에이전트에 요청을 보낼 수 없다. **(A10) 모델**: AA·서비스 honest-but-curious, 지갑은 사용자에게 신뢰됨, 네트워크는 TLS, 체인은 공개이며 재편성 깊이는 검증자의 읽기보다 얕음, 운영자 승인은 오라클 O_open.

## 3. 위협 모형(게임별 통제권)

| 게임 | 적이 통제·아는 것 | 정직 오라클 |
|---|---|---|
| G1·G2·G7(off)·G8 | 지갑(사용자 하나의 비밀 전부), 서비스 뷰 관찰 | O_issue, O_login/O_reval/O_req, O_publish |
| G3 | 모든 서비스(x_S 전부), 체인 전체 | AA(x_A 비밀), 지갑 |
| G4·G5 | AA(등록부, 발급 요청 전부, x_A), 체인 전체 | 서비스(x_S 비밀), 지갑 |
| G6 | 피싱 오리진의 페이지, 모든 등록 서비스의 공개값 | 지갑, AA |
| G7(on) | 세션키 없는 임의 당사자(릴레이어 포함), 체인 전체 | 지갑(sk_i), 컨트랙트 |
| G10 | 서비스 또는 AA 중 하나(자기 조각), 개봉 오라클 | 나머지 한쪽 |

## 4. 성질별 정의·정리·증명

### 4.1 G1 유일성

**정의 G1.** 게임 UNIQ(𝒜): 𝒜가 (uid₀, s₀) ≠ (uid₁, s₁)과 (chainid, arid)를 내고, H(uid₀, s₀, chainid, arid) = H(uid₁, s₁, chainid, arid)이면 이긴다. 두 등록 사용자의 uid는 AA가 서로 다르게 배정하므로 uid₀ ≠ uid₁이면 충분하다.

**정리 1.** (A2) 아래 Pr[UNIQ] ≤ q_H² / 2^{254} (RO 충돌) — 무시할 수 있다.

**증명.** PPID는 입력이 다른 두 RO 질의의 출력이 같아야 하며, 출력 공간이 𝔽(≈2^254)이므로 생일 경계가 적용된다. □

### 4.2 G2 불변성

**정의 G2 (두 번째 주소 게임).** 𝒜는 사용자 하나의 지갑이다(uid 고정, sk_u·s_u·r_u 자유롭게 선택, cm_u를 등록). 𝒜는 O_issue를 임의로 부른다(AA는 프로토콜대로 sig_u·π_issue를 검사하고 서명). 𝒜가 같은 (chainid, arid)에 대해 Vf를 통과하는 T = (pub, π), T′ = (pub′, π′)를 내고 pub.PPID ≠ pub′.PPID이면 이긴다.

**정리 2.** (A2)–(A5), (A7) 아래

Pr[𝒜 wins] ≤ 2·ε_KS + 2·ε_SS + 3·Adv^{DL}(B) + Adv^{EUF}_{EdDSA}(B′) + q_H·2^{−253},

여기서 ε_SS는 π_issue의 특수 건전성 추출 오차이다.

**증명.** Ext로 T, T′에서 증인 w, w′를 뽑는다(2·ε_KS). 조건 3에 의해 PPID = H(uid, s_u, chainid, arid), PPID′ = H(uid′, s_u′, chainid, arid). PPID ≠ PPID′이면 (uid, s_u) ≠ (uid′, s_u′)이다(같은 입력이면 같은 출력).

*uid = uid′.* 조건 1에 의해 σ_AA는 C = H(C_pt)에 대한 AA 서명이고, (A5)에 의해 AA가 실제로 서명한 C 중 하나다(위조 확률 Adv^{EUF}). AA는 O_issue에서 π_issue를 검사한 뒤에만 서명하고, π_issue의 공개 입력 uid는 인증된 계정의 uid다. π_issue의 특수 건전성으로 C_pt의 표현 (uid, arid₁, s₁, pk₁, a, blind₁)을 뽑을 수 있는데(ε_SS), 이 표현의 uid는 AA가 검사한 그 uid다(V2 에서는 uid 와 a 가 공개 입력이라 추출되는 것은 Y = C_pt − uid·G₁ − Σa_k·G_{4+k} 의 표현 (arid₁, s₁, pk₁, blind₁)이고, 여기에 AA 가 넣은 uid·a 를 더한 것이 C_pt 의 표현이다 — 논증은 같고, 덤으로 a 도 AA 기록값으로 고정된다). Ext가 뽑은 증인도 같은 C_pt의 표현이므로, 두 표현이 다르면 Pedersen 결합성이 깨진다(Adv^{DL}). 따라서 Ext의 uid = 인증 uid이고 T′도 마찬가지이며, 𝒜는 한 계정이므로 uid = uid′.

*s_u = s_u′.* 같은 논리로 Ext의 s_u는 π_issue 추출 표현의 s_u와 같고(결합성), π_issue의 둘째 등식은 cm_u = s_u·G₃ + r_u·H₀의 표현을 준다. T′에 대해서도 cm_u = s_u′·G₃ + r_u′·H₀. 같은 cm_u의 두 표현이 (s_u, r_u) ≠ (s_u′, r_u′)이면 결합성 위반(Adv^{DL}). 따라서 s_u ≡ s_u′ (mod ℓ). 조건 6·범위(회로의 250비트 제약)로 s_u, s_u′ < 2^250 < ℓ이므로 정수로도 같다.

그러므로 (uid, s_u) = (uid′, s_u′)이고 PPID = PPID′, 모순. 오차 항은 위 사건들의 합이다. □

**주.** 이 정리가 "지갑이 s_u를 바꿔 새 주소를 만들 수 없다"를 말하는 것이며, 250비트 범위 제약이 없으면 s_u + ℓ 같은 두 번째 대표원으로 다른 PPID를 만들 수 있다(논문 §IV-D).

### 4.3 G3 서비스·체인 간 비연결성

**정의 G3.** 조건부 프라이버시 문서의 정의 2와 같다: 𝒜는 모든 서비스와 체인을 통제하고, 도전 컨텍스트 (chainid*, arid*) 밖의 모든 트랜스크립트를 얻으며, u₀·u₁ 중 하나의 도전 컨텍스트 트랜스크립트를 받아 b를 맞힌다.

**정리 3.** (A1)–(A4) 아래 Adv ≤ 2·ε_ZK + Adv^{TAG}_{S} + q_H·2^{−250} + negl. 증명은 §4.10 정리 12(= 조건부 프라이버시 정리 2). 온체인 계정 주소는 PPID의 결정적 함수이므로 추가 항이 없다.

### 4.4 G4 서비스 비관측

**정의 G4 (발급 뷰만).** 𝒜는 AA다. 𝒜가 사용자 u와 두 서비스 arid₀, arid₁, 두 세션키를 내고(속성 벡터는 2026-09-22 부터 AA 기록이라 𝒜 가 이미 알며 도전의 일부가 아니다), 도전자가 arid_b에 대한 정직한 발급 요청 (uid, C_pt, chainid, allowAgent, max_height, π_issue, sig_u)을 준다. 𝒜가 b를 맞힌다.

**정리 4.** (A4), (A7) 아래 Adv ≤ Adv^{hide}(B) + ε_HVZK.

**증명.** π_issue를 HVZK 시뮬레이터로 바꾼다(ε_HVZK; Fiat–Shamir 아래 RO 프로그래밍). 남는 것은 C_pt와 그 위의 서명 sig_u뿐이고, sig_u는 C_pt의 함수다. C_pt는 arid_b를 G₂ 계수로 갖는 Pedersen 커밋이므로, b를 맞히는 것은 커밋 은닉성 게임이다(V2 에서 𝒜 가 uid·a 항을 빼고 남는 Y 도 blind 로 가려진 Pedersen 커밋이라 같다). 블라인딩이 250비트 구간이라 은닉은 계산적이며, 그 이점이 Adv^{hide}이다. □

**정의 G4′ (체인 포함).** 조건부 프라이버시 문서의 정의 3(추측 게임, 1/n). **정리 4′** = §4.10 정리 13.

### 4.5 G5 속성 사용처 비관측 (2026-09-22 재정의 — 이전 "속성 비밀"은 §8 참고)

속성 a 는 AA 계정 기록이므로 "AA 가 값을 모른다"는 더 이상 목표가 아니다. 남는 것은 두 가지다: (i) 검증자(서비스·체인 관찰자)는 사용자가 공개한 구간 밖의 것을 모른다, (ii) AA 는 값을 알지만 그것이 **어디서(어느 서비스·어느 트랜잭션에서) 공개됐는지** 모른다. 세션키 pk_i 에 대한 옛 정의는 그대로다.

**정의 G5a (검증자 측, 비공개 슬롯 비밀).** 𝒜는 모든 서비스와 체인을 통제한다. 𝒜가 사용자 u, 컨텍스트 (chainid, arid), 공개 술어 (mask, lo, hi)와 두 속성 벡터 a⁰ ≠ a¹ 을 내되, 둘 다 술어를 만족하고 mask 비트가 1 인 슬롯에서는 a⁰_k = a¹_k 이어야 한다(공개한 것은 같다). 도전자는 AA 기록을 a^b 로 두고 정직한 트랜스크립트 T* 를 준다. 𝒜가 b 를 맞힌다.

**정리 5.** (A3), (A4) 아래 Adv ≤ ε_ZK + negl. **증명.** T* 의 pub 에서 a 에 의존하는 것은 조건 7 을 통과했다는 사실뿐이고 두 벡터 모두 통과하므로 pub 의 분포는 b 와 무관하다. π 를 Sim(pub) 으로 바꾸면(ε_ZK) 뷰는 b 와 독립이다. C_pt 는 pub 에 없다(회로 안). □

**정의 G5b (AA 측, 사용처 비관측).** 정의 G4′(조건부 프라이버시 정의 3)의 AA 측 추측 게임을 그대로 두되, 도전 트랜잭션 T* 가 술어 (mask, lo, hi) 를 공개한다. 𝒜(AA)는 모든 사용자의 a 를 안다.

**정리 5′.** Pr[추측 성공] ≤ E[1/n′] + (n′_max − 1)·ε₂, 여기서 n′ = |{ i ∈ W(T*) : a^{(i)} 가 (mask, lo, hi) 를 만족 }| 이고 ε₂ 는 정리 13 의 값이다. **증명.** 정리 13 의 논증에서 클래스 W(T*) 를 술어로 한 번 더 걸러낸 것뿐이다: pub 의 [14..22] 는 AA 가 자기 기록으로 대조할 수 있는 값이므로 클래스를 n′ 로 줄이고, 클래스 안의 두 기록은 같은 술어를 만족하므로 [14..22] 가 둘을 구별하지 않으며 나머지 항은 정리 13 그대로다. □

**해석.** 정확한 값 공개(lo = hi)는 n′ 를 한 값의 사용자 수로, 구간 공개는 구간 안 사용자 수로 줄인다. n′ 는 배포의 성질이며 술어를 좁게 잡을수록 작아진다 — 논문 §VII-D·§IX 의 "익명 집합 축소" 한계다. 공개하지 않은 트랜잭션(mask = 0)은 정리 13 그대로다(n′ = n). 세션키: 온체인에서 pk_i는 공개 입력으로 드러나지만, 그것은 서비스·체인 관찰자에게 드러나는 것이고 AA가 C_pt에서 pk_i를 읽는 것과는 다르다(§4.10 정리 13의 논증). □

### 4.6 G6 서비스 인증(피싱 저항)

**정의 G6 (피싱 게임).** 𝒜는 오리진 o_𝒜의 페이지를 통제하고, 모든 등록 서비스의 (arid, cert_s, pk_T, origin)을 안다(공개값). 𝒜는 (A9) 아래 지갑 에이전트에 Origin = o_𝒜인 로그인 요청만 보낼 수 있고, 등록 오라클로 자기 오리진을 등록해 cert를 받을 수 있다(운영자 승인은 o_𝒜에 대해서만 난다). 𝒜가 이기는 것은 지갑이 어떤 (arid, cert) 요청에 대해 발급·증명을 진행했는데 cert가 덮는 origin ≠ o_𝒜인 경우.

**정리 6.** (A5), (A9), F의 충돌 저항성 아래 Pr[𝒜 wins] ≤ Adv^{EUF}_{EdDSA}(B) + Adv^{CR}_F(B′).

**증명.** 지갑은 (i) Origin 헤더 = 요청 본문의 origin, (ii) EdDSA.Verify(pk_A, H(D_cert, arid, F(origin), pk_T.x, pk_T.y), cert)를 모두 요구한다. (A9)에 의해 (i)는 origin = o_𝒜를 강제한다. 𝒜가 이기려면 cert가 F(o_𝒜)를 담은 메시지에 대해 검증되면서 그 cert가 실제로는 다른 origin에 대해 발급된 것이어야 한다. AA가 서명한 메시지는 H(D_cert, arid, F(origin_s), …)뿐이므로, 두 경우 중 하나다: F(o_𝒜) = F(origin_s)인 origin_s ≠ o_𝒜(F 충돌), 또는 AA가 서명한 적 없는 메시지에 대한 유효 서명(EdDSA 위조). 각각 Adv^{CR}_F, Adv^{EUF}로 상한된다. 등록 오라클로 얻은 cert는 origin = o_𝒜라 이기는 조건에 걸리지 않는다. □

**주.** cert가 pk_T까지 덮으므로, 같은 논증으로 𝒜는 정직한 서비스의 arid를 자기 오리진에서 쓰되 pk_T를 자기만 아는 키로 바꿔치기할 수도 없다(§4.10 경계 참고).

### 4.7 G7 오프체인 세션 바인딩과 재생

**정의 G7a (로그인 위조).** 𝒜는 sk_i를 모르는 임의 당사자로, 정직한 지갑이 만든 트랜스크립트·σ들을 관찰하고 O_login에 임의 (T, σ, r_s)를 낸다. 𝒜가 이기는 것은 서비스가 (i) 같은 r_s로 두 번 수락하거나, (ii) 정직한 지갑이 그 r_s에 대해 σ를 만든 적이 없는 로그인을 수락하는 경우.

**정리 7.** (A6) 아래 Pr[(i)] = 0이고 Pr[(ii)] ≤ Adv^{EUF}_{ECDSA}(B) + q·2^{−250}.

**증명.** (i) 서비스는 검증 전에 r_s를 소비하며(사용됨 표시), 소비된 r_s는 다시 수락되지 않는다 — 상태기계 불변식이다. (ii) 수락 조건은 ecrecover(EIP-191(r_s), σ) = pk_i이고 pk_i는 T의 공개 입력이다. 정직한 지갑이 그 r_s에 서명한 적이 없으면 σ는 메시지 r_s에 대한 새 서명이므로 EUF-CMA 위조다. 𝒜가 T를 바꿔 pk_i′ = 자기 키로 두면 조건 2에 의해 C_pt가 pk_i′를 담아야 하고 조건 1에 의해 AA가 그 C에 서명했어야 하므로, 𝒜 자신의 계정 성명이 되어 "정직한 지갑의 로그인"이 아니다(자기 계정으로 로그인하는 것은 공격이 아니다). r_s는 250비트 균일이라 다른 로그인의 σ가 재사용될 확률은 q·2^{−250}. □

**정의 G7b (세션 요청 위조).** 𝒜가 sk_i 없이 O_req에 (r_s, body, σ)를 내어, 정직한 지갑이 서명한 적 없는 body가 수락되면 이긴다. **정리 7b.** Pr ≤ Adv^{EUF}_{ECDSA}. (메시지 `${r_s}:${body}`에 대한 위조.) 같은 (r_s, body, σ)의 재생은 정의상 이기지 않는다 — 논문 §IX의 한계.

### 4.8 G7′ 온체인 실행 위조와 재생

**정의 G7c.** 𝒜는 sk_i를 모르는 임의 당사자(릴레이어 포함)로 체인 전체를 읽고, 정직한 지갑이 제출한 execute 호출들을 관찰한다. 𝒜가 이기는 것은 계정 addr(PPID)에서 execute가 성공했는데 그 (chainid, addr, to, value, data, nonce, disc_mask, disc_lo, disc_hi)에 대해 정직한 지갑이 서명한 적이 없는 경우. 공개 값 9워드가 튜플에 든 이유(2026-09-22): 같은 세션키로 만든 π 가 둘 이상 있으면(예: 정확한 값 공개와 구간 공개) 릴레이어가 다른 π 를 끼워 대상에 다른 공개 값을 전달할 수 있었다 — 다이제스트가 9워드를 덮으면 릴레이어는 지갑이 서명한 (mask, lo, hi) 의 π 만 쓸 수 있다.

**정리 8.** (A6) 아래 Pr[𝒜 wins] ≤ Adv^{EUF}_{ECDSA}(B).

**증명.** 성공 조건은 ecrecover(digest, σ_tx) = address(pub[2])이고 pub[2] = pk_i는 π에 의해 C_pt의 세션키와 같다(조건 2). digest = keccak(chainid, addr, to, value, data, nonce, pub[14], pub[15..18], pub[19..22])이며 nonce는 컨트랙트의 현재 값과 같아야 한다. 정직한 지갑이 이 튜플에 서명한 적이 없으면 σ_tx는 위조다. 재생: 같은 서명은 nonce가 다른 상태에서는 digest가 달라 실패한다(nonce는 성공마다 1 증가, 감소하지 않음). 다른 체인·다른 계정: digest에 chainid와 addr이 들어 있어 실패한다. 서명 가변성: 컨트랙트가 low-s·v ∈ {27,28}을 요구하므로 (r, s, v)의 표현은 유일하고, 트랜잭션 해시를 바꾼 재제출은 revert된다 — 권한과는 무관하나 §V-G의 해시 기반 개봉 장부의 무결성에 필요하다. pk_i = 0인 성명은 ecrecover의 address(0)과 공허하게 일치할 수 있어 별도로 거절된다. □

### 4.9 G8 폐기 건전성

**정의 G8.** 𝒜는 사용자 하나의 지갑(모든 비밀)이다. AA가 leaf(C)를 트리에 넣고 root R을 게시했다(O_publish). 𝒜가 이기는 것은 root = R인 T가 Vf(서비스 또는 컨트랙트)를 통과하면서 그 T의 증인이 담는 C가 폐기된 C인 경우.

**정리 9.** (A2), (A3) 아래 Pr[𝒜 wins] ≤ ε_KS + q_H²·2^{−252} + negl.

**증명.** Ext로 증인을 뽑는다. 조건 4는 leaf(C) = mask₂₅₂(H(3, C))에 대해 (v, v_next)와 경로 path가 존재해 v < leaf(C) < v_next(또는 v_next = 0인 최대 리프)이고 H로 계산한 머클 경로가 R에 이른다고 말한다. R은 leaf(C)를 리프로 갖는 트리의 root다. 인덱스드 트리의 불변식(리프들이 정렬된 연결 리스트를 이루고 각 리프가 다음 큰 리프를 가리킴)에서, leaf(C)가 리프이면 v < leaf(C) < v_next인 인접 리프 (v, v_next)는 트리에 없다. 따라서 𝒜의 경로는 트리에 없는 리프로 R에 도달해야 하고, 그것은 H의 충돌(경로 위 어느 노드에서의 두 번째 원상)이다. 비교는 252비트로 마스킹된 값 사이에서 이루어지므로 체 wrap-around로 순서를 속일 수 없다. 서비스와 컨트랙트가 R만 받아들이고(N=1) 이전 root의 증명을 거절하는 것은 상태기계 규칙이라 𝒜가 다른 root를 낼 여지가 없다. □

**따름정리 9′ (효력 시점).** 게시 블록 B_R 이후, 컨트랙트는 B_R부터, 서비스는 B_R + (읽기 지연 ≤ 600 s)부터 폐기된 성명을 거절한다. 계정 폐기는 disabled 플래그로 새 발급도 막는다(O_issue의 검사). 만료 max_height는 게시가 없어도 성명을 끝내는 둘째 상한이다.

### 4.10 G10 승인 개봉 — 조건부 프라이버시 문서의 편입

정의 11–15와 정리 11–15는 조건부 프라이버시 문서의 정의 1–5·정리 1–5와 같다(번호만 옮김):

- **정리 11** (한 조각 태그 익명성, 개봉 오라클 포함): Adv^{TAG}_{role} ≤ q_H·Adv^{CDH} + q_O·ε_KS + q_O·2^{−250}.
- **정리 12** (서비스·체인 측 세션 익명성): Adv ≤ 2·ε_ZK + Adv^{TAG}_S + q_H·2^{−250} + negl.
- **정리 13** (AA 측 세션 익명성, 체인 포함): Pr[추측 성공] ≤ E[1/n] + (n_max − 1)·ε₂.
- **정리 14** (추적 가능성: 정확성·무고 불가·2-of-2 필요성).
- **정리 15** (개봉 국소성).

### 4.11 G9 라이브니스 독립

**명제 10.** 검증·재검증·세션 요청·온체인 실행의 어느 단계도 AA와의 통신을 요구하지 않는다.

**근거.** 서비스의 Vf 입력은 (T, σ, r_s)와 체인 읽기(root, head)뿐이고 vk·pk_A·pk_T는 기동 시 고정된다. 지갑의 재증명 입력은 보유 성명 (C, max_height, chainid, allowAgent, σ_AA), 체인 이벤트로 재구성한 트리, 자기 비밀뿐이다. 컨트랙트의 입력은 calldata와 L의 상태뿐이다. AA가 관여하는 것은 발급(O_issue)과 게시(O_publish)이며, 후자가 멈추면 root가 그대로라 오프체인 검증은 계속되고, 온체인은 하트비트가 끊긴 뒤 MAX_ROOT_AGE 블록까지만 계속된다(명제 18). □

### 4.12 온체인 계정의 추가 성질

**명제 16 (주소 결정성·유일성).** addr(PPID) = keccak(0xff ‖ F_s ‖ PPID ‖ keccak(initCode))[12:]. 같은 팩토리에서 PPID ≠ PPID′이면 addr ≠ addr′, keccak 충돌을 제외하고(A8). 팩토리 주소는 (verifier, arid, pk_A, pk_T, L, MAX_ROOT_AGE)를 initCode에 넣으므로 다른 파라미터는 다른 주소를 준다(§IX의 "재배포 시 주소 변경"의 형식적 이유).

**명제 17 (재진입 안전).** execute의 가변 상태는 nonce 하나이고 외부 호출 전에 갱신되며, 재진입된 execute는 새 nonce에 대한 유효 서명을 요구한다. 그런 서명은 sk_i 보유자만 만들 수 있고 그것은 어차피 따로 제출할 수 있는 트랜잭션이므로 권한 상승이 없다(정리 8).

**명제 18 (보류 상한).** L의 마지막 게시 블록을 P라 하면 모든 계정은 블록 P + MAX_ROOT_AGE 이후 RootTooOld로 멈춘다. AA가 HEARTBEAT_BLOCKS < MAX_ROOT_AGE마다 재게시하면 정상 상태에서는 멈추지 않는다. 이것은 논문 §V-I의 "withholding 노출을 무한에서 MAX_ROOT_AGE로" 의 형식적 진술이며, 컨트랙트가 시계를 읽을 수 없다는 사실에서 나온 최선이다.

## 5. 형식화하지 않은 것(경계)

- **운영자 승인**은 오라클(A10)이다. 암호학이 보장하는 것은 2-of-2 필요성(정리 14c)까지다.
- **honest-but-curious.** AA의 위조 root, 정직하지 않은 x_A, 절차 밖 조각 결합, 서비스 사칭 등록은 모델 밖이다(논문 §III-B). 악의적 AA의 키 바꿔치기는 등록 시 x_A 지식 증명으로 닫힌다.
- **브라우저 오리진 모델(A9)**은 표준 가정이지만 XSS로 오리진 안에서 실행되는 스크립트는 막지 못한다. 그래서 자산 이동은 지갑 페이지(같은 오리진)에서만 시작한다(§6 P2).
- **릴레이어**는 트랜잭션 내용을 보고 지연·검열할 수 있다. 권한은 서명·증명에 있어 위조는 못 한다(정리 8). 제출은 무허가라 검열은 다른 릴레이어로 우회된다.
- **시각 상관**과 **익명 집합 크기 n**(정리 13)은 프로토콜이 아니라 배포의 성질이다.
- **오프체인 세션 요청의 재생**(정리 7b의 정의 밖)은 논문 §IX의 한계다.
- **재편성**(A10)이 검증자의 읽기보다 깊으면 폐기 효력 시점이 뒤로 밀린다.
- **Groth16 신뢰 설정**은 (A3)에 포함된 "올바르게 생성된 setup" 가정이다. 프로토타입의 phase-2 기여는 고정 엔트로피의 단일 기여라 이 가정이 실제로는 성립하지 않는다(§8 (a)).
- **공개 값에 의한 익명 집합 축소·폐기 시각 상관·데모 API** — §8 (c)(d)(e).

## 6. 구현 대응표 (feat/mode3-cia @ 4dd179a, 읽기 전용 점검 2026-09-18)

각 정리가 기대는 검사가 코드 어디에서 강제되는지. 판정: ENFORCED / PARTIAL / NOT ENFORCED. 총 62항목 중 ENFORCED 60, PARTIAL 1(P1), 설계상 미제약 1(C11).

### 6.1 회로 (정리 2·8·9·11·14의 가정)

| ID | 검사 | 위치 | 판정 |
|---|---|---|---|
| C1 | pk_i < 2^160 | `circuits/pi_cred.circom:74-75` | ENFORCED |
| C2 | max_height < 2^64 | `pi_cred.circom:98-99` | ENFORCED |
| C3 | allowAgent ∈ {0,1} | `pi_cred.circom:100` | ENFORCED |
| C4 | 커밋 스칼라 250비트(uid·s_u·blind·arid), 속성 4개는 64비트(2026-09-22) | `circuits/lib/mode3_commit.circom:66-70,118` | ENFORCED |
| C5 | C_pt·C를 증인에서 재계산(자유 입력 없음) | `pi_cred.circom:82-94` | ENFORCED |
| C6 | EdDSA over Poseidon(D_cred, C, max_height, chainid, allowAgent), 공개 pk_CIA | `pi_cred.circom:69,101-115` | ENFORCED |
| C7 | PPID = Poseidon(uid, s_u, chainid, arid), 같은 신호 | `pi_cred.circom:122-127` | ENFORCED |
| C8 | leaf = Poseidon(3, C) 252비트, 비회원 경로·252비트 비교 | `pi_cred.circom:130-143`, `imt_nonmembership_v2.circom:74-107` | ENFORCED |
| C9 | 태그: r 250비트, c1 = r·B8, K = r·pk_trace, c2 = Poseidon(uid, arid) + Poseidon(K) | `mode3_trace_tag.circom:31-54` | ENFORCED (pk_trace 곡선 검사는 검증자 대조에 위임, 의도) |
| C10 | 공개 입력 순서 23개([14] disc_mask, [15..18] disc_lo, [19..22] disc_hi) | `pi_cred.circom:191-195` | ENFORCED (2026-09-22 갱신) |
| C11 | r = 0 미배제 | `mode3_trace_tag.circom:31-32` | 설계상 미제약 — 서비스·컨트랙트가 검사(S9, K1) |
| C12 | 조건 7: disc_mask Num2Bits(4), lo·hi Num2Bits(64), 비트 k 가 1 이면 lo ≤ a_k ≤ hi (LessEqThan(64)×2), 0 이면 무제약 | `pi_cred.circom:74-77,173-182` | ENFORCED (2026-09-22 추가) |

### 6.2 지갑 (정리 7·8·12의 가정)

| ID | 검사 | 위치 | 판정 |
|---|---|---|---|
| W1 | r ≠ 0, r < 2^250 | `lib/mode3_trace.js:39-46,74` | ENFORCED |
| W2 | s_u, r_u, blind < 2^250; 속성 < 2^64 (`ATTR_MAX`) | `lib/mode3_credential.js:17,73`, `lib/mode3_wallet.js:26,49` | ENFORCED (2026-09-22 갱신) |
| W3 | 세션키 로그인마다 새로, sk_i 미노출 | `mode3_wallet_agent.js:82,94,120` | ENFORCED |
| W4 | σ = EIP-191(r_s), 요청 서명 `${r_s}:${body}` | `lib/mode3_wallet.js:133,138-139` | ENFORCED |
| W5 | 증명 캐시 (root, r_s, mask, lo, hi), root 나 공개 술어가 바뀌면 재증명 | `lib/mode3_wallet.js:83` (`disclosureKey`), `mode3_wallet_agent.js` `/wallet/tx` | ENFORCED (2026-09-22 갱신) |
| W6 | cert_s 검증 + Origin 헤더 = 인증서 오리진 | `mode3_wallet_agent.js:167-170`, `lib/mode3_rp_cert.js:34-38` | ENFORCED |
| W7 | /wallet/tx 같은 오리진만, raw digest 서명(다이제스트에 disc_mask·disc_lo·disc_hi 9워드 포함), 재사용·릴레이 | `mode3_wallet_agent.js:379-390`, `lib/mode3_onchain.js:66-73` (`payloadDigest`) | ENFORCED (2026-09-22 갱신) |
| W8 | 상태 파일 0600, 비밀 로그 없음 | `lib/mode3_state.js:13-16` | ENFORCED |
| W9 | `disclose` 검사: 길이 4, 0 ≤ lo ≤ hi < 2^64 (`bad_disclosure`), lo ≤ a_k ≤ hi 를 증명 전에 확인(`disclosure_unsatisfiable`) | `lib/mode3_wallet.js:68-78` (`normalizeDisclosure`) | ENFORCED (2026-09-22 추가) |
| W10 | 속성은 AA 에서만 받음: 등록 응답 `attrs` 저장, `bad_proof` 면 `/cia/attrs` 로 재동기화 뒤 1회 재시도, `/wallet/attrs/sync`; 사용자 입력 경로(`/wallet/attrs`) 삭제 | `mode3_wallet_agent.js:12,352` | ENFORCED (2026-09-22 추가) |

### 6.3 서비스 (정리 7·9·12의 가정)

| ID | 검사 | 위치 | 판정 |
|---|---|---|---|
| S1 | r_s 250비트 균일, TTL 120 s, 검증 전 소비 | `mode3_rp.js:28,149-161,193` | ENFORCED |
| S2 | head 먼저·root 그 블록에 고정, 600 s 신선도, fail-closed | `lib/mode3_rp.js:26-42` | ENFORCED |
| S3–S10 | root 일치(N=1), head ≤ max_height ≤ head + L, chainid, pk_CIA 고정, arid·pk_trace, allowAgent ≤ 1, c1 ≠ O, Groth16; 공개 입력 길이 23, disc_mask < 16 (`bad_disclosure`), [14..22] 를 세션·로그인 로그에 `disclosure` 로 기록(로그인 정책은 없음) | `lib/mode3_rp.js:47-79`, `mode3_rp.js:239-244` | ENFORCED (2026-09-22 갱신) |
| S11 | σ는 서버의 r_s 위, 공개 입력에서 읽지 않음 | `lib/mode3_rp.js:69-70`, `mode3_rp.js:194` | ENFORCED |
| S12 | 재검증: 살아 있는 세션, PPID·pk_i 일치 | `mode3_rp.js:211-215` | ENFORCED |
| S13 | 요청: 세션·만료(head)·root·서명 | `mode3_rp.js:226-233` | ENFORCED |
| S14 | 로그인 로그 0600, 조회는 r_s 축약 | `mode3_rp.js:55,165,198,296-297` | ENFORCED |
| S15 | 등록 파일 0600, sk_service·x_svc 미노출 | `mode3_rp.js:59,69,88,110,174` | ENFORCED |
| S16 | 개봉 메시지·D_svc | `mode3_rp.js:279-283`, `lib/mode3_opening.js:9-15` | ENFORCED |
| S17 | txHash 경로: execute 디코드, 성공 영수증, tx.to 의 Mode3Auth, b행 복원 | `mode3_rp.js:249-264`, `lib/mode3_onchain.js:63-76` | ENFORCED |
| S18 | 팩토리 1회 배포·영속, env 우선 | `mode3_rp.js:103-116` | ENFORCED |

### 6.4 CIA (정리 2·4·9·14의 가정)

| ID | 검사 | 위치 | 판정 |
|---|---|---|---|
| A1 | cm_u 부분군·정규 인코딩, 이중 등록 거절(await 뒤에도) | `cia.js:333-339`, `lib/mode3_issuance.js:107-113` | ENFORCED |
| A2 | 발급 형식·disabled·chainid·max_height < 2^64·sig_u(도메인 V3, max_height 포함)·allowAgent "0"/"1" | `cia.js` `/cia/issue` | ENFORCED (2026-09-18 갱신) |
| A3 | π_issue(V2, 도메인 `MODE3USERCRED2`): 점 검사, z < ℓ, 챌린지 재계산(uid·a 포함), Y = C − uid·G_UID − Σa_k·G_ATTR 로 두 등식; a 는 **AA 기록** `acct.attrs` 에서 — 요청 본문의 attrs 는 받지 않음 | `lib/mode3_issuance.js:19,80,106-117`, `cia.js:375-376` | ENFORCED (2026-09-22 갱신) |
| A4 | 체인별 생존 확인(헤드 조회), 503 fail-closed, disabled 재확인 | `cia.js` `chainAlive` | ENFORCED |
| A5 | max_height 는 요청 값 그대로 서명(양자화 ceil((head+300)/100)·100 은 지갑 `chooseMaxHeight`); 검증자 상한 L=400 — 서비스 `bad_expiry`, 컨트랙트 `TooFarExpiry` | `lib/mode3_wallet.js`, `lib/mode3_rp.js`, `contracts/Mode3Wallet.sol` | ENFORCED (2026-09-18 갱신) |
| A6 | C를 C_pt에서 CIA가 계산 | `cia.js:383,388` | ENFORCED |
| A7 | 기록 키 (leaf, chainid), 헤드 못 읽으면 보존 | `cia.js:229-238,397-400` | ENFORCED |
| A8 | 폐기: 자기 기록의 리프만 / 계정 전체 + disabled | `cia.js:416-447` | ENFORCED |
| A9 | 게시: 대조 → 서명(DOMAIN, 주소, root, epoch, keccak(leaves)) → 접두사만 제거, publishing 가드 | `cia.js:460-495`, `lib/mode3_log.js:26-36` | ENFORCED |
| A10 | 하트비트 조건·epoch+1·빈 리프 | `cia.js:501-510` | ENFORCED |
| A11 | 개봉 요청 검사 11단계, 중복 (arid, c1) | `cia.js:548-578` | ENFORCED (D_svc 검사가 더 앞에 옴 — 더 엄격) |
| A12 | 승인: K = D_svc + x_AA·c1, 역조회, x_AA 미노출 | `cia.js:586-601`, `lib/mode3_trace.js:83-99` | ENFORCED |
| A13 | 결과 조회에 서비스 서명·신선도 | `cia.js:610-617` | ENFORCED |
| A14 | 관리자 시크릿 timing-safe, 미설정 503 | `cia.js:193-202` | ENFORCED |
| A15 | 자기 폐기: 비밀번호 timing-safe, disabled + 리프 | `cia.js:523-537` | ENFORCED |
| A16 | 키·상태 0600, 비밀 미노출 | `cia.js:86,111` | ENFORCED |
| A17 | 속성 기록: `accounts[uid].attrs`(상태 v7, 마이그레이션 시 데모 값 채우고 활성 자격증명 물림), 등록 응답에 `attrs`, `POST /cia/attrs` (sig_u 검증 — **nonce 신선도는 검사하지 않음**, 데모 한계 M3), 관리자 `POST /cia/accounts/:uid/attrs` → 기록 갱신 + `retireActiveCred`(옛 리프 pending) | `cia.js:152,236,352-354,403-428` | ENFORCED (신선도만 PARTIAL, 2026-09-22 추가) |

### 6.5 컨트랙트 (정리 8·9, 명제 16–18의 가정)

| ID | 검사 | 위치 | 판정 |
|---|---|---|---|
| K1 | execute 검사 순서 12단계(§5.3 + BadTag + TooFarExpiry) + ⑤′ pub[14] < 16 (`BadDisclosure`); σ 다이제스트 = keccak(abi.encode(chainid, wallet, to, value, data, nonce, pub[14], pub[15..18], pub[19..22])) | `contracts/Mode3Wallet.sol:84-86,128` | ENFORCED (2026-09-22 갱신) |
| K2 | 서명 길이 65, low-s, v ∈ {27,28}, address(0) 거절 | `Mode3Wallet.sol:80,111-118` | ENFORCED |
| K3 | nonce++ 를 외부 호출 전에; 다른 가변 상태 없음 | `Mode3Wallet.sol:87-88` | ENFORCED |
| K4 | CREATE2 salt = PPID, initCode에 인자 9개, 멱등 배포, 주소 대조 | `contracts/Mode3WalletFactory.sol:28-48` | ENFORCED |
| K5 | epoch 증가, digest(DOMAIN, 주소, root, epoch, keccak(leaves)) + EIP-191, low-s·v, lastPublishedBlock, 무허가 제출 | `contracts/RevocationLog.sol:37,42-75` | ENFORCED |
| K6 | 검증자 공개 입력 23개(`uint[23]`), 체 범위 검사 | `contracts/PiCredVerifier.sol:125` | ENFORCED (2026-09-22 갱신) |
| K7 | viaIR 오버라이드 공유(CREATE2 주소 안정) | `hardhat.config.cjs:12-15,47-54` | ENFORCED |
| K8 | 꼬리 9워드(mask, lo[4], hi[4] = 288바이트)를 내부 호출 데이터 끝에 mask 값과 무관하게 붙임; 예외는 payload.data 비어 있고 mask = 0 (receive-only 송금); mask ≠ 0 이면 `Disclosure` 이벤트 | `Mode3Wallet.sol:110-118` | ENFORCED (2026-09-22 추가) |
| K9 | `Mode3WalletFactory.isWallet` — deploy 가 기록, 대상이 msg.sender 확인에 씀 | `contracts/Mode3WalletFactory.sol:20,47,52` | ENFORCED (2026-09-22 추가) |
| K10 | 데모 대상 `AttrGate.claim`: isWallet(msg.sender), calldata ≥ 4 + 288, 끝 9워드 읽기, mask & 3 == 3, lo[1] = hi[1] = countryEq, hi[0] ≤ birthYearMax, 계정당 1회 | `contracts/AttrGate.sol:20-47` | ENFORCED (2026-09-22 추가) |

### 6.6 페이지

| ID | 검사 | 위치 | 판정 |
|---|---|---|---|
| P1 | 서버 자유 문자열을 innerHTML에 넣지 않음 | `mode3/cia_admin.html:66-114` 등 | PARTIAL — `mode3/rp.html:154`가 세션 요청의 `echo`(요청 본문 그대로)를 innerHTML에 넣음(self-XSS) |
| P2 | 트랜잭션 폼은 지갑 페이지만 | `mode3/wallet.html:39-49`, `mode3/rp.html:43` | ENFORCED |

### 6.7 점검에서 새로 나온 것

1. **[Important] 비정규 10진 공개 입력이 개봉을 영구 불가로 만든다(추적성 우회).** 서비스 검증기는 공개 입력을 `BigInt()`로 정규화해 비교하고, snarkjs는 앞자리 0이 붙은 10진 문자열도 받아들인다. 변조된 지갑이 `publicSignals[1] = "0<arid>"` 같은 값을 내면 로그인은 통과·기록되지만, 개봉 때 서비스는 정규화한 값으로 서명하고 CIA는 원문 문자열로 메시지를 재구성·비교하므로 `bad_signature`/`wrong_arid`로 항상 실패한다. 정리 14(추적 가능성)의 "Vf 통과 ⇒ Open 성공" 전제가 구현에서 깨지는 유일한 지점이다. 온체인 경로는 정규화하므로 무관. 수정: `verifyLogin`이 정규화한 문자열을 돌려주고 로그에 그것을 기록(또는 비정규 입력 거절). (`lib/mode3_rp.js:49`, `mode3_rp.js:200,278-282`, `cia.js:559-561`)
2. [Minor] CIA 개봉 요청에 c1 ≠ O 검사가 없다(서비스·컨트랙트에는 있음). 심층 방어 공백. (`cia.js:548-578`)
3. [Minor] 지갑이 서비스가 준 factoryAddress를 검증 없이 쓴다. 스펙 §8의 "그 지갑도 같은 π 규칙을 따른다"는 논거는 틀렸다 — 팩토리는 임의 코드다. 손실은 지갑 UI가 정한 payload·value로 한정. `FACTORY_ABI`의 `arid()/log()/verifier()`로 대조하면 닫힌다. (`mode3_wallet_agent.js:150-153,292-295`)
4. [Minor] `POST /api/mode3/open`은 무인증(데모). 개봉 게이트는 CIA 운영자 승인이다 — 형식 문서가 이것을 승인 게이트로 읽지 않도록 명시.
5. [Minor] allowAgent 동의를 서비스 페이지에서 받는다. 악의적 서비스가 "사용자가 허용했다"를 지갑 없이 주장할 수 있다(부인 방지 공백). 스펙 §7의 결정과 일치하지만 문서에 적어야 한다.
6. [Minor] `isFreshTs`가 미래 ±300 s를 허용하고, 개봉 결과 조회의 ts·sig가 GET 쿼리에 실려 URL 로그로 300 s 재생 가능(현재는 서비스가 서버 측에서 프록시).
7. [Minor] 무한 성장: 발급 기록은 폐기 경로에서만 정리, 서비스 logins/sessions 맵·로그인 로그·지갑 ProofCache는 비우지 않음.
8. [Minor] `POST /cia/register_rp`가 무인증이라 오리진마다 상태를 만든다(루프백 바인딩만이 완화).
9. [Minor] `/api/mode3/request`가 r_s를 정규화하지 않아 login/revalidate와 키 형식이 다르다(비정규 키는 미스만).
10. [Minor] `cia.js:533` 주석 "만료 판정이 벽시계라"가 V4와 어긋남(코드는 맞음).

**형식 결과와의 대응과 조치(커밋 "fix(mode3): 보안 점검 반영", 2026-09-18).** 1번(Important)은 정리 14의 전제 위반이므로 고쳤다: 서비스 검증기가 정규 10진 공개 입력을 돌려주고 로그·개봉에 그것을 쓰며, CIA 도 개봉 요청의 공개 입력을 정규화한다(회귀 테스트: 서비스·CIA 각 1건). 2번(CIA c1 ≠ O)·3번(지갑의 팩토리 대조: arid·로그 주소·pk_CIA·pk_trace 를 온체인 getter 로 대조, 불일치·비컨트랙트면 bad_factory)·9번(r_s 정규화)·10번(주석)과 P1(echo 를 textContent 로)도 같은 커밋에서 고쳤다. 4·5번은 스펙 §8 에 한계로 적었고(개봉 API 무인증, allowAgent 동의 출처), 6·7·8번은 데모 범위의 운영 사항으로 남긴다. 남은 검증자 측 공백은 검증자 컨트랙트 주소를 지갑이 대조하지 못한다는 것뿐이며, 팩토리의 다른 인자가 전부 맞아도 검증자가 가짜면 폐기·만료가 무력화될 수 있다 — 검증자 주소를 AA 가 인증서에 싣거나 지갑이 vkey 해시와 대조하는 것이 후속이다. 나머지 정리(1–13, 15–18)의 가정은 모두 ENFORCED 로 확인됐다.


## 7. 2026-09-18 갱신 — 만료를 지갑이 정한다

커밋 58e73ea 부터 max_height 는 지갑이 고르고(⌈(head+T)/G⌉·G, T=300, G=100) sig_u 가 그 값을 덮으며(도메인 V3), AA 는 값이 2^64 미만인지만 보고 그대로 서명한다. 검증자는 head ≤ max_height ≤ head + L(L=400)을 강제한다(서비스 bad_expiry, 컨트랙트 TooFarExpiry). 정리들에 미치는 영향: (i) 정리 2·6(위조·연결 불가)은 서명 메시지에 인자가 하나 더 들어갈 뿐이라 그대로다. (ii) 정리 9·9′(폐기 효력)의 "만료가 노출을 제한한다"는 상한 L 로 바뀐다 — 지갑이 고를 수 있는 최장 노출은 L 블록이고, 없으면 2^64−1 로 영구 성명이 되므로 L 은 검증자에게 필수다. (iii) 조건부 프라이버시(별도 문서)의 익명 집합 n 은 이제 지갑의 양자화가 만든다 — 그리드를 무시한 지갑은 자기 발급 시각만 드러낸다. (iv) sig_u 가 max_height 를 덮지 않으면 중간자가 요청의 만료를 바꿔 AA 서명을 받을 수 있으므로 서명 범위 확장은 필수다. 대응표의 A2·A4·A5·S3·K1 행을 이에 맞춰 고쳤다.

## 8. 2026-09-22 갱신 — 속성 선택 공개(V6)

설계 `docs/superpowers/specs/2026-09-22-mode3-selective-disclosure-design.md`, 실측 `results/mode3_disclosure_bench_20260922.md`. 이 문서의 표기는 논문 v3·v4 와 같은 단일 커밋 C_pt / π_issue 이며, 코드의 자격증명 이중 구조(C_u/C_s, 2026-09-21)는 여기서 모델하지 않는다 — 코드의 π_u V2 가 이 문서의 π_issue V2 다. 슬롯 번호는 이 문서·논문의 a₁..a₄(코드는 a₀..a₃).

**무엇이 바뀌었나.**
1. **속성 출처.** a 는 AA 계정 기록(관리자만 변경)이고 [0, 2^64) 정수다. 등록 응답과 `/cia/attrs` 로 지갑이 받는다. π_issue V2 는 uid·a 를 공개 입력으로 두고 AA 가 uid·G₁ + Σa_k·G_{4+k} 를 뺀 나머지에 대한 PoK 만 받으므로, σ_AA 는 "C_pt 의 속성 = AA 기록"을 보증한다(정리 2 의 논증에 그대로 편입, §4.2).
2. **회로 조건 7.** 공개 입력 23개(14 + disc_mask + disc_lo[4] + disc_hi[4]). mask 비트가 1 인 슬롯만 lo ≤ a_k ≤ hi 를 강제(등식은 lo = hi), 0 인 슬롯은 무제약·lo = hi = 0. 로그인은 mask = 0. 제약 26,601 → 25,369(속성 250 → 64비트 절감이 술어 추가분 ≈ 1.1k 를 상쇄).
3. **온체인.** σ_tx 다이제스트가 9워드를 덮는다(정리 8, §4.8). `execute` 는 π 검증 뒤 내부 호출 데이터 끝에 9워드를 항상 붙인다 — "mask ≠ 0 일 때만"은 사용자가 payload.data 안에 위조 꼬리를 넣고 캐시된 mask = 0 π 를 재사용하는 공격(리뷰에서 PoC)으로 기각됐다. 예외: payload.data 가 비고 mask = 0 이면 붙이지 않는다(receive-only 송금; 위조 꼬리는 data 를 비울 수 없으므로 방어는 유지). 대상은 `factory.isWallet(msg.sender)` 와 calldata 끝 288바이트로 읽는다(데모 `AttrGate`: a₂ = 410 ∧ a₁ ≤ 2007).
4. **G5 재정의**(§4.5). "AA 가 값을 모른다" → "AA 가 사용처를 모른다"(정리 5′: 1/n′, n′ = 창 ∩ 술어 만족 집합) + "검증자는 비공개 슬롯을 모른다"(정리 5: hiding + ZK).
5. **바뀌지 않는 것.** G1·G2·G3·G6·G7·G8·G9·G10 의 정리는 서명·다이제스트에 인자가 늘어난 것 외에 그대로다. 두 서비스에 같은 값을 공개하면 그 값으로 이어질 수 있으나 이는 사용자가 고른 공개의 결과이고 PPID 자체(G3)는 독립이다.

**한계 (논문 §IX 에 적은 것).**
- (a) **신뢰 설정.** Groth16 phase-2 가 고정 엔트로피의 단일 기여(데모). 그 기계의 운영자는 증명을 위조할 수 있고, 배포에는 다자 의식이 필요하다. (A3) 의 전제가 프로토타입에서는 성립하지 않는다.
- (b) **개봉 담합·조각 유실.** AA 와 서비스가 절차 밖에서 조각을 합치면 운영자 승인 없이 그 서비스의 모든 태그가 열린다; 어느 한 조각을 잃으면 그 서비스의 과거 태그는 영구히 닫힌다(§5, 조건부 프라이버시 §5).
- (c) **폐기 시각 상관.** 계정 폐기는 미만료 성명의 리프를 한 게시에 넣으므로 그 사용자의 모든 서비스 세션이 같은 root 전이에서 끝난다. 두 서비스가 "어느 게시에서 어느 세션이 죽었나"를 비교하면 이을 수 있고, 익명 집합 = 그 게시의 리프 수. 완화는 게시 창을 넓혀 배치하는 것 — 미구현(프로토타입은 명령으로 게시).
- (d) **공개 값에 의한 익명 집합 축소.** 공개 값은 체인에 영구히 남고 PPID·서비스에 묶인다. AA 측 익명 집합은 (chainid, allowAgent, 양자화 max_height) 창 안에서 술어를 만족하는 사용자 집합으로 줄어든다(정리 5′); 정확한 값 공개가 구간 공개보다 더 줄인다.
- (e) **데모 API.** `/cia/attrs` 는 sig_u 만 검사하고 nonce 신선도를 검사하지 않는다(재생하면 같은 속성을 다시 읽음, M3). `/api/mode3/sessions`·`/api/mode3/logins` 는 인증 없는 데모 API 이고 이제 `disclosure` 까지 노출한다(M4).

대응표 갱신: C4·C10·C12, W2·W5·W7·W9·W10, S3–S10, A3·A17, K1·K6·K8·K9·K10. 실측(N=10 중앙값): pi_cred 25,369 제약, prove 809 ms, verify 10.7 ms; π_issue V2 79.7/98.7 ms; 로그인 1,054 ms; `/wallet/tx` mask=0 151 ms, mask=3(새 π) 1,000 ms; `execute` gas mask=0 402,130, 첫 tx 419,262, mask=3 + `AttrGate.claim` 444,509(+62,809 는 공개 입력 9개 추가분, +42,379 는 공개 경로). receive-only 예외는 실측 뒤에 추가됐다(수십 gas 차이 예상, 재실측 안 함).

## 9. 2026-09-23 갱신 — 자격증명 이중 구조(C_u/C_s), 오프체인 root 나이, 지갑 트리 캐시

구현 기준 feat/mode3-cia @ 48fdb5c. 이 절은 §1·§2·§4 의 표기와 정리를 이중 구조(2026-09-21 설계)와 2026-09-23 점검 결정에 맞춰 고친다. 위 절의 본문은 그대로 두고 여기서 덮어쓴다(§7·§8 과 같은 방식).

### 9.1 표기 (§1 "성명"·"관계 R"·"폐기 트리" 대체)

- **사용자 자격증명(사용자당 하나).** C_u = uid·G₁ + s_u·G₃ + Σ_k a_k·G_{4+k} + blind_u·H₀, Cf_u = H(C_u.x, C_u.y). 지갑이 (uid, C_u) 와 π_u 를 한 번 보내고, AA 는 Cf_u 를 **스스로** 계산해 계정의 활성 자격증명으로 기록한다(C_u 의 열림은 기록하지 않는다).
- **세션 커밋(로그인마다).** C_s = arid·G₂ + pk_i·G₄ + blind_s·H₀, Cf_s = H(C_s.x, C_s.y). 발급 요청은 (uid, Cf_u, C_s, chainid, allowAgent, max_height) 와 sig_u = Sign_{sk_u}(H(D_req, Cf_u, C_s.x, C_s.y, chainid, allowAgent, max_height)) 뿐이며 **ZKP 가 없다**.
- **성명.** σ_AA = Sign_AA(H(D_cred, Cf_u, Cf_s, max_height, chainid, allowAgent)). AA 는 발급 기록을 남기지 않는다(활성 Cf_u 와 그 리프만 사용자별로 보관).
- **관계 R.** 공개 pub 은 §8 과 같이 23개. 증인 w = (uid, s_u, blind_u, blind_s, a, σ_AA, r, path). 조건 1 은 위 메시지에 대한 서명 검증, 조건 2 는 C_u 를 증인으로·C_s 를 **공개 arid·pk_i** 로 재계산해 Cf_u·Cf_s 를 얻는 것, 조건 4 는 leaf(Cf_u) = mask₂₅₂(H(4, Cf_u)) ∉ Tree(root). 나머지 조건은 그대로.
- **폐기 트리.** 리프 = mask₂₅₂(H(4, Cf_u)), 자격증명당 하나(태그 3 → 4 로 도메인 분리 — 옛 리프와 겹치지 않는다). 계정 폐기와 속성 변경(자격증명 은퇴)이 같은 리프 하나를 넣는다.

### 9.2 가정 (A7) 대체

**(A7′) π_u**: 관계 PoK{ (s_u, blind_u, r_u) : C_u − uid·G₁ − Σ a_k·G_{4+k} = s_u·G₃ + blind_u·H₀ ∧ cm_u = s_u·G₃ + r_u·H₀ } 에 대한 특수 건전성과 특수 HVZK(Fiat–Shamir 아래 RO). 공개 입력은 (uid, a, C_u, cm_u) 이고 uid·a 는 AA 가 자기 기록에서 넣는다. 세션 발급에는 (A7′) 이 쓰이지 않고 (A5) 의 sig_u 만 쓰인다.

### 9.3 정리에 미치는 영향

- **정리 2 (G2 불변성).** 조건 2 가 C_u 를 어떤 s_u 로 열고, (A7′) 의 특수 건전성이 그 s_u 가 cm_u 의 s_u 임을 보장한다 — 세션마다가 아니라 자격증명 발급 때 한 번. σ_AA 가 Cf_u 를 덮으므로 (A5) 아래 AA 가 서명한 Cf_u 는 π_u 를 통과한 C_u 의 것뿐이고, (A2) 의 충돌 저항으로 Cf_u 가 같은 다른 C_u 는 없다. 결론(사용자당 하나의 s_u, 따라서 (chainid, arid) 당 하나의 주소)은 그대로다. 세션 발급이 증명을 요구하지 않아도 되는 이유가 바로 이것이다: C_s 의 내용(arid, pk_i)은 조건 2 가 공개 입력에서 재계산하므로 AA 가 확인할 것이 없다.
- **정리 4·5 (G4·G5).** AA 의 뷰는 자격증명 발급 때 (uid, C_u, π_u) 한 번과, 로그인마다 (uid, Cf_u, C_s, chainid, allowAgent, max_height, sig_u) 다. 서비스 식별자와 세션키는 C_s 안에만 있고(구간 DL 은닉성, Adv^{hide}), π_u 는 서비스가 관여하기 전에 만들어져 arid 에 대해 아무것도 줄 수 없다. C_u 는 사용자별 고정값이지만 어떤 트랜스크립트에도 나타나지 않으므로(조건 2 는 회로 안), 정리 5(G5) 의 "AA 는 값은 알되 사용처는 모른다"는 그대로다. **발급 기록이 없으므로** 조건부 프라이버시 정리 3 의 집합 I 는 AA 가 관측 시점에 스스로 적어야만 존재한다.
- **정리 9 (G8 폐기 건전성).** "폐기된 C" 를 "폐기된 Cf_u" 로 읽는다: leaf(Cf_u) 가 트리에 있으면 그 사용자의 **모든** 성명이(전부 같은 Cf_u 를 담으므로) 조건 4 를 만족하지 못한다. 상한 ε_KS + q_H²·2^{−252} + negl 은 같다. 따름정리 9′ 에 셋째 상한이 붙는다: **서비스도** root 의 마지막 게시가 MAX_ROOT_AGE 블록보다 오래되면 거절한다(2026-09-23 점검 C-1, 온체인 RootTooOld 와 같은 상한·같은 blockTag). 따라서 AA 가 게시(하트비트)를 멈추면 B_last + MAX_ROOT_AGE 부터 서비스·컨트랙트가 함께 닫힌다 — 게시가 멈춘 root 는 폐기도 멈춘 root 이기 때문이다. 세션 단위 폐기는 없다(AA 가 성명 기록을 갖지 않는다).
- **명제 19 (지갑 트리 캐시는 신뢰 가정이 아니다).** 지갑이 캐시 리프 열 L′ 로 복원하고 마지막 동기화 블록 이후의 Revoked 이벤트를 적용해 root r′ 를 얻은 뒤 같은 블록의 체인 root R 과 대조한다고 하자. 실제 리프 열 L 에 대해 R = root(Tree(L)) 이므로, r′ = R 이면 (A2) 의 충돌 저항 아래 Tree(L′∥Δ) 와 Tree(L) 의 리프 다중집합이 같다(인덱스드 트리는 삽입 순서에 결정적이고 root 는 리프 집합의 함수). 즉 캐시에서 폐기 리프를 지우거나 다른 리프를 넣거나 순서를 바꾸면 r′ ≠ R 이 되어 지갑은 창세기부터 재생하고, 재생한 root 도 다르면 거절한다. 캐시는 가용성(동기화 시간)에만 관여한다. 남는 관측: 델타 적용 중간 root 는 게시된 적 없는 root 라 검증자가 거절하므로(정리 9 의 N=1 규칙), 지갑은 델타를 한 틱에 적용해 동시 요청이 중간 root 로 증인을 만들지 않게 해야 한다(구현 lib/mode3_rcl_sync.js, 회귀 테스트 있음).

### 9.4 대응표 갱신 (§6 의 행을 이 절이 덮는다)

| 행 | 갱신 내용 | 구현 |
|---|---|---|
| A2 | leaf = mask₂₅₂(H(4, Cf_u)); Cf = H(C.x, C.y) 를 AA 가 스스로 계산 | `lib/mode3_revocation.js`, `lib/mode3_credential.js compressPoint`, `cia.js /cia/user_cred·/cia/issue` |
| A4 | C_u·C_s 두 Pedersen 커밋, blind_u·blind_s 250비트 | `circuits/lib/mode3_commit.circom`, `lib/mode3_credential.js` |
| A5 | σ_AA 메시지 (D_cred, Cf_u, Cf_s, …); sig_u 메시지 (D_req, Cf_u, C_s.x, C_s.y, chainid, allowAgent, max_height) | `lib/mode3_credential.js credMessageV5`, `lib/mode3_issuance.js issueRequestMessageV4` |
| A7′ | π_u 한 번, 세션 발급 무증명; AA 검사 순서 형식→범위→계정→chainid→sig_u→활성 Cf_u→C_s 부분군→체인 생존→재확인→서명 | `cia.js /cia/issue` |
| A8 | 계정 폐기·속성 변경 = 활성 Cf_u 리프 하나 + disabled | `cia.js retireActiveCred` |
| S3 | 서비스 검사에 b′(root 나이 ≤ MAX_ROOT_AGE) 추가, 로그인·재검증·세션 요청 모두 | `lib/mode3_rp.js verifyLogin`, `mode3_rp.js /api/mode3/request` |
| K1 | 검증자 상한(maxRootAge·maxLifetime)은 팩토리 immutable 이 정본 — RP 는 env 대신 팩토리 값을 채택하고 조회 실패는 fail-closed | `mode3_rp.js adoptFactoryConstants` |
| 신규 W1 | 지갑 트리 캐시: 복원·델타 뒤 root 대조, 불일치 시 전체 재생 1회, 델타 원자 적용 | `lib/mode3_rcl_sync.js`, `tests/test_mode3_rcl_sync.mjs` |
