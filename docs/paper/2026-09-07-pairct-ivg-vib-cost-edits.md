# §IV-G / §VI-B 폐기 비용 서술 수정 제안

2026-09-07. 대상 원고: `documents/PairCT_research_article_20260706_092133_with_figures_final47.docx`.

근거: 상위 경로 재계산 비용 측정(`lib/imt_v3.js`의 `computeTopPath`). 코드는 수정하지 않았다.

---

## 수정 1 — §IV-G, "ordinary calldata" 문장 교체

### 현재

> A proof is then bound only to its own subtree root, so a revocation in any other
> subtree leaves it valid and only the upper-level sibling hashes—ordinary calldata—have
> to be refreshed.

### 제안

> A proof is then bound only to its own subtree root, so a revocation in any other
> subtree leaves the argument valid; what must be refreshed is the upper-level sibling
> path, which the contract recomputes from calldata rather than inside the relation. The
> two are not, however, equally rare. An argument is regenerated only when the prover's
> own subtree changes, whereas the sibling path must be refreshed whenever any revocation
> is published, because every publication moves the top root. The split therefore trades a
> costly and infrequent event for a cheaper and frequent one, and Section VI-B reports
> where that trade lands in our prototype.

### 이유

"only ... ordinary calldata"는 갱신 비용이 사라졌다는 함의를 준다. 측정값은 그렇지 않다.
구조적 주장(타인 폐기에 증명이 살아남는다)은 그대로 유지하되, 무엇과 무엇을 맞바꿨는지를
명시한다.

---

## 수정 2 — §VI-B 끝에 문단 추가

> Revocation-path costs divide into two terms with different frequencies. Regenerating
> pi_pk_i costs 510.30 ms and is required only when the prover's own subtree changes;
> refreshing the upper-tree sibling path requires no proving but one traversal of the upper
> tree, measured at approximately 69 ms for the session and account layers together (4,096
> and 256 shards respectively). Which term dominates is a deployment question rather than a
> property of the construction. Taking 10^8 users authenticating once per day, a 0.01%
> session-revocation rate, and the shard parameters of Section IV-G, roughly 417 session
> leaves are live at any time across 2,656 live session shards, so a given credential
> expects 0.16 subtree changes over its lifetime, or about 80 ms of proof regeneration; if a
> root is published every block and six transactions are submitted per credential, the
> path-refresh term reaches about 414 ms. The refresh cost reflects how the prototype
> traverses the upper tree — densely, hashing 2^d − 1 nodes — rather than the split itself:
> a traversal that skips empty subtrees is bounded by the number of non-empty subtrees and
> is nearly independent of the shard count. We report the prototype's measured behavior and
> leave that optimization to future work.

---

## 반영 전 확인할 것

1. **69 ms는 아직 논문 등급 수치가 아니다.** 순회 함수만 떼어낸 warm 마이크로벤치(n=30,
   같은 호스트)이고, §VI-B의 다른 수치가 따르는 프로토콜(데모 스택 정지 → n=10 →
   `results/` CSV 기록)을 거치지 않았다. 제출 전 그 방식으로 재측정하고 CSV 파일명을
   문단에 넣을 것.

2. **414 ms는 "매 블록 게시" 가정에 달려 있다.** 게시 주기가 길면 작아지고, 설계 문서 §6의
   폐기 지연 목표(K=2~3블록)를 지킬수록 커진다. 레지스트리가 V4로 전환된 흔적이 있으므로
   게시 경로를 확인한 뒤 실제 주기로 문장을 바꿀 것.

## 손댈 필요 없는 곳

§I 서론의 "splits the accumulator so that a proof binds only to its own subtree, which keeps
one user's revocation from invalidating everyone else's proofs"는 그대로 둔다. 여기서 말하는
것은 **proofs**이고, 그 주장은 측정과 무관하게 성립한다. Abstract도 마찬가지다.

---

## 측정 기록 (참고)

`computeTopPath`, 밀집 구현, 비어 있지 않은 샤드 417개 기준:

| 샤드 수 | 상위 깊이 | ms/호출 |
|---|---|---|
| 256 | 8 | 4.9 |
| 1,024 | 10 | 15.3 |
| 4,096 | 12 | 74.4 |
| 16,384 | 14 | 311.4 |
| 65,536 | 16 | 1,354.3 |

- 세션(4,096) + 계정(256) 합계: 약 69 ms
- 비용 분해: keccak 94%, BigInt→bytes32 변환 6%
- `keccak256(concat(...))` 단건 12.6 μs (ethers, hex 문자열 왕복 오버헤드)

---

# Abstract 재작성안 (v1 — 미확정)

현행 252단어/10문장 → 250단어/9문장.

> For many Web3 applications, wallet login is only the entry point: a service must still
> recognize returning users and support accountability when misuse is reported. Reusable
> wallet addresses make users linkable across services and give no controlled path to the
> account behind disputed activity, while privacy-preserving SSO systems address
> identity-provider tracking only in conventional Web settings. We present PairCT, a
> privacy-preserving Web3 service-authentication protocol that uses signed login statements
> from an identity provider (IdP) while hiding the accessed service from the IdP during
> ordinary authentication. A service recognizes returning users without learning the user's
> IdP-side identifier; the signed statement, wallet session key, service challenge,
> expiration metadata, and zero-knowledge consistency checks are bound into one transcript.
> If a login is disputed and opening is authorized, joining retained service and IdP records
> identifies the account behind it, a conditional traceability that grants the IdP no global
> service-discovery capability. Statements must also be revocable before they expire, yet
> the on-chain verifier is a contract that can hold neither a revocation list nor a
> per-transaction query. PairCT therefore proves non-membership in the revocation set inside
> the same zero-knowledge relation and splits the accumulator so each proof binds only to
> its own subtree: one user's revocation leaves every other proof intact, and a non-revoked
> user reveals no per-credential identifier. We formalize seven properties spanning
> IdP-side RP hiding, cross-service unlinkability, conditional privacy with authorized
> opening, and revocation soundness. A prototype realizes the full flow, and one login's
> proving work measures 913 ms in the warm state.

## 해결한 것

| 진단 | 처리 |
|---|---|
| 왜 어려운가가 없음 | 문장 6 신설 — 온체인 검증자가 컨트랙트라 목록도 조회도 불가 |
| 샤딩이 빠짐 | 문장 7에 accumulator split 추가, §I 기여 문장과 표현 일치 |
| 마무리가 약함 | "demonstrates ... end to end" → 결과로 끝맺음 |
| 속성 나열 3회 반복 | 7개 열거 24단어 → 18단어 |
| 문장 1–2 중복 | 통합, "recognize returning users" 중복 정리 |
| 제목 정합 | "conditional traceability" 삽입 |

"Issued statements **can also be** withdrawn" → "Statements **must also be** revocable"로
바꿔 §I의 "a contribution in its own right"와 격을 맞췄다.

## 미해결 — 확정 전 결정할 것

1. **913 ms가 §VI-D와 충돌한다(가장 중요).** §VI-D 마지막 문장이 구현 결과를
   "prototype validation of the proposed security design, **not as an optimization claim**"
   으로 못 박는다. 초록에 성능 수치를 헤드라인으로 올리면 그 선언과 어긋난다.
   - (i) 숫자를 빼고 구조적 결과로 끝맺는다 — 논문 현 상태와 정합
   - (ii) §VI-D 입장을 바꿔 성능 주장을 한다 — 초록보다 큰 편집 결정
   - 참고: 넣고 싶었던 회로 감소(19,251 → 13,905, −27.8%)는 **논문 본문에 없다**
     (`19,251`·`27.8` 검색 0건, 설계 문서에만 존재). 쓰려면 §VI-B 보강이 선행돼야 한다.
2. **문장 7이 42단어** — 현행 최장(40단어)보다 길다. ①②를 혼자 지고 있어 위험.
3. **폐기 비중이 16% → 27%로 증가** — 제목은 Conditional Traceability를 앞세우는데
   초록은 폐기에 더 쓴다. 무게중심 이동이 의도라면 제목·§I도 같이 가야 한다.
4. **"seven properties" + 4개만 열거** — 숫자가 오히려 결손을 드러낸다.
5. **"warm state"가 초록에서 미정의 용어** (1번을 (i)로 풀면 같이 사라진다).
6. **문장 5 "a conditional traceability"** — 관사 오류.
7. **"give no controlled path to the account"** — 원문의 "for identifying"을 빼서
   모호해졌다. 되돌릴 것(+1단어).
8. **PairCT 약어가 여전히 안 풀린다** — 본문에 "pairwise" 9회, 초록 0회. 현행도 같고
   이 안도 안 고쳤다.
