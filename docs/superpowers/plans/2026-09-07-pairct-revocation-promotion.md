# PairCT 폐기 승격 개정 — 실행 계획

> **상태 (2026-09-07): Task 1~3 완료·검증됨.** 산출물
> `documents/2026-09-07_v48_PairCT_research_article.docx` (20 → 21페이지).
> 원본 `...final47.docx`는 무수정. 검증 11항목 전부 통과, 문단 +3 / 문자 +929(예상과 일치).
> 계획서의 "사람이 붙여넣는다" 단계는 실제로는 python-docx 경로로 자동 적용했다 —
> 대상 세 문단이 전부 단일 run 순수 텍스트여서 서식 손실 위험이 없었다.

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> (권장) 또는 `superpowers:executing-plans`로 task 단위 실행. 단계는 `- [ ]` 체크박스다.

**Goal:** 폐기(revocation)를 PairCT 논문에서 조건부 추적 가능성과 동급 기여로 드러낸다 —
§I 기여 문단, §VIII-C 신설, §IX 한 문장.

**Architecture:** 원고는 `.docx`이고 서식 파손 위험 때문에 **직접 편집하지 않는다.** 각 task는
`docs/paper/`에 교체 텍스트를 확정해 두고, 사람이 붙여넣은 뒤 변환·grep으로 검증한다.
"테스트"는 변환된 평문에 대한 문자열 검사와 페이지 수 확인이다.

**Tech Stack:** LibreOffice(`soffice --headless --convert-to txt:Text`), `pdfinfo`, grep, python3

**Spec:** `docs/paper/2026-09-07-pairct-revision-plan.md`

## Global Constraints

- 대상 원고: `documents/PairCT_research_article_20260706_092133_with_figures_final47.docx`
  (기준 시각 2026-09-06 19:50, 20페이지)
- 논문 본문은 **영어**. 계획·주석은 한글.
- **`.docx`를 프로그램으로 수정하지 않는다.** 붙여넣기는 사람이 한다.
- 커밋은 CLAUDE.md에 따라 **명시적 승인 없이 수행하지 않는다.** 각 task 끝의 커밋 단계는 제안이다.
- 확정 결정: 폐기는 **동급 기여**, **제목은 유지**. 정량 주장은 **폐기 구성에 한한 비용 회계**.
- 제외 확정: Freshness vs Autonomy 축, 1회 개입형(zkAA·zk-creds·SSI) taxonomy는 논문에 넣지 않는다.
- **범위 밖(보류):** 작업 ①②③④⑧(69 ms 재측정, §VI-B 비용 회계, §VI-D 카브아웃,
  §IV-G 정정, 초록 v2). `results/shard_axis_collateral_20260907.csv`가 근거를 바꾸는 중이라
  별도 계획으로 뺀다.

## File Structure

| 파일 | 역할 |
|---|---|
| `docs/paper/2026-09-07-pairct-promotion-edits.md` | **신규.** Task 1~3의 교체 텍스트 원본. 사람이 여기서 복사해 붙여넣는다 |
| `documents/...final47.docx` | 사람이 편집. 계획은 손대지 않는다 |
| `docs/paper/2026-09-07-pairct-revision-plan.md` | 스펙. 작업 완료 시 상태만 갱신 |

교체 텍스트를 한 파일에 모으는 이유: 세 곳이 모두 "폐기 승격"이라는 하나의 결정에서 나오므로
같이 바뀌고 같이 검토된다.

---

### Task 1: §I 기여 문단 — 두 축 선언

**Files:**
- Create: `docs/paper/2026-09-07-pairct-promotion-edits.md`
- Modify(사람): `documents/...final47.docx` §I 마지막 문단

**Interfaces:**
- Consumes: 없음
- Produces: §VIII-C(Task 2)와 초록(보류 중)이 이 문단의 "두 축" 표현을 그대로 따른다.
  확정 표현은 `two contributions` / `The first is ...` / `The second is a revocation
  construction for that setting.`

- [x] **Step 1: 현행 문단을 평문으로 뽑아 원본을 고정한다**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct && mkdir -p $S
soffice --headless --convert-to txt:Text --outdir $S \
  documents/PairCT_research_article_20260706_092133_with_figures_final47.docx >/dev/null 2>&1
grep -n 'The main contribution of this paper' $S/*.txt
```

기대: 1건 일치(§I 마지막 문단의 첫 문장).

- [x] **Step 2: 교체 텍스트 파일을 만든다**

`docs/paper/2026-09-07-pairct-promotion-edits.md`를 만들고 아래를 담는다.

교체 대상(현행, 앞 세 문장):

> The main contribution of this paper is a formulation and construction for wallet-bound
> Web3 service authentication with conditional privacy. PairCT shows how service-local
> account continuity, IdP-side accessed-service hiding, session-bound wallet
> authentication, authorized opening, and pre-expiry revocation can be combined in one
> authentication transcript. The revocation construction is a contribution in its own
> right: because the on-chain verifier is a contract that can hold neither a revocation
> list nor a per-transaction query, PairCT proves non-membership in-circuit and splits the
> accumulator so that a proof binds only to its own subtree, which keeps one user's
> revocation from invalidating everyone else's proofs.

교체 텍스트:

> This paper makes two contributions. The first is a formulation and construction for
> wallet-bound Web3 service authentication with conditional privacy: PairCT shows how
> service-local account continuity, IdP-side accessed-service hiding, session-bound wallet
> authentication, and authorized opening combine in one authentication transcript. The
> second is a revocation construction for that setting. Because the on-chain verifier is a
> contract that can hold neither a revocation list nor a per-transaction query, PairCT
> proves non-membership in-circuit; and because a single accumulator would let any one
> revocation invalidate every proof at once, it splits the accumulator so that a proof
> binds only to its own subtree.

이후 두 문장(`The paper also defines ...`, `Finally, a prototype ...`)은 **그대로 둔다.**

바뀐 점: (1) 기여를 둘로 선언 (2) 4항목 나열에서 `and pre-expiry revocation`을 빼
두 번째 축으로 독립 (3) 방어적 표현 `is a contribution in its own right` 삭제
(4) 분할에 자체 because절 부여.

- [x] **Step 3: 사람이 `.docx`에 붙여넣는다**

문단 서식(본문 스타일)이 유지되는지 확인. 붙여넣기 후 저장.

- [x] **Step 4: 검증 — 옛 문장 소멸, 새 문장 존재**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct && rm -f $S/*.txt
soffice --headless --convert-to txt:Text --outdir $S \
  documents/PairCT_research_article_20260706_092133_with_figures_final47.docx >/dev/null 2>&1
echo "옛 문장(0이어야 함):   $(grep -c 'contribution in its own right' $S/*.txt)"
echo "새 문장(1이어야 함):   $(grep -c 'This paper makes two contributions' $S/*.txt)"
echo "나열 잔재(0이어야 함): $(grep -c 'and pre-expiry revocation can be combined' $S/*.txt)"
```

기대: `0 / 1 / 0`.

- [x] **Step 5: 커밋 제안 (승인 후 실행)**

```bash
git add docs/paper/2026-09-07-pairct-promotion-edits.md
git commit -m "docs(paper): §I 기여 문단을 두 축 선언으로 교체하는 안"
```

---

### Task 2: §VIII-C "CREDENTIAL REVOCATION" 신설

**Files:**
- Modify: `docs/paper/2026-09-07-pairct-promotion-edits.md` (Task 1에서 생성)
- Modify(사람): `documents/...final47.docx` §VIII

**Interfaces:**
- Consumes: Task 1의 "두 축" 표현 — §VIII-C도 같은 두 축(비멤버십 / 분할)으로 서술한다
- Produces: 분할 축 서술. §VI-B 비용 회계(작업 ②)가 반영될 때 이 문단 끝에
  `The cost of that split is reported in Section VI-B.`를 덧붙인다

- [x] **Step 1: 현행 BAAR 서술의 위치를 확인한다**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct
grep -n 'BAAR' $S/*.txt | cut -c1-120
```

기대: 1건. §VIII-B의 익명 크레덴셜 문단 **안**에 있다(전용 소절 없음).

- [x] **Step 2: 교체 텍스트를 추가한다**

§VIII-B에서 아래 세 문장을 **삭제**한다:

> Revocation is a separate mechanism (Section IV-G) and is closer to the accumulator-based
> literature. BAAR [20] is the nearest recent design: it also uses a Merkle accumulator
> with an off-chain verifier and an on-chain root, but it proves membership in the set of
> valid credentials and transmits the credential commitment and its witness in the clear at
> every presentation, so a verifier sees a stable per-credential identifier across sessions.
> PairCT instead proves non-membership in a revocation set inside the Groth16 relation, so
> no per-credential identifier leaves the wallet and only a root is public; the cost is that
> the verifier must be given a fresh root, which is why the publication and grace-window
> discipline of Section IV-G exists at all.

§VIII-B 뒤에 새 소절을 만든다:

> **C. CREDENTIAL REVOCATION**
>
> Revocation for privately presented credentials is usually reduced to a set-membership
> question over an accumulator whose digest is published, so that a verifier can check
> status without holding the set. BAAR [20] is the nearest recent design to PairCT: it also
> uses a Merkle accumulator with an off-chain verifier and an on-chain root. It proves
> membership in the set of valid credentials and transmits the credential commitment and
> its witness in the clear at every presentation, so a verifier sees a stable
> per-credential identifier across sessions.
>
> PairCT differs on two axes, and the two are connected. First, it proves non-membership in
> a revocation set inside the Groth16 relation, so no per-credential identifier leaves the
> wallet and only a root is public. Moving the check inside the relation removes that leak,
> but it also changes what a root update costs: an off-chain verifier that receives a
> witness in the clear can simply be given a refreshed witness, whereas an argument that
> binds the root as a public signal must be produced again. Under a single accumulator,
> one revocation would therefore force every other user to re-prove. Second, PairCT
> therefore does not use a single accumulator: it splits the accumulator so that an
> argument binds only to its own subtree, and carries the remaining path as calldata that
> the contract recomputes, which confines re-proving to the users whose own subtree changed.

**주의 — 전방 참조를 넣지 않는다.** 초안에는 `The cost of that split is reported in Section
VI-B.`가 있었으나 §VI-B 비용 회계는 **보류(작업 ②)** 상태라, 지금 넣으면 존재하지 않는 보고를
가리킨다. 그 문장은 ②가 반영될 때 함께 추가한다.

- [x] **Step 3: 사람이 `.docx`에 반영한다**

§VIII-B에서 세 문장 삭제 → §VIII-B 끝에 새 소절 삽입. 소절 제목 스타일이 A/B와 같은지 확인.

- [x] **Step 4: 검증**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct && rm -f $S/*.txt
soffice --headless --convert-to txt:Text --outdir $S \
  documents/PairCT_research_article_20260706_092133_with_figures_final47.docx >/dev/null 2>&1
echo "소절 제목(1이어야 함):     $(grep -c 'C. CREDENTIAL REVOCATION' $S/*.txt)"
echo "분할 축(1이어야 함):       $(grep -c 'does not use a single accumulator' $S/*.txt)"
echo "옛 위치 잔재(0이어야 함):  $(grep -c 'Revocation is a separate mechanism' $S/*.txt)"
echo "옛 대비문 잔재(0이어야 함): $(grep -c 'PairCT instead proves non-membership in a revocation set' $S/*.txt)"
```

기대: `1 / 1 / 0 / 0`. (BAAR 총 등장 횟수는 세지 않는다 — 참고문헌·표에도 나오므로
기대값을 미리 못 박을 수 없다. 옛 문장 두 개가 사라졌는지로 이동을 확인한다.)

- [x] **Step 5: 페이지 수 확인**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct && soffice --headless --convert-to pdf --outdir $S \
  documents/PairCT_research_article_20260706_092133_with_figures_final47.docx >/dev/null 2>&1
pdfinfo $S/*.pdf | awk '/^Pages/{print "페이지: "$2"  (기준 20)"}'
```

21페이지를 넘으면 스펙 §5의 축소 후보(§V 속성별 논증, §VI-B 중복)를 검토한다.

- [x] **Step 6: 커밋 제안 (승인 후 실행)**

```bash
git add docs/paper/2026-09-07-pairct-promotion-edits.md
git commit -m "docs(paper): §VIII-C 폐기 관련연구 소절 신설안"
```

---

### Task 3: §IX — 파라미터가 배포 가정에 의존한다는 한 문장

**Files:**
- Modify: `docs/paper/2026-09-07-pairct-promotion-edits.md`
- Modify(사람): `documents/...final47.docx` §IX

**Interfaces:**
- Consumes: 없음
- Produces: 없음 (독립)

- [x] **Step 1: §IX의 폐기 경계 문장을 찾는다**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct
grep -n 'Revocation adds two boundaries of its own' $S/*.txt | cut -c1-100
```

기대: 1건. 이 문장이 끝나는 자리 뒤에 새 문장을 붙인다.

- [x] **Step 2: 교체 텍스트를 추가한다**

§IX의 `... revocation takes effect only after the grace window rather than immediately.`
바로 뒤에 삽입:

> A third boundary is that the shard parameters of Section IV-G are chosen against an
> assumed revocation rate and publication cadence; a deployment whose rates differ
> substantially will see different subtree occupancy and a different frequency of argument
> regeneration.

`two boundaries` → `three boundaries`로 같이 고친다.

- [x] **Step 3: 사람이 `.docx`에 붙여넣는다**

- [x] **Step 4: 검증**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct && rm -f $S/*.txt
soffice --headless --convert-to txt:Text --outdir $S \
  documents/PairCT_research_article_20260706_092133_with_figures_final47.docx >/dev/null 2>&1
echo "새 문장(1이어야 함):   $(grep -c 'A third boundary is that the shard parameters' $S/*.txt)"
echo "개수 정정(0이어야 함): $(grep -c 'Revocation adds two boundaries' $S/*.txt)"
echo "개수 정정(1이어야 함): $(grep -c 'Revocation adds three boundaries' $S/*.txt)"
```

기대: `1 / 0 / 1`.

- [x] **Step 5: 스펙 상태 갱신**

`docs/paper/2026-09-07-pairct-revision-plan.md` §1 표의 ⑤⑥⑦ 행에 완료 표시를 남긴다.

- [x] **Step 6: 커밋 제안 (승인 후 실행)**

```bash
git add docs/paper/
git commit -m "docs(paper): §IX 파라미터 가정 한계 문장 추가안 + 계획 상태 갱신"
```

---

## 완료 기준

- [ ] §I이 기여를 두 축으로 선언하고 `in its own right`가 사라졌다
- [ ] §VIII에 `C. CREDENTIAL REVOCATION` 소절이 있고 **분할** 축이 서술돼 있다
- [ ] §IX가 세 번째 폐기 경계를 명시한다
- [ ] 페이지 수가 21을 넘지 않는다 (넘으면 축소 후보 검토)
- [ ] 초록은 **손대지 않았다** — 보류된 ①②③④⑧이 끝난 뒤에 쓴다

## 다음 계획으로 넘어가는 것

`results/shard_axis_collateral_20260907.csv`의 의도가 정리되면 비용 회계 계획을 따로 쓴다.
그때 결정할 것: (1) §VI-B에 실을 지갑 측 수치를 무엇으로 할지(고립 순회 69 ms vs
`bench_wallet_revocation_v3.mjs`의 전체 왕복) (2) 계정 폐기율 가정 (3) 세션 층 만료 축의
session-wave 이득(any_rate 0.83 → 0.031)을 논문에 넣을지.
