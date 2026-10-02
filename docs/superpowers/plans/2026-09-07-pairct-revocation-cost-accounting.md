# PairCT 폐기 비용 회계 — 실행 계획

> **상태 (2026-09-08): Task 1·1b·2·3·4·5 완료·검증됨.** 산출물
> `documents/2026-09-08_v49_PairCT_research_article.docx` (21페이지, v48과 동일).
> 검증 20항목 전부 통과. 초록 252단어(원본과 동일), 최장 문장 40→33단어, 정량 수치 없음.
>
> **계획 밖에서 추가한 것 — Task 1b.** `ordinary calldata` 주장이 §IV-G(#112)뿐 아니라
> §VI-C(#223)에도 있었다. §VI-C 쪽을 두면 비용 회계를 넣은 바로 그 절이 자기 모순이 되므로
> 함께 고쳤다. 계획 수립 때 `grep`으로 전수 확인하지 않은 것이 원인이다.

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> 또는 `superpowers:executing-plans`. 단계는 `- [ ]` 체크박스다.

**Goal:** 분할(샤딩)이 무엇을 얻고 무엇을 치르는지를 논문에 정직하게 싣는다 — §VI-B 비용
회계, §VI-D 카브아웃, §IV-G 서술 정정, 초록 v2.

**Architecture:** 선행 시스템 대비 우위는 주장하지 않는다. 비교는 **같은 회로·같은 호스트·
같은 측정 프로토콜로 잰 자기 이전 설계(단일 트리)** 대상이다. `.docx`는 python-docx로
직접 편집한다(대상 문단이 단일 run 순수 텍스트임을 확인한 뒤).

**Tech Stack:** python-docx 1.1.2, LibreOffice(변환·페이지수), grep

**Spec:** `docs/paper/2026-09-07-pairct-revision-plan.md`
**선행 계획:** `docs/superpowers/plans/2026-09-07-pairct-revocation-promotion.md` (⑤⑥⑦ 완료)

## Global Constraints

- **대상 원고는 `documents/2026-09-07_v48_PairCT_research_article.docx`** (21페이지).
  `final47.docx`가 아니다 — v48에 ⑤⑥⑦이 이미 반영돼 있다.
- 산출은 새 파일 `documents/2026-09-08_v49_PairCT_research_article.docx`로 낸다. 입력은 덮어쓰지 않는다.
- 논문 본문은 영어. 계획·주석은 한글.
- 커밋은 명시적 승인 없이 하지 않는다(CLAUDE.md). 각 Task 끝의 커밋 단계는 제안이다.
- **수치는 아래 출처에서만 가져온다.** 새로 계산하지 않는다.

| 수치 | 출처 |
|---|---|
| 19,251 → 13,905 제약 | `results/mode2_sharded_circuit_constraints_20260904.csv` |
| 755.8 → 510.3 ms | `results/mode2_pi_pk_i_proof_20260904.csv`, `..._v3_proof_20260906.csv` |
| 276,709 → 330,079 gas | `results/mode2_execute_gas_20260904.csv`, `mode2_v3_execute_gas_20260906.csv` |
| 갱신 77.0 ms (세션 73.3 / 계정 3.7), 빈 포레스트 66.0 ms | `results/mode2_top_path_refresh_20260907.csv` |
| 트랜잭션당 재증명율 4.67% (Δ=10, uniform, max_height) | `results/shard_axis_collateral_20260907.csv` |
| grace 기본 3블록 | `scripts/deploy_v4_stack.cjs` |

- **축 비교와 용량(척도 C)은 §IV-G에 넣는다(Task 5).** 비용 회계가 아니라 설계 근거이므로
  §VI-B가 아니라 §IV-G가 자리다. 출처: `results/shard_axis_collateral_20260907.csv`,
  `scripts/exp_shard_axis_collateral.mjs`. **측정이 아니라 시뮬레이션이므로 본문에 그렇게 밝힌다.**
- **초록에는 정량 수치를 넣지 않는다.** 구조적 결과로 끝맺는다(Task 4).
- **계정 폐기율 가정은 여전히 미해결이므로 계정 층 무효화 빈도는 주장하지 않는다.**
  §VI-B는 세션 층 시나리오에서만 빈도를 말한다.

## File Structure

| 파일 | 역할 |
|---|---|
| `docs/paper/2026-09-07-pairct-cost-edits.md` | **신규.** Task 1~4 교체 텍스트 원본 |
| `documents/2026-09-08_v49_...docx` | **신규 산출.** v48 + 이번 4건 |
| `docs/paper/2026-09-07-pairct-ivg-vib-cost-edits.md` | 기존 초안. v1 초록과 §IV-G 초안이 여기 있고, 이번 계획이 **대체**한다 |

---

### Task 1: §IV-G — "ordinary calldata" 문장 교체

**Files:** Create `docs/paper/2026-09-07-pairct-cost-edits.md` / Modify v48 → v49

**Interfaces:**
- Consumes: 없음
- Produces: §VI-B로의 전방 참조 `Section VI-B reports both costs and the regime in which
  each dominates.` — Task 2가 그 보고를 실제로 만든다. **Task 2 없이 이 문장만 넣으면 안 된다.**

- [x] **Step 1: 대상 문단의 run 구조를 확인한다**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
python3 - <<'PY'
import zipfile, re
z=zipfile.ZipFile('documents/2026-09-07_v48_PairCT_research_article.docx')
xml=z.read('word/document.xml').decode('utf-8')
ps=re.findall(r'<w:p[ >].*?</w:p>', xml, re.S)
for i,p in enumerate(ps):
    t=''.join(re.findall(r'<w:t[^>]*>(.*?)</w:t>',p,re.S))
    if 'ordinary calldata' in t:
        print(f"#{i}  run={len(re.findall(r'<w:r[ >]',p))}  <w:t>={len(re.findall(r'<w:t[^>]*>',p))}")
        print('서식:', [f for f in ['w:i>','w:b>','vertAlign','w:hyperlink','w:fldChar'] if f in p] or '없음')
PY
```

기대: run 1개, 서식 없음. 아니면 중단하고 수동 편집으로 전환한다.

- [x] **Step 2: 교체 텍스트를 `docs/paper/2026-09-07-pairct-cost-edits.md`에 기록한다**

교체 대상:

> A proof is then bound only to its own subtree root, so a revocation in any other subtree
> leaves it valid and only the upper-level sibling hashes—ordinary calldata—have to be
> refreshed.

교체 텍스트:

> A proof is then bound only to its own subtree root, so a revocation in any other subtree
> leaves the argument valid; what must be refreshed is the upper-level sibling path, which
> the contract recomputes from calldata rather than inside the relation. The two are not
> equally rare, and neither is free. An argument is regenerated only when the prover's own
> subtree changes, whereas the sibling path must be rebuilt whenever the wallet's cached
> root is no longer acceptable to the registry. Section VI-B reports both costs and the
> regime in which each dominates.

- [x] **Step 3: Task 2·3의 텍스트까지 확정한 뒤 한 번에 적용한다**

네 곳을 각각 적용하면 중간 상태의 원고가 전방 참조를 깨뜨린다. Task 4까지 텍스트를 모두
확정하고 **한 스크립트에서 함께** `.docx`에 반영한다(Task 4 Step 3).

- [x] **Step 4: 커밋 제안 (승인 후)**

```bash
git add docs/paper/2026-09-07-pairct-cost-edits.md
git commit -m "docs(paper): §IV-G 갱신 비용 서술 교체안"
```

---

### Task 2: §VI-B — 비용 회계 문단 3개 추가

**Files:** Modify `docs/paper/2026-09-07-pairct-cost-edits.md` / v48 → v49

**Interfaces:**
- Consumes: Task 1의 전방 참조를 이 문단이 받는다
- Produces: §VI-D(Task 3)가 가리킬 대상 — "Section VI-B contrasts the sharded revocation
  relation with the single-tree relation it replaces"

- [x] **Step 1: 삽입 위치를 확인한다**

§VI-B 마지막 문단(`Proof representation sizes depend on serialization.`로 시작)의 **뒤**에
넣는다. `Measurement environment.` 문단보다 뒤여야 "on the environment stated above"가 성립한다.

```bash
cd /home/node1phi/Desktop/google-oidc-demo
python3 - <<'PY'
import zipfile, re
z=zipfile.ZipFile('documents/2026-09-07_v48_PairCT_research_article.docx')
ps=re.findall(r'<w:p[ >].*?</w:p>', z.read('word/document.xml').decode('utf-8'), re.S)
t=lambda p:''.join(re.findall(r'<w:t[^>]*>(.*?)</w:t>',p,re.S))
for i,p in enumerate(ps):
    s=t(p)
    if s.startswith(('Measurement environment','Proof representation sizes','C. ADDRESS ABSTRACTION')):
        print(f"#{i}: {s[:70]}")
PY
```

- [x] **Step 2: 세 문단을 기록한다**

문단 1 — 무엇을 얻었나 (내부 비교임을 첫 문장에 못 박는다):

> Revocation costs are reported here as an internal comparison against the single-tree
> relation this construction replaces, not as a claim against other systems. Splitting the
> accumulator reduces pi_pk_i from 19,251 to 13,905 non-linear constraints and its proving
> time from 755.8 ms to 510.3 ms, and raises the cost of an on-chain execution from 276,709
> to 330,079 gas. The gas increase is dominated not by the upper-tree path — twenty keccak
> invocations and 640 bytes of calldata — but by the three additional public signals, which
> cost the Groth16 verifier three ecMul invocations at 6,000 gas each together with the
> associated ecAdd work.

문단 2 — 무엇을 치렀나 (그리고 구현 산물임을 분리):

> The split also introduces a cost the single-tree construction does not have. When the
> wallet's cached root is no longer acceptable to the registry, the wallet must rebuild the
> upper-tree sibling path before it can submit: 77.0 ms in our prototype for the session and
> account layers together, over ten warm runs on the environment stated above (73.3 ms for
> the 4,096-shard session layer and 3.7 ms for the 256-shard account layer). This figure
> does not depend on how many revocations are outstanding — an empty forest costs 66.0 ms —
> because the prototype folds the upper tree densely, hashing 2^d − 1 nodes; a traversal
> that skipped empty subtrees would scale with the number of non-empty ones instead. The
> rebuild cost is therefore a property of this implementation rather than of the split.

문단 3 — 어느 쪽이 지배하나:

> Which cost dominates depends on how often a wallet transacts. Because the registry accepts
> a superseded root for a grace window of three blocks, a wallet that submits within that
> window pays neither cost. Beyond it, with a root published every block and revocations at
> the rate assumed in Section IV-G, a wallet transacting every ten blocks rebuilds the path
> on every submission but regenerates its argument on only 4.67 per cent of them, so the
> rebuild is the larger term by roughly a factor of three; a wallet transacting every sixty
> blocks regenerates often enough that the 510.3 ms argument dominates instead.

- [x] **Step 3: (Task 4에서 일괄 적용)**

- [x] **Step 4: 커밋 제안 (승인 후)**

---

### Task 3: §VI-D — 카브아웃 + 나열 정정

**Files:** Modify `docs/paper/2026-09-07-pairct-cost-edits.md` / v48 → v49

**Interfaces:**
- Consumes: Task 2가 만든 §VI-B 비교
- Produces: 없음

- [x] **Step 1: 두 대상 문자열을 확인한다**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct && mkdir -p $S && rm -f $S/*.txt
soffice --headless --convert-to txt:Text --outdir $S documents/2026-09-07_v48_PairCT_research_article.docx >/dev/null 2>&1
grep -o 'circuit constraint counts' $S/*.txt
grep -o 'not as an optimization claim' $S/*.txt
```

기대: 각 1건.

- [x] **Step 2: 교체 텍스트를 기록한다**

(a) 나열에서 `circuit constraint counts,`를 **삭제**한다. §VI-B가 13,905를 이미 보고하고
있어 현재도 내부 모순이며, Task 2가 19,251까지 실으면 더 어긋난다.

(b) 마지막 문장 교체:

> These boundaries define the implementation results as prototype validation of the proposed
> security design, not as an optimization claim.

→

> These boundaries define the implementation results as prototype validation of the proposed
> security design rather than an optimization claim against other systems. One comparison is
> reported as a result: Section VI-B contrasts the sharded revocation relation with the
> single-tree relation it replaces. That comparison is internal — the same circuits, host,
> and measurement protocol on both sides — and is included because the cost of the split is
> what justifies it.

- [x] **Step 3: (Task 4에서 일괄 적용)**

- [x] **Step 4: 커밋 제안 (승인 후)**

---

### Task 5: §IV-G — 축 선택의 근거 (회수 비대칭 · 꼬리 · 용량)

**Files:** Modify `docs/paper/2026-09-07-pairct-cost-edits.md` / v48 -> v49

**Interfaces:**
- Consumes: 없음 (§VI-B와 독립 — 설계 근거이지 비용 회계가 아니다)
- Produces: 없음

**주의 — 이미 있는 문장과 겹치지 않게 한다.** §IV-G에는 이미 이 문장이 있다:

> The two layers are sharded on different keys: session leaves by the credential's own
> max_height, which is already a public signal, and account leaves by low-order bits of the
> account leaf, because the expiry of an account revocation is by construction not known to
> the prover.

축이 무엇인지는 이미 쓰여 있다. 이번에 더하는 것은 **그 선택의 결과**다.

- [x] **Step 1: 위 문장이 있는 문단 번호와 run 구조를 확인한다**

`sharded on different keys`를 담은 문단을 찾아 run 수와 서식 요소를 출력한다 —
Task 1 Step 1과 같은 방식이며, 단일 run이 아니면 중단하고 수동 편집으로 전환한다.

- [x] **Step 2: 두 문단을 기록한다** (위 문장이 있는 문단 **뒤**에 삽입)

문단 A — 회수 비대칭 (구조적 논거, 시뮬레이션 아님):

> The difference has a consequence beyond addressability. A session shard is emptied
> wholesale once every credential it could hold has expired, a condition the contract checks
> from the block height alone, so reclaiming a session shard never invalidates a live
> argument. An account shard carries no expiry in its index and must instead be rebaselined,
> which re-roots the shard for every account in it, including those whose own revocation has
> not yet expired. Reclamation is therefore free on one layer and collateral on the other.

문단 B — 꼬리와 용량 (시뮬레이션 근거):

> We also considered sharding accounts by a contiguous identifier range. Simulating 10^8
> users at the revocation volume assumed above shows why we did not: a concentrated axis
> wins on the average and loses in the tail. A contiguous range leaves 99.9 per cent of
> provers untouched under a correlated burst but forces as many as 614 regenerations on the
> remainder, and drives the busiest shard to 451 per cent of a 1,023-leaf subtree, at which
> point insertion fails and the revocation cannot be published at all. A hash axis stays
> below 5 per cent of capacity in every scenario we simulated. Because a revocation that
> cannot be published is a loss of the security function rather than added latency, the two
> outcomes do not trade against each other, and accounts are sharded by hash. These figures
> are simulated rather than measured, and compare axes at a common revocation volume; they
> are not a claim about how often account revocations occur.

마지막 문장이 **결정 기록 3(계정 폐기율 미해결)을 지키는 장치**다. 빼지 않는다.

- [x] **Step 3: (Task 4에서 일괄 적용)**

- [x] **Step 4: 커밋 제안 (승인 후)**

---

### Task 4: 초록 v2 + 다섯 곳 일괄 적용·검증

**Files:** Modify `docs/paper/2026-09-07-pairct-cost-edits.md` / Create v49

**Interfaces:**
- Consumes: Task 1~3·5의 텍스트, 그리고 선행 계획에서 확정된 §I "두 축" 표현
- Produces: 최종 산출 v49

- [x] **Step 1: 초록 v2를 확정한다**

v1(`2026-09-07-pairct-ivg-vib-cost-edits.md`)에서 미해결로 남았던 8항목 중 이번에 처리할 것:

| 항목 | 처리 |
|---|---|
| 913 ms가 §VI-D와 충돌 | **해소됨** — Task 3이 카브아웃을 만든다. 다만 초록에 성능 수치를 넣을지는 아래 미결정 |
| 문장 7이 42단어 | 콜론 뒤를 독립 문장으로 분리 |
| 폐기 비중 27% | **철회** — 동급 기여로 확정됐으므로 정당하다 |
| "seven properties" + 4개 열거 | 숫자를 빼고 `properties including` |
| "warm state" 미정의 | 수치를 빼면 함께 사라짐 |
| `a conditional traceability` 관사 | 관사 삭제 |
| `for identifying` 복원 | 복원 |
| PairCT 약어 미해설 | `a pairwise identifier` 삽입 |

- [x] **Step 2: 네 곳을 한 스크립트로 적용한다**

Task 1·2·3·5의 텍스트와 초록을 하나의 python 스크립트에서 v48 → v49로 반영한다.
선행 계획(`...-promotion.md`)의 적용 스크립트를 그대로 본뜨되, 대상 문단이 단일 run임을
각각 assert로 확인하고 아니면 중단한다.

- [x] **Step 3: 검증**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
S=/tmp/pairct && rm -f $S/*.txt $S/*.pdf
soffice --headless --convert-to txt:Text --outdir $S documents/2026-09-08_v49_PairCT_research_article.docx >/dev/null 2>&1
T=$(ls $S/*v49*.txt)
echo "옛 ordinary calldata (0):        $(grep -c 'ordinary calldata' $T)"
echo "새 §IV-G 문장 (1):               $(grep -c 'Section VI-B reports both costs' $T)"
echo "§VI-B 내부비교 선언 (1):         $(grep -c 'internal comparison against the single-tree' $T)"
echo "갱신 수치 (1):                   $(grep -c '77.0 ms in our prototype' $T)"
echo "구현 산물 명시 (1):              $(grep -c 'property of this implementation rather than of the split' $T)"
echo "§VI-D 카브아웃 (1):              $(grep -c 'rather than an optimization claim against other systems' $T)"
echo "옛 §VI-D 문장 (0):               $(grep -c 'not as an optimization claim.' $T)"
echo "나열 정정 (0):                   $(grep -c 'circuit constraint counts' $T)"
echo "초록 관사 정정 (0):              $(grep -c 'a conditional traceability' $T)"
echo "§IV-G 회수 비대칭 (1):           $(grep -c 'free on one layer and collateral' $T)"
echo "§IV-G 용량 (1):                  $(grep -c '451 per cent' $T)"
echo "§IV-G 시뮬레이션 명시 (1):       $(grep -c 'simulated rather than measured' $T)"
soffice --headless --convert-to pdf --outdir $S documents/2026-09-08_v49_PairCT_research_article.docx >/dev/null 2>&1
pdfinfo $S/*v49*.pdf | awk '/^Pages/{print "페이지: "$2"  (v48: 21)"}'
```

- [x] **Step 4: 문단·문자 수 대조**

선행 계획과 같은 방식으로 v48 대비 증분이 의도한 만큼인지 확인한다.

- [x] **Step 5: 스펙 상태 갱신 후 커밋 제안 (승인 후)**

---

## 완료 기준

- [ ] §IV-G가 갱신을 "무료"로 부르지 않는다
- [ ] §VI-B가 얻은 것과 치른 것을 같이 보고하고, 갱신 비용이 **구현 산물**임을 명시한다
- [ ] §VI-D가 내부 비교를 예외로 두고, `circuit constraint counts` 모순이 사라졌다
- [ ] 초록 v2가 반영됐고 **정량 수치가 없다**
- [ ] §IV-G가 축 선택의 근거(회수 비대칭·꼬리·용량)를 담고, 시뮬레이션임을 밝힌다
- [ ] 페이지 수가 22를 넘지 않는다

## 결정 기록

1. **초록에 정량 수치를 넣지 않는다.** (2026-09-07 확정) 카브아웃이 생겨 넣을 수는 있게
   되지만, 구조적 결과 — 한 사용자의 폐기가 다른 사용자의 증명을 죽이지 않는다 — 가 이미
   초록에서 가장 강한 주장이고 비교 대상 없이도 의미가 선다.
2. **축 비교와 용량을 §IV-G에 넣는다.** (2026-09-07 확정) → Task 5.
3. **계정 폐기율 가정은 여전히 미해결.** 정해지기 전에는 계정 층의 **무효화 빈도**를
   주장하지 않는다. Task 5의 축 비교는 이 가정을 필요로 하지 않는다 — 모든 축을 **같은
   폐기량**에 놓고 비교하는 것이라 "이 축이 저 축보다 어떠하다"만 말하고 "계정 폐기가
   얼마나 잦다"는 말하지 않기 때문이다. 본문에도 그렇게 쓴다.
