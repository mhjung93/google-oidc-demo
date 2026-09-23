# Mode 3(zk-Delegation)의 영지식증명 정리 슬라이드 v5 (2026-09-23): π_u(사용자 자격증명, 사용자당 한 번, → AA)와 π_rp(pi_cred V6, 로그인·트랜잭션,
# → 서비스·컨트랙트). 세션 발급에는 ZKP 가 없다. 260918 판(make_zkp_slides.py, π_idp 표기)은 그대로 둔다. 교수님 덱 템플릿.
# 실측치: results/mode3_disclosure_bench_20260922.md(V6), results/zkp_inventory_20260921.md, results/mode3_rcl_sync_20260923.md.
from pptx import Presentation
from pptx.util import Emu, Pt

SRC = 'documents/260917_OVERALL.pptx'
DST = 'documents/260923_zkDelegation_ZKPs.pptx'
prs = Presentation(SRC)
sldIdLst = prs.slides._sldIdLst
for sldId in list(sldIdLst):
    prs.part.drop_rel(sldId.rId); sldIdLst.remove(sldId)
L_TITLE, L_BODY = prs.slide_layouts[0], prs.slide_layouts[1]

def title_slide(t, sub):
    s = prs.slides.add_slide(L_TITLE); s.shapes.title.text = t; s.placeholders[1].text = sub; return s

def bullets(title, items, size=20):
    s = prs.slides.add_slide(L_BODY); s.shapes.title.text = title
    tf = s.placeholders[1].text_frame; tf.clear(); first = True
    for lvl, txt in items:
        p = tf.paragraphs[0] if first else tf.add_paragraph(); first = False
        p.text = txt; p.level = lvl
        for r in p.runs: r.font.size = Pt(size - 3 * lvl)
    return s

def table_slide(title, header, rows, widths, size=13):
    s = prs.slides.add_slide(L_BODY); s.shapes.title.text = title
    ph = s.placeholders[1]; left, top, width, height = ph.left, ph.top, ph.width, ph.height
    ph._element.getparent().remove(ph._element)
    tbl = s.shapes.add_table(len(rows) + 1, len(header), left, top, width, Emu(int(height * 0.95))).table
    total = sum(widths)
    for j, w in enumerate(widths): tbl.columns[j].width = Emu(int(width * w / total))
    def put(cell, text, bold=False, sz=size):
        cell.text = ''; tf = cell.text_frame; tf.word_wrap = True
        p = tf.paragraphs[0]; p.text = text
        for r in p.runs: r.font.size = Pt(sz); r.font.bold = bold
        cell.margin_left = cell.margin_right = Emu(50000); cell.margin_top = cell.margin_bottom = Emu(30000)
    for j, h in enumerate(header): put(tbl.cell(0, j), h, bold=True)
    for i, row in enumerate(rows, 1):
        for j, v in enumerate(row): put(tbl.cell(i, j), v, bold=(j == 0))
    return s

title_slide('zk-Delegation의 영지식증명 두 개', 'π_u(사용자 자격증명, 사용자당 한 번 → AA)와 π_rp(로그인·트랜잭션 → 서비스·컨트랙트)\n세션 발급에는 ZKP 가 없다 — 2026-09-23')

bullets('한눈에', [
    (0, 'π_u — 지갑 → AA, 사용자당 한 번. "이 자격증명 C_u 는 인증된 uid, 등록 비밀 s_u(cm_u 의 것), AA 기록의 속성 a₁..a₄ 로 만들었다"'),
    (1, '시그마 프로토콜(Fiat-Shamir). 회로·zkey·신뢰 셋업 없음. 폐기 비멤버십 없음(자격증명이 아직 없으니 증명할 대상이 없다). 속성이 바뀔 때만 다시'),
    (0, '세션 발급 — 증명 없음. 지갑이 C_s = Commit(arid, pk_i; blind_s) 를 sk_u 로 서명해 보내면 AA 가 활성 Cf_u 와 함께 σ_AA 로 서명(≈ 30 ms)'),
    (1, 'AA 가 확인할 것이 없는 이유: 신원은 π_u 로 이미 증명됐고, C_s 의 내용은 π_rp 가 공개 입력(arid, pk_i)에서 다시 계산한다'),
    (0, 'π_rp — 지갑 → 서비스(오프체인) / Mode3Wallet(온체인). "AA 가 서명한 (자격증명, 세션 커밋)이 있고, 자격증명은 폐기되지 않았고, 이 가명·키·태그·공개 구간이 거기서 나왔다"'),
    (1, 'Groth16, 25,369 제약, 공개 입력 23. 로그인과 트랜잭션에 같은 증명(캐시 재사용), 속성 공개가 있을 때만 새 증명'),
    (0, '검증자는 셋(AA·서비스·컨트랙트), 증명 종류는 둘, AA 가 하는 영지식 검증은 사용자당 한 번'),
])

H = ['항목', 'π_u (사용자 자격증명)', 'π_rp (pi_cred V6)']
W = [1.2, 3.0, 3.6]
table_slide('두 증명의 비교', H, [
    ['시점 / 검증자', '자격증명 발급, 사용자당 1회(속성 변경 시 재발급) / AA', '로그인·재검증 / 서비스,  트랜잭션 / 계정 컨트랙트'],
    ['종류', '시그마 프로토콜, Baby Jubjub. 회로 없음', 'Groth16(BN254), circom. 비멤버십 깊이 32'],
    ['공개 값', 'uid, a₁..a₄(AA 기록), C_u, cm_u', 'PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_AA(x,y), pk_trace(x,y), tag c1(x,y)·c2, disc_mask, disc_lo[4], disc_hi[4] (23개)'],
    ['비공개 증인', 's_u, blind_u, r_u', 'uid, s_u, blind_u, blind_s, a₁..a₄, r, σ_AA(S, R8), 비멤버십 low 리프·경로'],
    ['검증자가 알게 되는 것', 'uid·속성(이미 앎). s_u·blind_u 는 못 봄', '가명·세션키·만료·태그·공개 구간. uid·s_u·C_u·C_s·비공개 슬롯은 못 봄'],
    ['폐기 비멤버십', '없음', '있음 — 매 제시마다 현재 root 기준, 리프 = Poseidon(4, Cf_u)'],
    ['증명 / 검증', '80 ms / 99 ms', '809 ms(witness 203 + prove 609) / 10.7 ms 오프체인, 402k–445k gas 온체인'],
    ['증명 크기', '691 B', '722 B (a, b, c 8워드) + 공개 입력 23워드'],
], W, size=12)

bullets('π_u — 사용자 자격증명 증명 (→ AA, 사용자당 한 번)', [
    (0, '공개: uid, a₁..a₄, C_u, cm_u.  비공개: s_u, blind_u, r_u'),
    (0, 'PoK{ C_u − uid·G₁ − Σaₖ·G₄₊ₖ = s_u·G₃ + blind_u·H  ∧  cm_u = s_u·G₃ + r_u·H }  — s_u 응답을 두 등식이 공유'),
    (1, 'AA 는 uid 를 인증 세션에서, aₖ 를 자기 계정 기록에서 넣고 그 항들을 C_u 에서 뺀 뒤 검사한다 → 다른 속성으로 만든 C_u 는 결합성 때문에 통과 못 함'),
    (1, '"C_u 안에 인증된 uid 와 등록 때 낸 cm_u 의 s_u, 그리고 AA 가 보증하는 속성이 있다" — 이것이 이후 모든 세션·공개 구간의 근거'),
    (0, 'AA 는 Cf_u = Poseidon(C_u) 만 계정의 활성 자격증명으로 기록. C_u 의 열림·s_u·blind_u 는 보지도 저장하지도 않는다'),
    (0, '왜 시그마 프로토콜인가: Pedersen 커밋의 표현 지식은 시그마로 충분하고, SNARK 로 하면 두 번째 회로·셋업이 생긴다'),
    (0, '왜 비멤버십이 없나: 폐기 리프는 Poseidon(4, Cf_u) 인데 Cf_u 는 이 요청에서 처음 생긴다. 계정 폐기는 AA 가 자기 DB(disabled·활성 Cf_u)로 직접 본다'),
], size=17)

bullets('π_rp — 자격증명 증명 (→ 서비스 · 컨트랙트)', [
    (0, '공개 입력 23개: PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_AA, pk_trace, tag(c1, c2), disc_mask, disc_lo[4], disc_hi[4]'),
    (0, '조건 (모두 한 회로 안, 논문 Table 2):'),
    (1, '① EdDSA.Verify(pk_AA, Poseidon(D_cred, Cf_u, Cf_s, max_height, chainid, allowAgent), σ_AA) — AA 가 이 자격증명·이 세션에 서명했다'),
    (1, '② C_u = Commit(uid, s_u, a; blind_u) 를 증인으로, C_s = Commit(arid, pk_i; blind_s) 를 **공개** arid·pk_i 로 재계산 — 남의 π 를 내 키·다른 서비스로 못 쓴다'),
    (1, '③ PPID = Poseidon(uid, s_u, chainid, arid) — 주소가 이 자격증명에서 나왔다'),
    (1, '④ Poseidon(4, Cf_u) ∉ Tree(root) — 자격증명이 폐기되지 않았다 (리프·경로는 비공개)'),
    (1, '⑤ c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace), r ≠ 0 — 태그가 같은 uid 로 바르게 만들어졌다'),
    (1, '⑥ allowAgent ∈ {0,1}, max_height < 2⁶⁴, 스칼라 250비트·속성 64비트'),
    (1, '⑦ mask 비트가 켜진 슬롯 k 마다 disc_lo_k ≤ a_k ≤ disc_hi_k — 선택 공개(구간, 등식은 lo = hi)'),
    (0, '증명 밖에서 묶는 것: 세션키 서명 σ — 서비스에는 Sign(r_s), 컨트랙트에는 Sign(keccak(chainid, wallet, to, value, data, nonce, 공개 9워드))'),
], size=16)

H2 = ['검사', '서비스 (오프체인 로그인·재검증·세션 요청)', 'Mode3Wallet (온체인 execute)']
W2 = [1.4, 3.0, 3.0]
table_slide('π_rp의 두 검증자 — 같은 증명, 같은 규칙', H2, [
    ['신선도', 'r_s 소비(발급한 것·미사용, 검증 전 소비)', 'nonce 일치 → 실행 뒤 nonce+1'],
    ['세션키 서명', 'σ = Sign_sk_i(r_s) (맨 뒤)', 'σ over 페이로드 다이제스트(공개 9워드 포함), low-s, v∈{27,28} (맨 앞)'],
    ['고정값 대조', 'chainid, pk_AA, arid, pk_trace = 설정값', 'PPID, arid, chainid = 자기 것; pk_AA, pk_trace = 팩토리 값'],
    ['만료', 'head ≤ max_height ≤ head + L(400)', 'block.number ≤ max_height ≤ block.number + maxLifetime'],
    ['폐기 root', 'root = 방금 읽은 현재 root (N=1) + 마지막 게시 ≤ MAX_ROOT_AGE(100) 블록(2026-09-23)', 'root = log.root(), 마지막 게시 ≤ MAX_ROOT_AGE(100) 블록'],
    ['태그·플래그·공개', 'allowAgent ≤ 1, c1 ≠ O, mask < 16; 비마스크 슬롯 lo/hi 는 0 으로 기록', 'allowAgent ≤ 1, c1 ≠ O (BadTag); 공개 9워드를 호출 꼬리로 전달'],
    ['Groth16', 'snarkjs verify 10.7 ms', 'PiCredVerifier 페어링 — execute 402k(캐시 π)/419k(첫)/445k(공개+AttrGate) gas'],
    ['결과', 'sessions[r_s] = {PPID, pk_i, max_height, allowAgent, root, disclosure}, 로그인 로그에 트랜스크립트', '내부 호출 + Executed·Mode3Auth·Disclosure 이벤트'],
], W2, size=12)

bullets('폐기 비멤버십이 π_rp에 매번 들어가는 이유', [
    (0, 'RCL 은 등록 목록이 아니라 폐기 목록 — 발급 때 트리에 아무것도 넣지 않는다. 비멤버십 = "내 자격증명 리프가 블랙리스트에 없다"'),
    (0, '검증자는 C_u 도 발급 시각도 못 본다 → "방금 발급된 자격증명"과 "발급 뒤 폐기된 자격증명"을 구별할 수 없다'),
    (1, '"첫 로그인은 면제" 같은 규칙은 첫 로그인인지 판별할 수 없어 성립하지 않는다'),
    (0, '리프는 자격증명당 하나(Poseidon(4, Cf_u)) — 계정 폐기·속성 변경이 리프 하나로 그 사용자의 모든 서비스 세션을 끝낸다. 세션 단위 폐기는 없다'),
    (0, '증명이 root 에 묶이므로 root 가 바뀌면 옛 π 는 stale → 재증명 필요 → 폐기된 자격증명은 재증명을 못 한다. 이것이 세션 중 폐기(G8·G9)'),
    (0, '비용: 깊이 32 경로 ≈ 25,369 제약 중 약 1/3; 지갑의 트리 동기화는 체크포인트+델타로 1,000 리프에서 40 ms(전체 재생 141 ms)'),
    (0, '빼면: 만료(300블록)에만 기대는 zkLogin 방식. 회로 1/3 감소, stale root·하트비트 소멸. 대신 폐기 효력이 최대 300블록 뒤'),
], size=17)

bullets('트랜잭션 — 새 증명이 아니라 같은 π_rp (공개가 있을 때만 새 π)', [
    (0, 'execute(payload{to, value, data, nonce}, σ, a, b, c, pub[23]) — 로그인 때 만든 π 를 그대로 첨부'),
    (1, '지갑은 (root, r_s, 공개 키)로 π 를 캐시. 공개 없는 트랜잭션은 캐시 히트(증명 비용 0, 왕복 151 ms). root 가 바뀌거나 공개 구간이 있으면 새 π(≈ 0.8 s, 왕복 1.0 s)'),
    (0, '선택 공개: mask·lo·hi 가 공개 입력이라 컨트랙트가 검증한 값을 호출 데이터 끝 9워드로 대상(AttrGate)에 넘긴다 — 항상 붙인다(위조 꼬리 차단)'),
    (0, '트레이스 태그는 π_rp 의 공개 입력 (c1.x, c1.y, c2). 별도 회로 없음'),
    (1, 'pk_trace = (x_svc + x_AA)·B8. 지갑이 증명마다 새 r 로 c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)'),
    (1, '개봉: 서비스가 D_svc = x_svc·c1 + txHash 로 요청 → 운영자 승인 → AA 가 x_AA·c1 을 더해 Poseidon(uid, arid) 복원 → 등록부 역조회(발급 기록은 없다)'),
    (0, '같은 π 재사용 = 같은 태그 암호문. sender 가 PPID 계정이라 어차피 같은 주소로 이어져 있어 태그가 더 드러내는 것은 없다'),
], size=17)

H3 = ['항목', 'π_u', 'π_rp (V6)']
W3 = [2.0, 2.2, 2.6]
table_slide('실측 (N=10 중앙값, 5950X·Node 22·snarkjs, 2026-09-22·23)', H3, [
    ['R1CS 제약', '— (회로 없음)', '25,369 (V5 26,601, V4 25,560)'],
    ['공개 / 비공개 입력', '7 / 3', '23 / 79'],
    ['zkey / vkey / wasm', '—', '15.4 MB / 6.9 KB / 4.7 MB'],
    ['witness 생성', '—', '203 ms'],
    ['증명 생성', '80 ms (79–295)', 'prove 609 ms; witness+prove 809 ms (799–1,210)'],
    ['검증', '99 ms (98–100)', '10.7 ms (7–13) 오프체인'],
    ['온체인 검증(execute 전체)', '—', '402,130 gas (캐시 π 호출) / 419,262 (첫 실행) / 444,509 (두 슬롯 공개 + AttrGate)'],
    ['증명 크기', '691 B (JSON)', '722 B (JSON); calldata 8 + 23 워드'],
    ['로그인 1회 합', 'π_u 는 첫 로그인에만(≈ 0.18 s 왕복)', '격리 스택 왕복 1,054 ms (동기화 29 · 세션 발급 124 · 증명 ≈ 810); 재검증 31 ms'],
    ['지갑 트리 동기화(1,000 리프)', '', '전체 재생 141 ms → 델타 1개 40 ms / 델타 0 23 ms'],
], W3, size=12)

bullets('덱(260917_OVERALL)·옛 판(260918)과의 대응', [
    (0, '13장 "Request AS" 의 ZKP → 옛 π_idp(세션마다) → 지금은 π_u(사용자당 한 번). auid 대조 대신 cm_u 등식, 속성은 AA 기록으로 고정'),
    (1, '세션 발급은 서명만: 요청 {uid, Cf_u, C_s, chainid, allowAgent, max_height, sig_u}, 응답 σ_AA. 옛 π_idp 155 ms + 검증 164 ms 가 로그인마다 사라졌다(422 → 124 ms)'),
    (0, '20·21·23장 Pseudonym Proof + 25장 Transaction ZKP → π_rp 하나. 2026-09-22 에 선택 공개 술어(⑦)와 공개 입력 9개가 더해짐'),
    (1, '조건은 그대로: AA 서명, pseudonym = H(uid, salt, cid, sid), 리프 ∉ Tree(root), 태그, allowAgent — 커밋이 둘로 갈라지고 리프가 자격증명 단위가 된 것이 차이'),
    (1, '공개 입력에서 뺀 것: r_s, auid_i, H(C), nonce — 온체인 공개 입력은 AA 도 읽으므로 발급 때 본 값을 두지 않는다(스펙 §2)'),
    (0, '태그 평문의 두 번째 인자는 arid(덱은 비움) — AA 가 승인 뒤 등록부에서 역조회하기 위해'),
])

prs.save(DST); print('saved', DST, len(prs.slides), 'slides')
