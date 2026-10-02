# Mode 3(zk-Delegation)의 영지식증명 두 개(π_idp = π_issue, π_rp = pi_cred) 정리 슬라이드 — 교수님 덱 템플릿 위에 새로 만든다.
# 실측치 출처: results/zkp_inventory_20260918.md, results/mode3_onchain_bench_20260918.md (2026-09-18).
from pptx import Presentation
from pptx.util import Emu, Pt

SRC = 'documents/260917_OVERALL.pptx'
DST = 'documents/260918_zkDelegation_ZKPs.pptx'
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

title_slide('zk-Delegation의 영지식증명 두 개', 'π_idp(발급 요청, → AA)와 π_rp(로그인·트랜잭션, → 서비스·컨트랙트)\n2026-09-18')

bullets('한눈에', [
    (0, 'π_idp — 지갑 → AA. "이 커밋 C는 인증된 uid와 등록 비밀 s_u로 만들었다"'),
    (1, '시그마 프로토콜(Fiat-Shamir). 회로·zkey·신뢰 셋업 없음. 폐기 비멤버십 없음(자격증명이 아직 없으니 증명할 대상이 없다)'),
    (0, 'π_rp — 지갑 → 서비스(오프체인) / Mode3Wallet(온체인). "AA가 서명한 자격증명이 있고, 폐기되지 않았고, 이 가명·키·태그가 거기서 나왔다"'),
    (1, 'Groth16, 25,560 제약. 로그인과 트랜잭션에 같은 증명(캐시 재사용). 덱 20·23장과 25장을 하나로 합친 것'),
    (0, '검증자는 셋(AA·서비스·컨트랙트), 증명 종류는 둘'),
    (1, '합칠 수 있었던 이유: 온체인 공개 입력은 AA도 읽으므로 r_s·auid_i·H(C)·nonce를 공개 입력에서 뺐고, 그러자 두 문장이 같아졌다'),
])

H = ['항목', 'π_idp (π_issue)', 'π_rp (pi_cred V4)']
W = [1.2, 3.0, 3.6]
table_slide('두 증명의 비교', H, [
    ['시점 / 검증자', '발급 요청 / AA', '로그인·재검증 / 서비스,  트랜잭션 / 계정 컨트랙트'],
    ['종류', '시그마 프로토콜, Baby Jubjub. 회로 없음', 'Groth16(BN254), circom. 비멤버십 깊이 32'],
    ['공개 값', 'uid, C_pt, cm_u (3개)', 'PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_AA(x,y), pk_trace(x,y), tag c1(x,y)·c2 (14개)'],
    ['비공개 증인', 'arid, s_u, pk_i, attrs[4], blind, r_u', 'uid, s_u, blind, attrs[4], r, σ_AA(S, R8), 비멤버십 low 리프·경로'],
    ['검증자가 알게 되는 것', 'uid(이미 앎). arid·pk_i·속성은 못 봄', '가명·세션키·만료·태그. uid·s_u·C·속성은 못 봄'],
    ['폐기 비멤버십', '없음', '있음 — 매 제시마다 현재 root 기준'],
    ['증명 / 검증', '155 ms / 164 ms', '858 ms(witness 218 + prove 637) / 14.6 ms 오프체인, 339k–388k gas 온체인'],
    ['증명 크기', '1,189 B', '722 B (a, b, c 8워드) + 공개 입력 14워드'],
], W, size=12)

bullets('π_idp — 발급 요청 증명 (→ AA)', [
    (0, '공개: uid, C_pt, cm_u.  비공개: arid, s_u, pk_i, a₁..a₄, blind, r_u'),
    (0, 'PoK{ C_pt = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + Σaₖ·G₄₊ₖ + blind·H  ∧  cm_u = s_u·G₃ + r_u·H }'),
    (1, '"C 안에 인증된 uid가 있고, s_u는 등록 때 낸 cm_u의 것과 같다" — 덱 13장의 auid 대조를 커밋 등식으로 바꾼 것'),
    (0, 'AA의 검사 순서: 형식 → disabled → chainid 허용·체인 생존 → max_height < 2⁶⁴ → sig_u → π_idp → σ_AA 서명'),
    (1, 'σ_AA = Sign(Poseidon(D_cred, C, max_height, chainid, allowAgent)). max_height는 지갑이 정한 값 그대로'),
    (0, '왜 시그마 프로토콜인가: Pedersen 커밋의 표현 지식은 시그마로 충분하고, SNARK로 하면 두 번째 회로·셋업이 생긴다'),
    (0, '왜 비멤버십이 없나: 폐기 리프는 Poseidon(TAG, C)인데 C는 이 요청에서 처음 생긴다. 계정 폐기는 AA가 자기 DB(disabled)로 직접 본다'),
], size=18)

bullets('π_rp — 자격증명 증명 (→ 서비스 · 컨트랙트)', [
    (0, '공개 입력 14개: PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_AA, pk_trace, tag(c1, c2)'),
    (0, '조건 (모두 한 회로 안):'),
    (1, '① EdDSA.Verify(pk_AA, Poseidon(D_cred, C, max_height, chainid, allowAgent), σ_AA) — AA가 발급했다'),
    (1, '② C = Commit(uid, arid, s_u, pk_i, attrs; blind)를 공개 pk_i·arid로 직접 계산 — 남의 π를 내 키로 못 쓴다'),
    (1, '③ PPID = Poseidon(uid, s_u, chainid, arid) — 주소가 이 자격증명에서 나왔다'),
    (1, '④ Poseidon(TAG, C) ∉ Tree(root) — 폐기되지 않았다 (리프·경로는 비공개)'),
    (1, '⑤ c1 = r·B8,  c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace) — 태그가 같은 uid로 바르게 만들어졌다'),
    (1, '⑥ allowAgent ∈ {0,1},  pk_i < 2¹⁶⁰,  max_height < 2⁶⁴'),
    (0, '증명 밖에서 묶는 것: 세션키 서명 σ — 서비스에는 Sign(r_s), 컨트랙트에는 Sign(keccak(chainid, wallet, to, value, data, nonce))'),
], size=17)

H2 = ['검사', '서비스 (오프체인 로그인)', 'Mode3Wallet (온체인 execute)']
W2 = [1.4, 3.0, 3.0]
table_slide('π_rp의 두 검증자 — 같은 증명, 검사 순서만 다르다', H2, [
    ['신선도', 'r_s 소비(발급한 것·미사용, 검증 전 소비)', 'nonce 일치 → 실행 뒤 nonce+1'],
    ['세션키 서명', 'σ = Sign_sk_i(r_s) (맨 뒤)', 'σ over 페이로드 다이제스트, low-s, v∈{27,28} (맨 앞)'],
    ['고정값 대조', 'chainid, pk_AA, arid, pk_trace = 설정값', 'PPID, arid, chainid = 자기 것; pk_AA, pk_trace = 팩토리 값'],
    ['만료', 'head ≤ max_height ≤ head + L(400)', 'block.number ≤ max_height ≤ block.number + maxLifetime'],
    ['폐기 root', 'root = 방금 읽은 현재 root (N=1)', 'root = log.root(), 마지막 게시 ≤ MAX_ROOT_AGE(100) 블록'],
    ['태그·플래그', 'allowAgent ≤ 1, c1 ≠ O', 'allowAgent ≤ 1, c1 ≠ O (BadTag)'],
    ['Groth16', 'snarkjs verify 14.6 ms', 'PiCredVerifier 페어링 — execute 339k(EOA 호출)/388k(값 전송) gas'],
    ['결과', 'sessions[r_s] = {PPID, pk_i, max_height, allowAgent, root}, 로그인 로그에 트랜스크립트', '내부 호출 + Executed·Mode3Auth(pk_i, max_height, allowAgent, tag) 이벤트'],
], W2, size=12)

bullets('폐기 비멤버십이 π_rp에 매번 들어가는 이유', [
    (0, 'RCL은 등록 목록이 아니라 폐기 목록 — 발급 때 트리에 아무것도 넣지 않는다. 비멤버십 = "내 리프가 블랙리스트에 없다"'),
    (0, '검증자는 C도 발급 시각도 못 본다 → "방금 발급된 자격증명"과 "발급 뒤 폐기된 자격증명"을 구별할 수 없다'),
    (1, '"첫 로그인은 면제" 같은 규칙은 첫 로그인인지 판별할 수 없어 성립하지 않는다'),
    (0, '증명이 root에 묶이므로 root가 바뀌면 옛 π는 stale → 재증명 필요 → 폐기된 자격증명은 재증명을 못 한다. 이것이 세션 중 폐기(G8·G9)'),
    (0, '비용: 깊이 32 경로 ≈ 25,560 제약 중 약 1/3, 지갑의 트리 동기화 31 ms'),
    (0, '빼면: 만료(300블록)에만 기대는 zkLogin 방식. 회로 1/3 감소, stale root·하트비트 소멸. 대신 폐기 효력이 최대 300블록 뒤'),
], size=18)

bullets('트랜잭션 — 새 증명이 아니라 같은 π_rp', [
    (0, 'execute(payload{to, value, data, nonce}, σ, a, b, c, pub[14]) — 로그인 때 만든 π를 그대로 첨부'),
    (1, '지갑은 (root, r_s)로 π를 캐시. 첫 트랜잭션도 이후 트랜잭션도 캐시 히트(증명 비용 0, 왕복 157 ms). root가 바뀔 때만 재증명(858 ms)'),
    (0, '트레이스 태그는 π_rp의 공개 입력 (c1.x, c1.y, c2). 별도 회로 없음'),
    (1, 'pk_trace = (x_svc + x_AA)·B8. 지갑이 증명마다 새 r로 c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)'),
    (1, '컨트랙트는 pk_trace 대조와 c1 ≠ O만 보고 Mode3Auth 이벤트에 태그를 남긴다'),
    (1, '개봉: 서비스가 D_svc = x_svc·c1 + txHash로 요청 → 운영자 승인 → AA가 x_AA·c1을 더해 Poseidon(uid, arid) 복원 → 발급 기록 역조회'),
    (0, '같은 π 재사용 = 같은 태그 암호문. 하지만 sender가 PPID 계정이라 어차피 같은 주소로 이어져 있어 태그가 더 드러내는 것은 없다'),
], size=18)

H3 = ['항목', 'π_idp', 'π_rp']
W3 = [2.0, 2.2, 2.6]
table_slide('실측 (N=10 중앙값, 5950X·Node 22·snarkjs)', H3, [
    ['R1CS 제약 / 와이어', '— (회로 없음)', '25,560 / 25,592'],
    ['공개 / 비공개 입력', '3 / 9', '14 / 78'],
    ['zkey / vkey / wasm', '—', '15.5 MB / 5.3 KB / 3.8 MB'],
    ['witness 생성', '—', '218 ms (211–223)'],
    ['증명 생성', '155 ms (152–375)', 'prove 637 ms (619–1,011); witness+prove 858 ms'],
    ['검증', '164 ms (162–168) — 지수승 9개', '14.6 ms (10–20) 오프체인'],
    ['온체인 검증(execute 전체)', '—', '339,341 gas (EOA 호출) / 387,905 gas (값 전송)'],
    ['증명 크기', '1,189 B (JSON)', '722 B (JSON); calldata 8 + 14 워드'],
    ['로그인 1회 합', 'π_idp 155 + π_rp 858 ≈ 1.0 s 증명; 격리 스택 왕복 1,394 ms (AA 발급 422 · 증명 898 · 동기화 31)', ''],
], W3, size=12)

bullets('덱(260917_OVERALL)과의 대응', [
    (0, '13장 "Request AS"의 ZKP(auid·auid_i·C 구성 증명) → π_idp. auid 대조 대신 cm_u 등식, auid_i 대신 pk_i를 C 안에'),
    (0, '20·21·23장 Pseudonym Proof + 25장 Transaction ZKP → π_rp 하나'),
    (1, '조건은 그대로: AA 서명, pseudonym = H(uid, salt, cid, sid), H(C) ∉ Tree(root), 태그, allowAgent'),
    (1, '공개 입력에서 뺀 것: r_s, auid_i, H(C), nonce — 온체인 공개 입력은 AA도 읽으므로 발급 때 본 값을 두지 않는다(스펙 §2)'),
    (1, 'r_s와 nonce는 증명 밖 세션키 서명 σ로 묶는다'),
    (0, '태그 평문의 두 번째 인자는 arid(덱은 비움) — AA가 승인 뒤 발급 기록을 역조회하기 위해'),
])

prs.save(DST); print('saved', DST, len(prs.slides), 'slides')
