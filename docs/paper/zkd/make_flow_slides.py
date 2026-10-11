# zk-Delegation(Mode 3) 전체 플로우 슬라이드 — 등록 → 로그인(발급·증명·검증) → 세션 → 온체인 트랜잭션 → 폐기 → 개봉.
# 교수님 덱(260917_OVERALL.pptx) 템플릿. 실측치: results/zkp_inventory_20260918.md, results/mode3_onchain_bench_20260918.md.
from pptx import Presentation
from pptx.util import Emu, Pt

SRC = 'documents/260917_OVERALL.pptx'
DST = 'documents/260918_zkDelegation_flow.pptx'
FIG = 'docs/paper/zkd/fig1_login_v3.png'
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

def picture_slide(title, path):
    s = prs.slides.add_slide(L_BODY); s.shapes.title.text = title
    ph = s.placeholders[1]; left, top, width, height = ph.left, ph.top, ph.width, ph.height
    ph._element.getparent().remove(ph._element)
    # 그림 비율(2600×2346)에 맞춰 높이에 맞추고 가운데 정렬
    h = height; w = int(h * 2600 / 2346)
    if w > width: w = width; h = int(w * 2346 / 2600)
    s.shapes.add_picture(path, left + (width - w) // 2, top, w, h)
    return s

title_slide('zk-Delegation 전체 플로우', '등록 → 로그인(발급·증명·검증) → 세션 → 온체인 트랜잭션 → 폐기 → 개봉\n2026-09-18 (feat/mode3-cia @ 6181cda)')

H0 = ['당사자', '가지고 있는 것', '역할']
W0 = [1.0, 3.4, 3.0]
table_slide('등장인물과 각자가 쥔 것', H0, [
    ['사용자 / 지갑', 'uid·pwd(AA 계정), 비밀 s_u(등록 커밋의 열쇠), 요청 서명키 sk_u, 속성 a₁..a₄, 세션마다 새 세션키 (sk_i, pk_i), 폐기 트리 사본, 증명 캐시', '커밋·증명을 만들고, 주소를 유도하고, 트랜잭션에 서명'],
    ['AA (Authentication Authority, CIA)', 'EdDSA 키 pk_AA, 계정 DB {pk_u, cm_u, disabled}, 발급 기록 issued[uid], 폐기 트리(RCL)와 게시 키, 서비스별 트레이스 조각 x_AA,s', '신원 인증, 성명(자격증명) 서명, 폐기·게시, 승인된 개봉'],
    ['서비스 (RP)', 'arid, cert_s, 서명키 pk_service, 트레이스 조각 x_svc, 세션 테이블, 로그인 로그(비공개), 온체인 팩토리 주소', '챌린지 발급, π_rp 검증, 세션 운영, 개봉 요청'],
    ['체인', 'RevocationLog(root, epoch, lastPublishedBlock), PiCredVerifier, Mode3WalletFactory(서비스별), Mode3Wallet 계정(사용자·서비스별, CREATE2 salt = PPID)', '폐기 root 의 공개 게시, 트랜잭션마다 π_rp 검증·실행'],
    ['운영자', 'AA 관리 페이지', '서비스 등록 승인, 개봉 승인·거절, 관리자 폐기'],
], W0, size=12)

picture_slide('한 장으로: 로그인(1–6), 트랜잭션(6′), 개봉(7–8)', FIG)

bullets('0. 등록 — 사용자 한 번, 서비스 한 번', [
    (0, '사용자 등록 (지갑 → AA): uid·pwd 로 인증, cm_u = s_u·G₃ + r_u·H 를 제출'),
    (1, 'AA 는 cm_u 가 부분군 점인지 보고 {pk_u, cm_u, disabled=false} 저장, 요청 서명키 sk_u 를 돌려줌. s_u 는 AA 에 가지 않는다'),
    (1, 'cm_u 가 "사용자당 비밀 하나"를 고정한다 — 이후 모든 발급에서 같은 s_u 임을 π_idp 로 증명(G2 불변성)'),
    (0, '서비스 등록 (서비스 → AA): {name, origin, pk_service, X_svc = x_svc·B8} 제출 → 운영자 승인 대기'),
    (1, '승인 시 AA 가 arid 배정, 자기 조각 X_AA,s 를 만들어 pk_trace = X_svc + X_AA,s, cert_s = Sign_AA(arid, origin, pk_service, pk_trace) 발급'),
    (1, '트레이스 키가 두 조각의 합이라 어느 한쪽도 혼자 태그를 못 연다'),
    (0, '온체인을 쓰는 서비스는 팩토리를 한 번 배포: 생성자 (verifier, arid, pk_AA, pk_trace, log, maxRootAge=100, maxLifetime=400)'),
], size=18)

bullets('1. 로그인 시작 — 서비스 인증과 챌린지', [
    (0, '서비스 → 지갑: {arid, origin, cert_s, pk_trace, factoryAddress, r_s}. r_s 는 250비트 난수, 서비스가 발급하고 120 s 뒤 만료'),
    (0, '지갑의 검사: cert_s 를 pk_AA 로 검증, 인증서의 origin 이 지금 대화 중인 Origin 헤더와 같은지(피싱 방지, G6), pk_trace 가 인증서 값과 같은지'),
    (1, 'factoryAddress 는 온체인에서 arid·log·pk_AA·pk_trace getter 를 읽어 인증서·고정값과 대조(bad_factory)'),
    (0, '챌린지는 사용자가 아니라 서비스가 고른다 — "이 로그인이 무엇을 위한 것인지"는 서비스가 정한다'),
    (0, 'r_s 는 AA 에 절대 가지 않는다. 증명 안에도 들어가지 않고, 세션키 서명 σ = Sign_sk_i(r_s) 로만 묶인다'),
], size=19)

bullets('2. 성명 발급 — 지갑 → AA → 지갑', [
    (0, '지갑: 세션키 (sk_i, pk_i) 생성(pk_i 는 160비트 주소), blind 뽑고 커밋'),
    (1, 'C_pt = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + Σaₖ·G₄₊ₖ + blind·H,   C = Poseidon(C_pt)'),
    (1, '만료 max_height = ⌈(head + 300)/100⌉·100 — 지갑이 정하고 그리드로 뭉갬(AA 의 시각 상관 완화)'),
    (1, '요청 {uid, C_pt, chainid, allowAgent, max_height, π_idp, sig_u}. sig_u = Sign_sk_u(D_req, C_pt, chainid, allowAgent, max_height)'),
    (0, 'AA 검사 순서: 형식 → disabled → chainid 허용·체인 생존 → max_height < 2⁶⁴ → sig_u → π_idp'),
    (1, 'π_idp: "C 안에 uid 가 있고 s_u 는 cm_u 의 것" — AA 는 arid·pk_i·속성을 못 본다'),
    (0, 'AA 서명 σ_AA = Sign(Poseidon(D_cred, C, max_height, chainid, allowAgent)), issued[uid] 에 (leaf, C, max_height, chainid) 기록'),
    (1, 'AA 가 로그인에서 보는 전부: uid, C, chainid, allowAgent, max_height. 서비스·가명·챌린지는 모른다'),
], size=17)

bullets('3. 가명 증명 — 지갑이 π_rp 를 만든다', [
    (0, '체인 동기화: RevocationLog 의 Revoked 이벤트를 재생해 폐기 트리를 맞추고 현재 root·head 를 읽음 (31 ms)'),
    (0, 'PPID = Poseidon(uid, s_u, chainid, arid) — 서비스·체인마다 다른 가명, 이것이 곧 계정 주소의 salt'),
    (0, '트레이스 태그: r ← [1, 2²⁵⁰), c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)'),
    (0, 'π_rp = Groth16 증명 (25,560 제약, 858 ms): AA 서명 · C 재계산 · PPID 유도 · Poseidon(TAG, C) ∉ Tree(root) · 태그 · 범위'),
    (1, '공개 입력 14개: PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_AA, pk_trace, tag'),
    (0, '지갑 → 서비스: {π, 공개 입력, σ = Sign_sk_i(r_s)}. 증명은 (root, r_s) 키로 캐시'),
], size=18)

bullets('4. 서비스 검증과 세션', [
    (0, '검사 순서: r_s 소비(발급한 것·미사용, 먼저 소비) → root·head 읽기(600 s 신선도) → root 일치 → head ≤ max_height ≤ head + 400'),
    (1, '→ chainid·pk_AA·arid·pk_trace 가 설정값 → allowAgent ≤ 1, c1 ≠ O → Groth16 검증(14.6 ms) → σ 검증'),
    (0, '통과하면 sessions[r_s] = {PPID, pk_i, max_height, allowAgent, root}. 사용자 식별자는 PPID. 트랜스크립트는 비공개 로그인 로그에 보관(개봉 재료)'),
    (0, '세션 중 요청: (r_s, body, Sign_sk_i(r_s ‖ body)) — 증명 없이 서명만'),
    (0, '재검증: root 가 그대로면 캐시 π 재사용(33 ms), root 가 바뀌면 revalidate_required → 지갑이 새 root 로 재증명'),
    (1, '폐기된 성명은 새 root 에 대한 비멤버십을 못 만든다 → 여기서 세션이 끊긴다(G8)'),
    (0, 'AA 는 이 경로에 없다 — 서비스는 체인만 읽는다(G9 가용성)'),
], size=17)

bullets('5. 온체인 트랜잭션 — 같은 π_rp 를 계정 컨트랙트에', [
    (0, '계정 주소 = factory.computeAddress(PPID) (CREATE2). 첫 트랜잭션 때 릴레이어가 factory.deploy(PPID) (713k gas)'),
    (0, '지갑: digest = keccak(chainid, wallet, to, value, data, nonce), σ = Sign_sk_i(digest); 캐시 π 첨부'),
    (0, 'execute(payload, σ, a, b, c, pub[14]) — 아무 릴레이어나 제출(권한은 σ 와 π 에 있음)'),
    (0, '컨트랙트 검사: nonce → σ(low-s, v∈{27,28}) → PPID·arid·chainid → pk_AA·pk_trace = 팩토리 값 → allowAgent·BadTag → root = log.root() → 마지막 게시 ≤ 100블록 → block.number ≤ max_height ≤ block.number + 400 → Groth16'),
    (1, '→ nonce+1 → 내부 호출 → Executed·Mode3Auth(pk_i, max_height, allowAgent, tag) 이벤트'),
    (0, '가스 339k(EOA 호출) / 388k(값 전송); 왕복 157 ms. 오프체인과 같은 회로·같은 문장 — 체인이 더하는 것은 "공개성" 뿐'),
], size=17)

bullets('6. 폐기 — 트리 삽입과 체인 게시', [
    (0, '폐기 대상: 성명 하나(리프 Poseidon(TAG, C)) 또는 계정 전체(미만료 성명 리프 전부 + disabled = true)'),
    (1, '관리자 폐기, 또는 사용자 자기 폐기(pwd 로 AA 에 인증 — 지갑 키를 잃어도 가능)'),
    (0, '트리는 append-only 인덱스드 머클 트리(깊이 32). 리프 삽입 → root 변경'),
    (0, '게시: publishRoot(newRoot, epoch, leaves[], sig) — epoch 증가 확인, AA 서명 확인, Revoked 이벤트, lastPublishedBlock 갱신'),
    (1, '리프는 calldata·이벤트로만(저장 안 함): 기본 ≈ 40k gas + 리프당 ≈ 1.1k. 10건 51k'),
    (0, '검증자는 "방금 읽은 root" 만 받는다. 게시 직후 옛 π 는 stale → 재증명. 폐기된 성명은 그때 죽는다'),
    (0, '하트비트: 폐기가 없어도 CIA 가 빈 게시(40k gas)로 lastPublishedBlock 을 갱신. 컨트랙트는 100블록 넘게 조용하면 RootTooOld 로 멈춤(withholding 방어)'),
], size=17)

bullets('7. 승인된 개봉 — 2-of-2 태그', [
    (0, '서비스가 분쟁 세션의 트랜스크립트를 고름: 로그인 로그, 또는 체인의 트랜잭션(txHash → calldata 의 π·공개 입력)'),
    (0, '요청: {arid, PPID, c1, D_svc = x_svc·c1, ts} 를 pk_service 로 서명해 AA 에 → AA 는 서명·신선도·트랜스크립트 검증 후 pending 으로 보관(uid 없음)'),
    (1, '트랜스크립트에 arid·pk_trace 가 묶여 있어 남의 서비스 세션은 못 연다(wrong_arid)'),
    (0, '운영자 승인 → AA: K = D_svc + x_AA·c1, h = c2 − Poseidon(K), Poseidon(uid, arid) = h 인 발급 기록을 역조회 → uid, allowAgent, max_height'),
    (0, '거절이면 denied. 결과는 AA 가 서명해 서비스가 조회'),
    (0, 'AA 혼자도, 서비스 혼자도 못 연다. 승인 전까지 AA 는 로그인별 기록을 아무것도 갖지 않는다'),
], size=18)

H1 = ['단계', 'AA 가 보는 것', '서비스가 보는 것', '체인(누구나)이 보는 것']
W1 = [1.0, 2.4, 2.6, 2.6]
table_slide('누가 무엇을 보는가', H1, [
    ['등록', 'uid, pwd, cm_u, pk_u', '—', '—'],
    ['발급', 'uid, C, chainid, allowAgent, max_height. arid·pk_i·속성·r_s 는 못 봄', '—', '—'],
    ['로그인', '—', 'PPID, pk_i, max_height, chainid, allowAgent, root, tag(암호문), π. uid·s_u·C 는 못 봄', '—'],
    ['트랜잭션', '(공개 입력을 체인에서 읽을 수 있음) — 대조 가능한 건 chainid·allowAgent·양자화 max_height 뿐', '서비스도 같은 공개 입력', 'PPID 계정 주소, pk_i, max_height, allowAgent, tag, π. 발급 기록과 잇는 값은 없음'],
    ['폐기', '리프 = Poseidon(TAG, C)', 'root 만', 'root, epoch, 리프 해시들'],
    ['개봉', '승인 뒤 uid ↔ (arid, PPID, 세션)', 'uid 가 아니라 "이 가명의 계정" 결과', '—'],
], W1, size=12)

H2 = ['무엇', '값']
W2 = [3.0, 4.0]
table_slide('비용 요약 (2026-09-18 실측, N=10 중앙값)', H2, [
    ['로그인 1회 (발급 + 증명 + 검증)', '지갑 왕복 1,394 ms = 동기화 31 + AA 발급 422(π_idp 155 + 검증 164) + π_rp 898; 서비스 검증 39 ms'],
    ['세션 중 요청 / 재검증(캐시 π)', 'ECDSA 서명 1회 / 33 ms'],
    ['root 변경 뒤 재증명', 'π_rp 858 ms (witness 218 + prove 637)'],
    ['온체인 트랜잭션', 'execute 339,341 gas (EOA 호출) / 387,905 (값 전송); 왕복 157 ms; 계정 배포 1회 713,542'],
    ['배포 1회', 'PiCredVerifier 648,683 / Mode3WalletFactory 1,269,466 gas'],
    ['폐기 게시', '리프 10건 50,968 gas; 하트비트(리프 0) 40,261'],
    ['회로', 'π_rp 25,560 제약, zkey 15.5 MB, 증명 722 B, 공개 입력 14; π_idp 는 회로 없음, 증명 1,189 B'],
], W2, size=13)

prs.save(DST); print('saved', DST, len(prs.slides), 'slides')
