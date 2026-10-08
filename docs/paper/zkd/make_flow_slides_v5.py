# zk-Delegation(Mode 3) 전체 플로우 슬라이드 v5 (2026-09-23) — 자격증명 이중 구조(C_u 한 번 / C_s 세션마다, 세션 발급 무증명),
# 선택 공개(V6, 공개 입력 23), 지갑 트리 체크포인트+델타, 서비스의 root 나이 검사 반영. 260918 판(make_flow_slides.py)은 그대로 둔다.
# 교수님 덱(260917_OVERALL.pptx) 템플릿. 실측치: results/mode3_disclosure_bench_20260922.md(V6), results/mode3_onchain_bench_20260921.md(V5),
# results/mode3_rcl_sync_20260923.md(트리 동기화).
from pptx import Presentation
from pptx.util import Emu, Pt

SRC = 'documents/260917_OVERALL.pptx'
DST = 'documents/260923_zkDelegation_flow.pptx'
FIG = 'docs/paper/zkd/fig1_login_v5.png'
FIG_W, FIG_H = 3000, 2618
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
    h = height; w = int(h * FIG_W / FIG_H)
    if w > width: w = width; h = int(w * FIG_H / FIG_W)
    s.shapes.add_picture(path, left + (width - w) // 2, top, w, h)
    return s

title_slide('zk-Delegation 전체 플로우', '등록 → 사용자 자격증명(한 번) → 로그인(세션 발급·증명·검증) → 세션 → 온체인 트랜잭션 → 폐기 → 개봉\n2026-09-23 (feat/mode3-cia @ 48fdb5c)')

H0 = ['당사자', '가지고 있는 것', '역할']
W0 = [1.0, 3.4, 3.0]
table_slide('등장인물과 각자가 쥔 것', H0, [
    ['사용자 / 지갑', 'uid·pwd(AA 계정), 비밀 s_u(등록 커밋의 열쇠), 요청 서명키 sk_u, 사용자 자격증명 C_u(blind_u), 속성 a₁..a₄(AA 기록 사본), 세션마다 (sk_i, pk_i)·C_s(blind_s), 폐기 트리 체크포인트(mode3_wallet_rcl.json), 증명 캐시. 브라우저 데모에서는 등록 비밀을 MetaMask Snap 이 보관', '자격증명·세션 커밋·증명을 만들고, 주소를 유도하고, 트랜잭션에 서명'],
    ['AA (Authentication Authority, CIA)', 'EdDSA 키 pk_AA, 계정 DB {pk_u, cm_u, attrs, disabled, 활성 Cf_u}, 폐기 트리(RCL)와 게시 키, 서비스별 트레이스 조각 x_AA,s. 발급 기록은 없다(세션 단위 기록 없음)', '신원 인증, 사용자 자격증명 검증(π_u), 세션 성명 서명, 속성 관리, 폐기·게시, 승인된 개봉'],
    ['서비스 (RP)', 'arid, cert_s, 서명키 pk_service, 트레이스 조각 x_svc, 세션 테이블, 로그인 로그(비공개), 온체인 팩토리·AttrGate 주소', '챌린지 발급, π_rp 검증(root 나이 포함), 세션 운영, 개봉 요청'],
    ['체인', 'RevocationLog(root, epoch, lastPublishedBlock), PiCredVerifier, Mode3WalletFactory(서비스별, isWallet), Mode3Wallet 계정(CREATE2 salt = PPID), AttrGate(공개 속성 소비 데모)', '폐기 root 의 공개 게시, 트랜잭션마다 π_rp 검증·실행, 공개 속성 꼬리 전달'],
    ['운영자', 'AA 관리 페이지', '서비스 등록 승인, 개봉 승인·거절, 관리자 폐기, 속성 변경'],
], W0, size=12)

picture_slide('한 장으로: 자격증명(0), 로그인(1–6), 트랜잭션(6′), 개봉(7–8)', FIG)

bullets('0. 등록과 사용자 자격증명 — 사용자 한 번, 서비스 한 번', [
    (0, '사용자 등록 (지갑 → AA): uid·pwd 로 인증, cm_u = s_u·G₃ + r_u·H 제출 → AA 는 {pk_u, cm_u, attrs, disabled=false} 저장, sk_u·속성 a₁..a₄ 를 돌려줌. s_u 는 AA 에 가지 않는다'),
    (0, '사용자 자격증명 (지갑 → AA, 사용자당 한 번): C_u = uid·G₁ + s_u·G₃ + Σaₖ·G₄₊ₖ + blind_u·H 와 π_u'),
    (1, 'π_u = PoK{(s_u, blind_u, r_u): C_u − uid·G₁ − Σaₖ·G₄₊ₖ = s_u·G₃ + blind_u·H ∧ cm_u = s_u·G₃ + r_u·H} — uid·aₖ 는 AA 가 자기 기록에서 넣는다(요청에서 받지 않음)'),
    (1, 'AA 는 Cf_u = Poseidon(C_u) 를 계정의 활성 자격증명으로 기록(열림은 기록 안 함). 속성이 바뀌면 옛 Cf_u 리프를 게시하고 다음 로그인에서 새 C_u'),
    (0, '서비스 등록 (서비스 → AA): {name, origin, pk_service, X_svc = x_svc·B8} → 운영자 승인 → arid, pk_trace = X_svc + x_AA·B8, cert_s = Sign_AA(arid, origin, pk_trace)'),
    (1, '트레이스 키가 두 조각의 합이라 어느 한쪽도 혼자 태그를 못 연다. AA 는 자기 조각의 Schnorr PoK 를 함께 둔다(rogue key 차단)'),
    (0, '온체인을 쓰는 서비스는 팩토리를 한 번 배포: 생성자 9인자 (verifier, arid, pk_AA, pk_trace, log, maxRootAge=100, maxLifetime=400) — 하나라도 바뀌면 PPID 주소가 전부 바뀐다'),
], size=17)

bullets('1. 로그인 시작 — 서비스 인증과 챌린지', [
    (0, '서비스 → 지갑: {arid, origin, cert_s, pk_trace, factoryAddress, r_s}. r_s 는 250비트 난수, 서비스가 발급하고 120 s 뒤 만료'),
    (0, '지갑의 검사: cert_s 를 pk_AA 로 검증, 인증서의 origin 이 지금 대화 중인 오리진과 같은지(피싱 방지, G6), pk_trace 가 인증서 값과 같은지'),
    (1, 'factoryAddress 는 온체인에서 arid·log·pk_AA·pk_trace getter 를 읽어 인증서·고정값과 대조(bad_factory). 브라우저 데모는 RP 페이지가 지갑 팝업을 열고 postMessage 오리진을 대조'),
    (0, '챌린지는 사용자가 아니라 서비스가 고른다 — "이 로그인이 무엇을 위한 것인지"는 서비스가 정한다'),
    (0, 'r_s 는 AA 에 절대 가지 않는다. 증명 안에도 들어가지 않고, 세션키 서명 σ = Sign_sk_i(r_s) 로만 묶인다'),
], size=19)

bullets('2. 세션 성명 발급 — 지갑 → AA → 지갑 (ZKP 없음)', [
    (0, '지갑: 세션키 (sk_i, pk_i) 생성(pk_i 는 160비트 주소), blind_s 뽑고 세션 커밋 C_s = arid·G₂ + pk_i·G₄ + blind_s·H'),
    (1, '만료 max_height = ⌈(head + 300)/100⌉·100 — 지갑이 정하고 그리드로 뭉갬(AA 의 시각 상관 완화)'),
    (1, '요청 {uid, Cf_u, C_s, chainid, allowAgent, max_height, sig_u}. sig_u = Sign_sk_u(D_req, Cf_u, C_s, chainid, allowAgent, max_height) — 증명은 없다'),
    (0, 'AA 검사 순서: 형식 → max_height < 2⁶⁴ → 계정·disabled → chainid 허용 → sig_u → Cf_u 가 활성 자격증명 → C_s 부분군 → 체인 생존 → disabled·활성 재확인 → 서명'),
    (1, '왜 증명이 필요 없나: 신원·비밀은 π_u 로 한 번 증명됐고, C_s 의 내용(arid, pk_i)은 π_rp 가 공개 입력에서 다시 계산하므로 AA 가 확인할 것이 없다'),
    (0, 'AA 서명 σ_AA = Sign(Poseidon(D_cred, Cf_u, Cf_s, max_height, chainid, allowAgent)) — 기록 없음(활성 Cf_u 만)'),
    (1, 'AA 가 로그인에서 보는 전부: uid, Cf_u, C_s, chainid, allowAgent, max_height. 서비스·세션키·가명·챌린지는 모른다'),
    (0, '비용: 지갑 왕복 124 ms(AA 안의 계산은 ≈ 30 ms). 옛 방식(세션마다 π_issue)은 422 ms'),
], size=16)

bullets('3. 가명 증명 — 지갑이 π_rp 를 만든다', [
    (0, '체인 동기화(체크포인트+델타, 2026-09-23): 메모리 트리 + 마지막 블록 이후 Revoked 이벤트만 적용 → root 가 컨트랙트와 같아야 사용(다르면 창세기부터 재생 1회)'),
    (1, '1,000 리프에서 전체 재생 141 ms → 델타 1개 40 ms / 델타 0 23 ms. 캐시 파일(mode3_wallet_rcl.json)은 공개 리프뿐 — 지워도 되고 조작해도 root 대조에 걸린다'),
    (0, 'PPID = Poseidon(uid, s_u, chainid, arid) — 서비스·체인마다 다른 가명, 이것이 곧 계정 주소의 salt'),
    (0, '트레이스 태그: r ← [1, 2²⁵⁰), c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)'),
    (0, 'π_rp = Groth16 (25,369 제약, 809 ms): σ_AA over (Cf_u, Cf_s) · C_u 열림(uid, s_u, a) · C_s 를 공개 arid·pk_i 로 재계산 · PPID · Poseidon(4, Cf_u) ∉ Tree(root) · 태그 · 술어(mask, lo, hi)'),
    (1, '공개 입력 23개: PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_AA, pk_trace, tag + disc_mask, disc_lo[4], disc_hi[4]. 로그인은 mask = 0'),
    (0, '지갑 → 서비스: {π, 공개 입력, σ = Sign_sk_i(r_s)}. 증명은 (root, r_s, 공개) 키로 캐시'),
], size=17)

bullets('4. 서비스 검증과 세션', [
    (0, '검사 순서: r_s 소비(먼저) → root·lastPublished·head 읽기(600 s 신선도) → root 일치 → root 나이 ≤ 100 블록(2026-09-23, 온체인과 같은 상한) → head ≤ max_height ≤ head + 400'),
    (1, '→ chainid·pk_AA·arid·pk_trace 가 설정값 → allowAgent ≤ 1, c1 ≠ O, mask < 16 → Groth16 검증(10.7 ms) → σ 검증. 비마스크 슬롯의 lo/hi 는 0 으로 지워 기록'),
    (0, '통과하면 sessions[r_s] = {PPID, pk_i, max_height, allowAgent, root, disclosure}. 사용자 식별자는 PPID. 트랜스크립트는 비공개 로그인 로그에(개봉 재료)'),
    (0, '세션 중 요청: (r_s, body, Sign_sk_i(r_s ‖ body)) — 증명 없이 서명만. 같은 root 나이 상한 적용'),
    (0, '재검증: root 가 그대로면 캐시 π 재사용(31 ms), root 가 바뀌면 revalidate_required → 지갑이 델타를 적용하고 새 root 로 재증명'),
    (1, '폐기된 자격증명은 새 root 에 대한 비멤버십을 못 만든다 → 그 사용자의 모든 세션이 여기서 끊긴다(G8)'),
    (0, 'AA 는 이 경로에 없다 — 서비스는 체인만 읽는다(G9). 다만 AA 가 게시(하트비트)를 100 블록 넘게 멈추면 오프체인 로그인도 root_too_old 로 닫힌다'),
], size=16)

bullets('5. 온체인 트랜잭션 — 같은 π_rp 를 계정 컨트랙트에', [
    (0, '계정 주소 = factory.computeAddress(PPID) (CREATE2). 첫 트랜잭션 때 factory.deploy(PPID) (≈ 852k gas). 브라우저 데모는 MetaMask 가 전송(EOA 노출은 한계)'),
    (0, '지갑: digest = keccak(chainid, wallet, to, value, data, nonce, disc_mask, disc_lo[4], disc_hi[4]), σ = Sign_sk_i(digest); π 첨부(공개 없으면 캐시, 있으면 새 π ≈ 0.8 s)'),
    (0, 'execute(payload, σ, a, b, c, pub[23]) — 아무 릴레이어나 제출(권한은 σ 와 π 에 있음)'),
    (0, '컨트랙트 검사: nonce → σ(low-s, v∈{27,28}) → PPID·arid·chainid → pk_AA·pk_trace = 팩토리 값 → allowAgent·BadTag → root = log.root() → 마지막 게시 ≤ 100블록 → block ≤ max_height ≤ block + 400 → Groth16'),
    (1, '→ nonce+1 → 내부 호출(호출 데이터 끝에 공개 9워드를 항상 붙임; 빈 data·mask 0 만 예외) → Executed·Mode3Auth·Disclosure 이벤트'),
    (0, 'AttrGate: msg.sender 가 팩토리가 만든 계정인지(isWallet) 보고 꼬리 9워드를 읽어 정책(국가 = 410, 출생연도 ≤ 2007) 검사'),
    (0, '가스 402k(캐시 π 호출) / 419k(첫 실행) / 445k(두 슬롯 공개 + AttrGate); 왕복 151 ms. 오프체인과 같은 회로·같은 문장 — 체인이 더하는 것은 "공개성" 뿐'),
], size=16)

bullets('6. 폐기 — 자격증명 단위, 트리 삽입과 체인 게시', [
    (0, '리프 = Poseidon(4, Cf_u) 의 하위 252비트 — 사용자 자격증명당 하나. 성명(세션) 단위 폐기는 없다(AA 가 성명 기록을 갖지 않는다)'),
    (1, '계정 폐기 = 리프 1개 + disabled = true → 그 사용자의 모든 서비스 세션이 다음 root 에서 함께 죽는다. 속성 변경도 같은 리프(자격증명 은퇴)'),
    (1, '관리자 폐기, 또는 사용자 자기 폐기(pwd 로 AA 에 인증 — 지갑 키를 잃어도 가능; 브라우저 데모는 Snap 대화상자 → 에이전트 프록시)'),
    (0, '트리는 append-only 인덱스드 머클 트리(깊이 32). 리프 삽입 → root 변경. 서비스는 리프를 알아볼 수 없다(Cf_u 는 어떤 트랜스크립트에도 없다)'),
    (0, '게시: publishRoot(newRoot, epoch, leaves[], sig) — epoch 증가, AA 서명(로그 주소 포함), Revoked 이벤트, lastPublishedBlock 갱신. 리프 1개 43,888 gas'),
    (0, '검증자는 "방금 읽은 root" 만 받는다. 게시 직후 옛 π 는 stale → 재증명. 폐기된 자격증명은 그때 죽는다'),
    (0, '하트비트: 폐기가 없어도 50블록마다 빈 게시(40,305 gas). 100블록 넘게 조용하면 컨트랙트(RootTooOld)와 서비스(root_too_old)가 함께 멈춤 — 게시가 멈춘 root 는 폐기도 멈춘 root'),
], size=16)

bullets('7. 승인된 개봉 — 2-of-2 태그', [
    (0, '서비스가 분쟁 세션의 트랜스크립트를 고름: 로그인 로그, 또는 체인의 트랜잭션(txHash → calldata 의 π·공개 입력)'),
    (0, '요청: {arid, PPID, c1, D_svc = x_svc·c1, ts} 를 pk_service 로 서명해 AA 에 → AA 는 서명·신선도·트랜스크립트 검증 후 pending 으로 보관(uid 없음)'),
    (1, '트랜스크립트에 arid·pk_trace 가 묶여 있어 남의 서비스 세션은 못 연다(wrong_arid). 중복 판정 키는 (arid, c1, c2, PPID) — 같은 r 을 쓴 다른 사용자와 섞이지 않는다(2026-09-23 점검)'),
    (0, '운영자 승인 → AA: K = D_svc + x_AA·c1, h = c2 − Poseidon(K), Poseidon(uid, arid) = h 인 uid 를 등록부에서 역조회 → uid, allowAgent, max_height'),
    (0, '거절이면 denied. 결과는 AA 가 서명해 서비스가 조회'),
    (0, 'AA 혼자도, 서비스 혼자도 못 연다. 승인 전까지 AA 는 로그인별 기록을 아무것도 갖지 않는다(발급 기록 자체가 없다)'),
], size=18)

H1 = ['단계', 'AA 가 보는 것', '서비스가 보는 것', '체인(누구나)이 보는 것']
W1 = [1.0, 2.6, 2.6, 2.4]
table_slide('누가 무엇을 보는가', H1, [
    ['등록', 'uid, pwd, cm_u, pk_u, 속성(자기 기록)', '—', '—'],
    ['자격증명(1회)', 'uid, C_u, π_u → Cf_u 만 보관', '—', '—'],
    ['세션 발급', 'uid, Cf_u, C_s, chainid, allowAgent, max_height. arid·pk_i·r_s 는 못 봄, 기록 없음', '—', '—'],
    ['로그인', '—', 'PPID, pk_i, max_height, chainid, allowAgent, root, tag(암호문), 공개 술어, π. uid·s_u·C_u·C_s·속성값은 못 봄', '—'],
    ['트랜잭션', '(공개 입력을 체인에서 읽을 수 있음) — 대조 가능한 건 chainid·allowAgent·양자화 max_height·공개 구간뿐', '서비스도 같은 공개 입력', 'PPID 계정 주소, pk_i, max_height, allowAgent, tag, 공개 구간, π. 발급과 잇는 값은 없음'],
    ['폐기', '리프 = Poseidon(4, Cf_u), 사용자당 1', 'root 만', 'root, epoch, 리프 해시들'],
    ['개봉', '승인 뒤 uid ↔ (arid, PPID, 세션)', 'uid 가 아니라 "이 가명의 계정" 결과', '—'],
], W1, size=12)

H2 = ['무엇', '값']
W2 = [3.0, 4.0]
table_slide('비용 요약 (2026-09-22·23 실측, N=10 중앙값)', H2, [
    ['사용자 자격증명 π_u (사용자당 1회)', '증명 80 ms / 검증 99 ms (시그마, 회로 없음)'],
    ['로그인 1회 (세션 발급 + 증명 + 검증)', '지갑 왕복 1,054 ms = 동기화 29 + AA 세션 발급 124(AA 계산 ≈ 30) + π_rp ≈ 810; 서비스 검증 38 ms'],
    ['세션 중 요청 / 재검증(캐시 π)', 'ECDSA 서명 1회 / 31 ms'],
    ['root 변경 뒤 재증명', 'π_rp 809 ms (witness 203 + prove 609), 검증 10.7 ms'],
    ['지갑 트리 동기화 (1,000 리프)', '전체 재생 141 ms → 델타 1개 40 ms / 델타 0 23 ms (체크포인트+델타)'],
    ['온체인 트랜잭션', 'execute 402,130 gas (캐시 π) / 419,262 (첫 실행) / 444,509 (두 슬롯 공개 + AttrGate); 왕복 151 ms(캐시) · 1,000 ms(새 π); 계정 배포 852,198'],
    ['배포 1회', 'PiCredVerifier ≈ 649k / Mode3WalletFactory ≈ 1,269k gas'],
    ['폐기 게시', '리프 1개 43,888 gas; 하트비트(리프 0) 40,305'],
    ['회로', 'π_rp 25,369 제약, 공개 입력 23, zkey 15.4 MB, 증명 722 B'],
], W2, size=12)

prs.save(DST); print('saved', DST, len(prs.slides), 'slides')
