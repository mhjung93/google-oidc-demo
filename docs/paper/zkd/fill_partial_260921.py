# documents/260921_partial.pptx(사용자 뼈대)를 채운다 → documents/260921_partial_filled.pptx. 원본은 건드리지 않는다.
# 내용 기준: 스펙 2026-09-21(자격증명 이중 구조 C_u/C_s, Pedersen 유지), 형식 문서 security_formal.md(G1–G10), 실측 2026-09-21(V5).
# 2026-09-21 밤 개정: V5 실측 반영, 동기 슬라이드·비교표 추가, Overall Flow 앞으로, Properties 2장 분할, 제목 서식 통일, AA 조각 PoK 반영.
from pptx import Presentation
from pptx.util import Emu, Pt, Inches
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE, MSO_CONNECTOR
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn
import copy

SRC = 'documents/260921_partial.pptx'
DST = 'documents/260921_partial_filled.pptx'
prs = Presentation(SRC)
IN = 914400
BLACK = RGBColor(0, 0, 0); GREY = RGBColor(0x55, 0x55, 0x55); RED = RGBColor(0xC0, 0x00, 0x30); BLUE = RGBColor(0x1F, 0x4E, 0x9A)
GREEN = RGBColor(0x1A, 0x7F, 0x37); LIGHT = RGBColor(0xF2, 0xF2, 0xF2); PALE = RGBColor(0xE8, 0xF0, 0xFB); PINK = RGBColor(0xFB, 0xE8, 0xEC)

# ---------- 공통 헬퍼 ----------
def body(slide):
    for ph in slide.placeholders:
        if ph.placeholder_format.idx == 1: return ph
    return None

def set_bullets(ph, items, size=18):
    tf = ph.text_frame; tf.clear(); first = True
    for lvl, txt in items:
        p = tf.paragraphs[0] if first else tf.add_paragraph(); first = False
        p.text = txt; p.level = lvl
        for r in p.runs: r.font.size = Pt(size - 2 * lvl)

def remove_shape(sh):
    sh._element.getparent().remove(sh._element)

def clear_body_keep_title(slide, drop_math_title=False):
    """본문 개체 틀은 지우고(자리만 쓰려고) 제목·번호는 둔다. drop_math_title 이면 수식(mc:AlternateContent)으로 된 제목도 지운다."""
    for sh in list(slide.shapes):
        if sh.is_placeholder and sh.placeholder_format.idx == 1: remove_shape(sh)
        elif sh.shape_type == 6: remove_shape(sh)   # 옛 덱에서 복사된 그룹 그림
    if drop_math_title:
        tree = slide.shapes._spTree
        for ch in list(tree):
            if ch.tag.endswith('}AlternateContent'): tree.remove(ch)   # python-pptx 가 열거하지 않는 수식 제목(거대한 Π_IdP 등)

def box(slide, x, y, w, h, text, size=11, fill=None, bold=False, color=BLACK, align=PP_ALIGN.CENTER, shape=MSO_SHAPE.RECTANGLE, line=True, italic=False, anchor=MSO_ANCHOR.MIDDLE):
    s = slide.shapes.add_shape(shape, Emu(x), Emu(y), Emu(w), Emu(h))
    if fill is None: s.fill.background()
    else: s.fill.solid(); s.fill.fore_color.rgb = fill
    if line: s.line.color.rgb = RGBColor(0x40, 0x40, 0x40); s.line.width = Pt(0.75)
    else: s.line.fill.background()
    s.shadow.inherit = False
    tf = s.text_frame; tf.word_wrap = True; tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Emu(45720); tf.margin_top = tf.margin_bottom = Emu(22860)
    lines = text.split('\n')
    for i, ln in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run(); r.text = ln; r.font.size = Pt(size); r.font.bold = bold; r.font.italic = italic; r.font.color.rgb = color
    return s

def label(slide, x, y, w, h, text, size=11, bold=False, color=BLACK, align=PP_ALIGN.LEFT, italic=False):
    return box(slide, x, y, w, h, text, size=size, bold=bold, color=color, align=align, line=False, italic=italic)

def arrow(slide, x1, y1, x2, y2, color=RGBColor(0x40, 0x40, 0x40), width=1.0, dashed=False):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Emu(x1), Emu(y1), Emu(x2), Emu(y2))
    c.line.color.rgb = color; c.line.width = Pt(width)
    ln = c.line._get_or_add_ln()
    tail = ln.makeelement(qn('a:tailEnd'), {'type': 'triangle', 'w': 'med', 'len': 'med'}); ln.append(tail)
    if dashed:
        d = ln.makeelement(qn('a:prstDash'), {'val': 'dash'}); ln.insert(0, d)
    return c

def table(slide, x, y, w, h, header, rows, widths, size=11, header_fill=RGBColor(0x1F, 0x4E, 0x9A)):
    tbl = slide.shapes.add_table(len(rows) + 1, len(header), Emu(x), Emu(y), Emu(w), Emu(h)).table
    total = sum(widths)
    for j, cw in enumerate(widths): tbl.columns[j].width = Emu(int(w * cw / total))
    # 머리글 행은 낮게, 나머지는 남은 높이를 균등 분배 (기본은 전 행 균등이라 머리글이 본문만큼 커진다)
    hh = min(400000, h // (len(rows) + 1)); tbl.rows[0].height = Emu(hh)
    for i in range(1, len(rows) + 1): tbl.rows[i].height = Emu((h - hh) // len(rows))
    def put(cell, text, bold=False, sz=size, fill=None, fg=BLACK):
        cell.text = ''; tf = cell.text_frame; tf.word_wrap = True
        for i, ln in enumerate(text.split('\n')):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph(); p.text = ln
            for r in p.runs: r.font.size = Pt(sz); r.font.bold = bold; r.font.color.rgb = fg
        cell.margin_left = cell.margin_right = Emu(45720); cell.margin_top = cell.margin_bottom = Emu(18000)
        if fill is not None: cell.fill.solid(); cell.fill.fore_color.rgb = fill
    for j, hd in enumerate(header): put(tbl.cell(0, j), hd, bold=True, fill=header_fill, fg=RGBColor(0xFF, 0xFF, 0xFF))
    for i, row in enumerate(rows, 1):
        for j, v in enumerate(row): put(tbl.cell(i, j), v, bold=(j == 0), fill=(LIGHT if i % 2 == 0 else RGBColor(0xFF, 0xFF, 0xFF)))
    return tbl

S = list(prs.slides)   # 표기 슬라이드를 끼워 넣어도 원래 인덱스가 유지되도록 스냅샷
X0, Y0, W0, H0 = 335359, 1442195, 11521282, 4351338   # 본문 개체 틀 영역
LAY = [l for l in prs.slide_layouts if l.name == '제목 및 내용'][0]
TITLE_SP = [sh for sh in S[1].shapes if sh.is_placeholder and sh.placeholder_format.idx == 0][0]._element

def set_title(slide, text, height=None):
    """템플릿 제목 개체 틀을 그대로 복제해 넣는다 — 수식 제목이던 슬라이드(π_u·π_rp·트랜잭션)도 다른 장과 같은 서식이 된다."""
    el = copy.deepcopy(TITLE_SP); slide.shapes._spTree.append(el)
    sh = slide.shapes[-1]; sh.text_frame.text = text
    # 개체 틀은 xfrm 이 없어 레이아웃 값을 상속한다 — 하나만 바꾸면 나머지가 0 이 되므로 넷을 다 적는다
    sh.left, sh.top, sh.width = Emu(335359), Emu(116632), Emu(11521282)
    sh.height = Emu(height or 1325563)
    return sh

def new_slide(title):
    g = prs.slides.add_slide(LAY)
    g.shapes.title.text = title
    for ph in list(g.placeholders):
        if ph.placeholder_format.idx == 1: remove_shape(ph)
    return g

# ---------- 1.5 표기 (표지 다음에 끼워 넣는다) ----------
g = new_slide('표기 (이 덱에서 쓰는 기호)'); G_NOTATION = g
table(g, X0, Y0 - 250000, W0 // 2 - 60000, 4900000,
      ['기호', '뜻'],
      [['uid', '사용자 ID. AA 계정 식별자(이메일 같은 것). AA 는 안다'],
       ['s_u', '사용자 비밀값(salt). 지갑만 안다. 주소를 AA 가 못 만들게 하는 값'],
       ['a₁..a₄', '사용자 속성 4슬롯(예: 생년, 국가). 사용자가 채우고 AA 는 못 본다'],
       ['cm_u', '등록 때 AA 에 낸 s_u 의 커밋. 이후 모든 자격증명이 같은 s_u 임을 여기에 대조'],
       ['C_u', '사용자 자격증명 커밋 = Commit(uid, s_u, a₁..a₄; blind_u). 사용자당 하나'],
       ['C_s', '세션 커밋 = Commit(arid, pk_i; blind_s). 로그인마다 새로'],
       ['Cf_u, Cf_s', 'C_u, C_s(곡선 점)를 Poseidon 으로 압축한 값 하나. 서명·리프에 쓴다'],
       ['blind_u, blind_s', '커밋 블라인딩 난수. 커밋을 숨기는 값'],
       ['sk_u / pk_u', '등록 때 AA 가 준 사용자 요청 서명키 쌍. AA 에 보내는 요청에 서명'],
       ['sig_u', '지갑이 AA 에 보내는 요청의 서명(sk_u 로)'],
       ['σ_AA (sigma)', 'AA 가 세션마다 내주는 서명. (Cf_u, Cf_s, max_height, chainid, allowAgent) 를 덮는다'],
       ['pk_AA', 'AA 의 서명 검증키(EdDSA)']],
      [1.2, 4.0], size=9)
table(g, X0 + W0 // 2 + 60000, Y0 - 250000, W0 // 2 - 60000, 4900000,
      ['기호', '뜻'],
      [['arid', '서비스(RP) ID. AA 가 서비스 등록 때 배정'],
       ['pk_i / sk_i', '세션 키 쌍(secp256k1). pk_i 는 이더리움 주소 형식. 로그인마다 새로'],
       ['r_s', '서비스가 로그인마다 주는 챌린지(난수). 증명 밖에서 sk_i 로 서명'],
       ['chainid', '체인 ID. 주소·서명이 어느 체인 것인지'],
       ['max_height', '만료 블록 높이. 지갑이 정하고 AA 가 서명, 검증자가 상한(L) 검사'],
       ['allowAgent', 'AI 에이전트 허용 플래그(0/1). 세션마다 사용자가 고름'],
       ['PPID', '가명(pseudonym) = Poseidon(uid, s_u, chainid, arid). 서비스가 보는 사용자 이름이자 온체인 계정 주소의 salt'],
       ['RCL / root', '폐기 목록(revoked credential list). 인덱스드 머클 트리. root 는 체인에 게시'],
       ['leaf', '폐기 트리 리프 = Poseidon(4, Cf_u). 사용자 자격증명당 하나'],
       ['NM path', '비멤버십(non-membership) 경로 — 내 리프가 트리에 없다는 증인'],
       ['pk_trace, x_svc, x_AA', '추적 태그 키 = 서비스 조각 + AA 조각. 둘 다 있어야 태그를 연다. AA 조각 X_AA 는 Schnorr 지식 증명과 함께 서비스에 전달'],
       ['tag (c1, c2), r', '추적 태그 암호문과 그 난수. 개봉 때 uid 로 돌아간다'],
       ['π_u, π_rp', 'AA 제출용 증명(시그마), RP 제출용 증명(Groth16)'],
       ['D_*', '도메인 태그 상수(어떤 용도의 해시인지 구분)']],
      [1.3, 4.0], size=9)
# ---------- 1.7 왜 자격증명을 둘로 나눴나 (새 장) ----------
m = new_slide('왜 자격증명을 둘로 나눴나 — V4 → V5'); G_MOTIVE = m
label(m, X0, Y0 - 250000, W0, 380000, 'V4 는 세션마다 커밋 하나에 사용자·세션 속성을 다 넣고 AA 에 ZKP 를 냈다. V5 는 세션과 무관한 사용자 속성을 한 번만 증명하고, 세션은 서명만 받는다.', size=14)
table(m, X0, Y0 + 200000, W0, 3000000,
      ['', 'V4 (2026-09-18)', 'V5 자격증명 이중 구조 (2026-09-21)'],
      [['커밋', '세션마다 C = Commit(uid, s_u, arid, pk_i, a₁..a₄; blind) 하나', '사용자당 C_u = Commit(uid, s_u, a₁..a₄; blind_u) 하나 + 세션마다 C_s = Commit(arid, pk_i; blind_s)'],
       ['AA 제출 ZKP', '세션마다 π_issue(시그마): C 가 인증된 uid·등록된 s_u 로 만들어졌다', '사용자당 한 번 π_u(시그마). 세션 발급은 요청 서명 sig_u + 활성 C_u 조회만 — ZKP 없음'],
       ['AA 서명', 'Sign(도메인, Cf, max_height, chainid, allowAgent)', 'Sign(도메인, Cf_u, Cf_s, max_height, chainid, allowAgent) — 서명 하나가 두 커밋을 덮는다'],
       ['폐기 리프', '세션마다 Poseidon(3, Cf) — 계정 폐기 = 활성 세션 수만큼 리프', '사용자당 Poseidon(4, Cf_u) 하나 — 리프 하나로 전 세션 무효'],
       ['속성 변경', '다음 세션부터 자동(매번 새 C)', '새 C_u 발급 + 옛 리프 게시(속성 변경 시각이 게시로 드러남 — 한계)'],
       ['실측 (N=10 중앙값)', '세션 발급 422 ms, 로그인 1,394 ms, 제약 25,560', '세션 발급 124 ms, 로그인 1,073 ms(π_u 122 ms 는 첫 로그인만), 제약 26,601 (+4%)']],
      [1.2, 3.3, 4.5], size=11)
label(m, X0, Y0 + 3350000, W0, 900000,
      '무엇이 같은가: 서비스가 보는 것(π_rp 공개 입력 14개), 가명 PPID, 온체인 검사, 조건부 추적. 보안 불변식(스펙 §2 a–g)은 그대로 성립한다.\n'
      '왜 C_s 를 여전히 AA 가 서명하나: 세션키·서비스 ID 가 AA 서명 아래 있어야 남의 세션 자격증명을 자기 키로 못 쓴다(②). AA 는 C_s 를 열지 못하므로 pk_i·arid 는 여전히 못 본다.',
      size=11, color=GREY)


# ---------- 2. Attributes ----------
s = S[1]; clear_body_keep_title(s)
label(s, X0, Y0, W0, 380000, '속성을 세션과 무관한 사용자 속성과 세션 속성으로 나눈다. AA 는 사용자 속성으로 만든 자격증명 하나(사용자당 하나)를 관리하고, 세션 속성은 세션마다 서명한다.', size=14)
table(s, X0, Y0 + 430000, W0, 1500000,
      ['', '사용자 속성 (user attribute)', '세션 속성 (AA attribute)'],
      [['담기는 값', 'uid(사용자 ID), s_u(사용자 비밀값·salt), a₁..a₄(사용자 속성 4개)', 'arid(서비스 ID), pk_i(세션 공개키), max_height(만료 블록), allowAgent(에이전트 허용 플래그)'],
       ['커밋', 'C_u = uid·G₁ + s_u·G₃ + Σaₖ·G₄₊ₖ + blind_u·H   (Pedersen, 사용자당 하나)', 'C_s = arid·G₂ + pk_i·G₄ + blind_s·H   (Pedersen, 세션마다).  max_height·allowAgent 는 평문'],
       ['AA 가 보는 것', 'uid 와 커밋 C_u 만  (s_u·속성·blind_u 는 못 봄)', '커밋 C_s, max_height, chainid, allowAgent  (세션 공개키 pk_i 는 못 봄)'],
       ['수명', '폐기될 때까지(속성 바꾸면 새 C_u)', '세션 하나(max_height 까지)']],
      [1.0, 3.2, 3.2], size=11)
label(s, X0, Y0 + 2010000, W0, 300000, 'AA 세션 서명 σ_AA = Sign(도메인, Cf_u(사용자 커밋 압축), Cf_s(세션 커밋 압축), max_height, chainid, allowAgent)  — 서명 하나가 두 커밋을 덮는다', size=12, bold=True, color=BLUE)
label(s, X0, Y0 + 2330000, W0, 300000, '폐기 트리(RCL) 리프 = Poseidon(태그 4, Cf_u)  — 사용자 자격증명당 리프 하나. 이 리프를 넣어 게시하면 그 사용자의 모든 세션이 무효가 된다.', size=12, bold=True, color=RED)
set_items = [
    (0, '세션 공개키를 AA 에게 평문으로 주지 않는 이유: 온체인 공개 입력에 pk_i 가 그대로 나가므로, AA 가 발급 때 pk_i 를 봤다면 트랜잭션 ↔ uid 가 바로 이어진다. 커밋 안에 두면 AA 는 "커밋된 세션키가 있다"만 안다.'),
    (0, 'C_s 를 Pedersen 으로 두는 이유: C_u 와 같은 스킴(가정 하나), 정보이론적 hiding, 나중에 C_s 위 시그마 증명 가능. 비용은 스칼라곱 3개(≈4k 제약). Poseidon(arid, pk_i, r) 이면 ≈240 제약이지만 대수 구조가 없다.'),
    (0, 'C_s 에 arid 가 있는 이유: 같은 세션키를 두 서비스에 쓰면 pk_i 로 이어진다 → 세션 자격증명을 서비스에 묶는다.'),
]
tb = s.shapes.add_textbox(Emu(X0), Emu(Y0 + 2700000), Emu(W0), Emu(1650000)); tf = tb.text_frame; tf.word_wrap = True
for i, (lvl, t) in enumerate(set_items):
    p = tf.paragraphs[0] if i == 0 else tf.add_paragraph(); p.text = '• ' + t
    for r in p.runs: r.font.size = Pt(12)

# ---------- 3. ZKPs 개관 ----------
s = S[2]; clear_body_keep_title(s)
label(s, X0, Y0, W0, 380000, '증명은 두 종류, 검증자는 셋. 트랜잭션 첨부용은 새 증명이 아니라 로그인 때 만든 π_rp 를 그대로 다시 낸다.', size=14)
table(s, X0, Y0 + 430000, W0, 2600000,
      ['', 'π_u  (AA 제출용)', 'π_rp  (RP 제출용)', '트랜잭션 첨부용'],
      [['언제', '사용자 자격증명 발급 — 첫 로그인, 속성 변경 때만', '로그인·재검증마다(캐시)', '트랜잭션마다 첨부(캐시 π 재사용)'],
       ['종류', '시그마 프로토콜(Fiat–Shamir). 회로·셋업 없음', 'Groth16 (BN254), circom', 'π_rp 와 동일한 증명'],
       ['공개 입력', 'uid(사용자 ID), C_u(사용자 커밋), cm_u(등록 커밋)', 'PPID(가명), arid(서비스 ID), pk_i(세션 공개키), max_height(만료), chainid, allowAgent, root(폐기 트리 루트), pk_AA(AA 키), pk_trace(추적 키), tag(추적 태그 c1,c2) — 14개', '같음 + 트랜잭션 내용(to, value, data, nonce)'],
       ['증명하는 것', '사용자 커밋 C_u 가 인증된 uid 와 등록 때의 비밀값 s_u 로 만들어졌다', 'AA 서명이 (C_u, C_s, 만료, 체인, 플래그)를 덮고, 가명 PPID 가 그 안의 (uid, s_u) 에서 나왔고, C_u 의 리프가 폐기 트리에 없고, 추적 태그가 같은 uid 로 만들어졌다', '같음. 증명 밖에서 세션키 서명 σ = Sign_sk_i(keccak(체인, 계정, to, value, data, nonce))'],
       ['검증자가 얻는 것', '"이 커밋은 이 사용자 것" — 서비스 ID·세션키·속성은 모름', '가명·세션키·만료·태그. 사용자 ID·비밀값·커밋 내용은 모름', '계정 컨트랙트(Mode3Wallet)가 같은 검사 + nonce·Groth16 을 온체인에서'],
       ['세션 발급에 ZKP?', '없음 — 요청 서명 sig_u + 활성 C_u 조회만', '', '']],
      [1.1, 2.4, 3.2, 2.6], size=10)
label(s, X0, Y0 + 3120000, W0, 1200000,
      '왜 둘로 합쳐졌나: 온체인 공개 입력은 AA 도 읽으므로 r_s·auid_i·H(C)·nonce 를 공개 입력에서 뺐고, 그러자 로그인 문장과 트랜잭션 문장이 같아졌다. r_s 와 nonce 는 세션키 서명 σ 로 증명 밖에서 묶는다.\n'
      '왜 π_u 에는 폐기 비멤버십이 없나: RCL 은 폐기 목록이고 발급 때 아무것도 넣지 않는다. C_u 는 이 요청에서 처음 생기므로 증명할 대상이 없고, 계정 상태는 AA 가 자기 DB(disabled)로 본다.',
      size=11, color=GREY)

# ---------- 4. π_u ----------
s = S[3]; clear_body_keep_title(s, drop_math_title=True)
for sh in list(s.shapes):
    if sh.has_text_frame and not sh.is_placeholder: remove_shape(sh)
set_title(s, 'π_u — AA 제출용 (사용자 자격증명 발급)', height=750000)
label(s, X0, 860000, W0, 300000, '시그마 프로토콜(Fiat–Shamir, Baby Jubjub). 회로·zkey·신뢰 셋업 없음. 증명 122 ms / 검증 141 ms(2026-09-21 실측, 지수승 9개). 사용자당 한 번 — 속성이 바뀔 때만 다시 만든다.', size=12, color=GREY)
# 왼쪽: 공개 / 증인
LW1, LW2, LW3 = 3050000, 4900000, 3300000; GX1 = X0 + LW1 + 130000; GX2 = GX1 + LW2 + 130000
box(s, X0, 1250000, LW1, 330000, '공개 (AA 도 안다)', size=12, bold=True, fill=PALE)
box(s, X0, 1580000, LW1, 1150000, 'uid — 사용자 ID(인증에 쓴 계정)\nC_u — 지갑이 낸 사용자 자격증명 커밋(곡선 점)\ncm_u — 등록 때 낸 비밀값 s_u 의 커밋', size=12, align=PP_ALIGN.LEFT)
box(s, X0, 2880000, LW1, 330000, '비공개 증인 (지갑만)', size=12, bold=True, fill=PINK)
box(s, X0, 3210000, LW1, 1250000, 's_u — 사용자 비밀값(salt)\na₁..a₄ — 사용자 속성 4개\nblind_u — C_u 의 블라인딩 난수\nr_u — cm_u 의 블라인딩 난수', size=12, align=PP_ALIGN.LEFT)
# 가운데: 관계
box(s, GX1, 1250000, LW2, 330000, '증명하는 관계 (PoK)', size=12, bold=True, fill=LIGHT)
box(s, GX1, 1580000, LW2, 1600000,
    'C_u = uid·G_UID + s_u·G_SU + a₁·G_A0 + a₂·G_A1 + a₃·G_A2 + a₄·G_A3 + blind_u·H\n∧  cm_u = s_u·G_SU + r_u·H          (G_*, H 는 고정 생성원)\n두 식의 s_u 가 같다 — "등록 때 고정한 비밀값과 같은 값으로 커밋했다"가 핵심(사용자당 주소 하나, G2)',
    size=12, align=PP_ALIGN.LEFT)
box(s, GX1, 3280000, LW2, 1180000,
    '프로토콜: 지갑이 T1, T2(무작위 커밋) → c = Poseidon(D_USERCRED, uid, C_u, cm_u, T1, T2) → 응답 z_su, z_attr[4], z_blind, z_ru\n'
    'AA 검증: 점 4개 부분군 검사 → z < ℓ → c 재계산 → 두 등식\n  z_su·G_SU + Σz_attr·G_A + z_blind·H = T1 + c·(C_u − uid·G_UID),   z_su·G_SU + z_ru·H = T2 + c·cm_u',
    size=11, align=PP_ALIGN.LEFT)
# 오른쪽: AA 가 하는 일
box(s, GX2, 1250000, LW3, 330000, 'AA 의 처리 (/cia/user_cred)', size=12, bold=True, fill=LIGHT)
box(s, GX2, 1580000, LW3, 2880000,
    '1. 형식 → 계정 존재·비활성(disabled) 아님\n2. C_u 가 올바른 곡선 점인지\n3. 요청 서명 sig_u = Sign_sk_u(도메인, C_u) 검증\n4. π_u 검증\n5. 기록: 사용자의 자격증명 목록 ← {Cf_u, 리프 = Poseidon(4, Cf_u)}\n    이미 활성 C_u 가 있으면 그 리프를 다음 게시 대기열(pending)에 (속성 변경)\n6. 응답 {Cf_u, 리프}.  AA 서명은 없다 — 세션 서명이 Cf_u 를 덮는다',
    size=11, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP)
label(s, X0, 4600000, W0, 700000,
      'AA 가 알게 되는 것: "C_u 는 이 사용자 ID 와 등록된 비밀값으로 만들어졌다" 뿐. 서비스 ID·세션키는 이 커밋에 없고, 비밀값·속성·블라인드는 커밋의 hiding 으로 숨는다(G4·G5).\n'
      '덱 13장의 auid 대조를 커밋 등식으로 바꾼 것. 발급 요청 인증은 비밀번호가 아니라 등록 키 sk_u 의 서명(비밀번호는 등록·자기 폐기에만).',
      size=11, color=GREY)

# ---------- 5. π_rp ----------
s = S[4]; clear_body_keep_title(s, drop_math_title=True)
for sh in list(s.shapes):
    if sh.has_text_frame and not sh.is_placeholder: remove_shape(sh)
set_title(s, 'π_rp — RP 제출용 (로그인·재검증)', height=750000)
label(s, X0, 860000, W0, 300000, 'Groth16(BN254), 26,601 제약(V5; V4 25,560). 증명 860 ms, 검증 11.5 ms(2026-09-21 실측). 공개 입력 14개의 순서는 서비스·컨트랙트가 의존한다.', size=12, color=GREY)
# 회로 상자
CX, CY, CW, CH = X0 + 2200000, 1870000, 7100000, 3250000
box(s, CX, CY, CW, CH, '', line=True)
# 비공개 증인 (위)
wit = ['uid\n사용자 ID', 's_u\n비밀값', 'a₁..a₄\n속성', 'blind_u\n블라인드', 'blind_s\n블라인드', 'σ_AA\nAA 서명', 'r\n태그 난수', 'NM path\n비멤버십 경로']
ww = CW // len(wit)
for i, w in enumerate(wit):
    label(s, CX + i * ww, CY - 420000, ww, 380000, w, size=8, bold=True, align=PP_ALIGN.CENTER, color=RED)
    arrow(s, CX + i * ww + ww // 2, CY - 40000, CX + i * ww + ww // 2, CY + 60000, color=RED)
label(s, CX, CY - 680000, CW, 260000, '비공개 증인 (지갑만 안다)', size=11, bold=True, align=PP_ALIGN.CENTER, color=RED)
# 공개 입력 (왼쪽)
pubs = ['PPID (가명)', 'arid (서비스 ID)', 'pk_i (세션 공개키)', 'max_height (만료)', 'chainid (체인)', 'allowAgent (플래그)', 'root (폐기 트리)', 'pk_AA (AA 키)', 'pk_trace (추적 키)', 'tag c1, c2 (태그)']
ph_ = CH // len(pubs)
label(s, X0, CY - 330000, 2000000, 300000, '공개 입력 (검증자가 본다, 14개)', size=11, bold=True, color=BLUE)
for i, pname in enumerate(pubs):
    label(s, X0 - 100000, CY + i * ph_, 1650000, ph_, pname, size=9, color=BLUE, align=PP_ALIGN.RIGHT)
    arrow(s, X0 + 1550000, CY + i * ph_ + ph_ // 2, CX + 20000, CY + i * ph_ + ph_ // 2, color=BLUE)
# 내부 블록
bw, bh = 1550000, 520000
blocks = [
    (CX + 150000,  CY + 150000,  '사용자 커밋 재계산\nC_u ← (uid, s_u, 속성, blind_u)\nCf_u = Poseidon(C_u)', PALE),
    (CX + 1850000, CY + 150000,  '세션 커밋 재계산\nC_s ← (공개 arid, 공개 pk_i, blind_s)\nCf_s = Poseidon(C_s)', PALE),
    (CX + 3550000, CY + 150000,  'AA 서명 검증 (EdDSA)\n키 pk_AA, 서명 σ_AA, 메시지 =\nPoseidon(도메인, Cf_u, Cf_s, max_height, chainid, allowAgent)', PINK),
    (CX + 5250000, CY + 150000,  '범위 검사\npk_i < 2¹⁶⁰, max_height < 2⁶⁴,\nallowAgent ∈ {0,1}, r ≠ 0, 스칼라 < 2²⁵⁰', LIGHT),
    (CX + 150000,  CY + 1500000, '가명 유도\nPPID == Poseidon(uid, s_u, chainid, arid)', PALE),
    (CX + 1850000, CY + 1500000, '폐기 비멤버십 (트리 깊이 32)\n리프 = Poseidon(4, Cf_u)\n리프 ∉ Tree(root)', PINK),
    (CX + 3550000, CY + 1500000, '추적 태그 생성\nc1 = r·B8\nc2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)', PALE),
    (CX + 5250000, CY + 1500000, '출력 대조\n공개 입력 tag c1, c2 == 계산값\n(다르면 증명 실패)', LIGHT),
]
for (bx, by, bt, bf) in blocks:
    box(s, bx, by, bw, 900000 if by == CY + 150000 else 900000, bt, size=9, fill=bf, align=PP_ALIGN.LEFT)
arrow(s, CX + 925000, CY + 1050000, CX + 925000, CY + 1500000)        # CommitUser → Pseudonym(uid,s_u 공유)
arrow(s, CX + 1700000, CY + 600000, CX + 1850000, CY + 600000)        # C_u → C_s (그림상 흐름)
arrow(s, CX + 3400000, CY + 600000, CX + 3550000, CY + 600000)        # → SigVerify
arrow(s, CX + 2625000, CY + 1050000, CX + 2625000, CY + 1500000)      # Cf_u → NonMembership
arrow(s, CX + 4325000, CY + 1050000, CX + 4325000, CY + 1500000)      # → TraceTag (uid)
arrow(s, CX + 5100000, CY + 1950000, CX + 5250000, CY + 1950000)      # TraceTag → 대조
label(s, CX + 150000, CY + 2500000, CW - 300000, 700000,
      '조건 ①~⑥: AA 서명(①) · 커밋 재계산으로 공개 세션키·서비스 ID 바인딩(②) · 가명 유도(③) · 폐기 비멤버십(④) · 추적 태그(⑤) · 범위(⑥).\n'
      '증명 밖: σ = Sign_sk_i(r_s) — 서비스가 준 챌린지에 대한 세션키 서명. 지갑은 (root, r_s) 키로 증명을 캐시하고 root 가 바뀔 때만 다시 만든다.',
      size=10, color=GREY)
label(s, X0, CY + CH + 100000, W0, 600000,
      '서비스 검사 순서: 챌린지 r_s 소비 → 체인에서 root·현재 블록 읽기 → root 일치 → 현재 블록 ≤ max_height ≤ 현재 블록 + L → chainid·pk_AA·arid·pk_trace 가 설정값 → allowAgent ≤ 1, c1 이 항등원 아님 → Groth16 검증 → 세션키 서명 σ.  통과하면 세션 테이블에 {PPID, pk_i, max_height, allowAgent, root}.',
      size=10, color=GREY)

# ---------- 6. 트랜잭션 첨부 ----------
s = S[5]; clear_body_keep_title(s, drop_math_title=True)
for sh in list(s.shapes):
    if sh.has_text_frame and not sh.is_placeholder: remove_shape(sh)
set_title(s, '트랜잭션 첨부용 — 같은 π_rp 를 계정 컨트랙트에', height=750000)
label(s, X0, 860000, W0, 300000, '새 증명이 아니다. 로그인 때 만든 π_rp(공개 입력 14개 포함)를 execute() 에 그대로 첨부하고, 권한은 세션키 서명 σ 가 payload·nonce 를 덮는 것으로 준다.', size=12, color=GREY)
# 왼쪽: 지갑
box(s, X0, 1200000, 3300000, 330000, '지갑 (트랜잭션마다)', size=12, bold=True, fill=PALE)
box(s, X0, 1530000, 3300000, 3050000,
    '1. 체인 동기화 → 현재 root. 캐시에 (root, r_s) 의 증명이 있으면 재사용, 없으면 π_rp 재증명(860 ms)\n'
    '2. 계정 주소 = factory.computeAddress(PPID)  (CREATE2). 코드가 없으면 릴레이어가 deploy(PPID)\n'
    '3. nonce = 계정 컨트랙트의 현재 nonce\n'
    '4. digest = keccak(chainid, 계정 주소, to, value, data, nonce);  σ = Sign_sk_i(digest)  (세션키 서명)\n'
    '5. execute(payload, σ, 증명(a, b, c), 공개 입력 14개) 를 릴레이어로 제출',
    size=11, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP)
arrow(s, X0 + 3300000, 2450000, X0 + 3650000, 2450000, width=1.5)
label(s, X0 + 3250000, 2050000, 500000, 300000, 'tx', size=10, bold=True, align=PP_ALIGN.CENTER)
# 가운데: 컨트랙트
box(s, X0 + 3700000, 1200000, 4300000, 330000, 'Mode3Wallet.execute() 검사 순서 (같은 문장, 검증자만 다르다)', size=12, bold=True, fill=PINK)
box(s, X0 + 3700000, 1530000, 4300000, 3050000,
    '① nonce 가 저장된 값과 같은가\n'
    '② 세션키 서명 σ: ecrecover(digest) == 공개 입력의 pk_i, low-s, v ∈ {27, 28}, 0 아님\n'
    '③ 공개 입력의 PPID·arid·chainid == 이 계정에 새겨진 값\n'
    '④ 공개 입력의 pk_AA·pk_trace == 팩토리에 새겨진 값\n'
    '⑤ allowAgent ≤ 1;  태그 c1 이 항등원 (0, 1) 아님\n'
    '⑥ 공개 입력의 root == 폐기 로그 컨트랙트의 현재 root;  마지막 게시가 100 블록 이내\n'
    '⑦ 현재 블록 ≤ max_height ≤ 현재 블록 + 400\n'
    '⑧ Groth16 검증자 컨트랙트로 증명 검증(페어링)\n'
    '⑨ nonce += 1 → 실제 호출 to.call{value}(data) → 이벤트 Executed, Mode3Auth(pk_i, max_height, allowAgent, tag)',
    size=11, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP)
# 오른쪽: 태그·비용
box(s, X0 + 8200000, 1200000, 3320000, 330000, '트레이스 태그 = π_rp 의 공개 입력', size=12, bold=True, fill=LIGHT)
box(s, X0 + 8200000, 1530000, 3320000, 1750000,
    '추적 키 pk_trace = (서비스 조각 x_svc + AA 조각 x_AA)·B8 — AA 는 승인 때 자기 조각의 Schnorr 지식 증명을 함께 주고 서비스가 pk_trace = X_svc + X_AA 를 확인(rogue key 차단)\n'
    '태그 c1 = r·B8,  c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace).  컨트랙트는 pk_trace 대조와 c1 ≠ 항등원만 보고 태그를 이벤트에 남긴다.\n'
    '개봉: 서비스가 자기 조각으로 D_svc = x_svc·c1 을 계산해 트랜잭션 해시와 함께 요청 → 운영자 승인 → AA 가 x_AA·c1 을 더해 평문 Poseidon(uid, arid) 복원 → 등록부 역조회 → uid',
    size=10, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP)
box(s, X0 + 8200000, 3350000, 3320000, 1230000,
    '비용 (2026-09-21 실측, V5)\nexecute 339,321 gas(캐시 π) / 356,453(첫 실행)\n캐시 π 왕복 157 ms, 계정 배포 1회 713k gas, 게시(리프 1) 43.9k, 하트비트 40.3k\n같은 π 재사용 = 같은 태그 암호문 — sender 가 PPID 계정이라 어차피 같은 주소로 이어져 있어 새로 드러나는 것은 없다',
    size=10, align=PP_ALIGN.LEFT, fill=LIGHT, anchor=MSO_ANCHOR.TOP)
label(s, X0, 4700000, W0, 500000,
      '체인이 더하는 것은 "공개성" 뿐: 공개 입력을 AA 도 읽는다. 발급 때 AA 가 본 값 중 공개 입력과 맞춰 볼 수 있는 것은 (chainid, allowAgent, 그리드로 뭉갠 max_height) 뿐이고, 세션키 pk_i 는 커밋 C_s 안에, 사용자 커밋 C_u 는 비공개 리프로만 쓰인다.',
      size=11, color=GREY)

# ---------- 7. Properties + proof sketch (2장으로 분할) ----------
PROP_HDR = ['특성', '정의(게임)', '가정', 'Proof sketch']
PROP_ROWS = [
    ['Conditional privacy / Traceability (G10)', '태그 IND(서비스·AA 단독), 추적 가능성, 국소성', 'CDH(RO), Groth16 KS, EdDSA, AA 조각 PoK(rogue key 차단)', '태그는 해시-ElGamal: 한 조각만으로는 K = r·pk_trace 를 못 구해 c2 가 무작위(IND). 회로가 c2 의 평문을 서명된 C_u 의 uid 로 묶어 개봉이 반드시 이 사용자로 간다(추적). arid·pk_trace 가 공개 입력이라 남의 서비스 세션은 못 연다(국소성). AA 가 조각의 지식 증명을 내므로 X_AA = X′ − X_svc 같은 rogue key 는 불가.'],
    ['IdP(AA) unobservability (G4, G4′)', '발급 뷰 구별 게임; 체인 포함은 추측 게임(1/n)', 'Pedersen hiding + 시그마 HVZK', 'AA 뷰 = (uid, C_u, C_s, chainid, allowAgent, max_height, π_u). C_u·C_s 는 완전 hiding, π_u 는 시뮬레이션 가능 → arid·pk_i·속성과 독립. 체인 포함: 공개 입력 중 AA 가 본 값과 겹치는 것은 (chainid, allowAgent, 양자화 max_height) → 같은 창의 n 명 중 1/n.'],
    ['RP unobservability (G3 의 일부 + ZK)', '서비스가 uid·s_u·속성·C_u 를 구별하는 게임', 'Groth16 ZK, RO', '서비스 뷰는 공개 입력 14개와 π. π 는 영지식, PPID 는 s_u(250비트) 를 포함한 RO 출력, 태그는 IND → 공개 입력이 드러내는 것 이상을 얻지 못한다. (같은 서비스 안 세션 연결은 PPID 로 의도된 것 — 주소가 곧 이름.)'],
    ['Cross-RP unlinkability (G3)', '두 컨텍스트(서비스/체인)의 트랜스크립트가 같은 사용자인지 구별', 'RO + 태그 익명성 + ZK', 'PPID = H(uid, s_u, chainid, arid): arid 가 다르면 s_u 를 모르는 한 RO 역상 문제. C_u 는 두 서비스에 공통이지만 비공개 증인이라 어느 트랜스크립트에도 안 나온다. 폐기 리프도 비공개(단, 리프 게시 시각에 두 서비스의 세션이 함께 죽는 시각 상관은 남는다).'],
    ['Attribute privacy (G5)', 'AA 가 (pk_i, a)₀ vs (pk_i, a)₁ 구별', 'Pedersen hiding + 시그마 HVZK', 'G4 의 특수 경우: 속성은 C_u 안, pk_i 는 C_s 안. AA 는 커밋과 π_u 만 본다.'],
    ['Uniqueness (G1) / Immutability (G2)', '충돌 게임 / 두 번째 주소 게임', 'Poseidon CR / Pedersen binding + π_u 특수 건전성 + Groth16 KS + 250비트 범위', 'G1: PPID 충돌 = RO 충돌. G2: 다른 s_u 로 두 번째 주소를 얻으려면 cm_u 를 두 s_u 로 열어야 함 → Pedersen binding(2^250 < ℓ 라 e 와 e+ℓ 구별) 위반.'],
    ['Session binding (G7, G7′)', '오프체인 로그인·요청 위조 / 온체인 실행 위조·재생', 'ECDSA EUF-CMA', 'r_s 는 검증 전 소비(재생 0), σ 는 sk_i 만 만든다. 온체인: digest 가 chainid·wallet·nonce 를 덮고 low-s 강제 → 다른 체인·계정·nonce 로 재생 불가.'],
    ['Revocation soundness (G8) / Liveness (G9)', '폐기 게시 뒤 수락 게임 / AA 없이 검증', 'IMT 비회원 건전성 + Groth16 KS + N=1', '리프 = Poseidon(4, Cf_u) 를 회로가 증인에서 유도 → 게시된 root 에 대해 비멤버십을 못 만든다. 검증자는 방금 읽은 root 만 받는다(N=1). 검증 경로에 AA 없음: 서비스는 체인만 읽고 지갑은 이벤트로 트리를 재구성.'],
]
s = S[6]; clear_body_keep_title(s); s.shapes.title.text = 'zk-Delegation’s Properties (1/2)'
table(s, X0, Y0 - 100000, W0, 4400000, PROP_HDR, PROP_ROWS[:4], [1.7, 2.0, 1.7, 5.4], size=11)
p2 = new_slide('zk-Delegation’s Properties (2/2)'); G_PROPS2 = p2
table(p2, X0, Y0 - 100000, W0, 4400000, PROP_HDR, PROP_ROWS[4:], [1.7, 2.0, 1.7, 5.4], size=11)

# ---------- 8. zkAA / BAAR 대응 ----------
s = S[7]
ph = body(s)
if ph: remove_shape(ph)
s.shapes.title.text = 'zkAA · BAAR 의 특성과의 대응'   # 원래 제목이 앞 장과 같아(Properties) 구분되게
for pic in [sh for sh in s.shapes if sh.shape_type == 13]: remove_shape(pic)   # 논문 캡처 둘은 투영하면 읽히지 않아 뺀다 — 출처는 아래 캡션
table(s, X0, Y0 - 150000, W0, 4000000,
      ['출처', '특성', 'zk-Delegation 에서의 대응', '비고'],
      [['zkAA', 'Injectiveness', 'G1 유일성 (PPID = H(uid, s_u, chainid, arid), RO 충돌)', '같은 서비스·체인에서 두 사용자 → 다른 주소'],
       ['zkAA', 'Unforgeability', 'G2 불변성 + G7′ 온체인 위조 불가', 'AA 서명·cm_u 결합·sk_i 서명 셋이 함께'],
       ['zkAA', 'Correctness', '완전성(정직한 지갑의 π_rp·σ 는 항상 수락)', '정리로 따로 두지 않고 회로·검증기 테스트로'],
       ['zkAA', 'Tamper resistance', 'G7′: σ 가 payload 다이제스트를 덮음, low-s', '릴레이어가 payload·서명을 못 바꿈'],
       ['zkAA', 'Chronicle', 'Mode3Wallet 의 nonce (execute 마다 +1, 서명이 덮음)', '계정별 단조 증가 순서'],
       ['zkAA', 'Privacy-preservation', 'G3 + G4: 개인키·uid 가 등록·게시 전후로 새지 않음', 'AA·서비스·체인 어느 쪽도 s_u 를 못 봄'],
       ['BAAR', 'Unforgeability', 'G2 + G7 (성명 위조 = AA EdDSA 위조 또는 cm_u 결합 파괴)', ''],
       ['BAAR', 'Unlinkability', 'G3 (서비스·체인 간). 같은 서비스 안은 의도적으로 연결(주소)', 'BAAR 는 제시 간 비연결, 우리는 서비스 내 연속성이 목표'],
       ['BAAR', 'Attribute privacy', 'G5 (속성은 C_u 안, AA 가 못 봄; 술어 증명은 후속)', ''],
       ['BAAR', 'Revocation soundness', 'G8 (리프 = Poseidon(4, Cf_u), 게시 root 기준 비멤버십)', '+ G9 라이브니스: 검증 경로에 AA 없음']],
      [0.8, 1.6, 4.2, 3.0], size=11)
label(s, X0, Y0 + 3950000, W0, 300000, '출처: zkAA Table 2 (Injectiveness·Unforgeability·Correctness·Tamper resistance·Chronicle·Privacy-preservation), BAAR §3.4.3 Security argument (Unforgeability·Credential integrity·Attribute privacy·Credential deactivation·Selective revocation·Unlinkability)', size=9, color=GREY)

# ---------- 9. Overall flow (2026-09-22 개정: 문장 대신 메시지 이름, 단계 띠) ----------
s = S[8]; clear_body_keep_title(s)
lanes = ['지갑 (사용자)', 'AA (CIA)', '서비스 (RP)', '체인']
LANE_FILL = [PALE, PINK, LIGHT, RGBColor(0xE6, 0xF4, 0xEA)]
PW = 560000                         # 왼쪽 단계 띠
LX = X0 + PW; LW = (W0 - PW) // 4; LY = Y0 - 260000; LH = 4950000
HDR = 320000; ROW = 455000; TOP = LY + HDR + 60000
NW = int(LW * 0.60); NH = 290000   # 노드를 좁게 — 이웃 레인 사이 틈(0.4·LW)에 메시지 이름이 들어간다
for i, ln in enumerate(lanes):
    box(s, LX + i * LW, LY, LW - 40000, HDR, ln, size=12, bold=True, fill=LANE_FILL[i])
    box(s, LX + i * LW, LY + HDR, LW - 40000, LH - HDR, '', line=True)
def cx(lane): return LX + lane * LW + (LW - 40000) // 2
def cy(row): return TOP + row * ROW + NH // 2
def node(lane, row, text, fill=None):
    return box(s, cx(lane) - NW // 2, TOP + row * ROW, NW, NH, text, size=9, fill=fill or RGBColor(0xFF, 0xFF, 0xFF))
def msg(a, b, row, text, reply=None, dashed=False, color=RGBColor(0x40, 0x40, 0x40)):
    """a → b 화살표(메시지 이름을 위에), reply 가 있으면 b → a 를 아래에."""
    y = cy(row); left = a < b
    x1 = cx(a) + (NW // 2 if left else -NW // 2); x2 = cx(b) - (NW // 2 if left else -NW // 2)
    if reply is None:
        arrow(s, x1, y, x2, y, color=color, dashed=dashed)
        label(s, min(x1, x2), y - 240000, abs(x2 - x1), 220000, text, size=8, color=BLUE, align=PP_ALIGN.CENTER, bold=True)
    else:
        arrow(s, x1, y - 70000, x2, y - 70000, color=color, dashed=dashed)
        arrow(s, x2, y + 70000, x1, y + 70000, color=color, dashed=dashed)
        label(s, min(x1, x2), y - 250000, abs(x2 - x1), 170000, text, size=8, color=BLUE, align=PP_ALIGN.CENTER, bold=True)
        label(s, min(x1, x2), y + 80000, abs(x2 - x1), 150000, reply, size=8, color=GREEN, align=PP_ALIGN.CENTER, bold=True)
def phase(r0, r1, text, fill):
    y0 = TOP + r0 * ROW - 50000; h = (r1 - r0 + 1) * ROW
    box(s, X0, y0, PW - 60000, h - 20000, text, size=10, bold=True, fill=fill, color=GREY)
phase(0, 0, '등록', PALE); phase(1, 5, '로그인', PINK); phase(6, 6, '세션', LIGHT); phase(7, 7, '트랜잭션', RGBColor(0xE6, 0xF4, 0xEA)); phase(8, 8, '폐기', PINK); phase(9, 9, '개봉', LIGHT)
# 0 등록 — 지갑·서비스가 각각 AA 에 등록
node(0, 0, 's_u, r_u → cm_u'); node(1, 0, 'cm_u·attrs 저장, sk_u / 승인 → cert_s'); node(2, 0, '서비스 등록 X_svc')
msg(0, 1, 0, 'uid, pwd, cm_u', reply='sk_u, attrs'); msg(2, 1, 0, 'X_svc', reply='arid, cert_s, pk_trace')
# 1 로그인 시작 (서비스 → 지갑)
node(2, 1, '로그인 시작 · 챌린지 r_s'); node(0, 1, 'cert_s · 오리진 검증')
msg(2, 0, 1, 'arid, cert_s, pk_trace, r_s')
# 2 체인 동기화 (읽기만)
node(0, 2, '폐기 트리 동기화'); node(3, 2, 'RevocationLog')
msg(3, 0, 2, 'Revoked 이벤트 · root (읽기)', dashed=True, color=GREEN)
# 3 사용자 자격증명 (사용자당 한 번)
node(0, 3, 'C_u = Commit(uid, s_u, a₁..a₄)'); node(1, 3, 'π_u 검증(AA 의 attrs) · Cf_u 기록')
msg(0, 1, 3, 'C_u, π_u, sig_u', reply='Cf_u')
# 4 세션 자격증명 (ZKP 없음)
node(0, 4, 'pk_i, C_s = Commit(arid, pk_i)'); node(1, 4, '활성 Cf_u 조회 · σ_AA 서명')
msg(0, 1, 4, 'C_s, sig_u, max_height', reply='σ_AA')
# 5 증명·검증
node(0, 5, 'π_rp(mask=0), σ = Sign_sk_i(r_s)'); node(2, 5, 'root·만료·키·Groth16·σ → 세션')
msg(0, 2, 5, 'π_rp, 공개 입력 23, σ', reply='ok, PPID')
# 6 세션 요청·재검증
node(0, 6, '요청 서명 · root 같으면 캐시 π'); node(2, 6, 'root 바뀌면 재검증 요구')
msg(0, 2, 6, 'r_s, body, σ_i  /  π_rp(새 root)')
# 7 트랜잭션 (선택 공개)
node(0, 7, 'π_rp(mask, lo, hi), σ(다이제스트)'); node(3, 7, 'execute → 대상(AttrGate)')
msg(0, 3, 7, 'payload, σ, π_rp, 공개 입력 23  (릴레이어)')
# 8 폐기
node(1, 8, '리프 = Poseidon(4, Cf_u) → 트리'); node(3, 8, 'RevocationLog.publish')
msg(1, 3, 8, 'root, epoch, 리프들, 서명')
# 9 개봉
node(2, 9, '개봉 요청 (D_svc)'); node(1, 9, '승인 → 복호 → uid')
msg(2, 1, 9, 'PPID/txHash, D_svc', reply='uid')
label(s, X0, LY + LH + 30000, W0, 260000, '파란 글자 = 메시지, 초록 = 응답, 점선 = 체인 읽기(트랜잭션 없음). 3 은 사용자당 한 번, 4·5 는 로그인마다, 7 은 트랜잭션마다. 체인에 쓰는 것은 8 과 7 뿐.', size=9, color=GREY)

# ---------- 10. Prototype ----------
s = S[9]; clear_body_keep_title(s)
table(s, X0, Y0 - 100000, W0 // 2 - 100000, 2800000,
      ['구성 요소', '내용'],
      [['프로세스 4', 'AA(cia.js), 지갑 에이전트(mode3_wallet_agent.js), 서비스(mode3_rp.js), hardhat 노드'],
       ['컨트랙트 4', 'RevocationLog, PiCredVerifier(snarkjs 생성), Mode3WalletFactory(서비스별), Mode3Wallet(사용자·서비스별, CREATE2)'],
       ['회로', 'circom 2.1.9 / snarkjs 0.7.5 Groth16(BN254), circomlib(Poseidon, EdDSA, Baby Jubjub), pot21'],
       ['암호', 'Pedersen 벡터 커밋(교과서형, NUMS 생성원 9개), EdDSA-Poseidon(AA), secp256k1 ECDSA(세션키), 해시-ElGamal 태그'],
       ['테스트', 'unit·circuit·contract·chain 그룹(격리 인스턴스), 데모 스택 시나리오']],
      [1.1, 4.0], size=10)
table(s, X0 + W0 // 2 + 100000, Y0 - 100000, W0 // 2 - 100000, 2800000,
      ['측정 (2026-09-21, V5, Ryzen 5950X, N=10 중앙값)', '값 (괄호는 V4 2026-09-18)'],
      [['π_rp 제약 / 증명 / 검증', '26,601 / 859.6 ms / 11.5 ms  (25,560 / 858 / 14.6)'],
       ['π_u(시그마) 증명 / 검증', '121.9 ms / 140.5 ms — 사용자당 1회  (155 / 164, 세션마다)'],
       ['로그인 왕복(세션 발급+증명)', '1,073 ms (세션 발급 124, 증명 ≈ 860)  (1,394: 발급 422, 증명 898)'],
       ['재검증(캐시 π) / 트랜잭션 왕복', '33 ms / 157 ms'],
       ['execute gas(캐시 π / 첫 실행) / 계정 배포', '339,321 / 356,453 / 713k  (339k / 388k 값 전송)'],
       ['게시(리프 1) / 하트비트 gas', '43,888 / 40,305  (리프 10: 51k / 40k)']],
      [2.2, 2.6], size=10)
set_items = [(0, '수치 자체보다 "어느 단계에 무엇이 드는가"가 요점: 증명은 로그인당 한 번(≈0.9 s), 세션 요청은 서명뿐, 온체인은 트랜잭션마다 Groth16 검증 가스.'),
             (0, '폐기 게시는 리프당 ≈1.1k gas 이고 배치가 싸다. 하트비트는 폐기가 없어도 100블록마다 빈 게시(40k).'),
             (0, '데모 한계: 릴레이어는 hardhat 언락 계정, 지갑은 확인 대화상자 없음, 개봉 API 무인증(게이트는 AA 서명 검증·운영자 승인).'),
             (0, '셋업 한계: Groth16 phase-2 기여가 고정 엔트로피 1회(재현용) — 이 머신 운영자는 π_rp 를 위조할 수 있다. 운영에는 다자간 ceremony 가 필요하다.')]
tb = s.shapes.add_textbox(Emu(X0), Emu(Y0 + 2850000), Emu(W0), Emu(1800000)); tf = tb.text_frame; tf.word_wrap = True
for i, (lvl, t) in enumerate(set_items):
    p = tf.paragraphs[0] if i == 0 else tf.add_paragraph(); p.text = '• ' + t
    for r in p.runs: r.font.size = Pt(12)

# ---------- 10.5 기존 연구와의 비교 (새 장) ----------
c = new_slide('기존 연구와의 비교'); G_COMPARE = c
label(c, X0, Y0 - 250000, W0, 330000, '"(확인)" 표시는 원 논문 재확인이 필요한 칸. zkLogin = Sui zkLogin, zkAA = zero-knowledge address abstraction, BAAR = 익명 속성 자격증명(폐기 포함).', size=11, color=GREY)
table(c, X0, Y0 + 120000, W0, 4300000,
      ['항목', 'zkLogin', 'zkAA', 'BAAR', 'zk-Delegation (이 연구)'],
      [['발급자(IdP) 개입', '로그인마다 OIDC JWT. IdP 가 aud(앱)·nonce(세션키 커밋) 를 본다', '신원 등록 1회(온체인), 이후 IdP 없음 (확인)', '자격증명 발급 1회(CIA), 제시마다 발급자 없음', '사용자 자격증명 1회(π_u) + 세션마다 서명(ZKP 없음). AA 는 서비스·세션키를 못 본다'],
       ['사용자 비밀(salt)', '제3자 salt 서비스가 보관', '사용자 비밀키 (확인)', '사용자 비밀키', 's_u 는 지갑만. 등록 커밋 cm_u 로 AA 에 결합(주소 유일성)'],
       ['폐기', '없음(만료 epoch 만)', '없음 (확인)', 'accumulator 갱신, 선택적 폐기', 'RCL 리프(사용자당 1) + 온체인 root, N=1 신선도·하트비트, AA 없이 검증'],
       ['조건부 추적(개봉)', '없음(IdP+salt 서비스 담합 시 연결 가능)', '없음', '없음 (확인)', '2-of-2 태그(서비스+AA, 운영자 승인), 검증 가능 암호화, AA 조각 PoK'],
       ['서비스 간 연결성', '앱(aud)별 주소 → 비연결', '같은 주소 재사용 (확인)', '제시마다 비연결', '서비스·체인별 PPID 비연결, 서비스 안은 주소로 연속'],
       ['체인 무관성', 'Sui 전용(네이티브 검증)', 'EVM 컨트랙트 (확인)', '체인 밖(오프체인 제시)', '체인 무관: Groth16 검증자 컨트랙트 + chainid 가 PPID 에. 오프체인 로그인도 같은 증명'],
       ['트랜잭션당 비용', 'Sui 네이티브 검증(낮음, 수치 확인)', 'Groth16 온체인 검증 (확인)', '해당 없음', 'execute 339k gas(캐시 π 재사용), 증명은 로그인당 1회 0.86 s']],
      [1.3, 2.2, 2.0, 2.0, 3.4], size=10)

# ---------- 11. Todo ----------
s = S[10]
set_bullets(body(s), [
    (0, '구현 완료: 자격증명 이중 구조(C_u/C_s) 8 Task, 전 테스트 그룹 통과, push (feat/mode3-cia b208d4b)'),
    (1, '추가(미커밋): 개봉 2-of-2 유지 + AA 조각 Schnorr PoK(rogue key 차단), 스펙·형식 문서 반영'),
    (0, '논문 v3 반영: V-B 사용자 자격증명 절, V-D 세션 발급 축소, Table 2·3 실측(V5), VI-D, IX 한계'),
    (1, '한계에 추가: 셋업 단일 기여(ceremony 필요), AA·서비스 담합, 조각 유실, 폐기 게시 시각 상관, 세션 단위 폐기 없음'),
    (0, 'Security analysis: security_formal.md 정리 2·6(서명 인자)·9(리프 하나), 대응표 A2·A5·A8 — conditional_privacy_formal.md 는 (A7) 반영됨'),
    (0, '기존 연구 비교표(앞 장) "(확인)" 칸 검토, zkLogin 비교 덱(260918_zkDelegation_vs_zkLogin.pptx) 와 통일'),
    (0, '후속: 속성 술어 증명(구간 — 2026-09-22 완료, 확장 남음), 검증자 주소를 cert_s 에, 증분 트리 동기화, 지갑 UI 확인 대화상자(Snap 으로), 폐기 게시 배치(한계로만 기록) — 다음 장'),
], size=16)

# ---------- 11.5 후속 연구 풀어 쓰기 (새 장, Todo 뒤) ----------
f = new_slide('후속 연구 — 무엇이 문제이고 무엇을 하면 되나'); G_FOLLOW = f
FW = (W0 - 2 * 120000) // 3; FH = 2050000
items = [
    ('1. 속성 술어 증명', '완료(구간)·확장 남음', PALE,
     '지금: π_rp 안에서 lo ≤ aₖ ≤ hi 를 증명하고 체인이 검증(2026-09-22, 공개 입력 23개).\n'
     '남은 것: "나이 ≥ 19" 는 지갑이 "출생연도 ≤ 2007" 로 환산해 공개 → 기준 연도가 공개 값에 박혀 시간이 지나면 어긋남. 회로가 체인 시각(블록)을 공개 입력으로 받아 현재 연도 − a₀ ≥ 19 를 직접 계산해야 함. 집합 소속(국가 ∈ {…})도 회로 확장.'),
    ('2. 검증자 주소를 cert_s 에', '보안 공백', PINK,
     '지금: 지갑은 팩토리 주소만 온체인 getter 로 대조하고, 팩토리가 가리키는 Groth16 검증자 컨트랙트는 대조 못 함.\n'
     '위험: 악의적 서비스가 "무엇이든 통과시키는 검증자" 를 넣은 팩토리를 주면 그 계정은 누구나 위조 증명으로 조작 가능.\n'
     '해결: AA 가 승인 때 서명하는 cert_s 에 검증자 주소(또는 팩토리 코드 해시)를 넣고 지갑이 대조.'),
    ('3. 증분 트리 동기화', '성능', LIGHT,
     '지금: 지갑이 로그인마다 폐기 이벤트를 처음부터 재생해 트리를 다시 만듦(리프 적을 땐 수십 ms).\n'
     '문제: 폐기가 쌓이면 로그인 비용이 선형으로 증가.\n'
     '해결: 마지막으로 본 블록·epoch 이후 이벤트만 받아 이어 붙임(2026-09-11 리뷰 R8, 보류).'),
    ('4. 지갑 UI 확인 대화상자', 'Snap 작업으로 흡수', PALE,
     '지금: 지갑 에이전트가 서비스의 로그인 요청·속성 공개·트랜잭션을 사용자 확인 없이 처리(데모 한계).\n'
     '필요: "이 서비스(오리진·arid)에 로그인?", "슬롯 0 을 [0, 2007] 로 공개?", "이 트랜잭션 전송?" 세 종류의 동의 창.\n'
     '방향: Mode 2 처럼 MetaMask Snap 의 snap_dialog 가 이 자리를 맡고, 비밀(s_u·sk_u·blind)도 Snap 상태에.'),
    ('5. 폐기 게시 배치', '한계로만 기록(구현 안 함)', LIGHT,
     '문제: 리프 하나가 게시되면 그 사용자의 모든 서비스 세션이 같은 root 전환에서 죽음 → 담합한 서비스들이 "그 root 직후 재검증 대신 새 로그인을 한 가명" 을 맞춰 묶을 수 있음. 익명 집합 = 그 배치의 리프 수.\n'
     '완화: 하트비트 주기(50블록)에 모아 게시. 대가: 폐기 효력이 최대 한 주기 지연.'),
]
for i, (title, status, fill, body_) in enumerate(items):
    col = i % 3; row = i // 3
    x = X0 + col * (FW + 120000); y = Y0 - 200000 + row * (FH + 120000)
    box(f, x, y, FW, 300000, f'{title}   [{status}]', size=12, bold=True, fill=fill)
    box(f, x, y + 300000, FW, FH - 300000, body_, size=11, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP)
label(f, X0 + 2 * (FW + 120000), Y0 - 200000 + FH + 120000 + 300000, FW, FH - 300000,
      '우선순위 제안: 2(보안) → 4(Snap, 다음 작업) → 1 확장 → 3. 5 는 논문 한계 절.\n셋업 ceremony(단일 기여)도 한계 절에만 둔다(스코프 밖).',
      size=11, color=GREY)

# ---------- 순서 ----------
order = [S[0], G_NOTATION, G_MOTIVE, S[8], S[1], S[2], S[3], S[4], S[5], S[6], G_PROPS2, S[7], S[9], G_COMPARE, S[10], G_FOLLOW, S[11]]
lst = prs.slides._sldIdLst
ids = {id(sl.part): el for el, sl in zip(list(lst), prs.slides)}   # 목록을 비우기 전에 잡아 둔다(slide_id 는 목록을 뒤진다)
for el in list(lst): lst.remove(el)
for sl in order: lst.append(ids[id(sl.part)])

prs.save(DST); print('saved', DST, len(prs.slides), 'slides')
