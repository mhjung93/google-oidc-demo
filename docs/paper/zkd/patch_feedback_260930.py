# documents/260923_meeting_MHJ_feedback.pptx(교수님이 1–9장을 고치고 10장에 사용자 Todo 를 적은 피드백 덱)의 빨간 표시·"???" 자리에
# 대응을 채워 documents/260930_meeting_MHJ_feedback_revised.pptx 로 저장한다(2026-09-30). 원본은 건드리지 않는다.
# - 내 대응은 파란색(1F4EB0)으로 넣어 교수님 텍스트(검정·빨강)와 구분한다.
# - 2·7장의 본문은 수식이 들어 mc:AlternateContent 라 python-pptx 가 못 본다 → lxml 로 <a:p> 를 직접 찾아 고친다. m:oMath 문단은 건드리지 않는다.
# - 결정이 필요한 두 건(Todo 1 슬롯 리프, π_rp 비멤버십)은 맨 뒤 부록 2장(표)으로 붙인다.
# 근거: security_formal.md §1·§4·§9·§10·§11, conditional_privacy_formal.md, 논문 v6, results/…_20260924·_20260925·_20260921.
import copy
from lxml import etree
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor

SRC = 'documents/260923_meeting_MHJ_feedback.pptx'
DST = 'documents/260930_meeting_MHJ_feedback_revised.pptx'
BLUE = '1F4EB0'
NS = {'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
      'p': 'http://schemas.openxmlformats.org/presentationml/2006/main',
      'm': 'http://schemas.openxmlformats.org/officeDocument/2006/math'}
A = '{%s}' % NS['a']

prs = Presentation(SRC)
sl = list(prs.slides)
LOG = []

# ---------------------------------------------------------------- lxml 헬퍼 (AlternateContent 안까지 닿는다)
def ptext(pel):
    return ''.join(t.text or '' for t in pel.iter(A + 't'))

def has_math(pel):
    return pel.find('.//{%s}oMath' % NS['m']) is not None

def paras(slide, pred):
    return [pel for pel in slide._element.iter(A + 'p') if pred(ptext(pel))]

def one(slide, pred, what):
    ps = paras(slide, pred)
    assert len(ps) == 1, (what, len(ps), [ptext(x)[:60] for x in ps])
    return ps[0]

def _rpr(r):
    rpr = r.find(A + 'rPr')
    if rpr is None:
        rpr = etree.SubElement(r, A + 'rPr'); r.remove(rpr); r.insert(0, rpr)
    return rpr

def _color(rpr, rgb):
    for f in rpr.findall(A + 'solidFill'): rpr.remove(f)
    sf = etree.Element(A + 'solidFill'); c = etree.SubElement(sf, A + 'srgbClr'); c.set('val', rgb)
    # ln 이 있으면 그 뒤, 아니면 맨 앞
    ln = rpr.find(A + 'ln'); rpr.insert(1 if ln is not None else 0, sf)

def set_para(pel, text, color=None, size=None, bold=None):
    """문단 텍스트를 통째로 바꾼다 — 첫 run 서식 유지. 수식 문단이면 건드리지 않고 False."""
    if has_math(pel): return False
    rs = pel.findall(A + 'r')
    for b in pel.findall(A + 'br'): pel.remove(b)
    if rs:
        r0 = rs[0]
        for r in rs[1:]: pel.remove(r)
        t = r0.find(A + 't')
        if t is None: t = etree.SubElement(r0, A + 't')
        t.text = text
    else:
        r0 = etree.SubElement(pel, A + 'r'); etree.SubElement(r0, A + 'rPr'); t = etree.SubElement(r0, A + 't'); t.text = text
        end = pel.find(A + 'endParaRPr')
        if end is not None: pel.remove(end); pel.append(end)
    rpr = _rpr(r0)
    if color: _color(rpr, color)
    if size: rpr.set('sz', str(int(size * 100)))
    if bold is not None: rpr.set('b', '1' if bold else '0')
    for k in ('strike',):
        if k in rpr.attrib: del rpr.attrib[k]
    LOG.append(('set', text[:70]))
    return True

def add_after(pel, text, level=None, color=BLUE, size=None):
    """pel 을 복제해 뒤에 새 문단을 넣는다(서식 상속). 수식은 복제하지 않는다."""
    new = copy.deepcopy(pel)
    for m in new.findall('.//{%s}oMath' % NS['m']): m.getparent().remove(m)
    for m in new.findall('.//{%s}oMathPara' % NS['m']): m.getparent().remove(m)
    if level is not None:
        ppr = new.find(A + 'pPr')
        if ppr is None: ppr = etree.Element(A + 'pPr'); new.insert(0, ppr)
        ppr.set('lvl', str(level))
    set_para(new, text, color=color, size=size)
    pel.addnext(new)
    LOG.append(('add', text[:70]))
    return new

def append_run(pel, text, color=BLUE, size=None):
    """문단 끝에 run 하나를 덧붙인다(상태 표시용)."""
    if has_math(pel): return False
    rs = pel.findall(A + 'r')
    r = copy.deepcopy(rs[-1]) if rs else etree.SubElement(pel, A + 'r')
    if rs:
        end = pel.find(A + 'endParaRPr')
        (end.addprevious(r) if end is not None else pel.append(r))
    t = r.find(A + 't')
    if t is None: t = etree.SubElement(r, A + 't')
    t.text = text
    rpr = _rpr(r); _color(rpr, color)
    if size: rpr.set('sz', str(int(size * 100)))
    for k in ('strike',):
        if k in rpr.attrib: del rpr.attrib[k]
    LOG.append(('run', text[:70]))
    return True

def textbox(slide, left, top, width, height, lines, size=13, color=BLUE):
    tb = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = tb.text_frame; tf.word_wrap = True
    first = True
    for lvl, txt in lines:
        p = tf.paragraphs[0] if first else tf.add_paragraph(); first = False
        p.text = txt; p.level = lvl
        for r in p.runs: r.font.size = Pt(size - 1.5 * lvl); r.font.color.rgb = RGBColor.from_string(color)
    LOG.append(('box', lines[0][1][:60]))
    return tb

# ================================================================ 2장 Attributes (AlternateContent)
s = sl[1]
p = one(s, lambda t: 'Session attributes' in t and '???' in t, '2장 예시 ???')
set_para(p, '예 : user attributes (출생연도, 국가 코드, KYC 등급, 계정 등급 — AA 계정 기록의 64비트 정수 4개). '
            'Session attributes (세션 키 pk_i, 만료 max_height, chainid, allowAgent, 서비스 arid)', color=BLUE)
p = one(s, lambda t: 'session key (pk)' in t and 'max_height' in t, '2장 세션 속성 임베딩')
add_after(p, '→ 본 설계: 세션 키 pk_i 는 세션 커밋먼트 C_s 안(reserved slot 방식), max_height·chainid·allowAgent 는 서명 본문 — '
             '세션 nonce 는 토큰에 넣지 않고 로그인 챌린지 r_s 를 sk_i 로 서명(1회용). 토큰 = 인증 성명 σ_AA(credential 아님)', level=2)

# ================================================================ 3장 Revocation
s = sl[2]
p = one(s, lambda t: '통합 구조 제안' in t, '3장 통합 구조 ???')
set_para(p, '통합 구조: 트리 하나(RCL)만 — "유효함"은 트리가 아니라 AA 서명이 보증한다. 세션마다 서명하기 전에 Cf_u 가 활성 자격증명인지 '
            'AA 상태에서 확인하므로 VCL 이 필요 없고, 트리는 "발급 뒤 만료 전에 폐기됐는가"(비멤버십)만 답한다 → 온체인 쓰기는 폐기 때만', color=BLUE, size=14)
p = one(s, lambda t: '별도 Merkle Tree 유지 관리' in t, '3장 별도 트리')
q = add_after(p, '→ 지원함(V8, 9/24): 별도 트리 없이 같은 트리에 세션 리프 mask(Poseidon(5, Cf_s)) 를 추가하고 비멤버십을 둘 증명 — '
                 '사용자가 세션 하나만 폐기 가능. 제약 +9,801, 증명 +0.36 s, 온체인 검증 gas 불변(공개 입력 25 그대로). Todo 1 슬롯 리프는 부록 A', level=1, size=14)

# ================================================================ 4장 ID Transformation — 토큰 상자 + 대응표
s = sl[3]
box = next(sh for sh in s.shapes if sh.name == 'Rounded Rectangle 4')
P4 = [pel for pel in box._element.iter(A + 'p')]
def find4(sub): return next(pel for pel in P4 if sub in ptext(pel))
set_para(find4('(* Token 관련 정보 *)'), '(* Token = σ_AA = Sign_AA(D, Cf_u, Cf_s, max_height, chainid, allowAgent) *)', color=BLUE, size=12)
set_para(find4('arid'), 'Cf_s 안: arid, pk_i (blind 로 은닉 — AA 는 못 본다)', color=BLUE, size=12)
set_para(find4('auid_i'), 'chainid, allowAgent, max_height (서명 본문)', color=BLUE, size=12)
set_para(find4('??? // 세부 포맷 정리'), 'auid_i 는 없음 — PPID 는 지갑이 계산하고 π_rp 로 증명', color=BLUE, size=12)
set_para(find4('H(user attributes)'), 'Cf_u = Poseidon(C_u),  C_u = uid·G1 + s_u·G3 + Σ a_k·G_{4+k} + blind_u·H', color=BLUE, size=12)
set_para(find4('expire time'), 'max_height (block height) — 지갑이 grid 100 으로 정함', color=BLUE, size=12)
set_para(find4('H(session key)'), 'Cf_s = Poseidon(C_s),  C_s = arid·G2 + pk_i·G4 + blind_s·H', color=BLUE, size=12)
textbox(s, 10.05, 1.2, 3.1, 4.6, [
    (0, '본 설계와의 대응'),
    (0, 'salt → s_u (등록 때 cm_u = s_u·G3 + r_u·H 로 AA 에 커밋, 사용자만 안다)'),
    (0, 'auid → 없음 (uid·s_u 는 C_u 안에만)'),
    (0, 'auid_i → PPID = Poseidon(uid, s_u, chainid, arid) — 서비스·체인마다 다름, AA 는 모름'),
    (0, 'rid → arid (AA 가 등록 때 부여, cert_s 로 origin 에 결속)'),
    (0, 'session nonce → r_s (토큰 밖; 서비스가 내고 지갑이 서명)'),
    (0, '정식 정의: security_formal §1, 논문 Table 1·2'),
], size=11)

# ================================================================ 5장 π_IdP — 취소선 항목의 대응
s = sl[4]
p = one(s, lambda t: t.startswith('(2) user attribute commitment'), '5장 취소선')
textbox(s, 7.7, 1.55, 5.4, 1.8, [
    (0, '→ 본 설계: 세션마다는 증명 없음 — sig_u 하나. uid·s_u 관계는 자격증명 발급 때 한 번 π_u(시그마 프로토콜, 회로 없음, 80 ms)로 C_u 안에서 증명 (auid 없음)'),
    (0, '→ (2)를 세션에서 뺀 대신 π_u 가 "속성 = AA 기록" 도 증명 — AA 가 사용자가 고른 임의 속성을 보증하지 않기 위해 (근거 확인 요청)'),
], size=11.5)

# ================================================================ 6장 π_RP — "// 재수정" 을 현재 내용으로
s = sl[5]
p = one(s, lambda t: 'Selective Disclosure' in t and '(4)' in t, '6장 (4)')
append_run(p, '  → 구현: 범위(lo ≤ a_k ≤ hi)·집합 소속(a_sel ∈ S) — 공개 입력 25개')
bx = next(sh for sh in s.shapes if sh.has_text_frame and sh.text_frame.text.strip() == '// 재수정')
bx._element.getparent().remove(bx._element)
MC = '{http://schemas.openxmlformats.org/markup-compatibility/2006}AlternateContent'
moved = 0
for ac in s._element.iter(MC):
    if ac.find('.//{%s}oMath' % NS['m']) is None: continue
    for off in ac.iter(A + 'off'):
        if int(off.get('y')) > int(Inches(3)):          # 제목 수식(맨 위)이 아니라 작은 재수정 수식
            off.set('y', str(int(Inches(4.45)))); moved += 1
assert moved >= 1, 'π_RP 작은 수식을 못 찾았다'
textbox(s, 0.5, 5.05, 12.3, 1.95, [
    (0, '재수정 — 현재 π_rp(Groth16, 공개 입력 25, 제약 37,130, 증명 1.19 s / 검증 10 ms)가 증명하는 것'),
    (1, '(1) σ_AA 가 (Cf_u, Cf_s, max_height, chainid, allowAgent) 위의 AA 서명이고, head ≤ max_height ≤ head + L (만료는 검증자가 대조)'),
    (1, '(2) C_u 가 (uid, s_u, a_1..a_4) 로, C_s 가 (arid, pk_i) 로 열린다 — "IDs 정확성" 에 해당 (auid·auid_i 대신 커밋먼트)'),
    (1, '(3) PPID = Poseidon(uid, s_u, chainid, arid)'),
    (1, '(4) 선택 공개: 마스크가 켜진 슬롯의 범위, 집합 술어 a_sel ∈ set_root 의 트리'),
    (1, '(5) 추적 태그 (c1, c2) = Enc(pk_trace, Poseidon(uid, arid)) — 7장'),
    (1, '(6) 비멤버십 ×2: leaf(Cf_u), leaf(Cf_s) ∉ 폐기 트리 — Todo 3 "merkle proof 빠지고" 와 관련: 빼면 세션 중 폐기 불가(만료만). 유지 권고, 득실표 부록 B'),
], size=12)

# ================================================================ 7장 π_i — "// 재수정", threshold
s = sl[6]
bx = next(sh for sh in s.shapes if sh.has_text_frame and sh.text_frame.text.strip() == '// 재수정')
bx._element.getparent().remove(bx._element)
th = next(sh for sh in s.shapes if sh.has_text_frame and sh.text_frame.text.strip() == 'threshold public key')
th.left = Inches(0.1); th.top = Inches(6.5); th.width = Inches(8.0); th.height = Inches(0.45)
set_para(next(th._element.iter(A + 'p')), 'threshold 제거(9/16) → 2-of-2: pk_trace = X_svc + X_AA, 조각은 Schnorr PoK', color=BLUE, size=12)
textbox(s, 4.0, 4.3, 9.1, 2.15, [
    (0, '재수정 — 현재'),
    (1, '별도 π_i 는 없다: 태그는 π_rp 의 조건 ⑤로 묶이고, 같은 π 를 트랜잭션에 그대로 첨부한다 (TX + π + 25 공개 입력)'),
    (1, '(1)(2) 는 π_rp 가 이미 증명 — 세션 키 pk_i 는 C_s 안, 트랜잭션 서명 σ_tx 는 sk_i 로'),
    (1, '(3) Trace Tag = Enc(pk_trace, Poseidon(uid, arid)) — "auid 기반" 대신 서비스별 가명 H(uid, arid) 을 암호화 (auid 의 역할)'),
    (1, 'σ_tx 다이제스트가 태그 3워드를 묶는다(9/25) — 같은 세션의 다른 π 로 바꿔 끼우기 불가'),
    (1, 'condition: 분쟁 세션·트랜잭션에 한해, 서비스 조각 D_svc + AA 조각 + 운영자 승인 → uid 까지만(세션 아님). 정리 11–15'),
], size=12)

# ================================================================ 8장 Properties — "Address Abstraction 특성은 어디에 ????"
s = sl[7]
bx = next(sh for sh in s.shapes if sh.has_text_frame and '어디에' in sh.text_frame.text)
bx.width = Inches(6.4); bx.height = Inches(3.2); bx.left = Inches(6.5); bx.top = Inches(2.2)
tf = bx.text_frame; tf.word_wrap = True
set_para(next(bx._element.iter(A + 'p')), 'Address abstraction 특성 = zkAA 의 셋 — 위 목록에 있다', color=BLUE, size=14, bold=True)
last = list(bx._element.iter(A + 'p'))[-1]
for txt in ['Injectiveness → Uniqueness (G1): PPID = H(uid, s_u, chainid, arid)',
            'Tamper resistance → Immutability (G2): 계정 = CREATE2(factory, PPID)',
            'Privacy-preservation → Unlinkability (G3)',
            '추가할 것: Correctness(완전성), Chronicle(온체인 개봉 장부 = Mode3Auth 이벤트)',
            'BAAR: Unforgeability(G6·G7), Attribute privacy(G5), Revocation soundness(G8)',
            '본 연구만: Service unobservability(G4), Liveness independence(G9), Conditional privacy(G10)',
            '→ 8장 목록을 이 대응표로 바꾸고 논문 §VII 앞에 Table 로']:
    last = add_after(last, txt, size=12)

# ================================================================ 9장 Current Work — 대상 서비스 결정 + 상태
s = sl[8]
p = one(s, lambda t: '대상 서비스 결정' in t, '9장 대상 서비스')
set_para(p, '대상 서비스: 가상자산거래소 인증 서비스 (결정) — KYC 속성(연령 범위·국적 집합)을 조건으로만 공개하는 로그인·트랜잭션, 현 코드로 시연 가능', color=BLUE)
status = {
    'user attribute와 session attribute의 분리': '  — 완료 (V5 9/21 이중 구조, V8 9/24 세션 폐기)',
    'ZKP 내용 보완': '  — 완료 (π_u 시그마 한 번 / 세션 무증명 / π_rp 25 입력)',
    '전체 flow 정리': '  — 완료 (논문 Fig. 1 구조도·Fig. 2 순서도, 9/30)',
    '프로토타잎 구현': '  — 완료 (AA·지갑 에이전트·서비스 + MetaMask Snap, 테스트 5그룹)',
    '데모 시나리오': '  — 초안: 로그인 / 조건부 트랜잭션(AttrGate) / 세션 폐기 / 승인 개봉',
    '대상 서비스와 통합 연계': '  — 착수 예정 (거래소 로그인 화면·KYC 속성 연동)',
    '성능 평가및 오버헤드 분석': '  — 완료 (로그인 1.50 s, execute 417,533 gas; 논문 §VIII)',
    'formal proof': '  — 완료 (security_formal 정리 1–19·명제 16–21, conditional_privacy; 9/25 갱신)',
    '기존 연구와의 비교': '  — 보류 (Todo 6)',
}
for key, add in status.items():
    append_run(one(s, lambda t, k=key: k in t, '9장 ' + key), add, size=14)

# ================================================================ 10장 Feedback Todo — 항목별 상태
s = sl[9]
todo = {
    '1. RCL, VCL': '  → 유지 권고, 득실표 부록 A (결정 요청)',
    '2. user attribute revoke': '  → 완료 (V8: 세션 리프·비멤버십 둘)',
    'pi_idp는': '  → 완료 (π_u 한 번, 세션 무증명)',
    'pi_rp는': '  → 토큰·ID·PPID 는 완료; Merkle(비멤버십) 유지 여부 결정 요청 (부록 B)',
    'pi_i는': '  → 완료 (태그 = Enc(pk_trace, H(uid, arid)), 조건 = 분쟁 + 2-of-2 + 운영자)',
    'threshold signature': '  → 완료 (9/16 제거)',
    '4. 특허': '  → (사용자 액션)',
    '5. 데모': '  → 9장: 거래소 인증, 시나리오 4개',
    '6. 기존 연구': '  → 보류 유지',
}
for key, add in todo.items():
    append_run(one(s, lambda t, k=key: k in t, '10장 ' + key), add, size=14)

# ================================================================ 부록 A·B (표)
LAY = next(l for l in prs.slide_layouts if '제목 및 내용' in l.name)
def table_slide(title, header, rows, widths_in, size=12, note=None, top_in=1.35, row_in=0.5):
    s = prs.slides.add_slide(LAY); s.shapes.title.text = title
    ph = s.placeholders[1]; ph._element.getparent().remove(ph._element)
    n_r, n_c = len(rows) + 1, len(header)
    gf = s.shapes.add_table(n_r, n_c, Inches(0.45), Inches(top_in), Inches(sum(widths_in)), Inches(row_in * n_r)); t = gf.table
    for j, w in enumerate(widths_in): t.columns[j].width = Inches(w)
    for i in range(n_r): t.rows[i].height = Inches(row_in)
    for j, h in enumerate(header):
        c = t.cell(0, j); c.text = h
        for pp in c.text_frame.paragraphs:
            for r in pp.runs: r.font.size = Pt(size); r.font.bold = True
    for i, row in enumerate(rows, start=1):
        for j, val in enumerate(row):
            c = t.cell(i, j); c.text = val
            for pp in c.text_frame.paragraphs:
                for r in pp.runs: r.font.size = Pt(size)
    if note:
        tb = s.shapes.add_textbox(Inches(0.45), Inches(6.7), Inches(sum(widths_in)), Inches(0.5)); tb.text_frame.word_wrap = True
        pp = tb.text_frame.paragraphs[0]; pp.text = note
        for r in pp.runs: r.font.size = Pt(12); r.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    return s

table_slide('부록 A. Todo 1 슬롯 리프 — 득실',
    ['항목', '현재: append-only 폐기 리프', '제안: 사용자당 슬롯(latest valid / latest revoked)'],
    [['온체인 쓰기 시점', '폐기·은퇴 때만 (발급 때 0)',            '자격증명 (재)발급 때마다 슬롯 갱신 → 발급당 1 tx (≈ 43,856 gas)'],
     ['상태 크기',       '폐기 수만큼 증가 (append-only)',          '사용자 수로 유계 — 이 점이 장점'],
     ['증명',           '비멤버십 ×2 (리프 + 경로)',               '"내 Cf_u = 슬롯의 latest valid" 멤버십 — 리프 + 경로, 비용 같음 (절감 없음)'],
     ['세션 폐기',       '세션 리프를 같은 트리에 추가',             'latest revoked 칸 하나 → 동시에 폐기된 세션 둘은 표현 불가; 세션 슬롯을 두면 세션 수만큼 증가'],
     ['프라이버시',      '리프 = 해시, 종류·주인 비공개',            '슬롯 키가 사용자에 고정 → 같은 슬롯의 갱신 시각들이 한 사용자로 이어진다'],
     ['권고',           '유지 — 상태 증가는 Todo 6 대로 보류, 필요해지면 재기준화(새 트리·재발급)로 상한', '원하시면 회로·AA 상태만 바꿔 프로토타입하고 두 수치를 나란히 잰다 (약 1주)']],
    [1.6, 4.6, 6.2], size=12,
    note='재기준화: 트리를 새로 시작하고 활성 자격증명을 재발급 — 옛 리프를 버린다. 스펙에 후속으로 적혀 있고 구현은 없다.')

table_slide('부록 B. π_rp 의 비멤버십(Merkle) 증명 — 유지 vs 제거',
    ['항목', '유지 (현재, V8)', '제거 (zkLogin 식: 만료에만 의존)'],
    [['세션 중 폐기',   '다음 root 게시부터 효력 (하트비트 H 블록 이내)',        '불가 — 만료(max_height)까지 유효. TTL 300 블록 ≈ 최대 지연'],
     ['Todo 2 세션 폐기', '지원',                                                 '세션 폐기 자체가 무의미해진다'],
     ['회로',           '37,130 제약, 증명 1.19 s',                               '약 17,500 (비멤버십 둘 ≈ 19,600 제거, 추정), 증명 약 0.6 s'],
     ['지갑',           '폐기 트리 동기화 (체크포인트+델타, 로그인당 25 ms)',      '동기화 없음'],
     ['AA·서비스',       '하트비트 필요, 서비스는 root·root 나이 대조',            '하트비트·폐기 로그 불필요, 서비스는 만료만'],
     ['권고',           '유지 — 세션 폐기가 요구사항(Todo 2)이고 비용은 증명자 0.36 s 뿐', '요구사항이 "만료로 충분"이면 이쪽 — 결정 요청']],
    [1.8, 5.2, 5.4], size=12,
    note='중간안: 비멤버십을 유지하되 하트비트 주기·TTL 을 줄여 폐기 효력 지연을 통제 — 회로는 그대로.')

prs.save(DST)
print('saved', DST, len(prs.slides), 'slides;', len(LOG), 'edits')
