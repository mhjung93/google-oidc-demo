#!/usr/bin/env python3
"""Build a focused deck separating soundness from liveness in PairCT revocation.


Reuses the POSTECH template from 260731_meeting_MHJ.pptx, same as
build_meeting_slides_260818.py.

Numbers in this deck are measured unless labelled 추정.
"""

import os

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR
from pptx.oxml.ns import qn

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

SRC = os.path.join(REPO_ROOT, "documents", "260731_meeting_MHJ.pptx")
LOGO = os.path.join(SCRIPT_DIR, "postech_logo.png")
OUT = os.path.join(REPO_ROOT, "documents", "260831_soundness_vs_liveness.pptx")

DARK = RGBColor(0x44, 0x54, 0x6A)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

prs = Presentation(SRC)
LAYOUT_TITLE = prs.slide_layouts[0]
LAYOUT_CONTENT = prs.slide_layouts[1]
LAYOUT_TITLE_ONLY = prs.slide_layouts[7]

xml_slides = prs.slides._sldIdLst
for sld_id in list(xml_slides):
    rId = sld_id.get(qn('r:id'))
    prs.part.drop_rel(rId)
    xml_slides.remove(sld_id)


def add_bullets(tf, items):
    tf.clear()
    first = True
    for item in items:
        level, text = item[0], item[1]
        bold = item[2] if len(item) > 2 else False
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.level = level
        p.text = text
        for run in p.runs:
            run.font.bold = bold


def add_title_slide(title, subtitle):
    slide = prs.slides.add_slide(LAYOUT_TITLE)
    slide.shapes.title.text = title
    slide.placeholders[1].text = subtitle
    slide.shapes.add_picture(LOGO, Emu(3971764), Emu(4951853), Emu(4248472), Emu(611893))
    return slide


def add_bullet_slide(title, items):
    slide = prs.slides.add_slide(LAYOUT_CONTENT)
    slide.shapes.title.text = title
    add_bullets(slide.placeholders[1].text_frame, items)
    return slide


def add_table_slide(title, headers, rows, col_widths, top=Inches(1.5), height=Inches(4.5),
                    font_size=13, header_size=13, left=Inches(0.5), width=Inches(12.3),
                    note=None):
    slide = prs.slides.add_slide(LAYOUT_TITLE_ONLY)
    slide.shapes.title.text = title
    n_rows = len(rows) + 1
    n_cols = len(headers)
    gframe = slide.shapes.add_table(n_rows, n_cols, left, top, width, height)
    table = gframe.table
    for i, w in enumerate(col_widths):
        table.columns[i].width = w
    for c_i, h in enumerate(headers):
        table.cell(0, c_i).text = h
    for r_i, row in enumerate(rows, start=1):
        for c_i, val in enumerate(row):
            table.cell(r_i, c_i).text = val
    for r_i, row in enumerate(table.rows):
        for cell in row.cells:
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            tf = cell.text_frame
            tf.word_wrap = True
            for p in tf.paragraphs:
                sz = header_size if r_i == 0 else font_size
                p.font.size = Pt(sz)
                if r_i == 0:
                    p.font.bold = True
                    p.font.color.rgb = WHITE
                for run in p.runs:
                    run.font.size = Pt(sz)
                    if r_i == 0:
                        run.font.bold = True
                        run.font.color.rgb = WHITE
            if r_i == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = DARK
    if note:
        box = slide.shapes.add_textbox(left, top + height + Inches(0.15), width, Inches(0.9))
        tf = box.text_frame
        tf.word_wrap = True
        add_bullets(tf, note)
        for p in tf.paragraphs:
            p.font.size = Pt(12)
            for run in p.runs:
                run.font.size = Pt(12)
    return slide


# ============================================================
# 1. Title
                # ============================================================
# 1. Title
# ============================================================
add_title_slide(
    "폐기 설계 — 건전성과 가용성은 다른 축이다",
    "\n\"폐기된 키가 통과하는가\"와 \"정상 트랜잭션이 성공하는가\"를 나눠 본다\nMoonhyeon Chung, POSTECH",
)

# ============================================================
# 2. 두 축
# ============================================================
add_table_slide(
    "먼저 두 축을 분리한다",
    ["", "묻는 것", "실패했을 때"],
    [
        ["건전성 (soundness)", "폐기된 키가 통과할 수 있는가?", "폐기 기능이 무의미해진다 — 보안 실패"],
        ["가용성 (liveness)", "정상 사용자의 트랜잭션이 성공하는가?", "재시도하면 된다 — UX·비용 문제"],
    ],
    [Inches(3.0), Inches(4.4), Inches(4.9)],
    height=Inches(1.8), font_size=14,
    note=[
        (0, "이 둘은 독립적이다. 건전성을 100%로 두면서 가용성에 결함이 남을 수 있고, 실제로 지금이 그 상태다."),
        (0, "지금까지 \"인플라이트 문제\"라고 부른 것은 전부 아래 축(가용성)의 이야기다. 보안이 뚫린다는 뜻이 아니다."),
    ],
)

# ============================================================
# 3. 건전성은 이미 100%
# ============================================================
add_bullet_slide("건전성은 이미 100%다", [
    (0, "폐기된 키가 통과할 수 있는 경로가 없다", True),
    (1, "컨트랙트가 현재 root에만 고정된다 — isCurrentRoot(root) = (root == latestRoot && latestRoot != 0)"),
    (1, "회로가 비멤버십을 강제한다 — 정렬 연결 리스트에 v가 있으면 low < v < next인 리프가 존재할 수 없다"),
    (1, "회로 밖 데이터를 신뢰하지 않는다 — Merkle 경로가 리프 값을 트리에 묶는다"),
    (0, "실측으로 확인한 것 (커밋 78817c0)", True),
    (1, "조작 5종 전부 거부: lowNextValue · lowNextIndex · 경로 원소 · 빈 슬롯 위장 · 폐기된 값"),
    (1, "lowNextIndex만 바꿔도 거부됨 — 리프 해시에 묶여 있어 별도 범위 검사가 불필요하다는 근거"),
    (1, "언링크된 낡은 리프가 거짓 증명을 통과시키는 것을 회로에서 재현 → remove()를 만들지 않은 이유"),
    (0, "즉 \"보안적으로 100%\"는 이미 달성돼 있다. 남은 것은 가용성뿐이다", True),
])

# ============================================================
# 4. 인플라이트 창 해부
# ============================================================
add_table_slide(
    "남은 것은 가용성 — 인플라이트 창의 해부",
    ["구성", "시간", "비중"],
    [
        ["폐기 트리 재구성 (정석 IMT 이후)", "1.98 ms", "0.02%"],
        ["pi_pk_i 증명 생성", "800 ms", "6%"],
        ["RPC 왕복·제출", "~100 ms", "1%"],
        ["채굴 대기 (1블록)", "12,000 ms", "93%"],
        ["합계", "약 12.9 초", "= 약 1.1블록"],
    ],
    [Inches(5.4), Inches(3.4), Inches(3.5)],
    height=Inches(2.9), font_size=13,
    note=[
        (0, "이 창 안에 폐기가 게시되면 root가 바뀌어 그 트랜잭션이 revert된다. 가스는 소모되고 사용자는 다시 시도한다."),
        (0, "실패 확률 ≈ 인플라이트 창 / 게시 주기.  게시 주기 50블록(10분)이면 약 2.2%, 100블록이면 약 1.1%."),
        (0, "폐기가 드물면 실제 빈도는 이보다 훨씬 낮다 — root는 폐기가 실제로 게시될 때만 바뀌기 때문이다."),
    ],
)

# ============================================================
# 5. grace는 건전성을 판다
# ============================================================
add_bullet_slide("grace window는 건전성을 팔아 가용성을 산다", [
    (0, "grace = \"밀려난 옛 root를 GRACE_BLOCKS 동안 계속 받아준다\"", True),
    (1, "인플라이트 창을 흡수하므로 정상 트랜잭션 실패가 0에 수렴한다"),
    (0, "그런데 그 창 동안 폐기된 키도 통과한다", True),
    (1, "옛 root에는 그 폐기가 반영돼 있지 않기 때문이다"),
    (1, "즉 건전성이 100%가 아니게 된다 — 폐기가 GRACE_BLOCKS만큼 무력해진다"),
    (0, "GRACE_BLOCKS = 200일 때 실제 손실", True),
    (1, "폐기 효력이 최대 40분 늦어진다"),
    (1, "크레덴셜 수명이 300블록(1시간)이므로, 수명의 첫 33% 안에 폐기해야만 의미가 있었다"),
    (1, "그보다 늦게 폐기하면 자연 만료가 먼저 와서 폐기가 아무것도 하지 않는다"),
    (0, "그래서 제거했다 — 건전성을 되찾고 가용성 결함(약 2%)을 감수하는 쪽을 택했다", True),
])

# ============================================================
# 6. 델타 분리
# ============================================================
add_bullet_slide("델타 분리는? 건전성은 지키지만 가용성을 못 산다", [
    (0, "아이디어: 증명을 둘로 쪼개 무거운 쪽을 캐시한다", True),
    (1, "π_base — EdDSA 검증 + PPID·auid 유도 + 체크포인트 비멤버십. 체크포인트마다만 재생성"),
    (1, "π_delta — 체크포인트 이후 추가분(Δ)에 대한 비멤버십. 게시마다 재생성"),
    (1, "두 증명을 커밋먼트 C = Poseidon(t, r)로 묶는다. r을 세션마다 새로 뽑으면 링커빌리티도 안 생긴다"),
    (0, "건전성은 유지된다 — Δ를 실제로 검사하므로 폐기된 키는 여전히 막힌다", True),
    (0, "그런데 가용성은 그대로다", True),
    (1, "컨트랙트는 (checkpointRoot, Δ)를 현재값에 고정해야 한다 — 안 그러면 낡은 Δ로 폐기가 새어나간다"),
    (1, "Δ는 게시마다 바뀌므로 π_delta는 여전히 신선해야 한다"),
    (1, "→ 인플라이트 창에 게시가 끼면 똑같이 실패한다"),
    (0, "얻는 것은 증명 시간뿐: 800 ms → 약 315 ms. 창은 12.9초 → 12.4초, 실패율 2.2% → 2.1%", True),
    (0, "내는 것: 온체인 검증 2회(+250k 가스), 회로·zkey 추가, 체크포인트 관리", True),
])

# ============================================================
# 7. 왜 더 못 줄이나
# ============================================================
add_bullet_slide("창의 93%가 블록 시간이다", [
    (0, "증명 생성을 0으로 만들어도 12초가 남는다", True),
    (1, "트리 재구성은 이미 24.75초 → 1.98 ms로 해결됐다 (정석 IMT, 실측 2,935배)"),
    (1, "증명 800 ms를 절반으로 줄여도 전체 창은 3% 줄어든다"),
    (0, "즉 어떤 암호학적 개선으로도 인플라이트 창을 의미 있게 줄일 수 없다", True),
    (0, "그리고 근본 제약이 하나 더 있다", True),
    (1, "비멤버십은 anti-monotone — 집합에 뭔가 추가되면 옛 증명이 거짓이 된다"),
    (1, "폐기란 곧 \"예전에 참이던 명제를 거짓으로 만드는 것\"이다"),
    (1, "옛 증명이 계속 유효하다면 그건 폐기가 안 되는 것과 같다 — 트리 구조를 바꿔도 마찬가지다"),
    (0, "검증자가 현재 상태에 고정돼야 폐기가 성립한다. 이건 구조가 아니라 정의에서 나온다", True),
])

# ============================================================
# 8. 정리
# ============================================================
add_table_slide(
    "정리 — 선택지와 그 대가",
    ["", "건전성", "가용성", "비용"],
    [
        ["현재 설계 (grace 없음)", "100%", "약 2% 실패", "—"],
        ["grace 도입", "폐기가 GRACE 동안 무력", "거의 100%", "낮음"],
        ["델타 분리", "100%", "약 2% 실패 (동일)", "검증 2회 + 회로 추가"],
    ],
    [Inches(3.4), Inches(3.2), Inches(3.0), Inches(3.1)],
    height=Inches(2.2), font_size=13,
    note=[
        (0, "델타 분리는 건전성을 지키지만 가용성을 사지 못한다 — 비용만 늘어 값어치가 맞지 않는다."),
        (0, "실질적인 조절 손잡이는 게시 주기 하나뿐이다: 늘리면 실패가 줄고 폐기 지연이 늘며, 줄이면 반대다."),
        (0, "그리고 이 실패는 재시도하면 성공하는 종류다. 폐기가 드물면 실제 빈도는 표의 수치보다 훨씬 낮다."),
    ],
)

prs.save(OUT)
print(f"wrote {OUT} ({len(prs.slides._sldIdLst)} slides)")
