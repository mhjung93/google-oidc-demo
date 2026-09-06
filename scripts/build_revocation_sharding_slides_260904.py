#!/usr/bin/env python3
# 폐기 트리 샤딩 설계 검토용 슬라이드.
#
# BAAR 세미나 덱(scripts/build_baar_seminar_slides_260903.py)과 같은 템플릿·헬퍼를
# 쓴다. 그 덱이 "BAAR는 유효 집합 멤버십, 우리는 비멤버십"을 정리했다면, 이 덱은
# 그 비멤버십 구조의 남은 약점(증명이 매 게시마다 죽는다)을 어떻게 없애는지를 다룬다.
#
# 출처: 2026-09-04 설계 논의. constraint는 circom 단독 컴파일로 실측했고
# (results/mode2_sharded_circuit_constraints_20260904.csv), 증명 시간만 환산치다.
import os

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

SRC = os.path.join(REPO_ROOT, "documents", "260731_meeting_MHJ.pptx")
LOGO = os.path.join(SCRIPT_DIR, "postech_logo.png")
OUT = os.path.join(REPO_ROOT, "documents", "260904_revocation_sharding.pptx")

DARK = RGBColor(0x44, 0x54, 0x6A)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT = RGBColor(0xE8, 0xEC, 0xF2)
ACCENT = RGBColor(0xC0, 0x39, 0x2B)

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
        # 표 명목 높이는 최소값일 뿐이라 내용이 넘치면 행이 커진다. note는 하단 고정.
        note_top = max(top + height + Inches(0.15), Inches(5.55))
        box = slide.shapes.add_textbox(left, note_top, width, Inches(1.6))
        tf = box.text_frame
        tf.word_wrap = True
        add_bullets(tf, note)
        for p in tf.paragraphs:
            p.font.size = Pt(12)
            for run in p.runs:
                run.font.size = Pt(12)
    return slide


def _box(slide, left, top, w, h, text, fill=LIGHT, color=DARK, size=11, bold=False):
    shp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, w, h)
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    shp.line.color.rgb = DARK
    tf = shp.text_frame
    tf.word_wrap = True
    tf.text = text
    for p in tf.paragraphs:
        p.font.size = Pt(size)
        p.font.bold = bold
        p.font.color.rgb = color
        for run in p.runs:
            run.font.size = Pt(size)
            run.font.bold = bold
            run.font.color.rgb = color
    return shp


def _caption(slide, left, top, w, lines, size=12):
    box = slide.shapes.add_textbox(left, top, w, Inches(1.5))
    tf = box.text_frame
    tf.word_wrap = True
    add_bullets(tf, lines)
    for p in tf.paragraphs:
        p.font.size = Pt(size)
        for run in p.runs:
            run.font.size = Pt(size)
    return box


def _label(slide, left, top, w, text, size=12, bold=False, color=DARK):
    box = slide.shapes.add_textbox(left, top, w, Inches(0.35))
    tf = box.text_frame
    tf.word_wrap = True
    tf.text = text
    for p in tf.paragraphs:
        p.alignment = PP_ALIGN.CENTER
        p.font.size = Pt(size)
        p.font.bold = bold
        p.font.color.rgb = color
        for run in p.runs:
            run.font.size = Pt(size)
            run.font.bold = bold
            run.font.color.rgb = color
    return box


# ============================================================
# 1. 표지
# ============================================================
add_title_slide(
    "폐기 트리 샤딩 — 증명을 로그인당 1회로",
    "PairCT Mode 2 폐기 구조 · 2026-09-04 설계, 2026-09-06 구현·전환 완료",
)

# ============================================================
# 2. 지금 무엇이 문제인가
# ============================================================
add_bullet_slide("지금 무엇이 문제인가", [
    (0, "증명이 revocationRoot 하나에 통째로 묶여 있다", True),
    (1, "pi_pk_i의 public signal에 revocationRoot가 들어간다"),
    (1, "PPIDWallet.execute는 registry.isCurrentRoot(revocationRoot)를 먼저 본다"),
    (1, "따라서 폐기가 하나만 게시돼도 전 지갑의 증명이 동시에 죽는다"),
    (0, "규모에서 이게 얼마나 나쁜가 (100M DAU, 폐기 1만/일 = 0.01%/일 가정)", True),
    (1, "폐기 0.116건/초 = 블록당 약 1.4건 — 매 블록 root가 바뀐다"),
    (1, "증명 생성에 755.8ms가 걸리는데, 만들자마자 죽는다"),
    (0, "지금은 배칭이 이걸 가려주고 있다", True),
    (1, "5분 배칭이면 폐기 35건을 root 변경 1회로 묶으므로 증명이 5분 산다"),
    (1, "대신 폐기가 최대 5분 늦게 듣는다 — BAAR 대비 우리가 지는 유일한 지점"),
    (1, "배칭 주기 = 증명 수명 = 폐기 지연이 한 덩어리로 묶여 있다", True),
])

# ============================================================
# 3. 레버는 셋
# ============================================================
add_bullet_slide("먼저: root와 무관한 증명은 만들 수 없다", [
    (0, "두 요구가 동시에 걸려 있다", True),
    (1, "리프(L_acct, L_sess)는 숨겨야 한다 — 드러나면 교차-RP 연결이 뚫린다"),
    (1, "컨트랙트는 현재 폐기 상태에 대해 검증해야 한다"),
    (0, "그런데 컨트랙트는 숨겨진 값의 멤버십을 볼 수 없다", True),
    (1, "따라서 신선도 검사는 회로 안에 있어야 하고, 그러면 회로가 root에 묶인다"),
    (1, "커밋먼트로 감싸도 마찬가지다 — 컨트랙트는 여전히 그 값을 트리에서 못 찾는다"),
    (0, "그래서 레버는 셋뿐이다", True),
    (1, "① 어떤 root에 묶느냐 — root가 덜 자주 바뀌게 만든다 (4~10번)", True),
    (1, "② 그 root가 얼마나 오래 유효하냐 — grace window (11번)", True),
    (1, "③ 그 root를 누가 정하느냐 — 갱신 정당성 (12~13번)", True),
])

# ============================================================
# 4. 설계 도해
# ============================================================
slide = prs.slides.add_slide(LAYOUT_TITLE_ONLY)
slide.shapes.title.text = "설계: 깊이 20 트리를 중간에서 자른다"

_box(slide, Inches(4.55), Inches(1.40), Inches(4.2), Inches(0.45),
     "latestTopRoot (bytes32 1개)  ·  레지스트리는 지금 그대로",
     fill=WHITE, size=11, bold=True)
_box(slide, Inches(3.15), Inches(2.00), Inches(7.0), Inches(0.55),
     "상위 트리  ·  keccak256  —  컨트랙트가 Solidity에서 검증",
     fill=LIGHT, size=12, bold=True)
_label(slide, Inches(0.5), Inches(2.68), Inches(12.3),
       "───────────────  절단면  ───────────────", size=11, color=ACCENT)
_box(slide, Inches(1.1), Inches(3.05), Inches(4.9), Inches(0.95),
     "세션 서브트리  4,096개\nPoseidon 깊이 8", fill=WHITE, size=12, bold=True)
_box(slide, Inches(7.3), Inches(3.05), Inches(4.9), Inches(0.95),
     "계정 서브트리  1,024개\nPoseidon 깊이 10", fill=WHITE, size=12, bold=True)
_label(slide, Inches(0.5), Inches(4.10), Inches(12.3),
       "회로가 비멤버십을 증명하는 구간  —  SNARK는 sess_root와 acct_root에만 묶인다",
       size=12, bold=True)

_caption(slide, Inches(0.5), Inches(4.60), Inches(12.3), [
    (0, "상위 트리는 회로에 들어가지 않으므로 SNARK 친화적일 필요가 없다 — 그래서 keccak을 쓴다. 회로 안의 keccak은 해시당 15만 constraint급이라 불가능하다."),
    (0, "총 경로 길이는 보존된다: 세션 8+12, 계정 10+10. 자르는 위치만 바뀔 뿐 용량도 그대로다."),
    (0, "두 층의 샤딩 기준이 다르다(6~7번). 세션은 만료 기반, 계정은 값 기반이다."),
])

# ============================================================
# 5. 증명이 두 조각으로
# ============================================================
add_table_slide(
    "그 결과: 증명이 두 조각으로 나뉜다",
    ["", "담는 것", "언제 죽나", "비용"],
    [
        ["SNARK", "target ∉ 내 서브트리\n(세션·계정 각 1건)", "내 서브트리가 바뀔 때만", "510.3 ms (실측)"],
        ["calldata", "sess_root, acct_root,\n샤드 인덱스, 상위 형제 22개",
         "top root가 바뀔 때\n(= 아무 폐기나)", "무료 · 제출 직전 갱신"],
    ],
    [Inches(1.5), Inches(3.9), Inches(3.6), Inches(3.3)],
    height=Inches(2.0), font_size=12,
    note=[
        (0, "컨트랙트가 (root_s, 샤드 인덱스, 형제)로 top root를 재계산해 latestTopRoot와 비교한다."),
        (0, "핵심: 다른 서브트리에서 폐기가 나도 내 root_s는 그대로다 → 비싼 SNARK가 살아남는다.", True),
        (0, "바뀌는 것은 상위 형제뿐이고, 그건 루트 목록만 다시 받으면 되는 calldata다."),
        (0, "실측: 샤드 인덱스 제약은 0 constraint다 — 회로가 이미 만든 targetBits의 선형 결합이라 공짜다."),
    ],
)

# ============================================================
# 6. 세션과 계정은 샤딩 기준이 다르다
# ============================================================
add_table_slide(
    "세션과 계정은 샤딩 기준이 다르다",
    ["층", "샤딩 기준", "증명자가 자기 샤드를 아는가", "회수"],
    [
        ["세션", "(max_height mod 512) x 8\n+ L_sess 하위 3비트",
         "안다 — max_height가 이미 public signal이다",
         "공짜: 만료 블록이 지나면\n샤드를 통째로 리셋"],
        ["계정", "L_acct 하위 10비트", "유도한다 — 회로가 s == f(target)을 강제",
         "재기준화. 단 샤드 단위라\n그 샤드 지갑만 영향"],
    ],
    [Inches(1.0), Inches(3.2), Inches(4.4), Inches(3.7)],
    height=Inches(2.2), font_size=12,
    note=[
        (0, "세션에서 만료 기반 샤딩이 성립하는 이유: 세션 리프의 만료가 곧 max_height이고, 그건 이미 공개값이다."),
        (0, "assertMaxHeightWithinBound가 max_height <= 현재 + 300 + 32를 보장하므로 512칸 링이면 충분하다."),
        (0, "결과가 크다: 세션 층에서 재기준화·epoch·용량 정책이 통째로 사라진다. 만료된 샤드는 빈 트리 상수로 리셋하면 끝이다.", True),
        (0, "계정은 안 된다 — 계정 폐기의 만료는 접수 시점 + 332라 증명자가 모른다(모르는 것이 요점이다)."),
    ],
)

# ============================================================
# 7. 리뷰에서 발견: 세션 층이 병목이었다
# ============================================================
add_bullet_slide("리뷰에서 발견: 세션 층이 병목이었다", [
    (0, "빠뜨린 것 두 가지", True),
    (1, "SNARK는 sess_root와 acct_root를 둘 다 public으로 갖는다 — 둘 중 먼저 바뀌는 쪽이 증명을 죽인다", True),
    (1, "세션 샤드를 max_height mod 512로만 잡으면 칸은 512개지만 실효는 332개다 " +
        "(max_height 범위가 332블록이라 그 이상 흩어지지 않는다)"),
    (0, "그래서 결합해 다시 계산하면 (폐기 1.4건/블록)", True),
    (1, "폐기가 전부 세션이면 239블록(48분)마다 변경 → 크레덴셜 1시간당 1.26회 재생성"),
    (1, "계정 층만 세면 0.41회지만 그건 세션 층을 빼놓은 값이다 — 초안이 그렇게 낙관적으로 잡혀 있었다", True),
    (0, "해법: 세션 샤드를 2차원으로", True),
    (1, "샤드 = (max_height mod 512) x 8 + L_sess 하위 3비트 → 4,096칸(실효 2,656)"),
    (1, "상위는 컨트랙트가 max_height % 512로 직접 계산하고, 하위 3비트만 회로가 고정한다 — 회로에 나눗셈이 필요 없다"),
    (1, "결과: 재생성 0.16~0.41회. 그리고 세션 깊이가 8로 줄어 회로가 더 싸진다(13,905 실측)", True),
])

# ============================================================
# 8. 효과
# ============================================================
add_table_slide(
    "효과: 시간당 12회 → 로그인당 1회",
    ["폐기 구성 (총 1.4건/블록)", "내 서브트리 변경 주기", "크레덴셜 1시간당 SNARK 재생성"],
    [
        ["전부 세션 폐기", "1,911블록  (6.4시간)", "0.16회"],
        ["세션·계정 절반씩", "1,063블록  (3.5시간)", "0.28회"],
        ["전부 계정 폐기", "737블록  (2.5시간)", "0.41회"],
        ["지금 (배칭 5분, 샤딩 없음)", "25블록  (5분)", "12회"],
    ],
    [Inches(4.2), Inches(3.9), Inches(4.2)],
    height=Inches(2.6), font_size=13,
    note=[
        (0, "어느 구성이든 변경 주기가 크레덴셜 수명(300블록 = 1시간)보다 길다 → 로그인 1회에 증명 1개가 보통이다.", True),
        (0, "증명이 짧게 사는 원인은 SNARK가 무거워서가 아니라, 리프 100만 개를 root 하나로 묶어놨기 때문이다."),
        (0, "묶음을 나누면 무효화 빈도도 그만큼 나뉜다. 남은 병목은 계정 층(0.41회)이고, 계정 샤드를 4,096으로 올리면 더 내려간다."),
    ],
)

# ============================================================
# 9. 폐기율 민감도
# ============================================================
add_table_slide(
    "이 설계의 유일한 민감 변수: 폐기율",
    ["시나리오", "폐기/일", "폐기/블록", "상주 리프", "크레덴셜 1시간당\nSNARK 재생성 (절반씩 기준)"],
    [
        ["0.001%/일 (계정 사고만)", "1,000", "0.14", "42", "0.03회"],
        ["0.01%/일  (이 덱의 기준)", "1만", "1.4", "417", "0.28회"],
        ["0.1%/일", "10만", "13.9", "4,167", "2.8회"],
        ["로그인의 1%", "100만", "139", "4.2만", "28회"],
        ["로그인의 10%", "1,000만", "1,389", "42만", "282회"],
        ["로그아웃마다 (100%)", "1억", "13,889", "417만", "2,819회"],
    ],
    [Inches(3.0), Inches(1.5), Inches(1.7), Inches(1.7), Inches(4.4)],
    height=Inches(3.1), font_size=11,
    note=[
        (0, "마지막 줄: 로그아웃마다 폐기하면 상주 리프가 417만 — 멤버십 트리와 정확히 같아지고 비멤버십의 이점이 사라진다."),
        (0, "정책으로 못박아야 한다 — 로그아웃은 폐기하지 않는다. 1시간 자연 만료로 충분하고, 폐기는 보안 사건에만 쓴다.", True),
        (0, "샤드 개수는 거의 공짜 knob이다: 회로 비용은 서브트리 깊이만 따르고 온체인은 log2(샤드) x keccak(레벨당 약 1,100 gas)이다."),
        (0, "그래서 폐기율이 높으면 샤드를 늘리면 된다 — 0.1%/일 구간도 샤드를 16배로 키우면 크레덴셜 수명을 넘긴다. 회로는 그대로다."),
    ],
)

# ============================================================
# 10. 비용
# ============================================================
add_table_slide(
    "비용 — 회로는 오히려 싸진다 (constraint는 실측)",
    ["항목", "지금", "제안", "출처"],
    [
        ["세션 비멤버십", "6,648  (깊이 20)", "3,732  (깊이 8)", "실측"],
        ["계정 비멤버십", "6,648  (깊이 20)", "4,218  (깊이 10)", "실측"],
        ["전체 회로", "19,251", "13,905  (−27.8%)", "실측"],
        ["증명 시간", "755.8 ms", "510.3 ms", "실측"],
        ["execute 가스", "276,709", "330,079  (+53,370, +19.3%)", "실측"],
        ["public signal", "6개", "9개", "실측"],
        ["온체인 상태", "bytes32 1개", "동일", ""],
    ],
    [Inches(2.7), Inches(2.6), Inches(4.6), Inches(2.4)],
    height=Inches(3.5), font_size=12,
    note=[
        (0, "circom 2.1.9 단독 컴파일. build/는 건드리지 않았다. results/mode2_sharded_circuit_constraints_20260904.csv"),
        (0, "기준선 재현 확인: IMTNonMembershipV2(20) = 6,648, 현행 pi_pk_i = 19,251 — 기록값과 일치."),
        (0, "레벨당 243, 고정 오버헤드 1,788로 분해된다. 상위 22단을 Poseidon에서 keccak으로 옮긴 만큼이 그대로 이득이다.", True),
        (0, "가스가 추정(+12,000)을 4배 넘었다. 상위 경로 keccak과 calldata만 세고, Groth16 verifier가 public signal마다 치르는 비용(6->9개, ecMul 3회 약 18k)을 빼먹었다.", True),
        (0, "증명 시간은 세 회로를 한 실행에서 순차로 돌린 통합 벤치 기준이다(데모 스택 정지). 로그인 1회분 합은 912.7 ms."),
    ],
)

# ============================================================
# 11. grace window
# ============================================================
add_bullet_slide("함께 얹을 것: 블록 단위 grace window", [
    (0, "왜 필요한가", True),
    (1, "top root는 여전히 매 블록 바뀌므로, 제출과 채굴 사이에 바뀌면 revert한다"),
    (1, "복구 비용은 가벼워졌지만(형제만 갱신, SNARK 재생성 불필요) 아예 없애는 편이 낫다"),
    (0, "방식", True),
    (1, "레지스트리가 (root, 게시블록)을 저장하고, 최근 K블록 안에 게시된 root를 허용한다"),
    (1, "폐기 지연 = K블록로 고정된다 — 폐기 빈도와 무관하다", True),
    (1, "K = 2~3이면 24~36초. 지금 배칭 지연(수 분)보다 오히려 짧다"),
    (0, "설계 주의", True),
    (1, "grace는 root 개수가 아니라 블록 수로 재야 한다 — 개수로 재면 변경이 드문 샤드에서 옛 root가 오래 남는다", True),
    (1, "이건 43ca1bc(grace 제거)를 의식적으로 되돌리는 것이다. 당시 근거는 '배칭 덕에 root가 드물게 바뀐다'였고, 그 전제가 바뀐다"),
])

# ============================================================
# 12. 신뢰 모델 — 지금 누가 무엇을 할 수 있나
# ============================================================
add_table_slide(
    "지금 누가 트리를 관리하고 누가 게시하나",
    ["역할", "주체", "자격"],
    [
        ["폐기 접수 · 트리 보관 · 상태 영속화", "IdP 프로세스 (custom_idp.js)", "— (체인 쓰기 없음, eth_blockNumber 읽기만)"],
        ["폐기 요청 · 계정 차단 · 재기준화", "운영자", "IDP_ADMIN_SECRET"],
        ["온체인 pushRoot", "운영자 (sweep 데몬)", "REVOCATION_IDP_ADDRESS의 이더리움 키"],
        ["게시 승인", "RevocationRegistry.idp (immutable)", "onlyIdP"],
    ],
    [Inches(4.3), Inches(3.9), Inches(4.1)],
    height=Inches(2.6), font_size=12,
    note=[
        (0, "IdP에 개인키를 두지 않으려고 게시를 분리했는데, sweep 데몬이 두 자격을 다 들고 있어 분리가 명목상이다."),
        (0, "컨트랙트는 게시된 root가 실제 트리와 맞는지 전혀 검증하지 않는다 — 갱신 정당성 증명이 없다.", True),
        (0, "그래서 레지스트리 키를 가진 사람은 (a) 옛 root를 다시 올려 전원의 폐기를 되돌리거나 (b) 쓰레기 root로 전원을 막을 수 있다."),
        (0, "사용자는 자기 세션을 폐기할 수 없다 — /idp/revoke는 관리자 전용이다."),
    ],
)

# ============================================================
# 13. 컨트랙트가 트리를 유지하게 하면?
# ============================================================
add_bullet_slide("③ 컨트랙트가 트리를 유지하게 하면?", [
    (0, "안 되는 두 가지부터", True),
    (1, "트리 전체 저장: 리프 100만 개 — 스토리지에서 끝난다"),
    (1, "삽입마다 root 재계산: Poseidon 약 40회. EVM에 precompile이 없어 폐기 1건당 100만 gas 안팎이다", True),
    (1, "Poseidon을 keccak으로 못 바꾼다 — 같은 트리를 회로에서도 봐야 하는데 회로 안 keccak은 해시당 15만 constraint급이다"),
    (0, "실현 가능한 형태: 갱신 정당성 증명 (zk-rollup 방식)", True),
    (1, "pushRoot(oldRoot, newRoot, proof) — 컨트랙트가 oldRoot == latestRoot를 강제하고 전이 증명을 검증한다"),
    (1, "Groth16 1회 약 25만 gas인데 게시 배치당 한 번이다 — 배치 35건이면 폐기 건당 7,000 gas"),
    (0, "무엇이 막히고 무엇은 안 막히나", True),
    (1, "막힘: 옛 root 재게시(폐기 되돌리기), 쓰레기 root로 전원 차단", True),
    (1, "안 막힘: 폐기 누락. 체인은 무엇이 폐기돼야 하는지 모른다 — 어떤 온체인 장치도 이건 못 막는다", True),
    (1, "세션 층은 증명이 아예 필요 없다 — 샤드 인덱스가 곧 만료라 컨트랙트가 block.number만 보고 스스로 리셋한다"),
])

# ============================================================
# 14. 함께 해결되는 기존 약점
# ============================================================
add_table_slide(
    "함께 해결되는 기존 약점",
    ["기존 약점", "해결"],
    [
        ["폐기 지연이 게시 주기만큼 (수 분)", "K블록으로 고정 — 24~36초"],
        ["root 전환 시 인플라이트 revert", "grace가 흡수"],
        ["재기준화가 전 지갑에 O(n) 재다운로드를 물림", "샤드 단위 — 해당 샤드 지갑만"],
        ["세션 폐기도 재기준화로만 회수됨", "세션 층은 재기준화 자체가 사라짐 — 만료 샤드를 리셋"],
        ["지갑 콜드 스타트가 O(n)", "리프 n/샤드 + 루트 목록"],
        ["증명이 매 게시마다 죽음", "내 서브트리 변경 시에만"],
        ["운영자가 옛 root를 올려 폐기를 되돌릴 수 있음", "갱신 정당성 증명으로 차단 (13번)"],
    ],
    [Inches(6.4), Inches(5.9)],
    height=Inches(3.6), font_size=12,
    note=[
        (0, "첫 줄이 BAAR 대비 우리가 지는 유일한 지점이었다(세미나 덱 26번). 이 설계가 그걸 없앤다."),
        (0, "마지막 줄은 BAAR가 Lemma 6에서 주장하지만 증명하지 못하는 지점이다 — 우리는 실제로 채울 수 있다.", True),
    ],
)

# ============================================================
# 15. 소트니스 조건
# ============================================================
add_bullet_slide("반드시 지켜야 할 소트니스 조건", [
    (0, "계정 층", True),
    (1, "① 회로가 s == f(L_acct)을 강제해야 한다 — 없으면 증명자가 비어 있는 서브트리를 골라 통과한다"),
    (0, "세션 층 — 상위·하위를 서로 다른 주체가 고정한다", True),
    (1, "② 컨트랙트가 상위를 max_height % 512로 직접 계산해야 한다 (호출자가 준 값을 쓰면 안 된다)"),
    (1, "③ 회로가 하위 3비트 == L_sess 하위 3비트를 강제해야 한다"),
    (1, "둘 중 하나만 있으면 나머지 축이 자유로워져 빈 샤드를 고를 수 있다", True),
    (0, "양쪽 공통", True),
    (1, "④ IdP는 반드시 f(leaf) 샤드에만 삽입해야 한다 — 엉뚱한 샤드에 넣으면 그 폐기는 증명에 보이지 않아 조용히 무효가 된다", True),
    (1, "지금 구조에 없던 종류의 실패 모드다. 테스트로 고정해야 한다"),
    (0, "함께 검증할 것", True),
    (1, "부하 균형은 샤드별로 봐야 한다 — 전역 용량 정책 1개가 샤드 수만큼으로 늘어난다"),
    (1, "재기준화가 샤드 단위가 되면서 epoch도 샤드별이 된다 — 지갑 동기화 프로토콜 변경"),
])

# ============================================================
# 16. 검토했다가 버린 안
# ============================================================
add_table_slide(
    "검토했다가 버린 안",
    ["안", "왜 버렸나"],
    [
        ["멤버십으로 전환 (BAAR 방식)",
         "트리 크기가 로그인 빈도에 비례 → 100M DAU에서 상주 리프 417만, 초당 2,315 쓰기.\n"
         "지갑이 코어 27%를 상시 태워야 한다. 그리고 배칭 지연이 폐기가 아니라 매 로그인으로 옮겨간다"],
        ["L_sess를 공개해 세션 비멤버십을\n온체인 keccak으로 검증",
         "회로가 크게 싸지지만, IdP가 issuanceLog를 r_token으로 키잉해 갖고 있다.\n"
         "체인만 보면 uid를 얻는다 → 조건부 추적이 상시 추적이 된다"],
        ["만료 기반 샤딩 — 계정 층에 한해",
         "계정 폐기의 만료는 접수 시점 + 332라 증명자가 모른다 → 전 샤드 증명이 필요하다.\n"
         "세션 층에서는 만료가 곧 public signal인 max_height라 성립하며, 채택했다(6번)"],
        ["상위 경로도 회로 안에 두기",
         "총 경로 길이가 보존되므로 이득이 0이다. 밖으로 빼야 의미가 생긴다"],
        ["서브트리 root를 스토리지에 직접 저장\n(top 트리 없이)",
         "사용자 가스는 오히려 싸다(SLOAD 2회 vs keccak 22회). 보류 사유는 확장성이다 —\n"
         "샤드를 2^16 이상으로 늘리는 경로에서 mapping 슬롯 비용이 붙는다. 재검토 여지 있음"],
    ],
    [Inches(3.6), Inches(8.7)],
    height=Inches(4.3), font_size=10,
)

# ============================================================
# 17. 남은 위험
# ============================================================
add_bullet_slide("남은 위험과 전제", [
    (0, "가스 — 배포 체인 선택에 의존한다", True),
    (1, "매 블록 게시는 하루 7,200 tx, 약 1억 8,700만 gas"),
    (1, "메인넷 20 gwei면 하루 약 3.75 ETH — 비현실적. L2 또는 전용 체인 전제다", True),
    (0, "무엇이 실측이고 무엇이 아닌가", True),
    (1, "constraint(3,732 / 4,218 / 13,905)는 circom 단독 컴파일 실측이다 — 기준선 6,648·19,251 재현으로 검증했다"),
    (1, "증명 시간(510.3 ms)과 가스(330,079)도 이제 실측이다 — zkey를 만들고 진짜 증명으로 execute를 통과시켰다", True),
    (1, "추정으로 남은 것은 온체인 Poseidon 100만 gas 하나다 — 이 설계는 keccak만 쓰므로 직접 영향은 없다"),
    (0, "가정에 의존한다", True),
    (1, "폐기 블록당 1.4건(1만/일, 0.01%)을 전제로 한 결론이다 — 9번의 민감도 표 참조", True),
    (1, "세션·계정 폐기 비율은 모른다. 8번은 세 경우를 모두 제시했다"),
    (0, "구현 규모와 재배포", True),
    (1, "lib/, IdP의 v2 섹션 전체, 지갑 동기화, 회로, 상태 파일 v5 + 마이그레이션"),
    (1, "zkey 재생성 + PPIDWalletFactory 재배포. chain_id를 public signal로 올리는 수정과 묶는 것이 낫다"),
])

# ============================================================
# 18. 다음 단계
# ============================================================
add_bullet_slide("진행 상황과 남은 것", [
    (0, "완료 (2026-09-04 ~ 09-06)", True),
    (1, "설계 문서, 회로(pi_pk_i_v3), 라이브러리(imt_v3), 컨트랙트(RegistryV3/WalletV3), IdP·지갑 배선"),
    (1, "zkey 생성 → 진짜 증명으로 execute 통과 → 실운영 스택 전환까지 마쳤다"),
    (1, "실측 확정: constraint 13,905 · 증명 510.3 ms · 가스 330,079", True),
    (1, "테스트 unit+circuit 16 / chain 3 / contract 31 / live 16 전부 통과"),
    (0, "논문 (final47에 반영 완료)", True),
    (1, "폐기 절(IV-G)과 Property 9 신설, Table 1에 Revocation 열과 BAAR 행"),
    (1, "정정: \"새 신뢰 주체 없음\"은 거짓이 됐다 — 온체인 게시자가 상시 역할이다", True),
    (1, "Property 5를 off-chain transcript로 한정 (계정 샤드 인덱스 누출)"),
    (0, "남은 것", True),
    (1, "v2 경로 정리(회로·IdP 트리·옛 컨트랙트)는 안정화 후"),
    (1, "갱신 정당성 증명(12번)은 별도 설계 — 롤백은 막지만 폐기 누락은 원리상 못 막는다"),
    (1, "온체인 Poseidon 가스만 추정으로 남았다(이 설계는 keccak만 쓴다)"),
])

# 렌더 자체 검사: 마크다운 강조는 pptx에서 파싱되지 않는다.
for _i, _s in enumerate(prs.slides, 1):
    for _sh in _s.shapes:
        _t = _sh.text_frame.text if _sh.has_text_frame else ""
        if _sh.has_table:
            _t += "".join(c.text for r in _sh.table.rows for c in r.cells)
        if "**" in _t:
            raise SystemExit(f"슬라이드 {_i}에 리터럴 마크다운 '**'가 남아 있다")

prs.core_properties.title = "폐기 트리 샤딩 설계 검토"
prs.core_properties.author = "Moonhyeon Chung"
prs.core_properties.subject = "PairCT Mode 2 revocation tree sharding design"
prs.core_properties.comments = "빌더: scripts/build_revocation_sharding_slides_260904.py"

prs.save(OUT)
print(f"wrote {OUT} ({len(prs.slides._sldIdLst)} slides)")
