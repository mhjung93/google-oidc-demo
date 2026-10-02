#!/usr/bin/env python3
"""Build a clean design deck for PairCT revocation — presents the design as
settled, without change history or before/after comparisons.

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
OUT = os.path.join(REPO_ROOT, "documents", "260826_revocation_design.pptx")

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
add_title_slide(
    "PairCT Revocation 설계",
    "\n크레덴셜 폐기 · Ephemeral 폐기 트리 · 온체인 Root Registry\nMoonhyeon Chung, POSTECH",
)

# ============================================================
# 2. 문제
# ============================================================
add_bullet_slide("문제 — 만료만으로는 부족하다", [
    (0, "크레덴셜은 max_height(1시간, 300블록)가 지나면 자연 만료된다", True),
    (0, "그러나 만료만 있으면 세션을 중간에 끊을 수 없다", True),
    (1, "세션키가 유출돼도 창이 닫힐 때까지 기다려야 한다"),
    (1, "SSI 폐기 분류상 ③번 단기 크레덴셜 — 네 범주 중 가장 약한 쪽"),
    (0, "IdP는 미래 발급을 거부할 수는 있다 — 토큰을 안 내주면 된다", True),
    (1, "하지만 이미 발급돼 나간 크레덴셜은 회수할 수 없다"),
    (1, "서명은 이미 지갑 손에 있고 max_height까지 유효하다"),
    (0, "→ 필요한 것: 발급된 크레덴셜을 만료 전에 무효화하는 수단", True),
    (0, "제약: 검증자가 스마트컨트랙트(PPIDWallet.execute)라 폐기 리스트를 보유할 수 없다", True),
])

# ============================================================
# 3. 전체 구조
# ============================================================
add_bullet_slide("전체 구조", [
    (0, "① IdP가 폐기 항목을 Indexed Merkle Tree(IMT)에 넣는다", True),
    (1, "리프는 해시라 목록을 공개해도 남의 값을 알 수 없다"),
    (0, "② root(32바이트)만 온체인 RevocationRegistry에 게시한다", True),
    (1, "리스트 자체는 오프체인 — IdP가 HTTP로 서빙"),
    (0, "③ 지갑이 목록을 받아 로컬에서 트리를 재구성하고, 자기 witness를 만든다", True),
    (1, "재구성한 root가 IdP가 알린 root와 일치하는지 대조한다"),
    (0, "④ pi_pk_i 회로가 \"내 세션과 계정이 그 트리에 없음\"을 증명한다", True),
    (1, "폐기 대상은 회로 밖으로 나오지 않는다 — private input"),
    (0, "⑤ PPIDWallet.execute()가 증명에 쓰인 root가 registry에 등록·유효한지 확인한다", True),
    (0, "BAAR(PLOS ONE 21(3):e0343696)의 \"오프체인 증명 + 온체인 컴팩트 root\" 구조를 따른다", True),
    (0, "구현 상태 — ①~⑤ 골격, 리프 수명 관리(만료·프루닝), 배칭까지 구현·검증 완료", True),
    (1, "남은 설계 단계: 계정 층(disabled 플래그·재바인딩 복구), 리스트 미러링"),
])

# ============================================================
# 4. 폐기 기준
# ============================================================
add_bullet_slide("폐기 기준 — 무엇을 리프로 삼는가", [
    (0, "두 단위를 한 트리에 도메인 태그로 구분해 담는다", True),
    (1, "세션 리프 = Poseidon(TAG_SESSION, r_token),  r_token = Poseidon(pk_i, max_height, rp_nonce)"),
    (1, "계정 리프 = Poseidon(TAG_ACCOUNT, auid),      auid = Poseidon(uid, salt)"),
    (1, "트리가 하나라 온체인에 게시하는 root도 하나뿐이다"),
    (0, "r_token — (그 로그인, 그 RP) 하나를 정확히 지목", True),
    (1, "세션키·유효창·RP 논스를 묶은 값 → 유출된 세션 하나만 끊는다"),
    (1, "계정 단위만 있으면 세션 하나 유출에 그 사용자의 모든 RP·기기를 통째로 죽여야 한다"),
    (0, "auid — 계정 전체, RP와 무관", True),
    (1, "rid가 들어가지 않으므로 어느 RP에서든 같은 값 → 리프 하나로 전역 적용"),
    (0, "회로가 두 값을 계정에 묶는다", True),
    (1, "PPID === Poseidon(uid, rid, salt),  auid === Poseidon(uid, salt) — 같은 uid·salt signal 공유"),
    (1, "→ 남의 auid를 자기 PPID에 갖다 붙일 수 없다"),
])

# ============================================================
# 5. 왜 그 값이어야 하는가
# ============================================================
add_table_slide(
    "왜 그 값이어야 하는가 — 아는 쪽이 갈려 있다",
    ["값", "IdP가 아는가", "체인이 아는가", "역할"],
    [
        ["r_token", "○ (token_nonce로 공개)", "✕ (pi_pk_i에서 private)", "세션 폐기 대상"],
        ["auid", "○ (로그인 시 지갑이 제시)", "✕ (회로 내부 유도)", "계정 폐기 대상"],
        ["pk_i", "✕ (pi_arid_i에서 private)", "○ (ecrecover에 필요)", "세션키 — 폐기 대상 불가"],
        ["PPID", "✕", "○ (지갑 주소 유도)", "지갑 식별 — 폐기 대상 불가"],
    ],
    [Inches(1.6), Inches(3.6), Inches(3.6), Inches(3.5)],
    height=Inches(2.6), font_size=13,
    note=[
        (0, "IdP가 아는 것과 체인이 아는 것이 의도적으로 겹치지 않는다. 폐기 대상 둘이 모두 \"IdP만 아는\" 쪽에 있어야 한다:"),
        (0, "IdP가 값을 알아야 폐기를 집행할 수 있고, 체인이 그 값을 몰라야 폐기가 온체인 활동과 IdP 기록을 잇는 다리가 되지 않는다."),
        (0, "pk_i를 리프로 삼으면 체인의 pk_i로 Poseidon(TAG, pk_i)를 계산해 공개 목록과 대조할 수 있다 — 어느 세션이 폐기됐는지 노출된다."),
    ],
)

# ============================================================
# 6. 폐기의 의미
# ============================================================
add_bullet_slide("폐기의 의미 — 크레덴셜 폐기", [
    (0, "폐기는 \"이미 발급된 크레덴셜의 무효화\"이지 \"사람의 추방\"이 아니다", True),
    (0, "근거 셋", True),
    (1, "① 트리가 유일하게 할 수 있는 일이 이것이다 — 미래 발급 차단은 IdP가 토큰을 안 내주면 되므로"),
    (2, "트리 없이 되는 일에 회로 제약 19,049개를 동원할 이유가 없다"),
    (1, "② 온체인 검증자는 \"사람\"을 모른다 — execute()는 무상태 크레덴셜 상태 조회를 할 뿐"),
    (1, "③ 체인에서는 가역성이 중요하다 — 오폐기에 항소 수단이 없고, 되돌릴 수 없으면 지갑 자산이 영구 동결된다"),
    (0, "두 층으로 분리한다", True),
    (1, "발급된 크레덴셜 무효화 → 폐기 트리 (가역) — 구현·검증 완료"),
    (1, "사람 차단 → IdP 계정 비활성화 — 아직 설계 단계"),
    (0, "재바인딩은 IdP가 판단한다", True),
    (1, "지갑이 일방적으로 새 salt를 제시하는 것은 거부 (auid 고정 검사)"),
    (1, "IdP가 uid를 인증한 복구 흐름에서만 고정을 해제한다 — 공격자는 스스로 풀 수 없다"),
])

# ============================================================
# 7. Ephemeral 트리
# ============================================================
add_bullet_slide("트리는 ephemeral하다", [
    (0, "폐기가 \"발급된 것의 무효화\"라면, 모든 리프에 자연 수명이 있다", True),
    (1, "max_height가 지나면 그 시점 이전에 발급된 것들은 전부 죽는다"),
    (1, "앞으로 발급하지 않는 것은 IdP 계정 층이 담당한다"),
    (1, "⟹ 세션 리프도 계정 리프도 만료 후엔 트리에서 뺄 수 있다"),
    (0, "트리 크기가 \"역대 폐기 수\"가 아니라 \"최근 한 창 안의 긴급 폐기 수\"가 된다", True),
    (1, "자연 만료되는 세션은 애초에 트리에 들어가지 않는다 — 긴급 폐기만 들어간다"),
    (0, "가역성이 따로 필요 없다", True),
    (1, "프루닝이 곧 폐기 해제다. 폐기를 유지하려면 갱신하고, 풀려면 갱신하지 않는다"),
    (0, "sweep은 heartbeat와 같은 작업이다", True),
    (1, "대기 중인 폐기를 반영하려면 주기적으로 게시해야 한다"),
    (1, "그 sweep에서 만료 리프를 같이 걷어내면 cron 하나가 둘 다 수행한다"),
])

# ============================================================
# 8. 규칙
# ============================================================
add_table_slide(
    "규칙 — 술어 하나를 두 시점에 적용한다",
    ["", "만료 블록", "입구 검사 (insert)", "sweep (주기)"],
    [
        ["세션\n(r_token)", "그 크레덴셜의\nmax_height",
         "발급 기록을 조회 → 기록이 없거나\n이미 만료면 거부", "만료되면 제거"],
        ["계정\n(auid)", "폐기 시각 + max_height\n(폐기 직전 발급분까지 덮기 위해)",
         "항상 통과 (만료가 항상 미래)", "만료되면 제거\n= 폐기 해제"],
    ],
    [Inches(1.6), Inches(3.2), Inches(4.3), Inches(3.2)],
    height=Inches(2.2), font_size=12,
    note=[
        (0, "술어는 하나:  만료블록 > 현재블록.  입구에서 쓰면 태어날 때부터 죽은 것을 막고, sweep에서 쓰면 살다가 죽은 것을 치운다."),
        (0, "입구 검사의 부수 효과: 만료를 판단하려면 \"이 r_token을 내가 발급했는가\"를 먼저 조회해야 한다."),
        (0, "→ 발급한 적 없는 값은 거부되므로, 임의의 숫자를 넣어 트리를 부풀리는 오염이 원천 차단된다."),
    ],
)

# ============================================================
# 8-2. 배칭
# ============================================================
add_bullet_slide("배칭 — 게시된 상태와 대기 상태의 분리", [
    (0, "폐기를 즉시 반영하면 지갑이 전부 막힌다", True),
    (1, "IdP 내부는 즉시 바뀌는데 온체인 root는 옛 값이다"),
    (1, "지갑이 새 목록으로 witness를 만들면 그 root가 미게시라 execute()가 거부된다"),
    (0, "해결: /idp/revocation_state는 게시된 상태만 서빙한다", True),
    (1, "폐기는 대기열(pendingAdds)에 쌓이고, 게시 때 한꺼번에 반영된다"),
    (1, "게시 전까지 지갑은 유효한 옛 root로 동작한다 — 장애 창이 없고, 폐기 지연은 게시 주기만큼으로 유계"),
    (0, "게시는 두 단계다 — push가 확정된 뒤에만 IdP가 전진한다", True),
    (1, "prepare: 대기분 적용 + 만료분 제거 후의 root를 변경 없이 계산"),
    (1, "pushRoot: 온체인 게시, 영수증 대기"),
    (1, "commit: prepare가 계산한 root와 일치할 때만 실제 교체 (불일치 409)"),
    (0, "실패 시 거동", True),
    (1, "push 실패 → 아무것도 안 바뀜"),
    (1, "commit 실패 → 체인이 더 최신인데 IdP는 옛 리프를 서빙 → 전면 장애 (즉시 재시도로 창을 좁힌다)"),
    (0, "wallet_agent.js 무수정으로 통과 — 지갑이 계약대로 게시된 상태만 보기 때문", True),
])

# ============================================================
# 9. 온체인 registry
# ============================================================
add_bullet_slide("온체인 — RevocationRegistry", [
    (0, "상태는 latestRoot 하나뿐이다 — 컨트랙트 전체가 43줄", True),
    (1, "isCurrentRoot(root) = (root == latestRoot && latestRoot != 0)"),
    (1, "창도 버퍼도 없다 — 새 root가 게시되면 직전 root는 즉시 무효"),
    (0, "왜 창이 필요 없나", True),
    (1, "배칭 덕에 heartbeat가 같은 root를 재게시할 때는 값이 안 바뀌어 무효화가 없다"),
    (1, "root가 실제로 바뀌는 건 폐기가 게시될 때뿐이고, 폐기는 드물다"),
    (0, "latestRoot == 0이면 아무것도 통과하지 못한다", True),
    (1, "배포 직후 부트스트랩 게시가 필수 — redeploy 스크립트가 함께 수행한다"),
    (0, "권한: IdP 운영자 주소만 pushRoot 가능", True),
    (0, "폐기 지연 = 게시 주기. 데몬 간격 하나로 조절된다", True),
])

# ============================================================
# 10. 왜 root만 온체인인가
# ============================================================
add_bullet_slide("왜 root만 온체인인가", [
    (0, "root가 온체인이어야 하는 이유", True),
    (1, "① 검증자가 스마트컨트랙트다 — PPIDWallet.execute()는 HTTPS를 호출할 수 없다"),
    (2, "검증자가 오프체인 서버였다면 웹 게시로 충분하다 (W3C Bitstring Status List가 그 방식)"),
    (1, "② 비-equivocation — 웹서버는 클라이언트마다 다른 응답을 줄 수 있다"),
    (2, "IdP가 A에겐 \"폐기됨\", B에겐 \"유효함\"을 보여줘도 아무도 모른다. 체인은 단일 공개 로그다"),
    (1, "③ 단일 최신값 — 어느 root가 \"지금 것\"인지에 모두가 같은 답을 본다"),
    (0, "리스트가 온체인일 이유는 없다", True),
    (1, "지갑이 목록을 받아 로컬에서 재구성하고 root로 무결성을 확인하면 충분하다"),
    (1, "CDN·IPFS 미러링이 바람직하다 — IdP가 조회 패턴을 보지 못하게 된다"),
    (2, "지갑이 tx 직전마다 IdP를 조회하면 IdP 로그와 온체인 활동이 타이밍으로 상관된다"),
])

# ============================================================
# 11. 회로
# ============================================================
add_bullet_slide("회로 — 비멤버십 증명", [
    (0, "pi_pk_i의 새 public input: revocationRoot 1개", True),
    (0, "새 제약", True),
    (1, "PPID === Poseidon(uid, rid, salt),   auid === Poseidon(uid, salt)"),
    (1, "NonMembership(Poseidon(TAG_SESSION, r_token), revocationRoot)"),
    (1, "NonMembership(Poseidon(TAG_ACCOUNT, auid),    revocationRoot)"),
    (1, "두 비멤버십이 같은 root에 배선된다 — 세션과 계정이 서로 다른 root를 쓸 수 없다"),
    (0, "폐기 집합(비멤버십)을 쓰는 이유", True),
    (1, "발급 집합 멤버십은 발급마다 root가 바뀌어 전 사용자의 witness가 상시 무효화된다"),
    (1, "발급은 잦고 폐기는 드물다 → 폐기 집합 쪽이 root 변경 빈도가 훨씬 낮다"),
    (0, "누적기는 Indexed Merkle Tree(IMT) — 다음 장에서 이유를 본다", True),
])

# ============================================================
# 11-2. 왜 IMT인가
# ============================================================
add_bullet_slide("왜 Indexed Merkle Tree인가", [
    (0, "IMT는 별도의 트리 구조가 아니다 — 평범한 이진 Merkle tree에 리프 인코딩만 다르다", True),
    (1, "leaf(i) = Poseidon(value[i], nextValue[i]) — 값을 정렬해 (값, 다음값) 쌍을 담는다"),
    (0, "평범한 리프(값 그 자체)로는 비멤버십을 증명할 수 없다", True),
    (1, "Merkle 경로는 \"L이 있다\"만 보인다"),
    (1, "\"L이 없다\"를 보이려면 모든 리프를 열어야 하고, 회로 안에서 O(n)이라 불가능하다"),
    (0, "비멤버십을 얻는 두 가지 길", True),
    (1, "Sparse Merkle Tree — 값 자체를 인덱스로 써서 그 위치가 0임을 증명. 깊이 = 필드 비트수 254"),
    (1, "Indexed Merkle Tree — 정렬 후 low < target < next인 리프 하나를 제시. 깊이를 실제 원소 수에 맞춤"),
    (0, "실측 비교 (비멤버십 1개)", True),
    (1, "IMT depth 20 : 6,627 제약     /     SMT depth 254 : 63,489 제약  (약 9.6배)"),
    (1, "pi_pk_i 전체로는 19,049 → 약 132,800 (약 7배). 증명 시간 800 ms → 5~6초대 추정"),
    (0, "IMT가 요구하는 것 — 공짜는 아니다", True),
    (1, "리프 정렬 유지 · anchor 리프 0 필요 · 삽입 시 이웃 리프의 next 갱신"),
    (1, "비교 2회 + range check가 고정 1,767 제약 (depth 20에서 전체의 27%)"),
])

# ============================================================
# 12. 비용
# ============================================================
add_table_slide(
    "비용 (실측)",
    ["항목", "값", "비고"],
    [
        ["pi_pk_i 제약", "19,049", "폐기 추가 전 4,820 → 약 4배"],
        ["증명 생성", "799.61 ms (±85.69, n=10)", "circom + snarkjs, groth16"],
        ["execute() gas", "297,837", "온체인 E2E 실측, 지갑 배포 별도"],
        ["isRecentRoot", "~2,100 gas", "콜드 SLOAD"],
        ["pushRoot", "~30K gas", "갱신 주기당 1회"],
        ["지갑 트리 재구성", "n=100: 34 ms / n=1,000: 288 ms", "캐시 미스 1회당 (build 3회)"],
    ],
    [Inches(3.0), Inches(4.6), Inches(4.7)],
    height=Inches(3.4), font_size=13,
    note=[
        (0, "트리 재구성은 build()가 getRoot 1회 + witness 2회로 세 번 도는 현재 구현 기준 — 메모이제이션으로 1/3로 줄일 수 있다."),
        (0, "n이 작을 때는 무시할 만하지만 1억 규모에서는 지배적 비용이 된다 — 19장 참조."),
    ],
)

# ============================================================
# 13. 확장성
# ============================================================
add_table_slide(
    "확장성 — depth별 회로 크기 (실측)",
    ["depth", "슬롯 수", "pi_pk_i 제약", "depth 20 대비"],
    [
        ["20 (현재)", "1,048,576", "19,049", "—"],
        ["24", "16.8M", "20,993", "+10.2%"],
        ["27", "134M", "22,451", "+17.9%"],
        ["30", "1.07B", "23,909", "+25.5%"],
    ],
    [Inches(2.2), Inches(3.0), Inches(3.4), Inches(3.7)],
    height=Inches(2.5), font_size=13,
    note=[
        (0, "정확히 선형:  pi_pk_i(d) = 19,049 + 486 × (d − 20).  레벨당 243제약(Poseidon 240 + mux 2 + 비트 1) × 비멤버십 2개."),
        (0, "깊이는 병목이 아니다 — 사용자 128배(depth 20→27)에 회로 1.18배."),
        (0, "Ephemeral 트리에서는 depth 20~21이면 충분하다 (18장에 규모별 수치)."),
    ],
)

# ============================================================
# 14. 프라이버시와 신뢰 가정
# ============================================================
add_bullet_slide("프라이버시 성질과 신뢰 가정", [
    (0, "불변식 — r_token과 auid는 어떤 회로의 public 입력도 되지 않는다", True),
    (1, "둘 중 하나라도 공개되면 폐기가 linkability oracle이 되어 conditional privacy가 무너진다"),
    (1, "Groth16에서 경로 검증을 회로 안에 넣는 4배 비용은 이 불변식의 대가다"),
    (0, "IdP는 새로운 정보를 얻지 않는다", True),
    (1, "트리에 넣는 값(r_token, auid)은 IdP가 발급 시점에 이미 알던 값이다"),
    (1, "단, 접근 패턴은 별개 — 리스트 미러링으로 분리해야 한다"),
    (0, "폐기 목록은 공개돼도 안전하다", True),
    (1, "리프가 Poseidon 해시라 목록만으로 남의 r_token이나 auid를 알 수 없다"),
    (0, "신뢰 가정", True),
    (1, "폐기 권한은 IdP 단독 — conditional privacy가 이미 IdP를 신뢰 주체로 두므로 새 가정이 아니다"),
    (1, "온체인 게시 권한은 IdP 운영자 주소 — 이 주소와 IdP 서명키는 별개 신뢰 경계다"),
])

# ============================================================
# 15. 명시할 한계
# ============================================================
add_bullet_slide("명시할 한계", [
    (0, "폐기 효력 지연 = 게시 주기 (데몬 간격)", True),
    (1, "폐기는 대기열에 쌓였다가 다음 게시에 반영된다"),
    (1, "간격을 줄이면 지연이 줄지만 인플라이트 실패가 늘어난다"),
    (0, "폐기된 동안에는 cross-RP unlinkability가 약해진다", True),
    (1, "계정 리프는 RP 무관 고정값이라, 두 RP가 같은 값을 관측하면 연결할 수 있다"),
    (1, "ephemeral 트리로 노출 창이 한 max_height로 제한되지만 없어지지는 않는다"),
    (1, "전역 폐기가 RP 무관 식별자를 요구하는 데서 오는 구조적 귀결이다"),
    (0, "재바인딩하면 지갑이 바뀐다", True),
    (1, "PPID = Poseidon(uid, rid, salt)이고 CREATE2 주소가 PPID에서 나온다"),
    (1, "새 salt = 새 지갑 → 옛 지갑 자산은 폐기가 풀려야 회수 가능하다"),
    (0, "가용성 — 데몬이 멈추면 모두 계속 동작하지만 폐기가 조용히 효력을 잃는다 (fail-open)", True),
    (1, "grace 제거로 fail-closed에서 뒤집혔다 — 데몬 중단 감지 책임이 운영자에게 있다"),
])

# ============================================================
# 17. 규모 분석 — 가정
# ============================================================
add_bullet_slide("규모 분석 — 가정", [
    (0, "전체 사용자 1억 명, max_height 창 = 300블록(1시간)", True),
    (0, "사용자당 1일 1회 로그인 → 시간당 약 417만 세션", True),
    (0, "세션 폐기율 — 만료를 기다리지 않고 중간에 끊는 세션의 비율", True),
    (1, "Ephemeral 트리에서 리프 수 = 시간당 세션 수 × 세션 폐기율"),
    (1, "폐기된 세션이 창 전체를 산다고 보는 보수적 가정 (평균은 그 절반)"),
    (0, "여기서는 특정 폐기율을 주장하지 않는다 — 무너지는 지점을 찾는다", True),
    (1, "현실 세션 폐기율에 대한 공개 통계를 갖고 있지 않다"),
    (1, "대신 \"어느 폐기율부터 감당이 안 되는가\"를 제시하고, 각자의 가정과 대보게 한다"),
    (0, "비교 기준: pi_pk_i 증명 생성 799.61 ms (실측)", True),
    (1, "트리 재구성이 이보다 커지면 폐기가 시스템의 지배적 비용이 된다"),
])

# ============================================================
# 18. 폐기율 스윕
# ============================================================
add_table_slide(
    "세션 폐기율별 비용 — 무너지는 지점 찾기",
    ["세션 폐기율", "리프 수 n", "지갑 재구성 시간", "증명 대비", "필요 depth"],
    [
        ["0.01%", "417", "약 0.12 초", "15%", "20"],
        ["0.05%", "2,085", "약 0.63 초", "79%", "20"],
        ["0.06%", "약 2,600", "약 0.80 초  ← 손익분기", "100%", "20"],
        ["0.1%", "4,170", "약 1.3 초", "1.7배", "20"],
        ["0.5%", "20,850", "약 11 초", "14배", "20"],
        ["1%", "41,700", "약 40 초 (외삽)", "50배", "20"],
        ["10%", "417,000", "약 45 분 (외삽)", "3,400배", "20"],
    ],
    [Inches(2.0), Inches(2.0), Inches(3.4), Inches(2.2), Inches(2.0)],
    height=Inches(3.9), font_size=12,
    note=[
        (0, "재구성 시간은 n=100~32,000 실측 구간의 보간이며, 1%·10% 두 행만 외삽이다 (build 선형 0.274 ms/leaf, insert 제곱 가정)."),
        (0, "필요 depth가 전 구간 20인 점에 주목 — 폐기율 10%(41.7만 리프)도 2^20 = 104.8만 안에 들어간다. 회로 깊이는 어떤 폐기율에서도 문제가 아니다."),
        (0, "프루닝이 없으면 이 값들이 누적된다: 사용자 1억의 1%가 폐기되면 100만 리프로 depth 21, 10%면 1,000만으로 depth 24가 필요해진다."),
    ],
)

# ============================================================
# 19. 결론
# ============================================================
add_bullet_slide("규모 분석 결론", [
    (0, "회로 깊이는 병목이 아니다", True),
    (1, "Ephemeral 설계에서는 폐기율 10%까지도 depth 20으로 들어간다"),
    (1, "프루닝이 없어야 비로소 depth 21~24가 필요해진다 (제약 +2.6% ~ +10.2%)"),
    (0, "실제 벽은 지갑 측 트리 재구성이고, 손익분기는 세션 폐기율 약 0.06%다", True),
    (1, "그 아래면 재구성이 증명 생성보다 싸다 — 비용 분석에서 무시해도 된다"),
    (1, "그 위로는 급격히 나빠진다: 0.1%에 1.3초, 0.5%에 11초, 1%에 40초"),
    (0, "왜 이렇게 가파른가", True),
    (1, "build()는 리프당 0.274 ms로 선형 (실측 n=100~32,000, 편차 2.4% 이내)"),
    (1, "insert()가 리프마다 배열 전체를 sort해 초선형 — 큰 n에서 이쪽이 지배한다"),
    (1, "그리고 캐시 미스마다 build()가 3회 돈다 (getRoot 1 + witness 2)"),
    (0, "개선 경로", True),
    (1, "build() 메모이제이션 — 3회를 1회로. 손익분기를 0.064% → 0.128%로 (약 2배)"),
    (1, "sort 제거는 거의 도움이 안 된다 (0.128% → 0.136%) — 배열 삽입마다 O(n) 이동이 남아 여전히 제곱이다"),
    (1, "증분 트리 유지 또는 IdP·미러가 witness 제공 — 점근 복잡도를 바꾸는 유일한 길"),
])

# ============================================================
# 20. grace 제거의 이유와 결과
# ============================================================
# ============================================================
# 20-2. 인플라이트 내성
# ============================================================
add_bullet_slide("인플라이트 실패 — 받아들이기로 한 대가", [
    (0, "지갑이 증명을 만든 시점과 그 트랜잭션이 채굴되는 시점 사이에 시간이 흐른다", True),
    (1, "그 사이에 폐기가 게시되면 증명에 쓴 root가 더 이상 최신이 아니다"),
    (0, "이 창의 실측 구성 — 합계 ≈ 13초 ≈ 1.1블록", True),
    (1, "트리 재구성 (캐시 미스 시)  34~288 ms   ← 리프 100~1,000개 기준"),
    (1, "pi_pk_i 증명 생성                800 ms"),
    (1, "RPC 왕복·제출                  ~100 ms"),
    (1, "채굴 대기                        최대 1블록 = 12 초"),
    (0, "그 창에 걸리면 execute()가 StaleRevocationRoot로 revert한다", True),
    (1, "가스는 소모되고, 폐기된 사용자가 아니라 아무 잘못 없는 사용자가 겪는 실패다"),
    (0, "재시도할 주체가 없다 — 의도된 선택이다", True),
    (1, "/submitTransaction은 calldata만 돌려주고 전송은 client.js가 한다"),
    (1, "revert는 wallet_agent가 끝난 뒤 체인에서 일어난다 → 사용자가 수동으로 다시 시도"),
    (0, "빈도는 root가 바뀌는 빈도에 묶인다 — 폐기가 드물면 실패도 드물다", True),
])

add_bullet_slide("grace window를 없앤 이유와 결과", [
    (0, "흔한 오해였던 것: \"캐시와 프라이버시를 위해 grace가 길어야 한다\"", True),
    (1, "pushRoot가 호출마다 pushedAt을 갱신하므로, 폐기가 없는 동안은 grace와 무관하게 캐시가 유효했다"),
    (1, "grace가 정하는 것은 \"밀려난 옛 root가 얼마나 더 사는가\" — 그건 폐기 지연 그 자체였다"),
    (0, "grace의 실질 역할은 인플라이트 내성 하나뿐이었고, 그 대가를 치르고 포기했다", True),
    (0, "얻은 것", True),
    (1, "컨트랙트 43줄 — 순환 버퍼·pushedAt·선형 탐색·filled 전부 소멸"),
    (1, "폐기 지연이 40분 고정에서 게시 주기로 — 데몬 간격 하나로 조절된다"),
    (0, "잃은 것", True),
    (1, "인플라이트 실패 (앞 장)"),
    (1, "fail-closed → fail-open: 데몬이 멈추면 모두 동작하지만 폐기가 조용히 효력을 잃는다"),
    (0, "부수 효과 — 2단계 게시의 안전성 논증이 깨졌다", True),
    (1, "\"push 후 commit 실패 → 지갑은 옛 root로 동작(안전)\"이 이제 전면 장애다"),
    (1, "데몬이 commit 실패 시 즉시 재시도(3회·2초)해 창을 좁히지만 약 6초가 남는다"),
])

prs.save(OUT)
print(f"wrote {OUT} ({len(prs.slides._sldIdLst)} slides)")
