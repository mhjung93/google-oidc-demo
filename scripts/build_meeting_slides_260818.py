#!/usr/bin/env python3
"""Build a meeting-discussion deck on Travel Rule scoping + zkAA/zkLogin
hybrid auth design, reusing the POSTECH template from 260731_meeting_MHJ.pptx."""

import os

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn

# 경로는 이 스크립트 위치 기준으로 잡아, 어느 디렉터리에서 실행해도 동작하게 한다.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

SRC = os.path.join(REPO_ROOT, "documents", "260731_meeting_MHJ.pptx")
LOGO = os.path.join(SCRIPT_DIR, "postech_logo.png")
OUT = os.path.join(REPO_ROOT, "documents", "260818_meeting_hybrid_auth_design.pptx")

DARK = RGBColor(0x44, 0x54, 0x6A)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
GREY = RGBColor(0x59, 0x59, 0x59)

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
                     font_size=13, header_size=13, left=Inches(0.5), width=Inches(12.3)):
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
    return slide


# ============================================================
# 1. Title
# ============================================================
add_title_slide(
    "Conditional Privacy Scope &\nHybrid Authentication Design",
    "\nTravel Rule 범위 · 발급자 개입 축 · Revocation 설계 옵션\nMoonhyeon Chung, POSTECH",
)

# ============================================================
# 2. Travel Rule — background & scope resolution
# ============================================================
add_bullet_slide("Travel Rule — Scope Resolution", [
    (0, "지난 논의: contribution 정리 시 major contribution이 conditional privacy로 좁혀짐"),
    (0, "우려 제기:", True),
    (1, "현재 설계된 conditional privacy 기능이 법정 Travel Rule을 준수한다고 보기 어려움"),
    (1, "→ Travel Rule을 준수하는 conditional privacy 기법 재설계가 필요한가?"),
    (0, "결론 (합의됨):", True),
    (1, "Travel Rule은 거래소 간(RP-RP) 자산 전송에 적용되는 규정"),
    (1, "본 프로토콜의 scope는 User ↔ RP 인증 — RP-RP 전송은 scope 밖"),
    (1, "→ Travel Rule 준수를 위한 conditional privacy 재설계는 불필요"),
    (0, "나머지 기능(IdP-side RP hiding, cross-service unlinkability 등)은 기존 논의대로 정리·검증"),
])

# ============================================================
# 3. 남은 과제
# ============================================================
add_bullet_slide("남은 과제 — 두 설계 방식의 하이브리드", [
    (0, "제안: zkAA와 zkLogin으로 대표되는 두 설계 방식의 장단점을 비교·정리"),
    (0, "축의 양 끝에서 각각 취할 것을 골라 결합하는 방향을 모색"),
    (0, "핵심 트레이드오프:", True),
    (1, "발급자 의존성 없음(1회 개입) vs. 세션 재사용으로 오버헤드 절감(세션 개입)"),
    (0, "선행 질문: PairCT는 이 축의 어디에 서 있는가?", True),
    (1, "당초 \"두 방식이 혼재된 하이브리드\"로 봤으나 코드 확인 결과가 달랐음"),
    (1, "이 답에 따라 비교의 전제와 하이브리드의 출발점이 달라짐 → 축을 세운 직후 먼저 확정"),
])

# ============================================================
# 4. zkAA — SSI 계열
# ============================================================
# ============================================================
# 6. 계열의 필연 vs 개별 논문의 선택
# ============================================================
# 4. 분석 축 세우기
# ============================================================
add_bullet_slide("두 설계를 가르는 축 — 발급자는 언제 개입하는가", [
    (0, "이 축은 본 발표의 분석 도구 — 문헌에 있는 분류명이 아님 (근거는 뒤 슬라이드)", True),
    (0, "축의 정의: 자격증명을 준 주체가 \"사용 시점\"에도 관여하는가", True),
    (1, "한쪽 끝 — 최초 발급 1회로 끝. 이후 검증자가 발급자에게 묻지 않음"),
    (1, "다른 쪽 끝 — 세션마다 발급자에게 다시 받아옴"),
    (0, "이 축은 신원관리 문헌의 대비와 대응한다", True),
    (1, "SSI: holder를 중심에 두고, 제시 시점에 발급자가 개입하지 않음 (SoK, arXiv:2404.06729)"),
    (1, "Federation (NIST SP 800-63C): \"별개 보안 도메인의 주체 간 신원·인증 정보 전달\" — IdP·RP·assertion 3요소"),
    (1, "assertion에는 속성값, IdP에서의 인증 정보, 제약조건과 만료시각이 담김 → 우리 max_height가 여기 대응"),
    (1, "통제권 소재도 갈림 — SSI는 개인, federation은 발급자·검증자 (Ruff, Three Models of Digital Identity)"),
    (0, "이 축에서 revocation·오버헤드·가용성이 갈린다 (상술은 뒤 트레이드오프 슬라이드)", True),
    (1, "혼동 주의: \"증명을 몇 번 만드는가\"는 별개 축 — zkAA는 발급자 1회 개입이지만 증명은 매 tx"),
])

# ============================================================
# 5. 축의 한쪽 끝 — 발급자 1회 개입
# ============================================================
add_bullet_slide("축의 한쪽 끝 — 발급자가 최초 1회만 개입", [
    (0, "공통 성질: 발급 이후 자율 동작 — 발급자가 사라져도 검증되고, 발급자가 사용을 관찰할 수 없음", True),
    (0, "zkAA (SAC 2025) — cert 1회 발급·등록 후 온체인 컨트랙트가 자율 검증. 식별자 = H(cert)", True),
    (0, "zk-creds (IEEE S&P 2023) — 서명 대신 \"발급된 집합의 멤버십\" 증명", True),
    (1, "리스트에서 빼면 즉시 폐기 → 이쪽 끝에서도 폐기가 가능함을 보여주는 사례"),
    (0, "ZK Proof-of-Identity (arXiv:1905.09093) — 기존 ePassport/eSIM 재사용, 정부는 최초 1회만 개입", True),
    (0, "익명 크레덴셜 서명 계보 — 이쪽 끝의 암호학적 토대", True),
    (1, "CL(2001) → BBS+ → PS(2017). 제시할 때마다 새 영지식 증명을 만들어 unlinkability 확보"),
    (0, "Revocable AC from ABE (arXiv:2308.06797) — bilinear accumulator로 폐기 지원", True),
])

# ============================================================
# 6. 축의 다른 끝 — 발급자 세션마다 개입
# ============================================================
add_bullet_slide("축의 다른 끝 — 발급자가 세션마다 개입", [
    (0, "공통 성질: 최신 상태를 반영할 수 있으나, 발급자 가용성에 의존하고 발급자가 매번 관찰함", True),
    (0, "공통 파이프라인 (개별 시스템에서 뽑은 공통점 — 문헌 정의 아님)", True),
    (1, "로그인 → IdP 서명 토큰 획득 → 토큰을 private witness로 회로 검증 → 클레임에서 식별자 유도 → 세션 재사용"),
    (0, "zkLogin (arXiv:2401.11735) — OIDC ID Token. zkaddr = H(sub, aud, iss, salt), ~1.1M constraints", True),
    (0, "PairCT (본 연구) — 토큰 형식이 다름에 유의", True),
    (1, "custom_idp.js는 OAuth 2.0 code+PAR 흐름만 차용. openid scope·id_token·JWKS·discovery 모두 미구현"),
    (1, "EdDSA-Poseidon 자체 토큰 발급 — 형식은 달라도 \"발급자가 세션마다 개입\"이라는 축 위치는 같음"),
])

# ============================================================
# 7. 이 축의 지위 — 문헌은 진영을 나누지 않는다
# ============================================================
add_bullet_slide("주의: 이 축은 분석 도구이지, 문헌의 진영 구분이 아니다", [
    (0, "zkLogin은 스스로를 SSI의 반대편으로 규정하지 않는다", True),
    (1, "자기 규정: \"기존 OpenID 계정으로 서명하는 signature scheme\", Identity-Based Signature(IBS)"),
    (1, "Related Work 비교 대상은 \"Deployed OAuth wallets\" (TEE: Magic·Face / MPC: Web3Auth·Privy)"),
    (1, "SSI·DID·anonymous credentials는 논문에 등장하지 않음"),
    (0, "오히려 두 논문은 서로를 이웃으로 인용한다", True),
    (1, "zkLogin이 가장 근접한 선행연구로 지목한 것이 zkAA. zkAA도 \"builds on concepts from zkLogin\"이라 인용"),
    (0, "→ \"두 진영의 대립\"으로 서술하면 문헌과 어긋남. 우리 축은 revocation·오버헤드 논의용 도구", True),
    (0, "같은 이유로, 개별 논문의 선택을 축 전체의 필연으로 일반화하지 말 것", True),
    (1, "예: zkAA에 revocation이 없는 건 zkAA의 선택 — zk-creds는 지원 (SoK 기준 만료/즉시해지 두 갈래)"),
])

# ============================================================
add_table_slide(
    "축을 따라 본 정성 비교",
    ["항목", "발급자 1회 개입형", "발급자 세션 개입형", "구분"],
    [
        ["발급기관 개입", "최초 발급 1회로 끝", "세션(로그인)마다 반복", "축 필연"],
        ["발급자–검증자 관계", "제시 시 직접 상호작용 없음", "IdP를 매개로 연결", "축 필연"],
        ["IdP 장애 시", "영향 없음", "신규 로그인 불가", "축 필연"],
        ["IdP의 관찰 범위", "발급 시점만", "로그인마다", "축 필연"],
        ["신원 출처", "자체 발급 인증서 (기존 것 재사용도 가능)", "기존 web2 계정 (OIDC sub)", "축 필연"],
        ["Revocation", "만료 기반 또는 즉시 해지\n(list / accumulator+ZKP)", "세션 만료 대기가 일반적", "구현마다 다름\n(zkAA 미지원, zk-creds 지원)"],
        ["증명 시점·빈도", "구현에 따라 매 사용 또는 세션 단위", "세션당 1회가 일반적", "구현마다 다름"],
        ["사용자 키 관리", "자격증명·키를 장기 보관", "ephemeral key + salt", "구현마다 다름"],
    ],
    [Inches(2.2), Inches(3.6), Inches(3.3), Inches(3.2)],
    top=Inches(1.3), height=Inches(5.2), font_size=11, header_size=12,
)

# ============================================================
# zkAA vs zkLogin — 대표 구현 직접 비교
# ============================================================
add_table_slide(
    "zkAA vs zkLogin — 축 양 끝의 대표 구현 비교",
    ["", "zkAA (1회 개입)", "zkLogin (세션 개입)"],
    [
        ["신뢰 기점", "발급기관이 준 cert (1회)", "IdP가 세션마다 주는 JWT"],
        ["식별자", "H(cert)", "H(sub, aud, iss, salt)"],
        ["증명 시점", "매 트랜잭션 (PublishProve)", "세션당 1회"],
        ["증명 내용", "cert 소유 + 메시지 바인딩", "JWT 서명 유효 + 클레임 + nonce에 ephemeral key 포함"],
        ["회로 크기", "publish 297 / register 4,504", "~1,100,000 (SHA-2 66%)"],
        ["tx당 서명", "없음 (증명이 곧 인가)", "ephemeral key로 서명"],
        ["폐기(revocation)", "미지원 — 회로에 상태 조회 없음", "세션 만료(max_epoch)까지 대기"],
        ["IdP 장애 시", "영향 없음", "신규 로그인 불가"],
    ],
    [Inches(2.3), Inches(4.4), Inches(5.6)],
    top=Inches(1.3), height=Inches(5.2), font_size=11, header_size=12,
)

# ============================================================
# 7. 트레이드오프의 구조적 원인
# ============================================================
# 용어 정의 — freshness / autonomy
# ============================================================
add_bullet_slide("용어 정의 — 신선도(freshness)와 자율성(autonomy)", [
    (0, "신선도 (freshness)", True),
    (1, "인증 진술에 부과되는 최신성 제약 — 충분히 최신인 진술이 제시되지 않으면 인증을 신뢰하지 않음"),
    (1, "제약을 조일수록 폐기가 반영되기까지의 지연을 임의로 좁힐 수 있음"),
    (1, "출처: Stubblebine, \"Recent-secure authentication: enforcing revocation in distributed systems\" (IEEE S&P 1995)"),
    (0, "자율성 (autonomy)", True),
    (1, "사용자가 제3자에 의존하지 않고 독립적으로 존재하며 자기 신원을 통제하는 성질"),
    (1, "SSI 10원칙의 Existence(\"independent, autonomous existence\")와 Control에 해당"),
    (1, "출처: Allen, \"The Path to Self-Sovereign Identity\" (2016); 속성 분류는 arXiv:2112.04155"),
    (0, "※ 본 발표에서 쓰는 범위 — 원론적 정의보다 좁혀서 사용", True),
    (1, "자율성 = \"발급자 없이도 검증이 성립하는가\"라는 운영상 독립성으로 한정"),
])

# ============================================================
add_bullet_slide("이 트레이드오프는 왜 생기는가 — 신선도 ↔ 자율성", [
    (0, "핵심: \"발급자가 언제 개입하는가\"가 나머지를 결정한다", True),
    (0, "1회 개입형 — 신뢰를 발급 시점에 한 번 고정", True),
    (1, "이후 발급기관 없이 자율 동작 (가용성·검열저항 유리)"),
    (1, "대가: 발급 이후의 상태 변화(폐기·권한 변경)를 반영할 통로가 없음"),
    (0, "세션 개입형 — 신뢰를 세션마다 갱신", True),
    (1, "로그인 때 IdP가 최신 상태를 반영해 크레덴셜 발급 (신선도 확보)"),
    (1, "대가: IdP가 매번 관여하고 관찰함 — 가용성·프라이버시 부담"),
    (0, "→ 본질은 신선도(freshness) ↔ 자율성(autonomy)의 교환", True),
    (0, "함의: 1회 개입형이 revocation을 지원하려면 자율성을 일부 되돌려줘야 함", True),
    (1, "revocation list·accumulator 조회 = \"발급자 없이 자율 동작\"이라는 강점의 부분 포기"),
])

# ============================================================
add_bullet_slide("재검토: PairCT의 온체인 설계는 사실상 zkLogin 구조", [
    (0, "당초 관찰: \"로그인은 세션 재사용(zkLogin), 온체인 실행은 매 tx 재증명(zkAA)\" → 이미 하이브리드"),
    (0, "코드 확인 결과 이 전제는 성립하지 않음", True),
    (1, "PPIDWallet.sol:55 — π_pk_i의 public signals = [pk_i, pk_IdP_x, pk_IdP_y, ppid, max_height]"),
    (1, "payload도 nonce도 public input에 없음. wallet_agent.js:922-936의 circuit input도 전부 세션 스코프"),
    (1, "트랜잭션별 진정성은 secp256k1 서명(sig) + payload.nonce가 담당 (PPIDWallet.sol:44-51)"),
    (0, "→ π_pk_i는 per-tx 증명이 아니라 세션 크레덴셜", True),
    (0, "→ 즉 온체인 단계도 zkLogin과 동일한 구조 (ZKP 1개 + ephemeral key 서명)", True),
    (0, "PairCT는 두 방식의 혼재가 아니라, 로그인·실행 모두 발급자 세션 개입형", True),
])

# ============================================================
# 7. 발견: 캐시 가능한 증명을 매 tx 재생성 중
# ============================================================
add_bullet_slide("개선 여지: π_pk_i는 세션 크레덴셜인데 매 tx 재증명 중", [
    (0, "circuits/pi_pk_i.circom (4,820 constraints — zkAA publish 297과는 별개 회로)", True),
    (0, "입력 13개가 전부 로그인 시점에 고정됨", True),
    (1, "rp_nonce는 r_token = Poseidon(pk_i, max_height, rp_nonce)에 묶여 IdP 서명 대상 → tx마다 바꾸면 EdDSA 검증이 깨짐"),
    (1, "→ 원리상 세션당 1회 증명으로 충분 (캐싱 가능한 구조)"),
    (0, "그런데 현재 구현은 /submitTransaction 호출마다 재증명 (wallet_agent.js:938)", True),
    (1, "캐싱 로직 없음 — 같은 세션 안에서 동일한 statement를 반복 증명하는 셈"),
    (0, "→ 개선 여지: 세션당 1회로 캐싱하면 tx당 295.50 ms가 소거됨", True),
    (1, "2번째 tx부터는 secp256k1 서명 + 온체인 검증만 남음"),
    (1, "캐시 무효화 조건은 단순 — 재로그인(세션키 재발급) 또는 max_height 만료"),
    (0, "현재 측정치는 이 상태 기준이므로, 캐싱 전후를 구분해 표기해야 함", True),
])


# ============================================================
# 6. SSI vs OIDC 기반 정성 비교
# ============================================================
# 8. 정량 비교 (실측)
# ============================================================
# 정량 비교 — 증명 생성 시간 (표)
# ============================================================
add_table_slide(
    "정량 비교 — 증명 생성 시간",
    ["회로", "constraints", "증명 시간", "증명 발생 빈도", "출처"],
    [
        ["zkAA register", "4,504", "246.26 ms", "최초 1회 (영구)", "실측 (본 머신)"],
        ["zkAA publish", "297", "121.10 ms", "매 tx (캐싱 불가)", "실측 (본 머신)"],
        ["PairCT pi_arid_i", "5,229", "270.97 ms", "로그인 1회", "실측 (본 머신)"],
        ["PairCT pi_ppid", "261", "92.92 ms", "로그인 1회", "실측 (본 머신)"],
        ["PairCT pi_pk_i", "4,820", "295.50 ms", "세션당 1회로 충분\n(현재는 매 tx)", "실측 (본 머신)"],
        ["zkLogin", "~1,100,000", "2,780 ms", "세션당 1회", "논문 보고값\n(다른 하드웨어·prover)"],
    ],
    [Inches(2.6), Inches(1.8), Inches(1.8), Inches(3.3), Inches(2.8)],
    top=Inches(1.4), height=Inches(3.6), font_size=12, header_size=13,
)

# ============================================================
# 정량 비교 — 해석
# ============================================================
add_bullet_slide("정량 비교 — 해석", [
    (0, "zkAA와 PairCT는 속도가 비슷하다", True),
    (1, "같은 프리미티브(Poseidon / EdDSA-Poseidon)와 같은 prover(snarkjs Groth16)를 쓰므로"),
    (1, "회로 크기가 비슷하면 시간도 비슷 — 실제 차이는 \"몇 번 증명하느냐\"에서 발생"),
    (0, "zkLogin은 회로 규모가 두 자릿수 이상 크다", True),
    (1, "JWT의 RSA 서명 + SHA-2 해시를 회로 안에서 검증해야 하기 때문 (~1.1M constraints, SHA-2가 66%)"),
    (1, "단 2,780 ms는 논문 보고값(다른 하드웨어·prover)이라 본 머신 실측치와 직접 비교 불가"),
    (0, "세션당 총비용 (N = 세션 내 트랜잭션 수)", True),
    (1, "PairCT: 로그인 364 ms(pi_arid_i+pi_ppid) + pi_pk_i 296 ms → 캐싱 시 N과 무관하게 약 660 ms"),
    (1, "zkAA: 121 ms × N (register는 최초 1회뿐이라 세션 비용에서 제외)"),
    (1, "→ 손익분기 N ≈ 5.5. 짧은 세션은 zkAA가, 긴 세션은 PairCT가 유리"),
    (0, "※ 손익분기는 실측치로부터 계산한 추정이며 별도 측정으로 검증하지 않음", True),
])

# ============================================================
# 8. 핵심 문제 — Revocation
# ============================================================
# 세션 길이와 손익분기
# ============================================================
# 세션 수명과 비용 구조
# ============================================================
add_bullet_slide("세션 수명과 세션당 비용 구조", [
    (0, "실제 세션 수명 (참고 기준) — 인증/인가를 구분해서 볼 것", True),
    (1, "[인증] OIDC ID Token: 기본 1시간 (Azure AD)"),
    (1, "[인가] OAuth access token: 30분~수시간 / Google STS(RFC 8693 토큰 교환): 기본 1시간, 15분~12시간"),
    (1, "우리 max_height는 \"세션키로 얼마나 인가할 수 있는가\" → 인증이 아니라 인가 창에 대응"),
    (1, "zkLogin maxEpoch도 동일 성격 (현재 epoch + 2, Sui 문서 예시)"),
    (1, "본 프로젝트: TOKEN_VALIDITY_SECONDS 3600초 ÷ 12초 슬롯 = 300블록 = 정확히 1시간"),
    (0, "세션당 총비용 (N = 세션 내 트랜잭션 수, π_pk_i 캐싱 전제)", True),
    (1, "zkAA     = 121.10 ms × N     (매 tx 증명, h_msg가 public input이라 캐싱 불가)"),
    (1, "PairCT   = 659.39 ms 고정    (로그인 363.89 + π_pk_i 295.50, 이후 tx는 서명만)"),
    (1, "zkLogin  = 2,780 ms 고정     (논문 보고값, 이후 tx는 ephemeral key 서명만)"),
    (0, "→ zkAA만 N에 비례. 나머지 둘은 세션당 고정", True),
])

# ============================================================
# 손익분기
# ============================================================
add_bullet_slide("손익분기 — 몇 건부터 세션 방식이 유리한가", [
    (0, "PairCT vs zkAA → N ≥ 6건", True),
    (1, "659.39 / 121.10 = 5.45. 1시간 세션 기준 평균 10분에 1건 이상이면 세션 방식이 이득"),
    (0, "zkLogin vs zkAA → N ≥ 23건", True),
    (1, "PairCT는 zkLogin 대비 항상 4.2배 저렴 (659 vs 2,780, 교차점 없음)"),
    (0, "구간별 최적: N ≤ 5는 zkAA, N ≥ 6부터 PairCT. zkLogin은 어느 구간에서도 최저가 아님", True),
    (0, "※ tx당 서명 비용을 넣어도 결론 불변", True),
    (1, "zkAA는 세션키 서명이 없음 — 컨트랙트가 Groth16 verifier뿐이고 증명 자체가 인가"),
    (1, "PairCT secp256k1 0.260 ms / zkLogin ed25519 0.302 ms (실측) — N=50에서도 13~15 ms"),
    (1, "반영해도 N = 5.46 (기존 5.45와 동일). 가스 지불 서명은 세 방식 공통이라 상쇄"),
    (0, "※ zkLogin 수치는 다른 하드웨어·prover의 논문값", True),
    (1, "본 머신 처리량(16~19k c/s)으로 환산 시 1.1M 회로는 약 57~67초 추정 → 격차는 더 벌어짐"),
])



# ============================================================
add_bullet_slide("Revocation (1/2) — \"매 tx 증명\"은 답이 아니다", [
    (0, "\"매 tx 증명 = revocation 지원\"은 성립하지 않음", True),
    (1, "zkAA publish 회로(circuit/zkaa_publish/publish.circom)에 revocation 체크가 없음"),
    (1, "h_cert === Poseidon(Rand, R, S) 확인이 전부 — 멤버십/상태 조회 없음"),
    (0, "매 tx 증명은 revocation의 필요조건일 뿐, 충분조건이 아님", True),
    (1, "실제 revocation에는 최신 상태(리스트/accumulator) 조회가 별도로 필요"),
    (0, "→ 따라서 zkAA의 per-tx 증명 비용은 revocation이라는 보상이 없는 순수 비용", True),
    (0, "증명을 per-tx로 만들려면 payload가 아니라 최신 상태를 묶어야 함", True),
    (1, "payload 진정성은 이미 secp256k1 서명 + nonce가 ecrecover로 보장 (PPIDWallet.sol:44-51)"),
    (1, "→ payload를 public input에 넣는 건 중복이며 보안을 늘리지 못함"),
])

# ============================================================
# 9. Revocation (2/2) — 세션 재사용의 한계
# ============================================================
add_bullet_slide("Revocation (2/2) — 세션 재사용의 구조적 한계", [
    (0, "zkLogin류 세션 재사용: 세션 중간에 revoke 불가능", True),
    (1, "한 번 발급된 ZKP/ephemeral key는 만료 전까지 계속 유효"),
    (0, "PairCT는 구조가 같으므로 이 문제를 그대로 상속함", True),
    (1, "세션키 sk_i가 max_height까지 유효 — 그 사이엔 revoke 수단 없음"),
    (1, "π_pk_i를 매 tx 재생성해도 상태 조회가 없어 revocation에 기여하지 못함"),
    (0, "기존 max_height는 부분적 답에 그침", True),
    (1, "블록 높이로 세션을 제한 → revoke 불가 구간의 \"피해 반경\"을 시간적으로 축소"),
    (1, "완화책일 뿐, revocation 자체를 가능하게 하는 건 아님"),
])

# ============================================================
# 10. 하이브리드 방향 — Option A/B/C (문헌 매핑 통합)
# ============================================================
# SSI revocation 분류 (표)
# ============================================================
add_table_slide(
    "SSI Revocation 분류 — 네 갈래",
    ["범주", "방식", "대표", "프라이버시", "오프라인 검증", "복잡도"],
    [
        ["① 상태 리스트", "크레덴셜별 상태 비트를\n공개하고 검증자가 조회", "W3C Bitstring Status List,\nIETF Token Status List, EBSI", "약함", "제한적", "낮음"],
        ["② 암호학적 누산기", "집합을 상수 크기로 압축,\n멤버십을 ZKP로 증명", "AnonCreds, zk-creds,\nBAAR, RSA·bilinear acc.", "강함", "가능", "높음"],
        ["③ 단기 크레덴셜", "폐기 인프라 없이\n짧은 유효기간 + 재발급", "시간제한 발급,\nrefresh 기반", "중간", "완전", "낮음"],
        ["④ DID 비활성화", "DID 자체를 무효화하거나\n거버넌스 규칙으로 처리", "SSI 거버넌스 프레임워크", "상황별", "제한적", "중간"],
    ],
    [Inches(1.9), Inches(2.8), Inches(3.1), Inches(1.5), Inches(1.6), Inches(1.4)],
    top=Inches(1.4), height=Inches(4.4), font_size=10, header_size=11,
)
add_bullet_slide("출처 및 분류 기준", [
    (0, "분류 출처", True),
    (1, "A Survey on Credential Revocation and DID Deactivation in SSI Systems"),
    (1, "CRSet: Private Non-Interactive Verifiable Credential Revocation (arXiv:2501.17089)의 Related Work"),
    (0, "두 문헌이 공통으로 쓰는 평가 축", True),
    (1, "보안 · 프라이버시 · 성능 · 확장성 · 운영 통합"),
    (1, "특히 \"프라이버시 ↔ 책임추궁의 균형\"과 \"오프라인 검증\"이 지속적 난제로 지목됨"),
    (0, "\"만능 해법은 없다\"는 것이 두 문헌의 공통 결론", True),
    (1, "→ 우리도 하나를 고르는 문제이지, 최선을 찾는 문제가 아님"),
])

# ============================================================
# 범주 ①② 설명
# ============================================================
add_bullet_slide("① 상태 리스트 · ② 암호학적 누산기", [
    (0, "① 상태 리스트 — 발급자가 \"누가 폐기됐는지\"를 공개 게시", True),
    (1, "각 크레덴셜에 리스트상의 위치를 배정하고, 그 비트가 1이면 폐기로 간주"),
    (1, "W3C Bitstring Status List는 최소 131,072비트(16KB), 폐기가 소수면 압축해 수백 바이트"),
    (1, "장점: 구현이 단순하고 폐기가 즉시 반영됨"),
    (1, "단점: 검증자가 리스트를 조회하는 행위 자체가 관찰돼 프라이버시가 약함. 리스트 다운로드 부담"),
    (0, "② 암호학적 누산기 — 집합 전체를 상수 크기 값 하나로 압축", True),
    (1, "발급된 집합의 멤버십(또는 비멤버십)을 영지식으로 증명 → 어떤 크레덴셜인지 드러나지 않음"),
    (1, "폐기는 집합에서 제거 후 누산기 값 갱신 → 폐기된 witness는 갱신에 실패해 자동 무효화"),
    (1, "장점: 프라이버시가 강하고 증명이 컴팩트, 오프라인 검증 가능"),
    (1, "단점: 구현이 복잡하고, 폐기가 일어날 때마다 보유자가 witness를 갱신해야 함"),
])

# ============================================================
# 범주 ③④ + 변종 설명
# ============================================================
add_bullet_slide("③ 단기 크레덴셜 · ④ DID 비활성화 · 프라이버시 보완 변종", [
    (0, "③ 단기 크레덴셜 — 폐기하지 않고 \"금방 만료시킨다\"", True),
    (1, "폐기 인프라를 아예 두지 않고, 유효기간을 짧게 잡아 재발급으로 대체 (positive confirmation)"),
    (1, "장점: 가장 단순하고 빠르며 완전한 오프라인 검증이 가능"),
    (1, "단점: 발급자의 재발급 부담이 크고, 만료 전 구간은 어떤 수단으로도 폐기 불가"),
    (0, "④ DID 비활성화 — 크레덴셜이 아니라 식별자 자체를 무효화", True),
    (1, "개별 크레덴셜 폐기가 아니라 DID를 비활성화하거나 거버넌스 규칙으로 처리"),
    (0, "①의 프라이버시 약점을 보완한 변종들", True),
    (1, "VLR 그룹서명(Boneh-Shacham 2004): 검증자만 리스트를 보유, 서명자는 갱신 불필요"),
    (1, "Lara(arXiv:2505.12968): Bloom filter로 조회를 은닉, HBFA로 지연 80%↓"),
    (1, "RRP(CCS'23): 유효기간을 이진 트리로 나눠 특정 시간 구간만 선택적으로 폐기"),
])

# ============================================================
# 우리 위치
# ============================================================
add_bullet_slide("우리 위치 — 현재는 ③번(단기 크레덴셜)", [
    (0, "PairCT는 아직 revocation을 구현하지 않았다", True),
    (1, "있는 것은 max_height 만료뿐 → 분류상 ③번, 네 범주 중 가장 약한 쪽"),
    (1, "세션 중 폐기 불가. π_pk_i를 매 tx 재생성해도 상태 조회가 없어 기여하지 못함"),
    (1, "②번(zk-creds, BAAR)은 즉시 폐기를 실제로 지원 — 이 축에서는 우리가 뒤처져 있음"),
    (0, "사실대로 말할 수 있는 것 두 가지", True),
    (1, "만료가 암호학적으로 강제됨 — max_height가 회로 public input이자 온체인 검사 대상(PPIDWallet.sol:58)"),
    (1, "→ 발급자 정책에만 의존하는 일반 단기 크레덴셜보다는 강제력이 있음 (단, ③번 안에서의 우위)"),
    (1, "conditional privacy는 별개 축 — 사후 책임추궁이지 사전 차단이 아니므로 폐기 능력으로 주장하면 안 됨"),
    (0, "→ Option A/B/C는 \"③번에서 어느 범주로 이동할 것인가\"의 선택", True),
    (1, "A: ③번을 RRP 방식으로 정교화 / B: ①번 + VLR·Bloom으로 프라이버시 보완 / C: ②번을 온체인화"),
])

# ============================================================
add_table_slide(
    "하이브리드 옵션 — 한눈에 비교",
    ["", "무엇을 바꾸나", "폐기 반영 시점", "증명 오버헤드", "구현 범위"],
    [
        ["A", "세션 유효기간 정책\n(윈도우 축소 / 구간 분할)", "구간 경계에서", "변화 없음", "지갑 세션키 발급 + 컨트랙트 검증"],
        ["B", "매 tx에 경량 상태 체크 추가", "RL 갱신 즉시", "+ 수 ms", "RL 발행·배포 인프라 + 검증 단계"],
        ["C", "폐기 판단을 온체인 registry로", "다음 블록", "+ root 검증", "회로·zkey·verifier 재생성 + factory 재배포"],
    ],
    [Inches(0.7), Inches(3.1), Inches(1.9), Inches(1.8), Inches(4.8)],
    top=Inches(1.5), height=Inches(3.2), font_size=12, header_size=13,
)

# ============================================================
# Option A 상세
# ============================================================
add_bullet_slide("Option A — 세션 유효기간 단축 / 구간별 폐기", [
    (0, "무엇을 바꾸나: max_height 윈도우 정책", True),
    (1, "현재는 로그인 시 max_height = 현재블록 + 유효윈도우로 고정되고, 그 사이엔 취소 수단이 없음"),
    (0, "단순안 — 윈도우를 짧게", True),
    (1, "얻는 것: 폐기 불가 구간이 짧아져 \"피해 반경\"이 줄어듦"),
    (1, "잃는 것: 재로그인 빈도 증가 → IdP 관여·관찰 증가, 사용자 마찰 증가. 증명 비용은 그대로"),
    (0, "정교안 — Range-Revocable Pseudonyms (CCS'23) 방식", True),
    (1, "세션 epoch를 이진 트리로 나눠 각 시간 슬롯에 latchkey 부여 → 특정 구간만 선택적으로 폐기"),
    (1, "폐기 정보가 구간 밖 사용과 링크되지 않음 (backward unlinkability). 비용은 O(log(구간 수))"),
    (1, "논문 실측: 폐기 데이터 9~13KB로 2.5억 pseudonym 규모 처리, 검증 지연 <3.5ms"),
    (0, "우리 코드에 적용하면", True),
    (1, "wallet_agent.js 세션키 발급부에 latchkey 파생 추가, execute()가 max_height 단순 비교 대신 구간 capability 검증"),
    (0, "남는 문제: 여전히 즉시 반영은 아님(구간 단위 지연). 증명 오버헤드도 그대로", True),
])

# ============================================================
# Option B 상세
# ============================================================
add_bullet_slide("Option B — 세션 재사용 + 매 tx 경량 상태 체크", [
    (0, "무엇을 바꾸나: 무거운 ZKP는 세션당 1회 그대로 두고, 매 tx마다 \"아직 폐기 안 됨\"만 싸게 확인", True),
    (0, "동작 흐름", True),
    (1, "IdP 또는 RP가 revocation list(RL)를 발행 → 사용자는 자기 토큰이 RL에 없음을 확인 후 제시 → 검증자는 RL 대조만 수행"),
    (0, "근거 문헌", True),
    (1, "VLR 그룹서명(Boneh-Shacham 2004): 검증자만 최신 리스트를 보유, 서명자는 갱신 불필요 → 사용자 수가 많을수록 유리"),
    (1, "Lara(2025): Hierarchical Bloom Filter Array로 지연 80%↓, 시계 동기화 불필요(비동기)"),
    (1, "Lara는 RL마다 고유 seed를 써서 서로 다른 RL의 토큰이 링크되지 않게 함"),
    (0, "비용", True),
    (1, "RL 발행·배포·동기화 인프라가 새로 필요. Bloom filter 오탐률 관리 필요(Lara는 0.01%를 균형점으로 제시)"),
    (0, "우리 코드에 적용하면", True),
    (1, "온체인이면 execute()에 RL root/필터 조회 추가, 오프체인이면 RP 검증 단계에 추가"),
    (0, "남는 문제: RL을 누가 발행·배포하나. 발행자가 사용자 활동을 관찰하지 못하도록 설계해야 함", True),
])
# ============================================================
# Option B 적용 비용 추정
# ============================================================
add_bullet_slide("Option B를 우리 시스템에 적용하면 — 비용 추정", [
    (0, "갈림길: PairCT의 인가는 온체인 execute()에서 일어난다", True),
    (0, "경로 1 — 오프체인 체크 (RP 검증 단계)", True),
    (1, "비용은 매우 쌈: 폐기 1만건·FP 1%면 Bloom filter 11.7 KB, 해시 6.6회. 회로·온체인 변경 없음"),
    (1, "그러나 세션키 보유자가 RP를 거치지 않고 execute()를 직접 호출하면 막지 못함 → 커버리지 구멍"),
    (0, "경로 2 — 온체인 Bloom filter: 가스에서 무너짐", True),
    (1, "폐기 1만건(FP 1%): 11.7 KB = 375 slot → 초기 적재 7,500,000 gas (블록의 25%)"),
    (1, "폐기 10만건(FP 0.1%): 175.5 KB = 5,617 slot → 초기 적재 112,340,000 gas = 블록 한도의 3.7배 (단일 tx 불가)"),
    (1, "비교: Option C는 온체인 상태가 32 byte(1 slot), 폐기 ~30K / 검증 ~60K gas"),
    (0, "경로 3 — 회로에서 비멤버십 증명: Option C로 수렴", True),
    (1, "Bloom 비멤버십은 \"k개 위치 중 하나가 0\"을 보이는 것 → filter 비트를 읽어야 함"),
    (1, "11.7 KB = 93,848비트를 witness로 인덱싱하는 비용이 Merkle 경로(4,860 constraints)보다 큼 → filter를 Merkle화하면 곧 C"),
    (0, "결론: 우리 구조에서 B는 온체인 인가에 적용 불가", True),
    (1, "Lara·VLR은 \"검증자가 리스트를 들고 있다\"를 전제하나, 우리 검증자는 스마트컨트랙트라 리스트를 들 수 없음"),
    (1, "B가 할 수 있는 것은 RP 로그인 단계의 오프체인 체크 — A와 같은 성격의 완화책이지 revocation 자체는 아님"),
    (0, "※ gas는 EIP-2929 기준(SSTORE 20K 신규/5K 갱신, 콜드 SLOAD 2.1K) 계산값 — 실제 배포 측정 아님", True),
])


# ============================================================
# Option C 상세
# ============================================================
add_bullet_slide("Option C — Revocation을 온체인 상태로 이전", [
    (0, "무엇을 바꾸나: 폐기 여부의 판단 주체를 RP/IdP가 아니라 스마트컨트랙트로", True),
    (0, "동작 흐름 (BAAR, PLOS ONE 2026-03)", True),
    (1, "크레덴셜 식별자를 Merkle 리프에 매핑하고 accumulator root만 온체인에 게시"),
    (1, "폐기 = 리프 제거 → root 갱신 → 이후 그 크레덴셜의 witness 검증이 자동 실패"),
    (1, "증명 생성·검증은 오프체인, 온체인에는 컴팩트한 root만 → 온체인 연산 최소화"),
    (0, "논문 실측", True),
    (1, "폐기 O(log n), 건당 200~310ms, gas ~30K(revoke) / ~60K(verify), 검증 ~200ms"),
    (0, "우리 코드에 적용하면", True),
    (1, "PPIDWalletFactory/PPIDWallet에 revocation registry 추가"),
    (1, "π_pk_i의 public input에 root 추가 → 회로·zkey·verifier 재생성 및 factory 재배포 필요 (가장 큰 변경)"),
    (0, "얻는 것: 전역 검증 가능성(누구나 같은 상태를 봄)과 감사 가능성", True),
    (0, "남는 문제: root 갱신 트랜잭션 비용·블록 확정 지연. 폐기 권한을 누가 갖나(IdP 단독? 다중서명?) — 중앙화 우려", True),
])
# ============================================================
# BAAR 상세
# ============================================================
add_bullet_slide("BAAR 상세 — Option C의 설계 원본", [
    (0, "Ahmed·Ahmad·Zeshan·Akram, PLOS ONE 21(3): e0343696 (2026-03-31), DOI 10.1371/journal.pone.0343696", True),
    (0, "설계 목표: pairing을 피하고 secp256k1 이산로그 설정만으로 구성", True),
    (1, "기존 익명 인증 다수가 pairing 기반이라 무겁고 Ethereum 배포가 어렵다는 문제의식"),
    (0, "세 부품", True),
    (1, "Pedersen vector commitment — C = Σ(aᵢ·Gᵢ) + r·H. 속성을 감추면서 바꿔치기 불가 (perfectly hiding, ECDLP 하 binding)"),
    (1, "Schnorr ZKP — Σ-protocol을 Fiat-Shamir로 비대화형화. 전체·선택적 공개 모두 지원"),
    (1, "Merkle 동적 accumulator — 크레덴셜 식별자를 리프에 매핑, accumulator 값 = Merkle root"),
    (0, "폐기가 작동하는 방식", True),
    (1, "발급기관이 리프를 제거 → O(log n) 노드만 갱신해 새 root 계산 → 온체인 게시"),
    (1, "폐기된 크레덴셜의 witness는 갱신된 root에 대해 검증 실패 → 별도 확인 절차 없이 자동 무효화"),
    (0, "오프체인/온체인 분리 — Option C의 핵심 아이디어", True),
    (1, "오프체인: 증명 생성·검증 / 온체인: Merkle root 하나(~32바이트)만. 개별 커밋먼트는 저장 안 함"),
])

# ============================================================
# BAAR 적용 비용 추정
# ============================================================
add_bullet_slide("BAAR를 우리 시스템에 적용하면 — 비용 추정", [
    (0, "주의: BAAR는 Schnorr Σ-protocol, 우리는 Groth16 — 논문 수치를 그대로 못 씀", True),
    (1, "Merkle 경로 검증을 circom 회로 안에 넣어야 하므로 회로가 커짐"),
    (0, "실측: 깊이 20 Merkle 경로 회로(2^20 ≈ 100만 크레덴셜 수용) = 4,860 constraints", True),
    (1, "pi_pk_i 4,820 + Merkle 4,860 = 9,680 constraints (2.01배)"),
    (1, "증명 시간 295.5 ms → 약 500~590 ms 추정 (본 머신 처리량 16~19k c/s로 외삽)"),
    (0, "세션 비용과 손익분기 이동", True),
    (1, "세션 고정비용 659 ms → 약 870~960 ms. 손익분기 N ≥ 6 → N ≥ 8"),
    (1, "1시간 세션 기준 평균 7.5분에 1건 이상이면 여전히 세션 방식이 유리"),
    (0, "변경 범위", True),
    (1, "pi_pk_i에 Merkle 검증 추가 → zkey 재생성 + verifier·factory 재배포. registry 컨트랙트 신설"),
    (1, "온체인 gas 부담은 작음 — execute()는 이미 Groth16 검증에 200K+ 사용, root 조회는 한계 증가분이 미미"),
    (0, "※ 500~590 ms와 깊이 20은 외삽·가정 — 합친 회로를 실제 컴파일해 측정한 값이 아님", True),
])


# ============================================================
# 옵션 공통 정리
# ============================================================
add_bullet_slide("옵션 공통 — 무엇을 택하든 남는 것", [
    (0, "세션 재사용을 포기하지 않는 한 revocation은 근사적(approximate)일 수밖에 없음", True),
    (1, "zkLogin 취약점 분석(eprint 2026/227)의 결론과 일치 — 논문에 한계로 명시할 필요"),
    (0, "A는 지연을 줄이고, B와 C는 반영 경로를 새로 만든다", True),
    (1, "A: 기존 구조를 유지한 채 노출 시간만 축소 — 가장 값싸지만 근본 해결은 아님"),
    (1, "B: 오프체인 경량 체크 — 성능은 유리하나 RL 발행 주체의 신뢰·관찰 문제를 새로 만듦"),
    (1, "C: 온체인 상태 — 신뢰 가정이 가장 깔끔하나 회로 재배포까지 필요해 변경 폭이 가장 큼"),
    (0, "B와 C는 결국 π_pk_i의 public input에 상태를 추가하는 방향으로 수렴", True),
    (0, "각 문헌의 상세 근거·수치는 부록 A 참고", True),
])

# ============================================================
# 11. 오늘 결정할 사항
# ============================================================
add_bullet_slide("오늘 결정할 사항", [
    (0, "1. PairCT를 \"발급자 세션 개입형\"으로 명확히 포지셔닝할 것인가", True),
    (1, "온체인 설계 재검토 결과를 논문 서술에 반영할지 — \"하이브리드\" 주장 철회 여부"),
    (0, "2. Revocation을 이번 논문 범위에 넣을 것인가", True),
    (1, "넣는다면 Option A/B/C 중 어느 방향으로 설계할지"),
    (1, "넣지 않는다면 Discussion/Future Work에 한계로만 명시할지"),
    (0, "3. 벤치마크 수치 표기 방식", True),
    (1, "π_pk_i 캐싱을 먼저 구현하고 측정할지, 현재 상태 수치를 쓰되 캐싱 여지를 병기할지"),
])

# ============================================================
# 12. Next Steps
# ============================================================
add_bullet_slide("Next Steps", [
    (0, "π_pk_i 세션 캐싱 구현 후 tx당 지연 재측정 — 현재 295.50 ms가 소거될 것으로 예상", True),
    (0, "zkAA / zkLogin 스타일 오버헤드 실측 비교 — 일부 진행됨(같은 머신, warm-state 벤치마크)"),
    (0, "Revocation 메커니즘 후보(Option A/B/C)의 보안성·비용 분석"),
    (0, "위 내용을 PairCT 논문 Discussion/Future Work에 반영할지 결정"),
])

# ============================================================
# 부록 (1/4) - SSI 계열
# ============================================================
add_bullet_slide("부록 A (1/4) — Related Work: 발급자 1회 개입형", [
    (0, "zkAA — Beyond the Blockchain Address: Zero-Knowledge Address Abstraction", True),
    (1, "출처: eprint 2023/191 (ACM SAC 2025). 본 프로젝트(zkaa-circom)가 구현하는 원 논문으로 확인됨"),
    (1, "GitHub zkAA-onchain/zkaa-zokrates README: \"최신 구현은 zkaa-circom 참조\" — 공식 후속 구현체"),
    (1, "ZoKrates 버전 회로: register 172,772 / publish 79,529 constraints (본 프로젝트 circom 버전은 4,504 / 297)"),
    (1, "차이 원인 = 프리미티브 선택 (SHA-256 vs Poseidon). 격리 회로 컴파일로 실증: Poseidon(4)=297, EdDSAPoseidon=4,207, 합계 4,504"),
    (1, "→ 논문 수치와 우리 수치를 직접 비교 금지. 단 온체인 gas는 public input 수에 의존하므로 비슷할 가능성 높음"),
    (1, "\"zkAA builds on concepts from zkLogin\" — zkAA 자신이 이미 zkLogin을 선행 연구로 인용"),
    (0, "Zero-Knowledge Proof-of-Identity (arXiv:1905.09093)", True),
    (1, "ePassport DG15/Active Authentication + eSIM(GSMA 루트 인증서) 기반 1회 등록형 Sybil-resistant 인증"),
    (1, "정부는 최초 발급 시 1회만 개입, 이후 \"발급자 목록만 유지, 실제 매칭은 비공개\" — zkAA와 동일 철학"),
    (0, "기타: Peer-Supervised SSI (MDPI 2024) — ZKP+블록체인 오버사이트+peer review로 SSI 신뢰 문제 보완", True),
])

# ============================================================
# 10. Related Work (2/4) - OIDC 기반 계열
# ============================================================
add_bullet_slide("부록 A (2/4) — Related Work: 발급자 세션 개입형", [
    (0, "zkLogin 원 논문 (arXiv:2401.11735)", True),
    (1, "nonce = H(vk_u, T_exp, r) → OIDC JWT에 포함, zkaddr = H(stid, aud, iss, salt)"),
    (1, "Groth16, ~1.1M constraints (SHA-2 66%). 실측: 증명생성 2.78±0.25초, 검증 2.04ms, E2E 3.52±0.36초"),
    (1, "논문 본문: \"단일 ZKP는 같은 세션 내 모든 트랜잭션에 재사용 가능\" — 명시적 revocation 메커니즘 없음"),
    (0, "zkAt / zkAt+ (eprint 2025/921, AFT 2025, Sui/Mysten Labs)", True),
    (1, "Equivocable Groth16 — 검증키가 인증 정책과 독립적, 정책 자체를 검증자에게 숨김"),
    (1, "zkAt+: 재귀적 NIZK로 온체인 검증키 불변 상태에서 정책 갱신 가능 (\"obliviously updateable\")"),
    (1, "실측: 증명 51ms, 검증 <1ms, 증명 크기 상수 — 단, 계정/자격 revoke 자체는 별도 문제로 미해결"),
    (0, "Analysis and Vulnerabilities in zkLogin (eprint 2026/227, Brave, 2026-02)", True),
    (1, "\"세션 바인드 아티팩트가 원래 OIDC 세션 의미론이 아닌 에포크/로컬 상태로 지배\" → targeted revocation 불가능을 명시적으로 지적"),
    (1, "결론: \"통일된 위협 모델 없이 웹 인증을 암호 인가로 확장할 때 발생하는 구조적 문제\" — 세션 개입형 전반에 대한 경고"),
])

# ============================================================
# 11. Related Work (3/4) - Revocation 메커니즘
# ============================================================
add_bullet_slide("부록 A (3/4) — Related Work: Revocation 메커니즘", [
    (0, "BAAR (PLOS ONE, 2026-03) — Option C 선례", True),
    (1, "Pedersen commitment + Schnorr ZKP + Merkle 동적 accumulator. 오프체인 증명, 온체인엔 root만 게시"),
    (1, "실측: revocation O(log n), 200–310ms/건, gas ~30K(revoke)/~60K(verify)"),
    (0, "VLR 그룹서명(Boneh-Shacham 2004) + Lara (arXiv:2505.12968) — Option B 선례", True),
    (1, "VLR: 검증자만 최신 리스트 보유, 서명자 갱신 불필요 — 30년 가까이 축적된 이론적 뿌리"),
    (1, "Lara: Hierarchical Bloom Filter Array로 지연 80%↓, 시계 동기화 불필요한 비동기 revocation auditability"),
    (0, "Range-Revocable Pseudonyms (CCS'23) — Option A 확장", True),
    (1, "이진 트리 latchkey 구조로 epoch 내 구간별 선택적 revoke, O(log(granularity)), backward-unlinkable"),
    (1, "실측 예시: 9–13KB revocation 데이터로 2.5억 pseudonym 규모 처리, 검증 지연 <3.5ms"),
    (0, "zk-creds / Revocable ABE Credentials — 매 사용시 멤버십 재증명형 revocation (zkAA와 유사 트레이드오프)", True),
])

# ============================================================
# 12. Related Work (4/4) - 종합 비교
# ============================================================
add_table_slide(
    "부록 A (4/4) — Related Work: 종합 비교",
    ["시스템", "IdP 개입", "매 사용 재증명", "Revocation", "핵심 가정"],
    [
        ["zkAA", "최초 1회", "필요 (실측 121ms)", "미지원 (publish 회로에 상태 조회 없음)", "Groth16, cert"],
        ["zkLogin", "세션마다 1회", "불필요", "불가 (2026/227 논문 지적)", "Groth16 (~1.1M)"],
        ["zkAt/zkAt+", "정책 발급 시", "필요 (~51ms)", "정책 갱신은 가능, 계정 revoke 별도", "Equivocable Groth16"],
        ["BAAR", "발급 시", "오프체인 증명만", "지원, O(log n), 200–310ms", "Pedersen+Schnorr+Merkle"],
        ["VLR / Lara", "그룹/의사명 발급 시", "불필요 (리스트 대조만)", "지원, 비동기", "Bloom filter / bilinear map"],
        ["RRP", "pseudonym 발급 시", "불필요 (capability 제시)", "지원, 구간별 선택적", "Bloom filter, TEE"],
    ],
    [Inches(1.6), Inches(1.7), Inches(2.1), Inches(3.4), Inches(2.1)],
    top=Inches(1.5), height=Inches(3.6), font_size=12, header_size=13,
)
prs.save(OUT)
print("Saved:", OUT)
print("Total slides:", len(prs.slides._sldIdLst))
