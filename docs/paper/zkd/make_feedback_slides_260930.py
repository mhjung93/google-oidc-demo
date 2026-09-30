# 2026-09-23 회의 피드백 덱(documents/260923_meeting_MHJ_feedback.pptx — 교수님이 1–9장을 고치고 10장에 사용자가 Todo 6항목을 적음)에
# 대한 대응 계획 덱 (2026-09-30). 교수님 덱(260917_OVERALL.pptx) 템플릿을 쓰고 기존 슬라이드는 비운다(make_flow_slides_v5.py 와 같은 방식).
# 원본 덱은 건드리지 않는다.
# 근거: docs/paper/zkd/security_formal.md(§1·§4·§9·§10·§11), conditional_privacy_formal.md, 논문 v6(§III-C·§V·§VI·§IX),
#      results/mode3_session_revocation_20260924.md(V7→V8), results/mode3_review_fixes_20260925.md, results/mode3_onchain_bench_20260921.md.
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor

SRC = 'documents/260917_OVERALL.pptx'
DST = 'documents/260930_meeting_MHJ_feedback_response.pptx'
prs = Presentation(SRC)
sldIdLst = prs.slides._sldIdLst
for sldId in list(sldIdLst):
    prs.part.drop_rel(sldId.rId); sldIdLst.remove(sldId)
L_TITLE, L_BODY = prs.slide_layouts[0], prs.slide_layouts[1]

def title_slide(t, sub):
    s = prs.slides.add_slide(L_TITLE); s.shapes.title.text = t; s.placeholders[1].text = sub; return s

def bullets(title, items, size=17):
    """items: [(level, text), ...]"""
    s = prs.slides.add_slide(L_BODY); s.shapes.title.text = title
    tf = s.placeholders[1].text_frame; tf.word_wrap = True
    first = True
    for lvl, txt in items:
        p = tf.paragraphs[0] if first else tf.add_paragraph(); first = False
        p.text = txt; p.level = lvl
        for r in p.runs: r.font.size = Pt(size - 2 * lvl)
    return s

def table_slide(title, header, rows, widths_in, size=12, note=None, top_in=1.35, row_in=0.36):
    s = prs.slides.add_slide(L_BODY); s.shapes.title.text = title
    ph = s.placeholders[1]; ph._element.getparent().remove(ph._element)      # 본문 개체 틀 대신 표
    n_r, n_c = len(rows) + 1, len(header)
    left = Inches(0.45); top = Inches(top_in)
    gf = s.shapes.add_table(n_r, n_c, left, top, Inches(sum(widths_in)), Inches(row_in * n_r))
    t = gf.table
    for j, w in enumerate(widths_in): t.columns[j].width = Inches(w)
    for i in range(n_r): t.rows[i].height = Inches(row_in)
    for j, h in enumerate(header):
        c = t.cell(0, j); c.text = h
        for p in c.text_frame.paragraphs:
            for r in p.runs: r.font.size = Pt(size); r.font.bold = True
    for i, row in enumerate(rows, start=1):
        for j, val in enumerate(row):
            c = t.cell(i, j); c.text = val
            for p in c.text_frame.paragraphs:
                for r in p.runs: r.font.size = Pt(size)
    if note:
        tb = s.shapes.add_textbox(left, Inches(6.7), Inches(sum(widths_in)), Inches(0.55))
        tb.text_frame.word_wrap = True
        p = tb.text_frame.paragraphs[0]; p.text = note
        for r in p.runs: r.font.size = Pt(12); r.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    return s

# ---------------------------------------------------------------- 1. 표지
title_slide('9/23 회의 피드백 대응 계획', 'zk-Delegation  ·  2026-09-30  ·  Moonhyeon Chung')

# ---------------------------------------------------------------- 2. 요약
table_slide('피드백 항목 — 출처·요지·대응·상태',
    ['#', '출처', '지적 요지', '대응', '상태'],
    [['A', '2장',      '속성을 사용자/세션으로 나눔 — 예시(???) 채울 것; 토큰은 credential 아님',
                       '예시 확정, 세션 토큰 = 인증 성명 σ_AA 로 명명',                          '완료 (예시는 회의 확인)'],
     ['B', '3장·Todo 1', 'VCL·RCL 통합 구조? 한 리프에 latest valid/revoked 를 함께',
                       'VCL 불필요 논증 + 단일 트리·두 리프; 슬롯 리프는 득실 비교 후 결정',       '결정 필요'],
     ['C', '3장·Todo 2', '세션 속성 변경에 의한 폐기 지원 — 별도 트리?',
                       'V8: 같은 트리에 세션 리프, 비멤버십 둘 — 별도 트리 없음',                 '완료'],
     ['D', '5–7장·Todo 3', 'ZKP 전면 수정: π_idp 분리, π_rp 에서 Merkle 빼고 토큰·ID·PPID, π_i 태그=auid·threshold 제거',
                       'π_u 한 번(시그마)/세션 무증명, π_rp 내용 일치, 태그 = Enc(H(uid, arid)), 2-of-2 + 운영자',  '완료 / Merkle 유지 여부 결정'],
     ['E', '4장',      'ID 변환·토큰 세부 포맷 정리(???)',
                       '명칭 대응표 + 정식 정의(C_u, C_s, σ_AA, PPID)',                              '완료'],
     ['F', '8장',      'Address abstraction 특성은 어디에? zkAA 특성으로 채울 것',
                       'zkAA·BAAR 특성 ↔ G1–G10 대응표(G1–G3 = 주소 추상화 특성)',                '표 완성 / 논문 삽입 계획'],
     ['G', '9장',      'Current Work — 프로토콜·프로토타입·데모·평가·증명',
                       '항목별 상태표',                                                            '대부분 완료, 데모 대상 미정'],
     ['H', 'Todo 4',   '특허 — 제안대로 대응, 특허법인에 메일(교수님 cc)',
                       '사용자 액션',                                                              '확인 필요'],
     ['I', 'Todo 5·9장', '데모 계획을 todo 에 — 대상 서비스 결정(거래소 vs 오픈소스 Web3)',
                       '시나리오 4개 + 대상 후보 2개 비교',                                        '결정 필요'],
     ['J', 'Todo 6',   '기존 연구 비교·RCL 상태 폭발은 아직 아님',
                       '비교는 §II 최소로, 상태 증가는 §IX 한계 한 줄 — 보류 유지',                 '보류']],
    [0.4, 1.1, 4.3, 4.6, 2.0], size=11, row_in=0.44,
    note='피드백 시점(9/23) 이후 V5(9/21 설계·구현)·V7(9/23)·V8(9/24)·9/25 리뷰가 들어갔다. "완료"는 그 리비전에서 반영된 것.')

# ---------------------------------------------------------------- 3. A 속성 분리
bullets('A. 속성 분리 — 2장의 "예시 ???" 와 토큰 구성', [
    (0, '나누는 기준: 세션에 관련되는가 — 그대로 채택'),
    (1, '사용자 속성 a_1..a_4 (AA 계정 기록, 64비트 정수): 출생연도, 국가 코드, 등급, 예비(미사용) — 데모는 앞 둘을 씀 (연령 범위·국가 집합)'),
    (1, '세션 속성: 세션 키 pk_i, 만료 max_height(블록 높이), chainid, allowAgent(에이전트 허용), 서비스 arid'),
    (0, '"IdP 가 발급하는 세션 토큰" = 인증 성명 σ_AA — credential 이라 부르지 않는다 (교수님 수정 그대로)'),
    (1, 'σ_AA = Sign_AA(D, Cf_u, Cf_s, max_height, chainid, allowAgent)'),
    (1, 'Cf_u = Poseidon(C_u), C_u = uid·G1 + s_u·G3 + Σ a_k·G_{4+k} + blind_u·H — 사용자 속성은 Pedersen 벡터 커밋먼트 (2장과 같음)'),
    (1, 'Cf_s = Poseidon(C_s), C_s = arid·G2 + pk_i·G4 + blind_s·H — 세션 키는 커밋먼트 안 (2장의 "reserved slot" 방식)'),
    (0, 'zkLogin 과의 차이: 토큰 nonce = H(max_height, pk, r) 대신, 세션 키는 C_s 안에·만료는 서명 본문에 — AA 는 pk_i 도 arid 도 못 본다'),
    (1, '세션 nonce r 은 토큰에 넣지 않는다 — 로그인 챌린지 r_s 는 서비스가 내고 지갑이 sk_i 로 서명(1회용)'),
], size=17)

# ---------------------------------------------------------------- 4. B 폐기 구조 — VCL 불필요
bullets('B. 폐기 구조 (3장) — VCL 은 필요 없다', [
    (0, 'BAAR 은 valid 트리와 revoked 트리를 따로 둔다 → 갱신·포함 증명 오버헤드 둘'),
    (0, '본 연구는 트리 하나(RCL)만 둔다 — "유효함"은 트리가 아니라 AA 서명이 보증한다'),
    (1, '세션마다 AA 가 서명하고, 서명 전에 Cf_u 가 그 uid 의 활성 자격증명인지 AA 상태에서 확인 → 발급 시점의 유효성은 서명 안에 있다'),
    (1, '트리가 답해야 하는 것은 "발급 뒤 만료 전에 폐기됐는가" 뿐 → 폐기 리프의 비멤버십만 증명하면 된다'),
    (1, '결과: 온체인 쓰기는 폐기 때만(발급 때 0), 증명은 비멤버십 하나(이제 둘), VCL 없음'),
    (0, '"별도 Merkle Tree 유지 관리"(세션) 도 필요 없다 — 같은 트리에 리프 종류만 둘'),
    (1, '사용자 리프 mask(Poseidon(4, Cf_u)), 세션 리프 mask(Poseidon(5, Cf_s)) — 도메인 태그로 충돌 없음, 같은 root·같은 동기화'),
    (1, '게시된 리프는 종류를 드러내지 않고, 서비스는 blind_s 가 없어 자기 세션과 잇지 못한다'),
    (0, '수치: 리프 1개 게시 43,856 gas, 하트비트(리프 0) 40.3k gas 내외; 트리 깊이 32'),
], size=17)

# ---------------------------------------------------------------- 5. B' 슬롯 리프 제안 득실
table_slide('B′. Todo 1 슬롯 리프 (latest valid / revoked) — 득실',
    ['항목', '현재: append-only 폐기 리프', '제안: 사용자당 슬롯(latest valid / latest revoked)'],
    [['온체인 쓰기 시점', '폐기·은퇴 때만 (발급 때 0)',            '자격증명 (재)발급 때마다 슬롯 갱신 → 발급당 1 tx (≈ 43,856 gas)'],
     ['상태 크기',       '폐기 수만큼 증가 (append-only)',          '사용자 수로 유계 — 이 점이 장점'],
     ['증명',           '비멤버십 ×2 (리프 + 경로)',               '"내 Cf_u = 슬롯의 latest valid" 멤버십 — 리프 + 경로, 비용 같음 (절감 없음)'],
     ['세션 폐기',       '세션 리프를 같은 트리에 추가',             'latest revoked 칸 하나 → 동시에 폐기된 세션 둘은 표현 불가; 세션 슬롯을 두면 세션 수만큼 증가'],
     ['프라이버시',      '리프 = 해시, 종류·주인 비공개',            '슬롯 키가 사용자에 고정 → 같은 슬롯의 갱신 시각들이 한 사용자로 이어진다 (타이밍 연결)'],
     ['AA 상태',        '활성 Cf_u 는 AA 에만',                     '활성 Cf_u 가 체인에도 (해시) — AA 가 이미 알지만 공개 기록이 하나 더'],
     ['권고',           '유지 — 상태 증가는 Todo 6 대로 지금은 보류, 필요해지면 재기준화(새 트리·재발급)로 상한', '결정 요청: 원하시면 슬롯 변형을 회로·AA 상태만 바꿔 프로토타입하고 두 수치를 나란히 잰다 (약 1주)']],
    [1.6, 4.6, 6.2], size=12, row_in=0.5,
    note='재기준화: 트리를 새로 시작하고 활성 자격증명을 재발급 — 옛 리프를 버린다. 스펙에 후속으로 적혀 있고 구현은 없다.')

# ---------------------------------------------------------------- 6. C 세션 폐기 완료
bullets('C. 세션 속성 폐기 (Todo 2) — V8 로 완료', [
    (0, '사용자가 세션 하나만 폐기: uid, Cf_s, Sign(sk_u, Poseidon(D_revsess, uid, Cf_s, nonce)) — 관리자도 가능'),
    (1, 'AA 는 인가를 먼저 검증하고 그 다음 세션을 찾는다 (존재 여부 누출 없음); 만료된 세션은 거절; 멱등'),
    (1, '이를 위해 AA 가 세션마다 (Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt) 를 남긴다 — arid·pk_i 는 없음(C_s 안)'),
    (0, '회로: 사용자 리프·세션 리프 비멤버십 둘, 같은 root'),
    (1, '제약 27,329 → 37,130 (+9,801), 증명 832.8 → 1,191.7 ms (+0.36 s), 검증 10.0 ms 그대로'),
    (1, '온체인 검증 gas 불변 (공개 입력 수 25 그대로) — 비용은 증명자가 진다'),
    (0, '효력: 다음 root 게시부터. 세션 하나만 죽고 자격증명·다른 세션은 그대로'),
    (0, '남은 것: 게시 정책(즉시 vs 하트비트 배치) — 타이밍 채널 폭 = 1 / 게시당 리프 수. 옵션·측정은 후속'),
], size=17)

# ---------------------------------------------------------------- 7. D ZKP 재구성 대응표
table_slide('D. ZKP 재구성 (Todo 3, 5–7장) — 교수님 항목 ↔ 현재',
    ['교수님 지시', '현재 (V5–V8)', '상태'],
    [['π_idp 를 몰아서 하지 말고 C_u 변경 여부로 나눠 따로',
      'π_u: 자격증명 발급(C_u 가 바뀔 때)에만, 시그마 프로토콜(회로 없음, 80/99 ms). 세션 발급: ZKP 없음 — sig_u 하나',  '완료'],
     ['π_idp 에서 "커밋먼트를 a, r 로 만들었는지" 삭제(취소선)',
      '세션에서는 없음. π_u 는 남긴다: AA 는 자기 기록의 속성이 든 C_u 에만 서명해야 한다(아니면 임의 속성 보증) — 한 번, 회로 없음', '완료 (근거 확인 요청)'],
     ['π_rp: valid token(서명, max_height) + auid_i·arid·PPID 관계',
      'σ_AA over (Cf_u, Cf_s) 검증, C_u 가 uid·s_u·a 로 열림, C_s 가 arid·pk_i 로 열림, PPID = H(uid, s_u, chainid, arid), 선택 공개(범위·집합)', '완료'],
     ['π_rp: merkle proof 빠지고',
      '비멤버십 ×2 가 아직 있다 — Todo 2(세션 폐기)를 세션 중에 강제하려면 필요. 빼면 zkLogin 식(만료만). 다음 장에서 결정', '결정 필요'],
     ['π_i: trace tag 를 auid 로, condition 재고, threshold 제거',
      'threshold 서명 없음(추적 키만 2-of-2 가산 복호, 9/16). 태그 = Enc(pk_trace, Poseidon(uid, arid)) — 서비스별 가명(auid 역할). 개봉 = 서비스 조각 + AA 조각 + 운영자 승인. 조건 = 분쟁 세션',  '완료'],
     ['π_i 를 트랜잭션에 첨부',
      '별도 π_i 없음 — 태그는 π_rp 안(조건 ⑤)이고 같은 π 를 트랜잭션에 재사용. σ_tx 가 태그 3워드를 묶어 바꿔치기 불가(9/25)', '완료']],
    [3.4, 7.0, 1.9], size=12, row_in=0.55)

# ---------------------------------------------------------------- 8. D' Merkle 증명 유지 vs 제거
table_slide('D′. π_rp 의 비멤버십(Merkle) 증명 — 유지 vs 제거',
    ['항목', '유지 (현재, V8)', '제거 (zkLogin 식: 만료에만 의존)'],
    [['세션 중 폐기',   '다음 root 게시부터 효력 (하트비트 H 블록 이내)',        '불가 — 만료(max_height)까지 유효. 최대 지연 ~400 블록 (TTL 300 + grid 반올림, L = 400)'],
     ['Todo 2 세션 폐기', '지원',                                                 '세션 폐기 자체가 무의미해진다'],
     ['회로',           '37,130 제약, 증명 1.19 s',                               '약 17,500 (비멤버십 둘 ≈ 19,600 제거, 추정), 증명 약 0.5 s (추정)'],
     ['지갑',           '폐기 트리 동기화 필요 (체크포인트+델타, 로그인당 25 ms)', '동기화 없음'],
     ['AA 하트비트',     '필요 (root 나이 상한)',                                  '불필요 — 체인에 폐기 로그 자체가 없어도 된다'],
     ['서비스 검사',     'root == 체인 root, root 나이 ≤ MAX_ROOT_AGE',            '만료만'],
     ['권고',           '유지 — 세션 폐기가 요구사항(Todo 2)이고 비용은 증명자 0.36 s 뿐', '요구사항이 "만료로 충분"이면 이쪽; 결정 요청']],
    [1.8, 5.2, 5.4], size=12, row_in=0.5,
    note='중간안: 비멤버십을 유지하되 하트비트 주기·TTL 을 줄여 폐기 효력 지연을 통제 — 회로는 그대로.')

# ---------------------------------------------------------------- 9. E ID 변환·토큰 형식
table_slide('E. ID 변환·토큰 형식 (4장) — 명칭 ↔ 현재 정의',
    ['4장의 이름', '역할', '현재 정의', '누가 아는가'],
    [['salt',            '사용자 프라이버시 비밀',                  's_u (등록 때 cm_u = s_u·G3 + r_u·H 로 AA 에 커밋)',           '사용자만'],
     ['auid = H(salt, uid)', 'AA 쪽 가명',                           '따로 두지 않는다 — uid·s_u 는 C_u 안에 있고 PPID 에만 쓰인다',   '—'],
     ['auid_i',          '서비스가 보는 가명',                       'PPID = Poseidon(uid, s_u, chainid, arid) — 서비스·체인마다 다름',   '서비스 (AA 는 모름)'],
     ['rid → arid',      '서비스 ID',                                'arid (AA 가 등록 때 부여), cert_s 로 origin 에 묶임',          '서비스·사용자 (AA 는 요청에서 못 봄)'],
     ['session nonce',   '재생 방지',                                'r_s — 토큰 밖. 서비스가 내고 지갑이 sk_i 로 서명, 1회용',      '서비스·사용자'],
     ['H(user attributes)', '속성 커밋',                             'Cf_u = Poseidon(C_u), C_u 는 Pedersen 벡터 커밋먼트',           'AA·사용자'],
     ['H(session key)',  '세션 키 결속',                             'pk_i 는 C_s = arid·G2 + pk_i·G4 + blind_s·H 안',                '사용자 (서비스는 로그인 때)'],
     ['expire time',     '만료',                                      'max_height (블록 높이, 지갑이 grid 100 으로 정함)',             '모두'],
     ['Session Token',   'IdP 발급',                                  'σ_AA = Sign_AA(D, Cf_u, Cf_s, max_height, chainid, allowAgent)', 'AA·사용자']],
    [2.0, 2.2, 5.6, 2.5], size=12, row_in=0.42,
    note='정식 정의: security_formal.md §1(+§9·§10 갱신), 논문 Table 1·2. 변수별 "왜 필요한가/빼면" 표는 형식 문서 §1 에 있다.')

# ---------------------------------------------------------------- 10. F 특성 대응표
table_slide('F. 특성 대응표 (8장) — zkAA·BAAR ↔ G1–G10',
    ['특성', '출처', '본 연구 목표', '메커니즘', '증명(형식 문서 §4)'],
    [['Injectiveness (주소 추상화)',    'zkAA',      'G1 Uniqueness',           'PPID = H(uid, s_u, chainid, arid)',                    '정리 1'],
     ['Tamper resistance (주소 추상화)', 'zkAA',     'G2 Immutability',         '계정 = CREATE2(factory, PPID); 검사는 온체인',         '정리 2'],
     ['Privacy-preservation (주소 추상화)', 'zkAA',  'G3 Privacy preservation', '서비스·체인 간 주소 연결 불가',                        '정리 3'],
     ['Unforgeability',       'zkAA·BAAR', 'G6·G7',                   'σ_AA(EdDSA), σ_tx 16워드, r_s 1회용',                   '정리 6–8'],
     ['Correctness',          'zkAA',      '(완전성)',                '정직한 지갑의 로그인·트랜잭션은 항상 통과',            '명제 16'],
     ['Chronicle',            'zkAA',      'G10 + 온체인 기록',       'Mode3Auth 이벤트 = 개봉 장부, 태그는 σ_tx 에 결속',     '정리 4·§V-G'],
     ['Unlinkability',        'BAAR',      'G3',                      '〃',                                                  '정리 3'],
     ['Attribute privacy',    'BAAR',      'G5',                      '선택 공개(범위·집합)만, AA 는 사용처 미관측',            '정리 5·5′'],
     ['Revocation soundness', 'BAAR',      'G8',                      '사용자·세션 리프 비멤버십 ×2, root 나이 상한',         '정리 9·9′'],
     ['—',                    '본 연구',   'G4 Service unobservability', 'AA 는 서비스·PPID·세션키를 못 봄',                 '정리 5'],
     ['—',                    '본 연구',   'G9 Liveness independence', '재검증·트랜잭션에 AA 불필요',                         '§4'],
     ['—',                    '본 연구',   'G10 Conditional privacy', '2-of-2 태그 + 운영자 승인으로만 개봉',                  '정리 11–15']],
    [2.9, 1.0, 2.3, 4.0, 2.1], size=11, row_in=0.38,
    note='주소 추상화의 특성 = zkAA 의 앞 세 줄 = G1–G3. 8장의 목록은 이 표로 바꾸고, 논문 §VII 앞에 Table 로 넣을 계획. 정리 번호는 삽입 전 대조.')

# ---------------------------------------------------------------- 11. I 데모 계획
bullets('I. 데모 계획 (Todo 5, 9장) — 시나리오와 대상 서비스', [
    (0, '지금 있는 것: 세 서버(AA·지갑 에이전트·서비스) + MetaMask Snap, 안내 바·용어·체험 모드(단계 잠금)·상태 패널, 스크린샷 18장'),
    (0, '시나리오 4개 — 모두 구현돼 있다'),
    (1, '① 로그인: 등록 → 자격증명 → 서비스 로그인(가명), 두 서비스에서 다른 주소'),
    (1, '② 조건부 트랜잭션: 연령 범위·국가 집합을 공개해 AttrGate.claim — 값이 아니라 조건만 드러남'),
    (1, '③ 세션 폐기: 사용자가 세션 하나 폐기 → 다음 root 뒤 그 세션만 죽음'),
    (1, '④ 승인 개봉: 분쟁 트랜잭션을 서비스 조각 + AA 조각 + 운영자 승인으로 uid 까지'),
    (0, '대상 서비스 — 결정 요청'),
    (1, '(a) 가상자산거래소 인증: KYC 속성(연령·국적)이 있어 ②가 자연스럽고, 지금 코드로 시연 가능 — 권고'),
    (1, '(b) 오픈소스 Web3 서비스 통합: 우리 PPID 계정으로 로그인·거래하는 dApp 하나 — 외부 코드 수정 필요, 2–3주'),
    (0, '평가: 로그인 1.50 s(증명 1.26 s) · 재검증 29 ms · 트랜잭션 164 ms · execute 417,533 gas — 오버헤드 분석은 논문 §VIII'),
], size=17)

# ---------------------------------------------------------------- 12. G Current Work 상태표
table_slide('G. Current Work (9장) — 항목별 상태',
    ['교수님 항목', '상태', '근거'],
    [['프로토콜 정리 — 사용자/세션 속성 분리·폐기 지원',  '완료', 'V5 이중 구조(9/21), V8 세션 폐기(9/24)'],
     ['프로토콜 정리 — ZKP 내용 보완',                     '완료', 'π_u 시그마 / 세션 무증명 / π_rp 25 입력 (7장)'],
     ['프로토콜 정리 — 전체 flow 정리',                    '완료', '논문 Fig. 1 구조도·Fig. 2 순서도 (9/30)'],
     ['프로토타입 구현',                                    '완료', 'Mode 3 데모 스택 + Snap, 테스트 7그룹 초록'],
     ['데모 시나리오',                                      '초안', '11장 — 시나리오 4개, 대상 서비스 미정'],
     ['대상 서비스와 통합 연계',                            '미착수', '대상 결정 뒤'],
     ['성능 평가 및 오버헤드 분석',                         '완료', 'results/…_20260924·_20260925, 논문 §VIII'],
     ['Security analysis formal proof',                     '완료', 'security_formal(정리 1–15·명제 10·16–21)·conditional_privacy — 9/25 갱신'],
     ['차별성 정리·기존 연구 비교',                         '보류', 'Todo 6 — §II 최소 유지']],
    [5.0, 1.2, 6.1], size=12, row_in=0.42)

# ---------------------------------------------------------------- 13. 결정·액션·일정
bullets('회의에서 결정할 것 · 액션 · 일정', [
    (0, '결정 요청'),
    (1, 'B′ 슬롯 리프(latest valid/revoked) — 유지 권고 vs 프로토타입 1주'),
    (1, 'D′ π_rp 비멤버십 — 유지 권고(세션 폐기 요구) vs 제거(만료만, 회로 절반)'),
    (1, 'I 데모 대상 — (a) 거래소 인증 권고 vs (b) 오픈소스 dApp 통합'),
    (1, 'D π_u 유지 근거 확인, A 속성 예시 확정'),
    (0, '보류 (Todo 6): 기존 연구 비교 심화, RCL 상태 증가 대책 — 논문엔 한계 한 줄만'),
    (0, '사용자 액션 (Todo 4): 특허 대응 메일 — 특허법인, 교수님 cc'),
    (0, '일정'),
    (1, '이번 주: A 예시·F 특성표·"VCL 불필요" 논증을 논문 §VI 에 명시, 데모 시나리오 문서'),
    (1, '다음 주: 결정에 따라 B′ 프로토타입 또는 게시 배치 옵션 + 측정; 데모 대상 착수'),
    (1, '이후: 논문 v7, 슬라이드(flow·ZKPs) 갱신'),
], size=17)

prs.save(DST)
print('saved', DST, len(prs.slides), 'slides')
