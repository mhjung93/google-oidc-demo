# Figure 1 (v6, 2026-09-30): one login, one on-chain transaction, one session revocation, one authorized opening in zk-Delegation.
# v5(draw_fig1_v5.py) 위에 다음을 반영한다 — V7 집합 소속 술어(set_sel/set_root, 공개 입력 25), V8 세션 단위 폐기(세션 리프·비멤버십 둘·AA 의
# 세션 기록), 지갑의 팩토리·검증자 참조 코드 대조와 상한 밴드, 2026-09-25 리뷰(정규 10진 공개 입력, 마스크 밖 슬롯 거절, σ_tx 16워드,
# 서비스의 set_root 정책 대조). 배치 개선: 화살표 라벨·구간 제목 뒤에 흰 바탕을 깔아 생명선과 겹치지 않게 하고, 범례가 잘리지 않게 자른다.
# 실행: 저장소 루트에서 python3 docs/paper/zkd/draw_fig1_v6.py  → docs/paper/zkd/fig1_login_v6.png (v5 파일은 건드리지 않는다). PIL 7.
from PIL import Image, ImageDraw, ImageFont

S = 1.0
SF = 1.3
W, H = int(3200*S), int(3900*S)
img = Image.new('RGB', (W, H), 'white')
d = ImageDraw.Draw(img)
F = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
FB = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
f_hdr = ImageFont.truetype(FB, int(40*S*1.1))
f_lbl = ImageFont.truetype(F, int(30*S*SF))
f_box = ImageFont.truetype(F, int(27*S*SF))
f_leg = ImageFont.truetype(F, int(28*S*SF))
f_sec = ImageFont.truetype(FB, int(30*S*SF))
BLACK, GREY, LIGHT, BLUE, RED, GREEN, ORANGE = (0, 0, 0), (110, 110, 110), (235, 238, 245), (0, 98, 155), (160, 40, 40), (20, 110, 60), (170, 95, 0)

cols = {k: int(v*S) for k, v in {'aa': 600, 'user': 1400, 'svc': 2180, 'chain': 2820}.items()}
names = {'aa': 'Authentication Authority (AA)', 'user': 'User / Wallet', 'svc': 'Service', 'chain': 'Chain (log + account)'}
TOP = int(60*S)
MARGIN = 40

def text_w(t, f):
    return f.getsize(t)

for k, x in cols.items():
    w, h = text_w(names[k], f_hdr)
    bw = w + 60
    x0 = max(MARGIN, min(x - bw / 2, W - MARGIN - bw))
    d.rectangle([x0, TOP, x0 + bw, TOP + int(90*S)], fill=LIGHT, outline=BLACK, width=3)
    d.text((x0 + 30, TOP + int(45*S) - h / 2 - 6), names[k], font=f_hdr, fill=BLACK)

def lifelines(bottom):
    for k, x in cols.items():
        y = TOP + int(90*S)
        while y < bottom:
            d.line([x, y, x, min(y + 18, bottom)], fill=GREY, width=3); y += int(30*S)

def dashed_line(x1, x2, y, style, color, width=4):
    if style == 'solid':
        d.line([x1, y, x2, y], fill=color, width=width); return
    seg, gap = (34, 18) if style == 'dashed' else (8, 12)
    sgn = 1 if x2 > x1 else -1
    x = x1
    while (x2 - x) * sgn > 0:
        xe = x + sgn * min(seg, abs(x2 - x))
        d.line([x, y, xe, y], fill=color, width=width); x = xe + sgn * gap

def head(x, y, direction, color):
    s = 22
    pts = [(x, y), (x - s, y - s * 0.6), (x - s, y + s * 0.6)] if direction > 0 else [(x, y), (x + s, y - s * 0.6), (x + s, y + s * 0.6)]
    d.polygon(pts, fill=color)

def label_bg(tx, ty, w, h):
    # 라벨 뒤 흰 바탕 — 생명선(회색 점선)이 글자 사이로 비치지 않게 한다
    d.rectangle([tx - 10, ty - 4, tx + w + 10, ty + h + 8], fill='white')

def arrow(src, dst, y, num, label, style='solid', color=BLACK, both=False):
    x1, x2 = cols[src], cols[dst]
    direction = 1 if x2 > x1 else -1
    a, b = x1 + direction * 8, x2 - direction * 8
    dashed_line(a, b, y, style, color)
    head(b, y, direction, color)
    if both: head(a, y, -direction, color)
    t = f'{num}  {label}' if num else label
    lines = t.split('\n')                                 # '\n' 으로 두 줄 이상 — 긴 라벨이 캔버스 밖으로 밀리지 않게
    lh = int(44*S)
    w = max(text_w(ln, f_lbl)[0] for ln in lines); h = text_w(lines[0], f_lbl)[1]
    tx = (x1 + x2) / 2 - w / 2
    tx = max(MARGIN, min(tx, W - MARGIN - w))            # 라벨이 캔버스 밖으로 나가지 않게
    assert tx + w <= W - MARGIN, (t[:60], 'label wider than the canvas')
    ty = y - h - 16 - lh * (len(lines) - 1)
    label_bg(tx, ty, w, h + lh * (len(lines) - 1))
    for i, ln in enumerate(lines):
        d.text((tx, ty + i * lh), ln, font=f_lbl, fill=color)

def selfbox(col, y, lines, color=BLACK):
    x = cols[col]
    lh = int(36*S*SF)
    width = max(text_w(ln, f_box)[0] for ln in lines) + 50
    hgt = lh * len(lines) + int(24*S)
    x = max(x, width / 2 + MARGIN)
    x = min(x, W - width / 2 - MARGIN)
    d.rectangle([x - width / 2, y, x + width / 2, y + hgt], fill='white', outline=color, width=3)
    for i, ln in enumerate(lines):
        w, h = text_w(ln, f_box)
        d.text((x - w / 2, y + 12 + i * lh), ln, font=f_box, fill=color)
    return y + hgt

def rule(y):
    d.line([MARGIN, y, W - MARGIN, y], fill=GREY, width=2)

def section(y, title, color):
    rule(y)
    w, h = text_w(title, f_sec)
    tx = W / 2 - w / 2; ty = y + int(14*S)
    label_bg(tx, ty, w, h)
    d.text((tx, ty), title, font=f_sec, fill=color)

lifelines(int(3800*S))

# ---------------- once per user / once per service ----------------
y = int(215*S)
arrow('user', 'aa', y, '', 'registration (once):  uid, password;  cm_u = s_u·G3 + r_u·H;  AA returns sk_u and the attributes a1..a4', 'solid', GREY)
y += int(75*S)
arrow('user', 'aa', y, '(0)', 'user credential (once):  uid, C_u = Commit(uid, s_u, a1..a4; blind_u),  π_u', 'solid')
y = selfbox('aa', y + int(30*S), ['π_u:  C_u carries the authenticated uid, the s_u of cm_u, and the a1..a4 on record   (sigma protocol, no circuit)',
                           'Cf_u = Poseidon(C_u);  store {uid: active Cf_u, leaf(Cf_u)}   — the AA keeps no opening of C_u'])
y += int(70*S)
arrow('svc', 'aa', y, '', 'service registration (once):  name, origin, pk_service, X_svc  →  operator approves  →  arid, pk_trace, cert_s;  service deploys its factory and verifier', 'solid', GREY)

# ---------------- login ----------------
y += int(60*S)
section(y, 'login — one session', BLUE)
y += int(130*S)
arrow('svc', 'user', y, '(1)', 'arid, origin, cert_s, pk_trace, factory, r_s   (r_s fresh, single-use)', 'dashed', BLUE)
y = selfbox('user', y + int(30*S), ['verify cert_s under pk_AA — it covers (arid, origin, pk_trace);  origin == cert_s.origin',
                             'factory and verifier bytecode == the wallet\'s reference build (immutable slots masked);  MAX_ROOT_AGE ∈ 1..200,  L ∈ 1..1600 blocks',
                             'fresh (pk_i, sk_i), blind_s;  C_s = Commit(arid, pk_i; blind_s);  choose allowAgent;  max_height = grid(head + TTL)'])
y += int(60*S)
arrow('user', 'aa', y, '(2)', 'uid, Cf_u, C_s, chainid, allowAgent, max_height,  sig_u = Sign(sk_u, ...)      — no proof', 'solid')
y = selfbox('aa', y + int(30*S), ['not disabled;  chainid allowed;  sig_u;  Cf_u == active credential;  C_s in the subgroup;  chain alive',
                           'σ_AA = Sign(D_cred, Cf_u, Poseidon(C_s), max_height, chainid, allowAgent)',
                           'sessions[uid] += (Cf_s, max_height, chainid, allowAgent, issuedAt)   — no arid, no pk_i (both inside C_s);  dropped when expired'])
y += int(60*S)
arrow('aa', 'user', y, '(3)', 'max_height, chainid, allowAgent, σ_AA', 'solid')
y = selfbox('user', y + int(30*S), ['tree: apply Revoked events since the last synced block to the checkpointed tree;  root == chain root (else replay)',
                             'PPID = Poseidon(uid, s_u, chainid, arid);  tag: r fresh, c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)',
                             'set predicate (optional): a_sel ∈ S, path in the service\'s set tree (depth 8) to set_root;  range predicates: disc_mask/lo/hi',
                             'π for Table 2 (1)–(8):  σ_AA over (Cf_u, Cf_s);  C_u opens to uid·s_u·a;  C_s to arid·pk_i;  leaf(Cf_u) ∉ tree;  leaf(Cf_s) ∉ tree;  σ = Sign(sk_i, r_s)'])
y += int(75*S)
arrow('user', 'chain', y - int(20*S), '', 'root, lastPublished, Revoked events since last sync', 'dotted', GREY, both=True)
y += int(40*S)
arrow('user', 'svc', y, '(4)', '25 public inputs: PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_AA, pk_trace, tag (c1, c2), disc_mask/lo/hi, set_sel/set_root;  π, σ', 'dashed', BLUE)
y = selfbox('svc', y + int(30*S), ['consume r_s;  every public input a canonical decimal (policy and Groth16 see the same values);  root == chain root, root age ≤ MAX_ROOT_AGE',
                            'head ≤ max_height ≤ head + L (5);  chainid, pk_AA, arid, pk_trace == mine;  c1 ≠ O;  set_sel ≠ 0 ⇒ set_root == my policy set;  verify π, σ',
                            'sessions[r_s] = {PPID, pk_i, max_height, allowAgent, root};  append transcript to private login log'])
y += int(75*S)
arrow('svc', 'chain', y - int(20*S), '(5)', 'root, lastPublished, block head', 'dotted', GREY, both=True)
y += int(40*S)
arrow('user', 'svc', y, '(6)', 'r_s, body, Sign(sk_i, r_s ‖ body)   (repeated; new π only when root changes)', 'dashed', BLUE)

# ---------------- on-chain transaction ----------------
y += int(60*S)
section(y, 'on-chain transaction — sender is the PPID account (same π, per transaction)', GREEN)
y += int(130*S)
y += int(44*S)
arrow('user', 'chain', y, "(6')", 'execute(payload, σ_tx, π, public inputs)   via a relayer — a swapped π of the same session fails σ_tx\n'
                                  'σ_tx = Sign(sk_i, chainid ‖ account ‖ payload ‖ nonce ‖ 11 disclosure words ‖ max_height ‖ allowAgent ‖ tag)   — 16 words; the call-data tail carries 11', 'solid', GREEN)
y = selfbox('chain', y + int(30*S), ['account = CREATE2(factory, PPID);  nonce;  ECDSA under pk_i over the 16-word digest',
                              'PPID, arid, chainid, pk_AA, pk_trace == mine;  allowAgent bit;  c1 ≠ O;  mask < 16;  set_sel ≤ 4;  lo/hi == 0 outside the mask',
                              'root == log.root, root age ≤ MAX_ROOT_AGE, block ≤ max_height ≤ block + L;  verify π;  nonce++;  call (+ 11-word tail);  emit tag, allowAgent'], color=GREEN)

# ---------------- revocation ----------------
y += int(60*S)
section(y, 'revocation — a session, or the whole account;  effective at the next published root', ORANGE)
y += int(130*S)
arrow('user', 'aa', y, '(R1)', 'session: uid, Cf_s, Sign(sk_u, Poseidon(D_revsess, uid, Cf_s, nonce))     account: uid, password     (an administrator can do either)', 'solid', ORANGE)
y = selfbox('aa', y + int(30*S), ['authorization first, lookup second (no existence leak);  session: Cf_s ∈ sessions[uid] and not expired → insert leaf(Cf_s) = mask(Poseidon(5, Cf_s))',
                           'account: disable, insert leaf(Cf_u) = mask(Poseidon(4, Cf_u));  the tree is append-only;  a published leaf does not say which kind it is'], color=ORANGE)
y += int(60*S)
arrow('aa', 'chain', y, '(R2)', 'publishRoot(root, new leaves, Sign_AA)   — also as a heartbeat with no leaves, so that root age stays below MAX_ROOT_AGE', 'solid', ORANGE)
y = selfbox('user', y + int(30*S), ['next login or transaction of that session: leaf(Cf_s) ∈ tree, so no π can be made — the session is dead;  the credential and the user\'s other sessions are untouched',
                             'a service cannot tell a session leaf from a user leaf, nor link a published leaf to its own session (it never holds blind_s)'], color=ORANGE)

# ---------------- opening ----------------
y += int(60*S)
section(y, 'authorized opening — only for a disputed session or transaction', RED)
y += int(130*S)
arrow('svc', 'aa', y, '(7)', 'transcript (login log or tx calldata), D_svc = x_svc·c1, ts, Sign(sk_service, arid‖PPID‖c1‖D_svc‖ts)', 'solid', RED)
y = selfbox('aa', y + int(30*S), ['approved service;  ts fresh;  signature under pk_service;  transcript arid, pk_AA, pk_trace == registry;  verify π (canonical inputs)',
                           'pending — nothing decrypted until an operator approves;  then K = D_svc + x_AA·c1,  h = c2 − Poseidon(K),  uid: Poseidon(uid, arid) = h'], color=RED)
y += int(60*S)
arrow('aa', 'svc', y, '(8)', 'uid, allowAgent (after approval; denied → nothing);  opening names the user, never the session', 'solid', RED)

# ---------------- legend ----------------
y += int(40*S)
d.rectangle([0, y, W, H], fill='white')
ly = y + int(60*S)
items = [('solid', BLACK, 'seen by the AA (C_u and π_u once;  Cf_u, C_s, chainid, max_height, allowAgent and a session record per login)'),
         ('dashed', BLUE, 'never seen by the AA (arid, cert_s, pk_trace, PPID, pk_i, tag, disclosed ranges and sets, r_s)'),
         ('dotted', GREY, 'read from the chain'),
         ('solid', GREEN, 'on-chain execution (public — the AA can read it too)'),
         ('solid', ORANGE, 'revocation (user or administrator → AA → chain)'),
         ('solid', RED, 'opening (needs both shares + operator)')]
rows = [[0], [1], [2, 3], [4, 5]]
for ri, row in enumerate(rows):
    x = 100; yy = ly + ri * int(60*S)
    for i in row:
        style, color, label = items[i]
        dashed_line(x, x + int(110*S), yy, style, color)
        d.text((x + int(130*S), yy - 18), label, font=f_leg, fill=BLACK)
        x += 130 + text_w(label, f_leg)[0] + 70

bottom = ly + len(rows) * int(60*S) + int(30*S)
img = img.crop((0, 0, W, bottom))
img.save('docs/paper/zkd/fig1_login_v6.png', dpi=(300, 300))
print('saved', img.size)
