# Figure 1 (v5, 2026-09-23): one login, one on-chain transaction, one authorized opening in zk-Delegation — 자격증명 이중 구조(C_u 한 번 / C_s 세션마다,
# 세션 발급 무증명), 지갑 트리 체크포인트+델타, 서비스의 root 나이 검사 반영. v3(draw_fig1_v3.py)의 배치를 유지하되 캔버스를 넓혀 v3 의 잘림을 없앤다. PIL 7.
from PIL import Image, ImageDraw, ImageFont

S = 1.0
SF = 1.3
W, H = int(3000*S), int(3050*S)
img = Image.new('RGB', (W, H), 'white')
d = ImageDraw.Draw(img)
F = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
FB = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
f_hdr = ImageFont.truetype(FB, int(40*S*1.1))
f_lbl = ImageFont.truetype(F, int(30*S*SF))
f_box = ImageFont.truetype(F, int(27*S*SF))
f_leg = ImageFont.truetype(F, int(28*S*SF))
BLACK, GREY, LIGHT, BLUE, RED, GREEN = (0, 0, 0), (110, 110, 110), (235, 238, 245), (0, 98, 155), (160, 40, 40), (20, 110, 60)

cols = {k: int(v*S) for k, v in {'aa': 560, 'user': 1330, 'svc': 2060, 'chain': 2640}.items()}
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

def arrow(src, dst, y, num, label, style='solid', color=BLACK, both=False):
    x1, x2 = cols[src], cols[dst]
    direction = 1 if x2 > x1 else -1
    a, b = x1 + direction * 8, x2 - direction * 8
    dashed_line(a, b, y, style, color)
    head(b, y, direction, color)
    if both: head(a, y, -direction, color)
    t = f'{num}  {label}' if num else label
    w, h = text_w(t, f_lbl)
    tx = (x1 + x2) / 2 - w / 2
    tx = max(MARGIN, min(tx, W - MARGIN - w))            # 라벨이 캔버스 밖으로 나가지 않게
    d.text((tx, y - h - 16), t, font=f_lbl, fill=color)

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

lifelines(int(2950*S))

# ---------------- once per user / once per service ----------------
y = int(215*S)
arrow('user', 'aa', y, '', 'registration (once):  uid, password;  cm_u = s_u·G3 + r_u·H;  AA returns sk_u and the attributes a1..a4', 'solid', GREY)
y += int(75*S)
arrow('user', 'aa', y, '(0)', 'user credential (once):  uid, C_u = Commit(uid, s_u, a1..a4; blind_u),  π_u', 'solid')
y = selfbox('aa', y + int(30*S), ['π_u:  C_u carries the authenticated uid, the s_u of cm_u, and the a1..a4 on record   (sigma protocol, no circuit)',
                           'Cf_u = Poseidon(C_u);  store {uid: active Cf_u, leaf(Cf_u)}   — the AA keeps no opening of C_u and no per-login record'])
y += int(70*S)
arrow('svc', 'aa', y, '', 'service registration (once):  name, origin, pk_service, X_svc  →  operator approves  →  arid, pk_trace, cert_s;  service deploys its factory', 'solid', GREY)
rule(y + int(45*S))

# ---------------- login ----------------
y += int(150*S)
arrow('svc', 'user', y, '(1)', 'arid, origin, cert_s, pk_trace, factory, r_s   (r_s fresh, single-use)', 'dashed', BLUE)
y = selfbox('user', y + int(30*S), ['verify cert_s under pk_AA — it covers (arid, origin, pk_trace);  origin == cert_s.origin',
                             'fresh (pk_i, sk_i), blind_s;  C_s = Commit(arid, pk_i; blind_s);  choose allowAgent;  max_height = grid(head + TTL)'])
y += int(60*S)
arrow('user', 'aa', y, '(2)', 'uid, Cf_u, C_s, chainid, allowAgent, max_height,  sig_u = Sign(sk_u, ...)      — no proof', 'solid')
y = selfbox('aa', y + int(30*S), ['not disabled;  chainid allowed;  sig_u;  Cf_u == active credential;  C_s in the subgroup;  chain alive',
                           'σ_AA = Sign(D_cred, Cf_u, Poseidon(C_s), max_height, chainid, allowAgent)   — nothing stored'])
y += int(60*S)
arrow('aa', 'user', y, '(3)', 'max_height, chainid, allowAgent, σ_AA', 'solid')
y = selfbox('user', y + int(30*S), ['tree: apply Revoked events since the last synced block to the checkpointed tree;  root == chain root (else replay)',
                             'PPID = Poseidon(uid, s_u, chainid, arid);  tag: r fresh, c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)',
                             'π for Table 2 (1)–(7):  σ_AA over (Cf_u, Cf_s), C_u opens to uid·s_u·a, C_s to arid·pk_i, leaf(Cf_u) ∉ tree;  σ = Sign(sk_i, r_s)'])
y += int(75*S)
arrow('user', 'chain', y - int(20*S), '', 'root, lastPublished, Revoked events since last sync', 'dotted', GREY, both=True)
y += int(40*S)
arrow('user', 'svc', y, '(4)', 'PPID, arid, pk_i, max_height, chainid, allowAgent, root, pk_trace, tag (c1, c2), disc_mask/lo/hi, π, σ', 'dashed', BLUE)
y = selfbox('svc', y + int(30*S), ['consume r_s;  root == chain root and root age ≤ MAX_ROOT_AGE;  head ≤ max_height ≤ head + L (5);  chainid, pk_AA, arid, pk_trace == mine',
                            'c1 ≠ O;  verify π, σ;  sessions[r_s] = {PPID, pk_i, max_height, allowAgent, root};  append transcript to private login log'])
y += int(75*S)
arrow('svc', 'chain', y - int(20*S), '(5)', 'root, lastPublished, block head', 'dotted', GREY, both=True)
y += int(40*S)
arrow('user', 'svc', y, '(6)', 'r_s, body, Sign(sk_i, r_s ‖ body)   (repeated; new π only when root changes)', 'dashed', BLUE)

# ---------------- on-chain transaction ----------------
y += int(60*S)
rule(y)
t = 'on-chain transaction — sender is the PPID account (same π, per transaction)'
w, h = text_w(t, f_lbl); d.text((cols['user'] - w / 2 + 300, y + int(12*S)), t, font=f_lbl, fill=GREEN)
y += int(110*S)
arrow('user', 'chain', y, "(6')", 'execute(payload, Sign(sk_i, chainid ‖ account ‖ payload ‖ nonce ‖ disclosure), π, public inputs)   via a relayer', 'solid', GREEN)
y = selfbox('chain', y + int(30*S), ['account = CREATE2(factory, PPID);  nonce;  ECDSA under pk_i;  PPID, arid, chainid, pk_AA, pk_trace == mine;  c1 ≠ O',
                              'root == log.root, root age ≤ MAX_ROOT_AGE, block ≤ max_height;  verify π;  nonce++;  call (+ disclosure tail);  emit tag, allowAgent'], color=GREEN)

# ---------------- opening ----------------
y += int(60*S)
rule(y)
t = 'authorized opening — only for a disputed session or transaction'
w, h = text_w(t, f_lbl); d.text((cols['user'] - w / 2, y + int(12*S)), t, font=f_lbl, fill=RED)
y += int(110*S)
arrow('svc', 'aa', y, '(7)', 'transcript (login log or tx calldata), D_svc = x_svc·c1, ts, Sign(sk_service, arid‖PPID‖c1‖D_svc‖ts)', 'solid', RED)
y = selfbox('aa', y + int(30*S), ['approved service;  ts fresh;  signature under pk_service;  transcript arid, pk_AA, pk_trace == registry;  verify π',
                           'pending — nothing decrypted until an operator approves;  then K = D_svc + x_AA·c1,  h = c2 − Poseidon(K),  uid: Poseidon(uid, arid) = h'], color=RED)
y += int(60*S)
arrow('aa', 'svc', y, '(8)', 'uid, allowAgent (after approval; denied → nothing)', 'solid', RED)

# ---------------- legend ----------------
y += int(40*S)
d.rectangle([0, y, W, H], fill='white')
ly = y + int(60*S)
items = [('solid', BLACK, 'seen by the AA (C_u and π_u once;  Cf_u, C_s, chainid, max_height, allowAgent per login)'),
         ('dashed', BLUE, 'never seen by the AA (arid, cert_s, pk_trace, PPID, pk_i, tag, disclosed ranges, r_s)'),
         ('dotted', GREY, 'read from the chain'),
         ('solid', GREEN, 'on-chain execution (public — the AA can read it too)'),
         ('solid', RED, 'opening (needs both shares + operator)')]
rows = [[0], [1], [2, 3], [4]]
for ri, row in enumerate(rows):
    x = 100; yy = ly + ri * int(60*S)
    for i in row:
        style, color, label = items[i]
        dashed_line(x, x + int(110*S), yy, style, color)
        d.text((x + int(130*S), yy - 18), label, font=f_leg, fill=BLACK)
        x += 130 + text_w(label, f_leg)[0] + 70

img = img.crop((0, 0, W, ly + int(190*S)))
img.save('docs/paper/zkd/fig1_login_v5.png', dpi=(300, 300))
print('saved', img.size)
