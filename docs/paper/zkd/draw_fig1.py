# Figure 1: one login + one authorized opening in zk-Delegation (sequence diagram), drawn with PIL 7.
from PIL import Image, ImageDraw, ImageFont

S = 1.0
SF = 1.3
W, H = int(2600*S), int(2400*S)
img = Image.new('RGB', (W, H), 'white')
d = ImageDraw.Draw(img)
F = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
FB = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
f_hdr = ImageFont.truetype(FB, int(40*S*1.1))
f_lbl = ImageFont.truetype(F, int(30*S*SF))
f_box = ImageFont.truetype(F, int(27*S*SF))
f_leg = ImageFont.truetype(F, int(28*S*SF))
BLACK, GREY, LIGHT, BLUE, RED = (0, 0, 0), (110, 110, 110), (235, 238, 245), (0, 98, 155), (160, 40, 40)

cols = {k: int(v*S) for k, v in {'aa': 500, 'user': 1170, 'svc': 1840, 'chain': 2330}.items()}
names = {'aa': 'Authentication Authority (AA)', 'user': 'User / Wallet', 'svc': 'Service', 'chain': 'Revocation chain'}
TOP = int(60*S)

def text_w(t, f):
    return f.getsize(t)

for k, x in cols.items():
    w, h = text_w(names[k], f_hdr)
    bw = w + 60
    d.rectangle([x - bw / 2, TOP, x + bw / 2, TOP + int(90*S)], fill=LIGHT, outline=BLACK, width=3)
    d.text((x - w / 2, TOP + int(45*S) - h / 2 - 6), names[k], font=f_hdr, fill=BLACK)

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
    d.text(((x1 + x2) / 2 - w / 2, y - h - 16), t, font=f_lbl, fill=color)

def selfbox(col, y, lines, color=BLACK):
    x = cols[col]
    lh = int(36*S*SF)
    width = max(text_w(ln, f_box)[0] for ln in lines) + 50
    hgt = lh * len(lines) + int(24*S)
    x = max(x, width / 2 + 40)
    x = min(x, W - width / 2 - 40)
    d.rectangle([x - width / 2, y, x + width / 2, y + hgt], fill='white', outline=color, width=3)
    for i, ln in enumerate(lines):
        w, h = text_w(ln, f_box)
        d.text((x - w / 2, y + 12 + i * lh), ln, font=f_box, fill=color)
    return y + hgt

lifelines(int(2300*S))

# registration (once)
y = int(215*S)
arrow('user', 'aa', y, '', 'registration (once):  cm_u = s_u·G3 + r_u·H', 'solid', GREY)
arrow('svc', 'aa', y + int(70*S), '', '', 'solid', GREY)
t = 'service registration (once):  name, origin, pk_service, X_svc  →  operator approves  →  arid, pk_trace, cert_s'
w, h = text_w(t, f_lbl); d.text(((cols['aa'] + cols['svc']) / 2 - w / 2, y + int(70*S) - h - 16), t, font=f_lbl, fill=GREY)
d.line([cols['aa'] - 300, y + int(120*S), cols['chain'] + 200, y + int(120*S)], fill=GREY, width=2)

# login
y = int(430*S)
arrow('svc', 'user', y, '(1)', 'arid, origin, cert_s, pk_trace, r_s   (r_s fresh, single-use)', 'dashed', BLUE)
y = selfbox('user', y + int(30*S), ['verify cert_s under pk_AA — it covers (arid, origin, pk_trace);  origin == cert_s.origin',
                             'fresh (pk_i, sk_i), blind;  C_pt = Commit(uid, arid, s_u, pk_i, a1..a4; blind)'])
y += int(60*S)
arrow('user', 'aa', y, '(2)', 'uid, C_pt, chainid, r_s, π_issue, sig_u', 'solid')
y = selfbox('aa', y + int(30*S), ['not disabled;  chainid allowed;  sig_u;  π_issue (C_pt carries uid and the s_u of cm_u)',
                           'exptime = now + TTL;  σ_AA = Sign(D_cred, C, exptime, chainid, r_s)   — nothing stored per login'])
y += int(60*S)
arrow('aa', 'user', y, '(3)', 'exptime, chainid, r_s, σ_AA', 'solid')
y = selfbox('user', y + int(30*S), ['read root and Revoked events from the chain;  PPID = Poseidon(uid, s_u, chainid, arid)',
                             'tag: r fresh, c1 = r·B8, c2 = uid + Poseidon(r·pk_trace);  π for Table 2 (1)–(5);  σ = Sign(sk_i, r_s)'])
y += int(75*S)
arrow('user', 'chain', y - int(20*S), '', 'root, Revoked events (non-membership witness)', 'dotted', GREY, both=True)
y += int(40*S)
arrow('user', 'svc', y, '(4)', 'PPID, arid, pk_i, exptime, chainid, r_s, root, pk_trace, tag (c1, c2), π, σ', 'dashed', BLUE)
y = selfbox('svc', y + int(30*S), ['consume r_s;  root == chain root (5);  exptime, chainid, pk_AA, arid, pk_trace == mine',
                            'verify π, σ;  sessions[r_s] = {PPID, pk_i, exptime, root};  append transcript to private login log'])
y += int(75*S)
arrow('svc', 'chain', y - int(20*S), '(5)', 'root, block head', 'dotted', GREY, both=True)
y += int(40*S)
arrow('user', 'svc', y, '(6)', 'r_s, body, Sign(sk_i, r_s ‖ body)   (repeated; new π only when root changes)', 'dashed', BLUE)

# opening (only for a disputed session)
y += int(60*S)
d.line([cols['aa'] - 300, y, cols['chain'] + 200, y], fill=GREY, width=2)
t = 'authorized opening — only for a disputed session'
w, h = text_w(t, f_lbl); d.text((cols['user'] - w / 2, y + int(12*S)), t, font=f_lbl, fill=RED)
y += int(110*S)
arrow('svc', 'aa', y, '(7)', 'transcript (public inputs, π), D_svc = x_svc·c1, ts, Sign(sk_service, arid‖r_s‖PPID‖D_svc‖ts)', 'solid', RED)
y = selfbox('aa', y + int(30*S), ['approved service;  ts fresh;  signature under pk_service;  transcript arid, pk_AA, pk_trace == registry;  verify π',
                           'pending — nothing decrypted until an operator approves;  then K = D_svc + x_AA·c1,  uid = c2 − Poseidon(K)'], color=RED)
y += int(60*S)
arrow('aa', 'svc', y, '(8)', 'uid (after approval; denied → nothing)', 'solid', RED)

# legend
y += int(40*S)
d.rectangle([0, y, W, H], fill='white')
ly = y + int(60*S)
items = [('solid', BLACK, 'seen by the AA (C, chainid, r_s, exptime)'),
         ('dashed', BLUE, 'never seen by the AA at login (arid, cert_s, pk_trace, PPID, pk_i, tag, attributes)'),
         ('dotted', GREY, 'read from the chain'),
         ('solid', RED, 'opening (needs both shares + operator)')]
x = 100
for i, (style, color, label) in enumerate(items):
    yy = ly + (0 if i < 2 else int(60*S))
    if i == 2: x = 100
    dashed_line(x, x + int(110*S), yy, style, color)
    d.text((x + int(130*S), yy - 18), label, font=f_leg, fill=BLACK)
    x += 130 + text_w(label, f_leg)[0] + 70

img = img.crop((0, 0, W, ly + int(130*S)))
img.save('/tmp/zkd_paper/fig1_login.png', dpi=(300, 300))
print('saved', img.size)
