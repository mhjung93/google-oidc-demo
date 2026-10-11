# zk-Delegation 원고 v2 → v3: 온체인 실행(덱 260917) 반영. 스펙 2026-09-18 §11 목록.
import copy
from docx import Document
from docx.oxml.ns import qn
from docx.text.paragraph import Paragraph
from docx.shared import Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from lxml import etree

SRC = 'documents/2026-09-16_v2_zk-Delegation_research_article.docx'
DST = 'documents/2026-09-18_v3_zk-Delegation_research_article.docx'
FIG = 'docs/paper/zkd/fig1_login_v3.png'

d = Document(SRC)
XMLNS = '{http://www.w3.org/XML/1998/namespace}space'

def find(prefix, style=None):
    for p in d.paragraphs:
        if p.text.startswith(prefix) and (style is None or p.style.name == style):
            return p
    raise KeyError(prefix)

def set_text(p, text):
    rs = p.runs
    assert len(rs) >= 1, p.text[:40]
    rs[0].text = text
    for r in rs[1:]:
        r._r.getparent().remove(r._r)

def replace_in(p, old, new):
    t = p.text
    assert old in t, (old[:60], t[:80])
    set_text(p, t.replace(old, new, 1))

def clone_after(p, text, template=None):
    el = copy.deepcopy((template or p)._p)
    ts = el.findall('.//' + qn('w:t'))
    assert len(ts) >= 1
    ts[0].text = text
    ts[0].set(XMLNS, 'preserve')
    for t in ts[1:]:
        t.getparent().remove(t)
    p._p.addnext(el)
    return Paragraph(el, p._parent)

def set_cell(tc, text):
    ps_ = tc.findall(qn('w:p'))
    for q in ps_[1:]: tc.remove(q)
    q = ps_[0]
    rs = q.findall(qn('w:r'))
    for r in rs[1:]: q.remove(r)
    if not rs: rs = [etree.SubElement(q, qn('w:r'))]
    ts = rs[0].findall(qn('w:t'))
    for t in ts[1:]: rs[0].remove(t)
    if not ts: ts = [etree.SubElement(rs[0], qn('w:t'))]
    ts[0].text = text; ts[0].set(XMLNS, 'preserve')

def row_after(table, key, row):
    tbl = table._tbl
    trs = tbl.findall(qn('w:tr'))
    for tr in trs:
        if tr.findall(qn('w:tc'))[0].xpath('string(.)').strip() == key:
            new = copy.deepcopy(tr)
            for tc, text in zip(new.findall(qn('w:tc')), row): set_cell(tc, text)
            tr.addnext(new); return
    raise KeyError(key)

def set_row(table, key, row):
    for r in table.rows:
        if r.cells[0].text.strip() == key:
            for tc, text in zip(r.cells, row): set_cell(tc._tc, text)
            return
    raise KeyError(key)

PARA_T = find('A Web3 service must recognize a returning user')
SUB_T = find('A. ENTITIES')

# ---------------- 초록 ----------------
a = find('ABSTRACT ')
set_text(a, "ABSTRACT A Web3 service identifies its users by an address, in practice a blockchain account: reuse across services and chains makes a user linkable, and a login says nothing about who holds the key. Delegating authentication to an existing account keeps a Web2-style login but tells the authority which service the user visits. zk-Delegation redefines the address as the name under which a service knows a user, derived from one user secret for every chain and service, and realized on chain as a contract account whose transactions carry the login's proof. The authentication authority (AA) verifies the login and signs a user-chosen Pedersen commitment with a block-height expiry; it learns neither pseudonym, service, nor attributes and cannot recognize the user's transactions on the chain. Each service receives a pairwise pseudonym with a zero-knowledge proof of its derivation and non-revocation, and cannot link a user across services or chains. A trace tag, the identity encrypted under a key shared by the AA and the service, lets a disputed session be opened only by both with an operator. One proof serves a session: off-chain requests carry a signature, on-chain transactions re-submit it, and revocation takes effect at the next re-validation or transaction. Revocation is an append-only tree whose root the AA publishes on a public chain, so verification continues while the AA is offline; users can revoke their own accounts. A prototype's proof has about 25,600 constraints, proves in under a second, and verifies in milliseconds off chain or 390,000 gas on chain.")
print('abstract words:', len(a.text.replace('ABSTRACT', '').split()))

# ---------------- 서론 ----------------
p = find('We take a different view of what an address is.')
replace_in(p, 'It is not an on-chain account and it does not sign transactions.',
           'It need not be an externally owned account: where a service acts on a chain, the name locates a contract account derived from it, and every transaction of that account carries the same proof as a login (Section V-I).')
p = find('zk-Delegation combines address abstraction with delegated authentication')
replace_in(p, 'and signs the commitment, an expiry, the chain identifier, and the challenge.',
           'and signs the commitment, an expiry expressed as a block height, the chain identifier, and a per-session agent-permission flag; the challenge is not signed, because everything the AA signs may later appear on a public chain.')
replace_in(p, 'The service checks that the embedded challenge is the one it issued, that the expiry and chain match, and that the session key signs the request.',
           'The service checks that the session key signs the challenge it issued, that the expiry and chain match, and that the proof verifies.')
replace_in(p, 'A statement is scoped to one session and the proof is reused for every request in that session, so after the first request each request costs a signature under the session key. This is what lets the protocol keep a Web2-style login while removing the proof-per-transaction cost of schemes such as zkAA [20]; it is also why revocation must work inside a session, which Section VI addresses.',
           'A statement is scoped to one session and the proof is reused for every request in that session: off chain each request costs a signature under the session key, and on chain each transaction from the user\'s account re-submits the same proof, which a contract verifies against the revocation root published on that chain. This keeps a Web2-style login while the address itself can act on chain, as in zkAA [20]; it is also why revocation must work inside a session, which Section VI addresses.')
set_text(find('2) We construct zk-Delegation'),
         '2) We construct zk-Delegation, a delegated-authentication protocol in which the AA signs a user-chosen commitment with a block-height expiry and learns neither the service nor the pseudonym nor the user\'s attributes, not even by reading the chain, while the service authenticates itself to the user through an AA-issued certificate, and in which every login carries a 2-of-2 trace tag that supports authorized opening of a disputed session.')
replace_in(find('3) We give a pseudonym proof'), 'let the proof be reused across requests.',
           'let the proof be reused across requests, and that the same proof authorizes transactions from a contract account located by the pseudonym.')
replace_in(find('4) We implement a prototype'), 'administrator- and user-initiated revocation, and authorized opening on a local chain,',
           'administrator- and user-initiated revocation, on-chain execution from pseudonym accounts, and authorized opening of a login or a transaction on a local chain,')
replace_in(find('The remainder of the paper is organized'), 'authorized opening, and a per-session agent-permission flag.',
           'authorized opening, a per-session agent-permission flag, and on-chain execution.')

# ---------------- III ----------------
p = find('zk-Delegation has five parties.')
replace_in(p, 'a small log contract to which the AA publishes revocation roots.',
           'a small log contract to which the AA publishes revocation roots and, per service, an account factory that realizes addresses as contract accounts (Section V-I).')
p = find('Table 1 lists the values each party holds.')
replace_in(p, 'the combined trace key pk_trace, and its own view of the revocation chain.',
           'the combined trace key pk_trace, the address of its account factory, and its own view of the revocation chain.')
t1 = d.tables[0]
set_row(t1, 'r_s', ['r_s', 'service-chosen login challenge, answered by the session key', 'per login', 'no', 'yes'])
set_row(t1, 'exptime', ['max_height', 'statement expiry as a block height, grid-quantized', 'yes', 'yes', 'yes'])
row_after(t1, 'max_height', ['allowAgent', 'per-session agent-permission flag', 'yes', 'yes', 'yes'])
p = find('The AA is honest-but-curious.')
replace_in(p, 'The network is assumed to be protected by TLS, and traffic-analysis attacks are out of scope.',
           'The network is assumed to be protected by TLS, and traffic-analysis attacks are out of scope. The chain is public: whatever a transaction carries, including the public inputs of its proof, is visible to the AA as well as to every service.')
set_text(find('G4 Service unobservability.'),
         'G4 Service unobservability. The AA does not learn which service a statement is issued for, nor the address the user will present, even by reading the chain.')

# ---------------- IV ----------------
set_text(find('The address is a name, not an account.'),
         'The address is first a name. The service stores it as the key of its local user record, exactly as it would store a subject identifier from an identity provider, and for a service that never touches a chain that is all it is. A service that does act on a chain deploys an account factory, and the name then locates a contract account at a deterministic address derived from PPID (Section V-I); the account holds assets and executes transactions, but only under the session key and the proof that a login carries. The AA cannot compute the name, so it cannot locate the account either.')
p = find('Nothing in the derivation is stored on a chain or issued by one.')
replace_in(p, 'rather than owners of it.',
           'rather than owners of it. The account of Section V-I is counterfactual: its address follows from the name and it exists on chain only once first used.')

# ---------------- V-A + 그림 ----------------
p = find('Fig. 1 shows one login.')
replace_in(p, 'and asks the AA for a statement over C and r_s (step 2).',
           'chooses whether an AI agent may act in this session (allowAgent), and asks the AA for a statement over C (step 2).')
replace_in(p, 'returns a signature over C, an expiry, the chain identifier, and r_s (step 3).',
           'returns a signature over C, an expiry given as a block height, the chain identifier, and the flag (step 3).')
replace_in(p, 'The service checks r_s against its own record, verifies the proof',
           'The service checks the session-key signature over r_s against its own challenge record, verifies the proof')
replace_in(p, 'Later requests in the session are signed under the session key (step 6).',
           'Later requests in the session are signed under the session key (step 6). If the service is a chain application, the wallet sends transactions from the user\'s pseudonym account, each carrying the session-key signature and the same proof, and the account contract verifies them against the root published on that chain (step 6\', Section V-I).')
replace_in(p, 'it sends the login transcript and its own partial decryption of the tag',
           'it sends the transcript of the login or of the transaction and its own partial decryption of the tag')
for q in d.paragraphs:
    if q._p.findall('.//' + qn('w:drawing')):
        for r in list(q.runs): r._r.getparent().remove(r._r)
        q.alignment = WD_ALIGN_PARAGRAPH.CENTER
        q.add_run().add_picture(FIG, width=Inches(6.5))
        break
set_text(find('FIGURE 1.'),
         'FIGURE 1. One login (steps 1–6), one on-chain transaction (step 6\'), and one authorized opening (steps 7–8) in zk-Delegation. Solid black arrows carry what the AA sees at login (C, chainid, max_height, allowAgent); dashed arrows carry values the AA never sees at login (arid, cert_s, pk_trace, PPID, pk_i, tag, attributes, r_s); dotted arrows are chain reads; the green arrow is public on the chain. Steps 7–8 happen only for a disputed session, after an operator approves; the AA holds nothing per login until then.')

# ---------------- V-C ----------------
p = find('To begin a login the service sends the wallet')
replace_in(p, '{arid, origin, cert_s, pk_trace, r_s}, where r_s', '{arid, origin, cert_s, pk_trace, factory, r_s}, where factory is the address of the service\'s account factory on the chain, empty for a service that does not act on chain, and r_s')
set_text(find('The challenge replaces the nonce of a classical challenge-response.'),
         'The challenge replaces the nonce of a classical challenge-response and is chosen by the service rather than the user, so that the service, and not the wallet, decides what a login is for. It is answered by a signature under the session key and is not embedded in the AA signature: a statement may later appear on a public chain inside a transaction, and a challenge the AA had seen at issuance would let the AA link that transaction to the login (Section VII-C). A statement is therefore bound to a session by its session key and its expiry, and single use of a login is enforced by the service consuming the challenge.')

# ---------------- V-D ----------------
p = find('All scalars lie in [0, 2^250); unused attribute slots are zero.')
replace_in(p, 'the tuple (uid, C_pt, chainid, r_s), a proof π_issue, and a signature sig_u = Sign_sk_u(Poseidon(C_pt.x, C_pt.y, chainid, r_s)).',
           'the tuple (uid, C_pt, chainid, allowAgent), a proof π_issue, and a signature sig_u = Sign_sk_u(Poseidon(D_req, C_pt.x, C_pt.y, chainid, allowAgent)) with D_req a domain tag.')
p = find('with uid, C_pt, and cm_u public.')
replace_in(p, 'sig_u under the stored pk_u, π_issue, and that no statement over the same C has been issued. It then sets exptime to the current time plus a configured lifetime (one hour in the prototype), computes C itself from C_pt, and signs',
           'sig_u under the stored pk_u, and π_issue. It then reads the head height of the chain named by chainid and sets max_height = ⌈(head + T) / G⌉·G, with a lifetime T of 300 blocks and a grid G of 100 blocks in the prototype, so that every statement issued within one grid window carries the same expiry (Section VII-C); it computes C itself from C_pt and signs')
set_text(find('σ_AA = Sign_AA(Poseidon(D_cred, C, exptime, chainid, r_s)),'), 'σ_AA = Sign_AA(Poseidon(D_cred, C, max_height, chainid, allowAgent)),')
p = find('an EdDSA signature over Baby Jubjub with Poseidon as the message hash')
replace_in(p, 'The AA records (uid, leaf(C), C, exptime) until expiry,', 'The AA records (uid, leaf(C), C, max_height, chainid) until the chain has passed max_height by a margin,')
replace_in(p, 'and returns (exptime, chainid, r_s, σ_AA); it keeps no other record of the login. The four values outside C',
           'and returns (max_height, chainid, allowAgent, σ_AA); it keeps no other record of the login. The three values outside C')
replace_in(p, 'AA attributes (the expiry, the chain, the challenge)', 'AA attributes (the expiry, the chain, the agent flag)')
set_text(find('The AA does not remember r_s.'),
         'The AA never sees the challenge. A replayed issuance request obtains a fresh signature over the same commitment; the AA then merely extends the expiry of its record for that C, and the statement remains bound to the same session key, which the replayer does not hold, so no service and no contract accepts anything made from it. The only per-login state in the system is the service\'s own challenge record, which is what allows the AA to hold nothing that links a user to a login once the statement has expired.')

# ---------------- V-E ----------------
p = find('The wallet derives PPID = Poseidon(uid, s_u, chainid, arid), draws a fresh')
replace_in(p, 'PPID, arid, pk_i, exptime, chainid, r_s, root,', 'PPID, arid, pk_i, max_height, chainid, allowAgent, root,')
t2 = d.tables[1]
set_row(t2, '1', ['1', 'EdDSA.Verify(pk_AA, Poseidon(D_cred, C, max_height, chainid, allowAgent), σ_AA) = 1', 'the AA issued a statement over C for this chain, expiry, and agent flag'])
set_row(t2, '5', ['5', 'r < 2^250,  c1 = r·B8,  K = r·pk_trace,  c2 = Poseidon(uid, arid) + Poseidon(K.x, K.y)', 'the tag encrypts a service-specific hash of this statement\'s uid under the certified combined key (verifiable encryption)'])
row_after(t2, '5', ['6', 'allowAgent ∈ {0, 1},  max_height < 2^64', 'the flag is a bit and the expiry fits the contract\'s block comparison'])
p = find('Condition 5 is a hashed ElGamal encryption')
replace_in(p, 'of uid under pk_trace, computed inside the circuit from the same uid signal that opens the commitment and derives the address. The service therefore knows that the ciphertext it stores, if ever opened, yields exactly the identity behind this statement, without learning anything about it now;',
           'of h = Poseidon(uid, arid) under pk_trace, computed inside the circuit from the same uid signal that opens the commitment and derives the address. The service therefore knows that the ciphertext it stores, if ever opened, yields a value that the AA\'s account registry resolves to exactly the identity behind this statement, and to nothing without that registry;')
p = find('The service compares pk_AA.x and pk_AA.y')
replace_in(p, 'since r = 0 would leave uid unmasked.', 'since r = 0 would leave the plaintext unmasked. The account contract of Section V-I performs the same comparisons.')

# ---------------- V-F ----------------
p = find('The wallet sends the service the proof, its public inputs, and a signature')
replace_in(p, 'It checks that the current time is at most exptime,', 'It checks that the block head it just read is at most max_height,')
replace_in(p, 'sessions[r_s] = {PPID, pk_i, exptime, root}', 'sessions[r_s] = {PPID, pk_i, max_height, allowAgent, root}')

# ---------------- V-G ----------------
p = find('Opening a disputed session takes three parties and three steps.')
replace_in(p, 'selects a transcript of the pseudonym in question from its login log,',
           'selects a transcript of the pseudonym in question, either from its login log or from a transaction of the user\'s account on the chain, whose calldata carries the same proof and public inputs,')
replace_in(p, 'over (arid, r_s, PPID, D_svc, timestamp).', 'over (arid, PPID, c1, D_svc, timestamp).')
replace_in(p, 'that its pk_AA is the AA\'s own key,', 'that its pk_AA is the AA\'s own key, that its chainid is one the AA serves,')
p = find('An operator approves or denies the pending request.')
replace_in(p, 'computes K = D_svc + x_AA·c1 and uid = c2 − Poseidon(K.x, K.y), checks that uid is a registered account, and records the result in a permanent audit log;',
           'computes K = D_svc + x_AA·c1 and h = c2 − Poseidon(K.x, K.y), looks up the registered uid with Poseidon(uid, arid) = h, and records the result, together with the statement\'s agent flag, in a permanent audit log;')
replace_in(p, 'A request for a session that is already pending or approved returns the existing record, while a failed or denied one may be requested again, since a wrong partial decryption must be correctable.',
           'A request for a tag that is already pending or has been opened returns the existing record, while one whose lookup found no account or that was denied may be requested again, since a wrong partial decryption must be correctable.')
p = find('Verifying the transcript before opening is what confines')
replace_in(p, 'The AA stores nothing per login;', 'A transaction on the chain is such a transcript too, so a service can ask about a transaction it never verified off chain. The AA stores nothing per login;')

# ---------------- V-H + 신설 V-I ----------------
p = find('A session may be driven by an AI agent')
replace_in(p, 'The flag costs one field element in the signature message and one equality in the circuit. The prototype does not yet implement it; Section IX lists it among the extensions.',
           'The flag costs one field element in the signature message and one boolean constraint in the circuit; on chain the account contract emits it with every transaction, so the permission under which an agent acted is on the public record.')
h = clone_after(p, 'I. ON-CHAIN EXECUTION FROM THE ADDRESS', template=SUB_T)
i1 = clone_after(h, 'A service that acts on a chain deploys, once, an account factory bound to its identifier, the AA key, its combined trace key, the revocation log, and a root-age bound MAX_ROOT_AGE; the wallet learns the factory\'s address at login. The user\'s account is the contract the factory creates at CREATE2(factory, PPID): its address is known before anything is deployed, it can receive assets counterfactually, and the first transaction deploys it. Because PPID contains chainid and arid, one user has a different account at every service and on every chain, and because the AA never learns PPID, the AA cannot locate the account.', template=PARA_T)
i2 = clone_after(i1, 'A transaction is execute(payload, σ, π, public inputs), submitted by any relayer, since the authority is in the signature and the proof. The wallet signs the payload under sk_i together with the chain identifier, the account address, and the account\'s nonce, so that neither another chain nor another account can reuse the signature; the contract requires a low-s signature with v ∈ {27, 28}, so that a relayer cannot change the transaction hash by malleating it. The contract checks, in this order, the nonce; the signature against pk_i from the public inputs; that PPID, arid, and chainid equal its own; that pk_AA and pk_trace equal the factory\'s; that allowAgent is a bit and c1 is not the identity point; that root equals the log\'s current root and that the log\'s last publication is at most MAX_ROOT_AGE blocks old; that the block number is at most max_height; and finally the Groth16 argument. It then increments the nonce, performs the call, and emits the outcome together with pk_i, max_height, allowAgent, and the tag, so that a transaction is a transcript in the sense of Section V-G. These are the service\'s checks of Section V-F in the same order, with the service\'s challenge replaced by the account\'s nonce.', template=PARA_T)
i3 = clone_after(i2, 'The proof is the session\'s proof. The wallet re-submits it with every transaction while the root is unchanged and re-proves when the root advances, exactly as for an off-chain re-validation; verification, however, is paid at every transaction, about 390,000 gas (Section VIII-C), because a contract cannot cache a verified session without a further trust assumption. A transaction mined in the same window as a root publication fails with a stale root and burns its gas; the wallet re-proves and re-submits. A contract cannot tell how old the root it holds is, so the log records the block of its last publication and the AA republishes an unchanged root every H blocks, a heartbeat, and a withheld or absent publication stops the accounts after MAX_ROOT_AGE blocks rather than never; the prototype uses H = 50 and MAX_ROOT_AGE = 100.', template=PARA_T)
clone_after(i3, 'Off-chain login and on-chain execution share one circuit and one statement. What the chain adds is publicity: the public inputs of every transaction are readable by the AA. Section VII-C shows that this gives the AA nothing beyond the chain identifier it already knows and a coarse expiry.', template=PARA_T)

# ---------------- VI ----------------
p = find('The AA publishes the tree root through a log contract')
replace_in(p, 'with two state variables, the current root and the last epoch, and one function,',
           'with three state variables, the current root, the last epoch, and the block of the last publication, and one function,')
p = find('publishRoot(newRoot, epoch, leaves[], sig):')
replace_in(p, 'root := newRoot;  lastEpoch := epoch.', 'root := newRoot;  lastEpoch := epoch;  lastPublished := block.number.')
p = find('The newly inserted leaves travel as calldata')
replace_in(p, 'The prototype publishes on an administrator\'s command.',
           'The prototype publishes on an administrator\'s command, and a publication with no leaves is allowed: it re-signs the unchanged root under a new epoch and serves as the heartbeat that the account contracts of Section V-I require.')
p = find('Services read the root and the block head directly from the chain')
replace_in(p, 'since it sits inside the signed statement.',
           'since it sits inside the signed statement. The account contract applies the same rule with the block number in place of the clock: it accepts only the log\'s current root and refuses if the last publication is older than MAX_ROOT_AGE blocks.')
p = find('This is where the liveness goal G9 is met.')
replace_in(p, 'but every session in progress continues.',
           'but every session in progress continues; on chain, accounts continue until the heartbeat lapses and stop MAX_ROOT_AGE blocks later, which is the price of a verifier that cannot read a clock.')

# ---------------- VII ----------------
p = find('A service sees PPID, arid, pk_i, exptime, chainid, r_s, the root')
replace_in(p, 'A service sees PPID, arid, pk_i, exptime, chainid, r_s, the root,', 'A service sees PPID, arid, pk_i, max_height, chainid, allowAgent, the root,')
replace_in(p, 'pk_i is fresh per session and r_s is chosen by the service itself, so neither links', 'pk_i is fresh per session and r_s never enters the proof, so neither links')
replace_in(p, 'The same holds for two services on different chains.',
           'The same holds for two services on different chains. On chain the same public inputs are visible to everyone and the account address is a function of PPID; both link exactly what PPID links and nothing more.')
p = find('The AA receives uid, C_pt, chainid, r_s, π_issue, and sig_u.')
replace_in(p, 'The AA receives uid, C_pt, chainid, r_s, π_issue, and sig_u.', 'The AA receives (uid, C_pt, chainid, allowAgent), π_issue, and sig_u.')
replace_in(p, 'The challenge r_s is uniformly random and chosen by the service, so its value carries no information about which service chose it. ', '')
clone_after(p, 'The chain is a second channel. Every public input of a transaction is readable by the AA, so nothing the AA saw at issuance may appear there in a form it can match: the commitment stays inside the circuit, the challenge is not signed, and the account address is a function of PPID, which the AA cannot compute. What remains matchable is (chainid, allowAgent, max_height). The first two carry a few bits; max_height is quantized to a grid, so every statement issued within one window of G blocks carries the same value, and the AA\'s issuance log narrows a transaction to the users issued in that window. This is the price of the chain: the anonymity set of a transaction against the AA is the set of statements issued in its window, large in a deployment and possibly one in a demonstration. Widening G enlarges the set at the cost of expiry precision.', template=PARA_T)
set_text(find('A statement is accepted only if the r_s in its public inputs'),
         'Off chain, a login is accepted only if σ is a signature under pk_i over a challenge the service issued and has not yet consumed, and the challenge is consumed before verification. Presenting the same login twice fails at the first check. Presenting a statement obtained for one service to another fails because arid is a public input compared with the verifier\'s own identifier, and because the AA signature covers C, which commits to arid. Presenting a statement on another chain fails because chainid is signed and compared. Re-submitting an old issuance request to the AA yields a statement bound to the same session key, which the replayer does not hold, and the AA merely extends its record of C. On chain, replay is excluded by the account\'s nonce, which the session-key signature covers together with the chain and the account address; a statement is meant to be reused for many transactions. Session requests are signed under sk_i, which the wallet holds and C commits to; an attacker without sk_i cannot produce them. Off-chain requests carry no counter, so a captured (r_s, body, signature) can be replayed until the session expires or the root changes; this is a limitation for non-idempotent requests and is discussed in Section IX.')
p = find('Once leaf(C) is in the tree and the root is published')
replace_in(p, 'which the ten-minute bound caps.', 'which the ten-minute bound caps; on chain it is dead from that block, since the account contract compares against the log in the same state.')
p = find('The tag (c1, c2) is a hashed ElGamal ciphertext')
replace_in(p, 'guarantees that what is opened is the identity behind that very statement,', 'guarantees that what is opened is Poseidon(uid, arid) for the identity behind that very statement, which only the AA\'s registry resolves to uid,')

# ---------------- VIII ----------------
p = find('The prototype consists of four Node.js processes and one contract.')
replace_in(p, 'The prototype consists of four Node.js processes and one contract.',
           'The prototype consists of four Node.js processes and four contracts: the revocation log, the Groth16 verifier generated from the circuit, a per-service account factory, and the account contract it creates.')
replace_in(p, 'The revocation log is a Solidity contract deployed to a local Hardhat node.',
           'The contracts are Solidity 0.8.24 deployed to a local Hardhat node; the service deploys the verifier and its factory at start, and the wallet submits transactions through a relayer account of the node.')
p = find('Table 3 gives the size of the pseudonym circuit')
replace_in(p, 'Times are medians of ten runs', 'Times are medians of five runs')
t3 = d.tables[2]
set_row(t3, 'R1CS constraints', ['R1CS constraints', '25,560'])
set_row(t3, 'Proving key (zkey) / witness generator (wasm)', ['Proving key (zkey) / witness generator (wasm)', '15.5 MB / 3.8 MB'])
set_row(t3, 'Groth16 proving time (min – max)', ['Groth16 proving time (median)', '863 ms'])
set_row(t3, 'Groth16 verification time', ['Groth16 verification time (off chain)', '13.6 ms'])
set_row(t3, 'Statement lifetime / challenge lifetime', ['Statement lifetime (T, grid G) / challenge lifetime', '300 blocks, G = 100 / 120 s'])
set_row(t3, 'Chain head freshness bound at the service', ['Root freshness bound: service / account contract', '600 s / MAX_ROOT_AGE = 100 blocks, heartbeat every 50'])
row_after(t3, 'Groth16 verification time (off chain)', ['execute() gas on chain (verification + call)', '387,682'])
p = find('Two earlier versions of the circuit give the cost of each addition.')
replace_in(p, 'brought it to 25,505, about 15 percent more, with proving time within the run-to-run variation of the previous version.',
           'brought it to 25,505, about 15 percent more, with proving time within the run-to-run variation of the previous version; replacing the wall-clock expiry and the public challenge by a block height and an agent flag and hashing the tag plaintext brought it to 25,560, since one Poseidon call was added while a 250-bit range check on the challenge became a 64-bit check on the height.')
p = find('Per-login cost is one issuance round trip')
replace_in(p, 'since a window without revocations publishes nothing.',
           'since a window without revocations publishes nothing. An on-chain transaction costs the same proof, reused, plus about 390,000 gas for verification and execution, roughly fifteen times a plain transfer; this is the cost of verifying at every transaction that Section V-I accepts.')
p = find('An end-to-end suite runs the AA, wallet agent, service, and chain in isolation')
replace_in(p, 'The circuit suite checks the relation against forged inputs,',
           'The contract suite deploys the log, verifier, and factory on an in-process chain and checks the account contract case by case: execution with value transfer and the emitted tag; re-use of one proof for a second transaction; nonce replay; signatures under another key, for another account, or malleated to a high s; public inputs with another PPID, arid, chain, AA key, or trace key; an agent flag of 2; a tag with the identity point; a stale root after a publication; a root older than MAX_ROOT_AGE, and recovery after a heartbeat; an expired height; a corrupted proof; and a failed inner call that still consumes the nonce. The end-to-end suite adds account deployment on the first transaction, a second transaction with the cached proof, a transaction refused after revocation, and an opening requested from a transaction hash rather than the login log, with the agent flag reported in the result. The circuit suite checks the relation against forged inputs,')
replace_in(p, 'a revoked leaf, and a tag whose ciphertext, key, or randomness has been altered.',
           'a revoked leaf, an agent flag that is not a bit, and a tag whose ciphertext, key, or randomness has been altered.')
p = find('Publication cost was measured on the local Hardhat node')
replace_in(p, 'since publication happens a few times a day at most.',
           'since publication happens a few times a day at most. An execute() call with a valid proof consumed 387,682 gas, the bulk of it the pairing check of the Groth16 verifier; a heartbeat is a publication with no leaves and costs the base of roughly 40,000 gas.')

# ---------------- IX ----------------
p = find('The AA is on the login path.')
replace_in(p, 'sessions in progress are unaffected.', 'sessions in progress are unaffected off chain, and on chain they continue until the heartbeat lapses and stop MAX_ROOT_AGE blocks later.')
set_text(find('The AA sees the chain identifier.'),
         'The AA sees the chain identifier and, through the chain, the quantized expiry of every transaction (Section VII-C). Where its allow list has several entries it learns which chain the user is using, and a small deployment gives a transaction a small anonymity set against the AA.')
p = find('Attributes are hidden but not attested.')
replace_in(p, 'are the next step, as is the per-session agent-permission flag of Section V-H, which is specified but not implemented in the prototype.', 'are the next step.')
set_text(find('Expiry is wall-clock.'),
         'Expiry is a block height. A service or contract that reads a lagging head accepts a statement for that lag past what the AA considers expired; the AA keeps issuance records for fifty blocks past max_height so that account revocation still covers such statements, and a larger lag reopens the gap. On chain every transaction pays for proof verification, a transaction mined in the same window as a root publication fails and burns its gas, and a service chooses the factory that realizes its users\' accounts, so a service that redeploys its factory strands the assets at the old addresses. The prototype\'s wallet asks for no confirmation before a transaction, and its relayer sees every transaction it submits.')
p = find('The commitment is computationally rather than perfectly hiding')
replace_in(p, 'the session key is encoded as a 160-bit address, an inheritance from an on-chain design that no longer applies and could be tightened;',
           'the session key is encoded as a 160-bit address so that the account contract can check it with ecrecover, which leaves it 96 bits below the field;')

# ---------------- X ----------------
p = find('This paper separated two things that Web3 services conflate')
replace_in(p, 'gives every service a stable, unique, and unlinkable name for each user on each chain, with no registry and no on-chain state.',
           'gives every service a stable, unique, and unlinkable name for each user on each chain, with no registry; on a chain the same name locates a contract account that acts under the login\'s proof, so the address is a name first and an account only where a service needs one.')
replace_in(p, 'and embedding a service-chosen challenge in the signed statement makes each statement single-use without a second round of signatures.',
           'and keeping the service\'s challenge out of the signed statement keeps the authority from recognizing its own statements when they reappear in public transactions.')
p = find('The prototype shows that the whole flow fits in one Groth16 argument')
replace_in(p, 'with a per-request cost of a single signature. Sessions are the reason revocation exists here at all: a scheme that proves at every transaction, like zkAA, needs no revocation and pays for that with a proof per transaction.',
           'with a per-request cost of a single signature off chain and one verification per transaction on chain, at about 390,000 gas. Sessions are the reason revocation exists here at all: a scheme that proves a fresh statement at every transaction, like zkAA, needs no revocation and pays for that with an issuance per transaction; reusing one statement across a session moves that cost to a revocation root the chain publishes.')
replace_in(p, 'Future work is to add attribute predicate proofs over the committed slots,',
           'Future work is to add attribute predicate proofs over the committed slots, to constrain r ≠ 0 in the circuit rather than in the verifiers, to let a contract cache a verified session so that verification is paid once per session rather than per transaction,')

d.save(DST)
print('saved', DST)
