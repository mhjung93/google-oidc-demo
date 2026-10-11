# PairCT 초안 final46 -> final47. 2026-09-06 리뷰 반영.
#
# 원칙: 기존 문단은 통째로 갈아끼우지 않고, 사실과 다른 문장만 바꾼다. 새 절은
# 기존 스타일(PARA / Normal 소제목)을 그대로 따른다.
import copy, sys
from docx import Document

SRC = 'documents/PairCT_research_article_20260706_092133_with_figures_final46.docx'
OUT = 'documents/PairCT_research_article_20260706_092133_with_figures_final47.docx'
d = Document(SRC)
P = d.paragraphs

def set_text(idx, text):
    """문단 텍스트를 통째로 바꾸되 첫 run의 서식을 유지한다."""
    p = P[idx]
    if not p.runs:
        p.text = text
        return
    p.runs[0].text = text
    for r in p.runs[1:]:
        r.text = ''

def replace_in(idx, old, new, label):
    p = P[idx]
    if old not in p.text:
        print(f'  MISS {label}'); return False
    set_text(idx, p.text.replace(old, new, 1))
    print(f'  OK   {label}')
    return True

def insert_before(idx, blocks):
    """blocks = [(style, text), ...] 를 P[idx] 앞에 순서대로 넣는다."""
    anchor = P[idx]
    for style, text in blocks:
        anchor.insert_paragraph_before(text, style=style)

print('== 텍스트 정정 ==')

# (6) client.js에 uid가 없다
replace_in(191,
  'The hardcoded value uid = 12345 in the client-side demo state represents the result of that prior verified binding',
  'The demo account table in the IdP (uid = 12345 for the demo user) represents the result of that prior verified binding',
  '191 uid=12345')

# (5) 실측값 갱신
old_warm = P[202].text
new_warm = (
 'Warm-state prototype measurements were collected over 10 runs per circuit after initialization. '
 'The mean proof-generation-path duration (sample standard deviation) was 201.30 ms (117.17 ms) for pi_arid_i, '
 '85.00 ms (16.85 ms) for pi_ppid, and 507.20 ms (12.60 ms) for pi_pk_i. The pi_pk_i figure reflects the '
 'revocation-enabled circuit described in Section G, whose relation is substantially larger than the original '
 'key-binding-only relation (13,905 non-linear constraints versus 4,820); the earlier 239.20 ms figure measured '
 'that smaller circuit and no longer applies. Summing the three per-circuit means gives approximately 793.5 ms '
 'under sequential execution. This is a sum of means rather than a per-run sum, so it does not carry a run-level '
 'distribution; it is a circuit-level prototype metric, not an end-to-end service-login latency. '
 'Only the warmed measurements are reported; one-time initialization behavior is excluded (cold-start pi_pk_i was '
 '1,315.8 ms).')
set_text(202, new_warm); print('  OK   202 측정값')

# (5) 크기/공개입력 갱신
replace_in(204,
  'the five public inputs for pi_pk_i occupied 160 bytes, giving 416 bytes of total calldata',
  'the nine public inputs for pi_pk_i occupied 288 bytes, giving 544 bytes of proof-and-signal calldata (the '
  'on-chain revocation witness of Section G adds a further 640 bytes of Merkle siblings)',
  '204 public inputs')

# (6) PPIDWallet 서술 갱신
replace_in(209,
  'pi_pk_i must verify on-chain against the public inputs pk_i, pk_IdP_x, pk_IdP_y, ppid, and max_height',
  'pi_pk_i must verify on-chain against the public inputs pk_i, pk_IdP_x, pk_IdP_y, ppid, max_height, and the '
  'revocation-subtree roots and shard indices of Section G',
  '209 public inputs 목록')
replace_in(209,
  'Recovering the signer from the payload hash and the supplied signature must yield exactly pk_i',
  'The payload hash is domain-separated by the chain identifier and the wallet address, so a signature cannot be '
  'replayed onto another chain or wallet; recovering the signer from it must yield exactly pk_i, and a zero '
  'recovery result is rejected outright',
  '209 도메인 분리')

# (6) 곡선 조정은 해결됐다
replace_in(210,
  'Deriving pk_i’s underlying signing key from a persistent k_user rather than per-session randomness, and '
  'reconciling the secp256k1 curve required for on-chain ecrecover with the Baby Jubjub curve used inside the '
  'pi_pk_i relation, remain open prototype questions.',
  'Deriving pk_i’s underlying signing key from a persistent k_user rather than per-session randomness remains '
  'an open prototype question. The two curves coexist without reconciliation: the relation verifies only the '
  'IdP’s EdDSA-Poseidon signature over Baby Jubjub, while pk_i is the secp256k1-derived Ethereum address that '
  'ecrecover returns, so the contract compares it directly.',
  '210 곡선')
# 그래도 안 되면 다른 표현 시도
if 'reconciling the secp256k1 curve' in P[210].text:
    replace_in(210, 'reconciling the secp256k1 curve required for on-chain ecrecover with the Baby Jubjub curve used inside the pi_pk_i relation, remain open prototype questions',
               'remains an open prototype question; the two curves coexist without reconciliation, because the relation '
               'verifies only the IdP’s Baby Jubjub EdDSA-Poseidon signature while pk_i is the secp256k1-derived '
               'address that ecrecover returns', '210 곡선(대체)')

# (4) 온체인 게시가 가정이 아니라 현재형이다
replace_in(218,
  'Transcript-artifact confidentiality is central to the deployment model. If a service wants to publish PairCT '
  'artifacts on-chain, it must add another privacy layer or accept that IdP-side correlation may become possible.',
  'Transcript-artifact confidentiality is central to the deployment model, and the address-abstraction layer of '
  'Section VI-C already places some artifacts on-chain by construction: every PPIDWallet execution publishes pk_i, '
  'max_height, the PPID-derived wallet address, and the account shard index of Section G. Services that publish '
  'further PairCT artifacts must add another privacy layer or accept that IdP-side correlation may become possible.',
  '218 온체인 전제')

# (1) 새 상시 신뢰 주체가 생겼다
replace_in(227,
  "PairCT's conditional opening instead reuses the existing IdP's and RP's own retained records without "
  'introducing a new standing role, while still hiding the RP identifier from the IdP during ordinary authentication.',
  "PairCT's conditional opening instead reuses the existing IdP's and RP's own retained records without "
  'introducing a new standing role for opening, while still hiding the RP identifier from the IdP during ordinary '
  'authentication. Revocation, by contrast, does introduce a standing on-chain publisher role: the account '
  'authorized to update the revocation registry can withhold an update, republish a superseded root and thereby '
  'reinstate revoked credentials, or publish an unusable root and block every wallet. Section G states this '
  'explicitly rather than folding it into the opening path.',
  '227 상시 역할')

# (2) 폐기 메커니즘과의 차별화 문장을 정정
set_text(230,
 'PairCT differs from anonymous-credential opening mechanisms and public-chain trace tags in how accountability is '
 'reached: it joins retained authentication records instead of embedding a tracing tag in a credential or requiring '
 'a credential-opening authority to decrypt an identity from a presentation. The resulting accountability path is '
 'transcript-based: the RP supplies the accepted session transcript, the IdP locates the corresponding issuance '
 'record, and an external authorization process defines when the record join is permitted. Revocation is a separate '
 'mechanism (Section G) and is closer to the accumulator-based literature. BAAR [20] is the nearest recent design: '
 'it also uses a Merkle accumulator with an off-chain verifier and an on-chain root, but it proves membership in the '
 'set of valid credentials and transmits the credential commitment and its witness in the clear at every '
 'presentation, so a verifier sees a stable per-credential identifier across sessions. PairCT instead proves '
 'non-membership in a revocation set inside the Groth16 relation, so no per-credential identifier leaves the wallet '
 'and only a root is public; the cost is that the verifier must be given a fresh root, which is why the publication '
 'and grace-window discipline of Section G exists at all.')
print('  OK   230 폐기 차별화')

print('== 신규 절 ==')
d.save(OUT)
print('1차 저장:', OUT)
