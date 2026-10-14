pragma circom 2.0.0;

include "poseidon.circom";
include "bitify.circom";
include "escalarmulfix.circom";
include "babyjub.circom";

// Mode 3 커밋 — 교과서 Pedersen 벡터 커밋 둘(2026-09-21 자격증명 이중 구조).
// 설계: docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md §3.1·§3.2
// 속성 6슬롯(최초 4슬롯 설계: docs/superpowers/specs/2026-09-14-mode3-attribute-credential-design.md §3/§5,
// 4→6 로 늘린 V9: docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md §5.3)
// 스킴 선택(Pedersen vs Poseidon) 근거: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §4.1, §11
//
//   C_u = uid·G_UID + s_u·G_SU + attr₀·G_ATTR0 + … + attr₅·G_ATTR5 + blind_u·H   (사용자당 하나)
//   C_s = pk_i·G_PKI + max_height·G_EXP + r_s·G_RS + r_rp·H (세션마다, V11)
//
//   uid     — 계정 식별자. PPID 유도에 쓰인다
//   s_u     — 사용자 비밀. IdP 가 PPID를 열거하지 못하게 막는다 (Mode 2의 salt)
//   attrs   — 속성 6슬롯. IdP 는 값을 모른다
//   blind_u — C_u 블라인딩. IdP 가 자기가 아는 uid 로 C_u 를 재계산해 대조하는 것을 막는다
//   pk_i       — 세션키. 이 π가 이 서명자의 것임을 묶는다
//   max_height — 세션 만료(블록 높이). V11 에서 토큰 메시지 대신 C_s 에 묶인다(D5)
//   r_s        — 세션 nonce(RP 챌린지, 250비트). RP 가 1회 소비해 재전송을 막는다
//   r_rp       — C_s 블라인딩. IdP 가 공개된 (pk_i, max_height, r_s)로 C_s 를 재계산해 대조하는 것을 막고, auid_s·arid_s 와도 같은 값을 묶는다(D7)
//
// 왜 교과서 형태인가. circomlib 의 Pedersen(n) 은 비트를 4비트 창으로 잘라 부호 반전을 섞는
// 인코딩이라, 그 위에서 발급 시 시그마 프로토콜(π_u, §3.5 — V5~V10. V11 부터는 Groth16 회로 π_IdP 로 대체됐다)을 짜면
// 이웃 스칼라와 세그먼트를 공유하는 문제가 생긴다. 스칼라마다 생성원을 따로 두면 PoK 가 교과서 그대로다.
//
// 스칼라 상한 2^250. baby jubjub 소수 부분군 위수 r 은 251비트(≈2^250.6)라 2^250 < r.
// 이 검사가 없으면 e 와 e+r 이 같은 점을 만들어 binding 이 깨진다 — 한 C_u 를 두 s_u 로
// 열어 PPID 두 개를 얻는 Sybil 이 가능해진다. lib/mode3_credential.js 도 같은 상한을 지킨다.
//
// 생성원은 circomlib pedersen.circom 의 NUMS 점 BASE[0..12]. 서로의 이산로그를 아무도 모른다.
// circomlib 표는 index 0..9 까지라, index 10(attr5) 은 표에는 없고 circomlibjs getBasePoint('blake', 10) 으로 계산한 값이다(lib/mode3_credential.js 와 같다).
// 2026-09-10 circomlibjs 로 (그때는 9개였던) 생성원 전부의 inCurve·inSubgroup 을 확인했다. V9 에서 속성이
// 6슬롯으로 늘며 추가된 attr4·attr5(index 9·10), V11(2026-10-12)에서 C_s 에 추가된 exp·rs(index 11·12) 까지
// 지금은 13개 생성원 전부를 tests/test_mode3_commit_scheme.mjs 가 곡선·부분군(inCurve·inSubgroup)으로 확인하고,
// circomlibjs getBasePoint 와의 문자열 대조(생성원이 바로 그 값인지)는 tests/test_mode3_credential_v11.js(32~42행)가
// 13개 전부 deepEqual 로 자동 확인한다 — 더 이상 수기 대조에만 의존하지 않는다. 두
// 커밋이 생성원을 나눠 쓴다(H 만 공유) — 각 커밋의 binding 은 자기 항의 생성원만으로 성립한다.

// 2026-09-21 자격증명 이중 구조(설계 §3.1). 사용자 자격증명 커밋 — 사용자당 하나.
//   C_u = uid·G_UID + s_u·G_SU + attr₀·G_ATTR0 + … + attr₅·G_ATTR5 + blind_u·H
// pk_i 항이 없다(세션 커밋에). arid 는 V11 부터 C_s 에도 없다 — 토큰의 arid_s(별도 해시)로 옮겨갔다(D5). 생성원·순서는
// lib/mode3_credential.js userCommit 과 같다.
template CommitUser() {
    signal input uid;
    signal input s_u;
    signal input blind_u;
    signal input attrs[6];
    signal output Cx;
    signal output Cy;

    var N = 250;
    var NA = 64;   // 속성은 64비트 정수(2026-09-22 선택 공개 §4.1) — pi_cred 의 LessEqThan(64) 전제. 다른 스칼라는 250비트 그대로
    var G_UID[2]   = [10457101036533406547632367118273992217979173478358440826365724437999023779287,
                      19824078218392094440610104313265183977899662750282163392862422243483260492317];
    var G_SU[2]    = [5802099305472655231388284418920769829666717045250560929368476121199858275951,
                      5980429700218124965372158798884772646841287887664001482443826541541529227896];
    var G_ATTR[6][2] = [
        [1487999857809287756929114517587739322941449154962237464737694709326309567994,
         14017256862867289575056460215526364897734808720610101650676790868051368668003],
        [14618644331049802168996997831720384953259095788558646464435263343433563860015,
         13115243279999696210147231297848654998887864576952244320558158620692603342236],
        [6814338563135591367010655964669793483652536871717891893032616415581401894627,
         13660303521961041205824633772157003587453809761793065294055279768121314853695],
        [3571615583211663069428808372184817973703476260057504149923239576077102575715,
         11981351099832644138306422070127357074117642951423551606012551622164230222506],
        [18597552580465440374022635246985743886550544261632147935254624835147509493269,
         6753322320275422086923032033899357299485124665258735666995435957890214041481],
        [16246587114701919230396141881596483298016809673932703125119295166936827150109,
         2008259283001433748666303325888612438000671916354550248296035439458960131795]
    ];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bUid   = Num2Bits(N);  bUid.in   <== uid;
    component bSu    = Num2Bits(N);  bSu.in    <== s_u;
    component bBlind = Num2Bits(N);  bBlind.in <== blind_u;
    component bAttr[6];
    for (var j = 0; j < 6; j++) { bAttr[j] = Num2Bits(NA); bAttr[j].in <== attrs[j]; }
    component mUid   = EscalarMulFix(N, G_UID);
    component mSu    = EscalarMulFix(N, G_SU);
    component mBlind = EscalarMulFix(N, H_BLIND);
    component mAttr[6];
    for (var j = 0; j < 6; j++) mAttr[j] = EscalarMulFix(NA, G_ATTR[j]);
    for (var i = 0; i < N; i++) {
        mUid.e[i]   <== bUid.out[i];
        mSu.e[i]    <== bSu.out[i];
        mBlind.e[i] <== bBlind.out[i];
    }
    for (var i = 0; i < NA; i++) for (var j = 0; j < 6; j++) mAttr[j].e[i] <== bAttr[j].out[i];
    // 덧셈 순서: uid + s_u + attr0..5 + blind_u (JS userCommit 과 같다).
    component a1 = BabyAdd();
    a1.x1 <== mUid.out[0];  a1.y1 <== mUid.out[1];
    a1.x2 <== mSu.out[0];   a1.y2 <== mSu.out[1];
    component aAttr[6];
    for (var j = 0; j < 6; j++) {
        aAttr[j] = BabyAdd();
        if (j == 0) { aAttr[j].x1 <== a1.xout; aAttr[j].y1 <== a1.yout; }
        else        { aAttr[j].x1 <== aAttr[j-1].xout; aAttr[j].y1 <== aAttr[j-1].yout; }
        aAttr[j].x2 <== mAttr[j].out[0]; aAttr[j].y2 <== mAttr[j].out[1];
    }
    component a2 = BabyAdd();
    a2.x1 <== aAttr[5].xout; a2.y1 <== aAttr[5].yout;
    a2.x2 <== mBlind.out[0]; a2.y2 <== mBlind.out[1];
    Cx <== a2.xout;
    Cy <== a2.yout;
}

// V11(2026-10-12 §3.2·D5): 세션 커밋 — 로그인마다.  C_s = pk_i·G_PKI + max_height·G_EXP + r_s·G_RS + r_rp·H
//   pk_i 160비트(세션키 주소), max_height 64비트(만료 블록), r_s·r_rp 250비트(RP 챌린지·RP 난수). lib/mode3_credential.js sessionCommit 과 같다.
//   arid 는 빠졌다 — RP 바인딩은 토큰의 arid_s·auid_s(둘 다 r_rp 로 묶인다)가 맡는다. 블라인딩은 RP 가 준 r_rp:
//   RP 는 C_s 의 열림값을 모두 알고(심층 방어), IdP 는 r_rp 를 몰라 C_s 를 열지 못한다.
//   G_EXP·G_RS 는 circomlibjs getBasePoint('blake', 11)·(12) — 2026-10-12 inCurve·inSubgroup 확인(tests/test_mode3_credential_v11.js 가 글자 일치를 검사).
template CommitSessionV11() {
    signal input pk_i;
    signal input max_height;
    signal input r_s;
    signal input r_rp;
    signal output Cx;
    signal output Cy;

    var N = 250;
    var NP = 160;   // pk_i 는 이더리움 주소 — pi_cred 의 옛 Num2Bits(160) 을 여기로 옮겼다
    var NH = 64;    // max_height — 토큰 메시지에서 빠진 대신 여기서 범위가 잡힌다
    var G_PKI[2]   = [7107336197374528537877327281242680114152313102022415488494307685842428166594,
                      2857869773864086953506483169737724679646433914307247183624878062391496185654];
    var G_EXP[2]   = [15213743939064641260146023541489016041952046087348720940641996397552589095764,
                      12626463709848357735089296069583194130598330177778437327210365765201604869873];
    var G_RS[2]    = [3794846596710804728427490183747125272829051653079153052879417268450674798099,
                      21842435477255044883863745269531290629657425422620774125328061317110773122799];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bPki = Num2Bits(NP);  bPki.in <== pk_i;
    component bMh  = Num2Bits(NH);  bMh.in  <== max_height;
    component bRs  = Num2Bits(N);   bRs.in  <== r_s;
    component bRrp = Num2Bits(N);   bRrp.in <== r_rp;
    component mPki = EscalarMulFix(NP, G_PKI);
    component mMh  = EscalarMulFix(NH, G_EXP);
    component mRs  = EscalarMulFix(N, G_RS);
    component mRrp = EscalarMulFix(N, H_BLIND);
    for (var i = 0; i < NP; i++) mPki.e[i] <== bPki.out[i];
    for (var i = 0; i < NH; i++) mMh.e[i]  <== bMh.out[i];
    for (var i = 0; i < N; i++) { mRs.e[i] <== bRs.out[i]; mRrp.e[i] <== bRrp.out[i]; }
    // 덧셈 순서: pk_i + max_height + r_s + r_rp (JS sessionCommit 과 같다).
    component a1 = BabyAdd();
    a1.x1 <== mPki.out[0]; a1.y1 <== mPki.out[1];
    a1.x2 <== mMh.out[0];  a1.y2 <== mMh.out[1];
    component a2 = BabyAdd();
    a2.x1 <== a1.xout;     a2.y1 <== a1.yout;
    a2.x2 <== mRs.out[0];  a2.y2 <== mRs.out[1];
    component a3 = BabyAdd();
    a3.x1 <== a2.xout;     a3.y1 <== a2.yout;
    a3.x2 <== mRrp.out[0]; a3.y2 <== mRrp.out[1];
    Cx <== a3.xout;
    Cy <== a3.yout;
}
