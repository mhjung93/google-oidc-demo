# ZKP 전체 목록과 실측 (2026-09-21, Mode 3 자격증명 이중 구조 V5)

2026-09-18 판(`results/zkp_inventory_20260918.md`)에서 Mode 3 행만 바뀌었다: π_issue(세션마다) → π_u(사용자 자격증명, 속성 바뀔 때만), pi_cred V4 → V5(커밋 둘). **세션 발급(`/cia/issue`)에는 ZKP 가 없다** — Cf_u 조회 + sig_u 만. Mode 1·2 행은 이번에 다시 잰 값이다(같은 스크립트, 같은 회로).

측정 환경: AMD Ryzen 9 5950X(16코어), Node v22.20.0, snarkjs(Groth16, BN254), WASM witness 생성기. N=10, 중앙값 (최소–최대) ms.
스크립트: `scripts/bench_zkp_inventory.mjs`(Mode 3·v4 삽입·pi_uid), `scripts/bench_mode2_zkp_all.mjs`(Mode 2 세 회로, 같은 크레덴셜, CSV `results/mode2_zkp_all_20260918.csv` — Mode 2 세 회로는 이번에 다시 재지 않아 2026-09-18 값 그대로), `scripts/bench_pi_cred.mjs`.
증명 생성은 지갑(브라우저 아님) 기준이고, 검증은 서비스/IdP/CIA 프로세스 기준이다. 온체인 검증 가스는 `results/mode3_onchain_bench_20260921.md`.

## 1. 목록 — 입력·출력·조건

| # | 증명 | 모드 / 증명자 → 검증자 | 종류 | 공개 입력 | 비공개 증인 | 증명하는 조건 |
|---|---|---|---|---|---|---|
| 1 | `bind_key_to_idtoken` | Mode 1 / 지갑 → 서비스 | Groth16 (RSA-2048 JWT 검증 포함) | 출력 2개: Ax, Ay(Baby Jubjub 공개키) — 별도 공개 입력 없음 | JWT payload(1600 B 패킹), 클레임 선택자(sub/aud/iss/nonce), RSA 서명·모듈러스·해시, iss/aud 기대값 | Google RS256 서명이 맞고, iss/aud 가 기대값이며, `sk = H(iss, aud, sub, salt)` 로 유도한 키의 공개키가 (Ax, Ay) 다 |
| 2 | `pi_uid` | Mode 2 (레거시, 현재 흐름 미사용) | Groth16 | commitment | uid, secret | `commitment = Poseidon(uid, secret)` |
| 3 | `pi_ppid` | Mode 2 / 지갑 → 서비스 | Groth16 | rid, ppid | uid, salt | `ppid = Poseidon(uid, rid, salt)` |
| 4 | `pi_arid_i` | Mode 2 / 지갑 → IdP(발급) | Groth16 | uid, arid_i, auid_i, max_height, token_nonce, auid, pk_IdP | rp_nonce, salt, rid, pk_i, origin, RP_REG 서명(S, R8) | IdP 가 서명한 RP 등록(rid, origin) 검증, `arid_i = rid·rp_nonce`, `auid_i = ppid·rp_nonce`, `token_nonce = Poseidon(pk_i, max_height, rp_nonce)`, `auid = Poseidon(uid, salt)`, pk_i < 2^160 |
| 5 | `pi_pk_i_v3` | Mode 2 / 지갑 → 서비스·컨트랙트 | Groth16 (이중 트리) | pk_i, pk_IdP, PPID, max_height, sess_root, sess_shard_low, acct_root, acct_shard | rp_nonce, arid_i, auid_i, r_token, chain_id, IdP 토큰 서명(S, R8), uid, rid, salt, 비멤버십 경로 2개(깊이 8·10) | IdP 토큰 서명 `Poseidon(DOMAIN, arid_i, auid_i, r_token, max_height, chain_id)`, `auid_i = PPID·rp_nonce`, `r_token = Poseidon(pk_i, max_height, rp_nonce)`, `PPID = Poseidon(uid, rid, salt)`, 세션 리프 ∉ 세션 샤드, 계정 리프 ∉ 계정 샤드(샤드 인덱스 공개값과 일치) |
| 6 | `pi_pk_i` (v2) | Mode 2 (v3 로 대체됨) | Groth16 (단일 트리 깊이 20) | pk_i, pk_IdP, PPID, max_height, revocationRoot | 위와 같되 경로 2개(깊이 20) | 위와 같되 루트 하나 |
| 7 | `pi_ins_sess` | Mode 2 v4 / IdP → RevocationRegistryV4 | Groth16 (IMT 삽입 전이, 깊이 8, K=4) | oldRoot, newRoot | 삽입 K건의 low 리프·경로·새 리프·경로 | 세션 샤드 서브트리가 oldRoot 에서 newRoot 로 정렬 삽입 K건으로 정확히 전이했다 |
| 8 | `pi_ins_acct` | Mode 2 v4 / IdP → RevocationRegistryV4 | Groth16 (IMT 삽입 전이, 깊이 10, K=4) | oldRoot, newRoot | 위와 같음 | 계정 샤드 서브트리 전이 |
| 9 | `π_u` | Mode 3 / 지갑 → CIA(사용자 자격증명 발급, `/cia/user_cred`) | 시그마 프로토콜(Fiat-Shamir, Baby Jubjub; 회로·셋업 없음) | uid, C_u_pt, cm_u | s_u, attrs[4], blind_u, r_u | `C_u = uid·G_UID + s_u·G_SU + Σa_k·G_ATTR_k + blind_u·H` 이고 `cm_u = s_u·G_SU + r_u·H` 의 s_u 와 같다. 사용자당 한 번(속성 바뀔 때만 다시). 세션 발급에는 ZKP 없음 |
| 10 | `pi_cred` (V5) | Mode 3 / 지갑 → 서비스·Mode3Wallet 컨트랙트 | Groth16 (비멤버십 깊이 32) | PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA(x,y), pk_trace(x,y), tag c1(x,y), c2 — 14개 | uid, s_u, blind_u, blind_s, attrs[4], r, CIA 서명(S, R8), 비멤버십 경로 | ① `EdDSA.Verify(pk_CIA, Poseidon(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent))` ② C_s 를 공개 pk_i·arid 로 직접 계산, C_u 를 증인 uid·s_u·attrs 로 계산 ③ `PPID = Poseidon(uid, s_u, chainid, arid)` ④ `Poseidon(TAG=4, Cf_u) ∉ Tree(revRoot)` ⑤ `c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)`, r ≠ 0 ⑥ allowAgent ∈ {0,1}, pk_i < 2^160, max_height < 2^64 |

## 2. 회로 크기

| 회로 | R1CS 제약 | 와이어 | 비공개 입력 | 공개 입력 | zkey | wasm |
|---|--:|--:|--:|--:|--:|--:|
| bind_key_to_idtoken (Mode 1) | 561,638 | 555,067 | 1,434 | 0 (출력 2) | 382,496,286 B | — |
| pi_uid (레거시) | 31.9 (30.3–34.6) | 37.4 (36.0–39.0) | 69.3 (66.9–72.0) | 10.1 (9.8–11.3) | 723 B | |
| pi_ppid | 261 | 265 | 2 | 2 | 175,608 B | — |
| pi_arid_i | 5,389 | 5,397 | 8 | 8 | 3,384,376 B | — |
| pi_pk_i_v3 | 13,905 | 13,924 | 53 | 9 | 8,587,780 B | — |
| pi_pk_i (v2, 대체됨) | 19,251 | 19,291 | 97 | 6 | 12,285,848 B | — |
| pi_ins_sess (v4) | 39,336 | 39,314 | 152 | 2 | 23,995,732 B | 2,392,983 B |
| pi_ins_acct (v4) | 47,112 | 47,090 | 184 | 2 | 27,840,308 B | 2,424,090 B |
| pi_cred (Mode 3 V5) | 26,601 | 26,633 | 79 | 14 | 16,022,463 B | 4,712,707 B |
| π_u (Mode 3) | 회로 없음 | — | — | 3 | — | — |

## 3. 증명 생성·검증 속도

| 증명 | witness | prove | witness+prove | verify | 증명 크기(JSON) | 비고 |
|---|--:|--:|--:|--:|--:|---|
| bind_key_to_idtoken | — | — | — | — | — | 실제 Google ID 토큰이 필요해 여기서 측정하지 않음(제약 56만, zkey 382 MB) |
| pi_uid (레거시) | 31.9 (30.3–34.6) | 37.4 (36.0–39.0) | 69.3 (66.9–72.0) | 10.1 (9.8–11.3) | 723 B | |
| pi_ppid | — | — | 66.6 (62.9–76.1) | 10.6 | 722 B | Mode 2 로그인당 3회로 중 하나(같은 크레덴셜, warm) |
| pi_arid_i | — | — | 239.4 (236.6–260.1) | 13.9 | 725 B | 〃 |
| pi_pk_i_v3 | — | — | 450.4 (443.0–458.2) | 15.2 | 726 B | 〃. 세 회로 per-run 합 중앙값 762.0 ms(744.9–785.9), cold 1회차 1,321 ms |
| pi_ins_sess, 1건 | 85.3 (82.7–89.1) | 1,049.9 (1,029.6–1,080.6) | 1,138.7 | 13.1 | 724 B | IdP 게시 시 |
| pi_ins_sess, 4건 | 86.5 (82.5–90.0) | 1,062.0 (1,043.9–1,083.8) | 1,150.2 | 12.8 | 721 B | 배치 크기와 무관(K 고정) |
| pi_ins_acct, 1건 | 96.6 (94.4–102.2) | 1,164.0 (1,146.2–1,216.8) | 1,262.9 | 13.5 | 724 B | |
| pi_ins_acct, 4건 | 106.5 (102.3–115.5) | 1,210.5 (1,200.1–1,236.8) | 1,321.2 | 13.8 | 724 B | |
| π_u (Σ) | — | 121.9 (120.1–333.8) | 121.9 | 140.5 (138.2–144.4) | 1,017 B | 검증도 스칼라곱 11개(증명 17개)라 증명과 비슷. 2026-09-18 π_issue(arid·pk_i 항 포함) 는 155.3 / 163.9 |
| pi_cred (Mode 3 V5) | 237.4 (229.2–250.9) | 624.1 (611.0–1,029.4) | 859.6 (840.3–1,280.3) | 11.5 (10.5–16.6) | 722 B | `bench_pi_cred.mjs` fullProve 중앙값 841.6 ms, 검증 13.6 ms. 2026-09-18 V4 는 857.6 / 14.6 |

주: Mode 2 pi_ins 회로는 4건까지 K 슬롯이 고정이라 1건이든 4건이든 시간이 같다(차이는 잡음). π_u 행의 첫 회(333.8 ms)에 circomlibjs 초기화가 섞여 최대값이 크다. Groth16 검증은 공개 입력 수에 거의 무관하게 10–17 ms 다. pi_cred 는 V4 → V5 에서 제약 25,560 → 26,601(+1,041, 스칼라곱·Poseidon 압축 각 +1)이지만 증명 시간은 잡음 범위(857.6 → 859.6 ms).

로그인당 ZKP 비용(Mode 3): 첫 로그인은 π_u(≈ 122 ms 생성 + CIA 검증 ≈ 140 ms) + pi_cred(≈ 860 ms); 이후 로그인은 pi_cred 만 — 세션 발급에 ZKP 가 없어 2026-09-18 의 π_issue 155 + 164 ms 가 빠졌다.
