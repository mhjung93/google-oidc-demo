# ZKP 전체 목록과 실측 (2026-09-18)

측정 환경: AMD Ryzen 9 5950X(16코어), Node v22.20.0, snarkjs(Groth16, BN254), WASM witness 생성기. N=10, 중앙값 (최소–최대) ms.
스크립트: `scripts/bench_zkp_inventory.mjs`(Mode 3·v4 삽입·pi_uid), `scripts/bench_mode2_zkp_all.mjs`(Mode 2 세 회로, 같은 크레덴셜, CSV `results/mode2_zkp_all_20260918.csv`), `scripts/bench_pi_cred.mjs`.
증명 생성은 지갑(브라우저 아님) 기준이고, 검증은 서비스/IdP/CIA 프로세스 기준이다. 온체인 검증 가스는 `results/mode3_onchain_bench_20260918.md`.

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
| 9 | `π_issue` | Mode 3 / 지갑 → CIA(발급) | 시그마 프로토콜(Fiat-Shamir, Baby Jubjub; 회로·셋업 없음) | uid, C_pt, cm_u | arid, s_u, pk_i, attrs[4], blind, r_u | `C_pt = uid·G1 + arid·G2 + s_u·G3 + pk_i·G4 + Σa_k·G_{4+k} + blind·H` 이고 `cm_u = s_u·G3 + r_u·H` 의 s_u 와 같다 |
| 10 | `pi_cred` (V4) | Mode 3 / 지갑 → 서비스·Mode3Wallet 컨트랙트 | Groth16 (비멤버십 깊이 32) | PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA(x,y), pk_trace(x,y), tag c1(x,y), c2 — 14개 | uid, s_u, blind, attrs[4], r, CIA 서명(S, R8), 비멤버십 경로 | ① `EdDSA.Verify(pk_CIA, Poseidon(D_cred, C, max_height, chainid, allowAgent))` ② C 를 공개 pk_i·arid 로 직접 계산 ③ `PPID = Poseidon(uid, s_u, chainid, arid)` ④ `Poseidon(TAG, C) ∉ Tree(revRoot)` ⑤ `c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)` ⑥ allowAgent ∈ {0,1}, pk_i < 2^160, max_height < 2^64 |

## 2. 회로 크기

| 회로 | R1CS 제약 | 와이어 | 비공개 입력 | 공개 입력 | zkey | wasm |
|---|--:|--:|--:|--:|--:|--:|
| bind_key_to_idtoken (Mode 1) | 561,638 | 555,067 | 1,434 | 0 (출력 2) | 382,496,286 B | — |
| pi_uid (레거시) | 240 | 243 | 2 | 1 | 137,488 B | 1,739,229 B |
| pi_ppid | 261 | 265 | 2 | 2 | 175,608 B | — |
| pi_arid_i | 5,389 | 5,397 | 8 | 8 | 3,384,376 B | — |
| pi_pk_i_v3 | 13,905 | 13,924 | 53 | 9 | 8,587,780 B | — |
| pi_pk_i (v2, 대체됨) | 19,251 | 19,291 | 97 | 6 | 12,285,848 B | — |
| pi_ins_sess (v4) | 39,336 | 39,314 | 152 | 2 | 23,995,732 B | 2,392,983 B |
| pi_ins_acct (v4) | 47,112 | 47,090 | 184 | 2 | 27,840,308 B | 2,424,090 B |
| pi_cred (Mode 3 V4) | 25,560 | 25,592 | 78 | 14 | 15,459,179 B | 3,777,234 B |
| π_issue (Mode 3) | 회로 없음 | — | — | 3 | — | — |

## 3. 증명 생성·검증 속도

| 증명 | witness | prove | witness+prove | verify | 증명 크기(JSON) | 비고 |
|---|--:|--:|--:|--:|--:|---|
| bind_key_to_idtoken | — | — | — | — | — | 실제 Google ID 토큰이 필요해 여기서 측정하지 않음(제약 56만, zkey 382 MB) |
| pi_uid (레거시) | 38.0 (31.2–41.0) | 40.7 (38.8–44.8) | 77.7 (71.9–84.6) | 11.1 | 722 B | |
| pi_ppid | — | — | 66.6 (62.9–76.1) | 10.6 | 722 B | Mode 2 로그인당 3회로 중 하나(같은 크레덴셜, warm) |
| pi_arid_i | — | — | 239.4 (236.6–260.1) | 13.9 | 725 B | 〃 |
| pi_pk_i_v3 | — | — | 450.4 (443.0–458.2) | 15.2 | 726 B | 〃. 세 회로 per-run 합 중앙값 762.0 ms(744.9–785.9), cold 1회차 1,321 ms |
| pi_ins_sess, 1건 | 111.2 (93.7–183.4) | 1,379.4 (1,237.3–1,528.7) | 1,501.6 | 16.6 | 722 B | IdP 게시 시 |
| pi_ins_sess, 4건 | 92.2 (90.0–95.3) | 1,133.9 (1,114.7–1,311.9) | 1,225.0 | 14.1 | 723 B | 배치 크기와 무관(K 고정) |
| pi_ins_acct, 1건 | 106.9 (102.2–142.1) | 1,243.2 (1,195.1–1,608.9) | 1,378.6 | 14.4 | 725 B | |
| pi_ins_acct, 4건 | 115.2 (107.2–124.3) | 1,291.0 (1,235.8–1,392.3) | 1,408.3 | 13.4 | 723 B | |
| π_issue (Σ) | — | 155.3 (152.0–374.6) | 155.3 | 163.9 (161.7–168.4) | 1,189 B | 검증도 지수승 9개라 증명과 비슷 |
| pi_cred (Mode 3) | 217.9 (210.9–222.7) | 637.3 (618.7–1,010.6) | 857.6 (829.6–1,233.3) | 14.6 (10.3–19.6) | 722 B | `bench_pi_cred.mjs` fullProve 중앙값 857.3 ms, 검증 14.4 ms 와 일치 |

주: Mode 2 pi_ins 회로는 4건까지 K 슬롯이 고정이라 1건이든 4건이든 시간이 같다(차이는 잡음). pi_ins_sess 1건 행의 첫 회에 WASM 초기화가 섞여 최대값이 크다. Groth16 검증은 공개 입력 수에 거의 무관하게 10–17 ms 다.
