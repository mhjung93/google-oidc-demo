#!/usr/bin/env bash
# Mode 3 pi_cred 회로 컴파일 + Groth16 셋업. 산출물은 전부 build/mode3/ 아래.
#
#   bash scripts/build_mode3_circuit.sh [pot21_final.ptau]
#
# 그동안 이 절차는 tests/test_pi_cred_witness.mjs(컴파일, 단 witness_test/ 하위)와
# scripts/bench_pi_cred.mjs(zkey)에 나뉘어 있어 사람이 순서를 기억해야 했다. 회로를 바꾸면
# 반드시 이 스크립트로 zkey·vkey·wasm 을 한 세트로 다시 만든다 — 셋이 어긋나면 지갑의
# 로그인이 전부 bad_proof 가 된다.
#
# == 신뢰 설정에 관한 경고 ==
# contribute 는 고정 엔트로피 문자열을 쓴다(재현 가능한 데모 설정). 운영이라면 ceremony 가 필요하다.
set -euo pipefail
cd "$(dirname "$0")/.."

PTAU="${1:-pot21_final.ptau}"
if [ ! -f "$PTAU" ]; then
  echo "$PTAU 가 없습니다. pi_cred 는 2^14 를 넘어 pot21_final.ptau(2^21) 가 필요합니다." >&2
  exit 1
fi

OUT=build/mode3
mkdir -p "$OUT"
rm -f "$OUT/pi_cred_0000.zkey" "$OUT/pi_cred_final.zkey" "$OUT/pi_cred_vkey.json"

echo "=== compile ==="
circom circuits/pi_cred.circom --r1cs --wasm --sym -o "$OUT" \
  -l circuits -l circuits/lib -l node_modules/circomlib/circuits

echo "=== groth16 setup ==="
npx snarkjs groth16 setup "$OUT/pi_cred.r1cs" "$PTAU" "$OUT/pi_cred_0000.zkey"
npx snarkjs zkey contribute "$OUT/pi_cred_0000.zkey" "$OUT/pi_cred_final.zkey" --name=mode3 -v -e=mode3-bench
npx snarkjs zkey export verificationkey "$OUT/pi_cred_final.zkey" "$OUT/pi_cred_vkey.json"

echo "완료: $OUT/pi_cred_final.zkey, $OUT/pi_cred_vkey.json, $OUT/pi_cred_js/pi_cred.wasm"
