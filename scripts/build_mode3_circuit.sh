#!/usr/bin/env bash
# Mode 3 회로 둘(pi_cred·pi_idp) 컴파일 + Groth16 셋업. 산출물은 전부 build/mode3/ 아래.
#
#   bash scripts/build_mode3_circuit.sh [pot21_final.ptau]
#
# 회로를 바꾸면 반드시 이 스크립트로 zkey·vkey·wasm 을 **한 세트로** 다시 만든다 — 셋이 어긋나면 지갑의 로그인이 전부
# bad_proof 가 된다(tests/test_mode3_artifacts.mjs 가 소스와 산출물의 공개 입력 수·순서를 대조한다).
# V11(2026-10-12): pi_idp(세션마다 IdP 에 내는 π_IdP)가 추가됐다. 온체인에 가지 않으므로 solidity 검증기는 pi_cred 만 만든다.
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

for NAME in pi_cred pi_idp; do
  rm -f "$OUT/${NAME}_0000.zkey" "$OUT/${NAME}_final.zkey" "$OUT/${NAME}_vkey.json"
  echo "=== compile $NAME ==="
  circom "circuits/${NAME}.circom" --r1cs --wasm --sym -o "$OUT" \
    -l circuits -l circuits/lib -l node_modules/circomlib/circuits
  echo "=== groth16 setup $NAME ==="
  npx snarkjs groth16 setup "$OUT/${NAME}.r1cs" "$PTAU" "$OUT/${NAME}_0000.zkey"
  npx snarkjs zkey contribute "$OUT/${NAME}_0000.zkey" "$OUT/${NAME}_final.zkey" --name=mode3 -v -e=mode3-bench
  npx snarkjs zkey export verificationkey "$OUT/${NAME}_final.zkey" "$OUT/${NAME}_vkey.json"
done

echo "=== solidity verifier (pi_cred) ==="
# snarkjs 0.7 템플릿의 컨트랙트 이름은 Groth16Verifier 다 — 저장소 관례(PiPkIVerifier)대로 회로 이름으로 바꾼다.
npx snarkjs zkey export solidityverifier "$OUT/pi_cred_final.zkey" contracts/PiCredVerifier.sol
sed -i -E 's/contract (Groth16Verifier|Verifier) /contract PiCredVerifier /' contracts/PiCredVerifier.sol
grep -q 'contract PiCredVerifier' contracts/PiCredVerifier.sol || { echo "PiCredVerifier 이름 치환 실패" >&2; exit 1; }
grep -q 'uint\[33\] calldata _pubSignals' contracts/PiCredVerifier.sol || { echo "PiCredVerifier 의 공개 입력이 33개가 아니다 — circuits/pi_cred.circom 을 확인" >&2; exit 1; }

echo "완료: $OUT/pi_cred_final.zkey, $OUT/pi_cred_vkey.json, $OUT/pi_cred_js/pi_cred.wasm, contracts/PiCredVerifier.sol"
echo "      $OUT/pi_idp_final.zkey, $OUT/pi_idp_vkey.json, $OUT/pi_idp_js/pi_idp.wasm"
echo "다음: npx hardhat compile (artifacts/ 의 PiCredVerifier 갱신) — 그 뒤 팩토리·AttrGate 재배포(docs/MODE3_DEMO.md '처음 한 번')"
