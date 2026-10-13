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
# snarkjs contribute 는 난수를 섞으므로 빌드마다 키가 바뀐다(재현 불가). 운영이라면 ceremony 가 필요하다.
set -euo pipefail
cd "$(dirname "$0")/.."

PTAU="${1:-pot21_final.ptau}"
if [ ! -f "$PTAU" ]; then
  echo "$PTAU 가 없습니다. pi_cred 는 2^14 를 넘어 pot21_final.ptau(2^21) 가 필요합니다." >&2
  exit 1
fi

OUT=build/mode3
mkdir -p "$OUT"
rm -f "$OUT/MANIFEST.sha256"   # pack_mode3_build.sh 가 다시 만든다 — 묵은 매니페스트를 새 빌드와 섞어 두지 않는다

for NAME in pi_cred pi_idp; do
  rm -f "$OUT/${NAME}_0000.zkey" "$OUT/${NAME}_final.zkey" "$OUT/${NAME}_vkey.json"
  echo "=== compile $NAME ==="
  circom "circuits/${NAME}.circom" --r1cs --wasm --sym -o "$OUT" \
    -l circuits -l circuits/lib -l node_modules/circomlib/circuits
  echo "=== groth16 setup $NAME ==="
  npx snarkjs groth16 setup "$OUT/${NAME}.r1cs" "$PTAU" "$OUT/${NAME}_0000.zkey"
  npx snarkjs zkey contribute "$OUT/${NAME}_0000.zkey" "$OUT/${NAME}_final.zkey" --name=mode3 -v -e=mode3-bench
  npx snarkjs zkey export verificationkey "$OUT/${NAME}_final.zkey" "$OUT/${NAME}_vkey.json"

  # pi_cred 의 zkey 가 막 나온 직후, 같은 반복 안에서 솔리디티 검증기를 뽑는다(부분 실패 보호). pi_idp 가 이어서
  # 실패해도 PiCredVerifier.sol 은 이미 이 pi_cred_final.zkey 와 짝이 맞은 채로 남는다 — 전에는 루프 밖(둘 다
  # 끝난 뒤)에서 export 해서, pi_idp 단계가 실패하면 디스크의 새 pi_cred_final.zkey 와 옛 PiCredVerifier.sol(이전
  # 빌드의 delta)이 어긋난 채로 남았다.
  if [ "$NAME" = "pi_cred" ]; then
    echo "=== solidity verifier (pi_cred) ==="
    # snarkjs 0.7 템플릿의 컨트랙트 이름은 Groth16Verifier 다 — 저장소 관례(PiPkIVerifier)대로 회로 이름으로 바꾼다.
    npx snarkjs zkey export solidityverifier "$OUT/pi_cred_final.zkey" contracts/PiCredVerifier.sol
    sed -i -E 's/contract (Groth16Verifier|Verifier) /contract PiCredVerifier /' contracts/PiCredVerifier.sol
    grep -q 'contract PiCredVerifier' contracts/PiCredVerifier.sol || { echo "PiCredVerifier 이름 치환 실패" >&2; exit 1; }
    grep -q 'uint\[33\] calldata _pubSignals' contracts/PiCredVerifier.sol || { echo "PiCredVerifier 의 공개 입력이 33개가 아니다 — circuits/pi_cred.circom 을 확인" >&2; exit 1; }
  fi
done

echo "완료: $OUT/pi_cred_final.zkey, $OUT/pi_cred_vkey.json, $OUT/pi_cred_js/pi_cred.wasm, contracts/PiCredVerifier.sol"
echo "      $OUT/pi_idp_final.zkey, $OUT/pi_idp_vkey.json, $OUT/pi_idp_js/pi_idp.wasm"
echo "다음: npx hardhat compile (artifacts/ 의 PiCredVerifier 갱신) — 그 뒤 팩토리·AttrGate 재배포(docs/MODE3_DEMO.md '처음 한 번')"
