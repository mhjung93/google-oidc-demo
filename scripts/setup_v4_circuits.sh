#!/usr/bin/env bash
# 전이 증명 회로(설계 문서 13.2절)의 컴파일 + Groth16 신뢰 설정.
#
#   bash scripts/setup_v4_circuits.sh
#
# 산출물은 전부 build/mode2_v4/ 아래에 생기고, 검증자 컨트랙트만 contracts/에 나온다.
# **기존 회로(build/mode2, build/mode2_v3)는 건드리지 않는다.**
#
# build/는 .gitignore 대상이라 zkey/wasm이 저장소에 없다. 이 스크립트가 그것을 다시 만드는
# 유일한 경로다 — tests/test_insert_transition_circuit.mjs와 test/RevocationRegistryV4.test.mjs가
# 여기 산출물을 전제로 한다.
#
# == 신뢰 설정에 관한 경고 ==
# 아래 contribute는 **고정 엔트로피 문자열**을 쓴다. 재현 가능한 데모 설정을 위한 것이고,
# 실제 배포에서는 그대로 쓰면 안 된다 — 기여자 한 명의 toxic waste를 아는 쪽이 임의의
# 전이를 위조할 수 있다(= 폐기 롤백). 운영에 쓰려면 여러 참가자의 ceremony가 필요하다.
set -euo pipefail
cd "$(dirname "$0")/.."

PTAU=pot21_final.ptau
if [ ! -f "$PTAU" ]; then
  echo "$PTAU 가 없습니다. 회로가 47,112 제약이라 2^16 이상이 필요합니다." >&2
  exit 1
fi

CIRCOMLIB=node_modules/circomlib/circuits
mkdir -p build/mode2_v4

for C in pi_ins_sess pi_ins_acct; do
  echo "=== $C: compile ==="
  circom "circuits/$C.circom" --r1cs --wasm --sym -l "$CIRCOMLIB" -l circuits -o build/mode2_v4

  echo "=== $C: groth16 setup ==="
  npx snarkjs groth16 setup "build/mode2_v4/$C.r1cs" "$PTAU" "build/mode2_v4/${C}_0000.zkey"

  echo "=== $C: contribute (고정 엔트로피 — 위 경고 참고) ==="
  npx snarkjs zkey contribute "build/mode2_v4/${C}_0000.zkey" "build/mode2_v4/${C}_final.zkey" \
      --name="13.2 transition proof contribution" -e="mode2-v4-transition-proof-setup"

  echo "=== $C: export vkey + solidity verifier ==="
  npx snarkjs zkey export verificationkey "build/mode2_v4/${C}_final.zkey" "build/mode2_v4/${C}_vkey.json"
  npx snarkjs zkey export solidityverifier "build/mode2_v4/${C}_final.zkey" "contracts/${C}_verifier.sol"
done

echo
echo "완료. 검증:"
echo "  node tests/test_insert_transition_circuit.mjs"
echo "  npx hardhat test test/RevocationRegistryV4.test.mjs"
