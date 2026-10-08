#!/usr/bin/env bash
set -euo pipefail

# ==== Directories ====
BUILD_DIR="build/mode2"
CIRCUITS_DIR="circuits"
PTAU_FILE="pot21_final.ptau" # pi_pk_i가 2^14를 넘어 상향

mkdir -p "$BUILD_DIR"

# ==== Helper: Compile a circuit ====
compile_circuit() {
    local name="$1"
    echo "▶ Compiling $name..."
    
    # 1. Circom Compile
    circom "$CIRCUITS_DIR/$name.circom" \
        --r1cs --wasm --sym \
        -l "$CIRCUITS_DIR" \
        -o "$BUILD_DIR"
        
    # 2. Patch generated JS for ESM compatibility (CommonJS rename)
    local js_dir="$BUILD_DIR/${name}_js"
    if [ -d "$js_dir" ]; then
        mv "$js_dir/generate_witness.js" "$js_dir/generate_witness.cjs"
        mv "$js_dir/witness_calculator.js" "$js_dir/witness_calculator.cjs"
        sed -i "s/witness_calculator.js/witness_calculator.cjs/g" "$js_dir/generate_witness.cjs"
    fi
    
    # 3. SnarkJS ZKey Setup
    echo "▶ ZKey setup for $name..."
    npx snarkjs groth16 setup "$BUILD_DIR/$name.r1cs" "$PTAU_FILE" "$BUILD_DIR/${name}_0000.zkey"
    npx snarkjs zkey contribute "$BUILD_DIR/${name}_0000.zkey" "$BUILD_DIR/${name}_final.zkey" --name="First Contribution" -v -e="$(openssl rand -hex 32)"
    npx snarkjs zkey export verificationkey "$BUILD_DIR/${name}_final.zkey" "$BUILD_DIR/${name}_vkey.json"
    
    echo "✅ $name build complete."
    echo "-------------------------------------------"
}

# ==== Main Build ====
# 이 스크립트는 매번 새 랜덤 기여로 zkey를 다시 만들고 contracts/PiPkIVerifier.sol을
# 무조건 덮어쓴다. 즉 **이미 배포된 verifier와 되돌릴 수 없이 불일치**하게 되고, 기존
# 증명은 전부 무효가 된다. 재배포(scripts/redeploy_ppid_factory.cjs)가 반드시 뒤따라야 한다.
if [[ "${BUILD_CIRCUITS_CONFIRM:-}" != "yes" ]]; then
    echo "!!! 이 스크립트는 zkey를 새로 생성하고 PiPkIVerifier.sol을 덮어씁니다."
    echo "    - 기존 증명과 배포된 verifier가 모두 무효가 됩니다(되돌릴 수 없음)."
    echo "    - 실행 후 scripts/redeploy_ppid_factory.cjs로 재배포하고, wallet_agent를"
    echo "      새 주소로 재기동해야 합니다."
    echo "    진행하려면 BUILD_CIRCUITS_CONFIRM=yes 를 설정하고 다시 실행하십시오."
    exit 1
fi

if [[ ! -f "$PTAU_FILE" ]]; then
    echo "❌ $PTAU_FILE not found! Please ensure it exists in the root."
    exit 1
fi

compile_circuit "pi_arid_i"
compile_circuit "pi_ppid"
compile_circuit "pi_pk_i"

# pi_pk_i는 온체인에서도 검증해야 하므로, Solidity verifier도 같이 export한다
# (pi_arid_i/pi_ppid는 오프체인 검증만 하므로 이 단계가 필요 없음).
echo "▶ Exporting Solidity verifier for pi_pk_i..."
npx snarkjs zkey export solidityverifier "$BUILD_DIR/pi_pk_i_final.zkey" "contracts/PiPkIVerifier.sol"
# 컨트랙트 이름을 바꾸지 못하면 한참 뒤 getContractFactory("PiPkIVerifier")에서 터진다.
# sed는 매칭이 없어도 exit 0이라 set -e에 걸리지 않으므로 직접 확인한다(2026-09-04 리뷰).
sed -i 's/contract Groth16Verifier/contract PiPkIVerifier/' "contracts/PiPkIVerifier.sol"
if ! grep -q 'contract PiPkIVerifier' "contracts/PiPkIVerifier.sol"; then
    echo "❌ contracts/PiPkIVerifier.sol의 컨트랙트 이름을 바꾸지 못했습니다."
    echo "   snarkjs가 내보낸 이름이 Groth16Verifier가 아닐 수 있습니다. 파일을 확인하십시오."
    exit 1
fi

echo "🎉 All Mode 2 circuits compiled successfully in $BUILD_DIR"
