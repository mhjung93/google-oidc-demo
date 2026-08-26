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
sed -i 's/contract Groth16Verifier/contract PiPkIVerifier/' "contracts/PiPkIVerifier.sol"

echo "🎉 All Mode 2 circuits compiled successfully in $BUILD_DIR"
