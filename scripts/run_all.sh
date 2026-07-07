#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  echo "▶ cleanup (trap)..."

  # PID가 있으면 프로세스 그룹 전체 종료(자식까지)
  for p in "${SERVER_PID:-}" "${SNAP_PID:-}" "${HARDHAT_PID:-}"; do
    if [[ -n "$p" ]]; then
      kill -TERM -- "-$p" 2>/dev/null || true
    fi
  done

  sleep 1

  for p in "${SERVER_PID:-}" "${SNAP_PID:-}" "${HARDHAT_PID:-}"; do
    if [[ -n "$p" ]]; then
      kill -KILL -- "-$p" 2>/dev/null || true
    fi
  done

  # 최후의 안전장치: 포트 점유 프로세스도 제거
  for port in 8081 8545 3000; do
    lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
  done

  echo "✅ cleanup done."
}
trap cleanup EXIT INT TERM

# ==== helper: ms timestamp ====
now_ms() {
  date +%s%3N 2>/dev/null || python3 - <<'PY'
import time; print(int(time.time()*1000))
PY
}

step() {
  local name="$1"; shift
  local start=$(now_ms)
  echo "▶ $name"
  "$@"
  local end=$(now_ms)
  echo "⏱  ${name} took $((end-start)) ms"
  echo "-------------------------------------------"
}

# --- Pre-clean ports to avoid EADDRINUSE (optional but strongly recommended) ---
for port in 8081 8545 3000; do
  pids=$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    echo "[run_all] Port $port already in use by: $pids. Killing..."
    echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
    sleep 0.5
    echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
  fi
done

# set AUD_EXPECTED, ISS_EXPECTED
export AUD_EXPECTED="588661703676-so4rftcahdeo203pdge9csmse64dlfd8.apps.googleusercontent.com"
export ISS_EXPECTED="https://accounts.google.com"

# ==== Generate/Load Auditor Keys ====
step "Generate/Load Auditor Keys" node scripts/generate_auditor_keys.js

# ==== Install Snap dependencies ====
step "Install Snap dependencies" npm install --workspace=google-oidc-demo-snap

# ==== Build Snap ====
step "Build Snap" bash -c "rm -rf snap/dist && npm run snap:build"

# ==== Compile contracts ====
step "Compile contracts" npx hardhat compile



# ==== Start background servers ====
echo "▶ Starting background servers (Hardhat and Snap)..."
#npm run hardhat:node &
#HARDHAT_PID=$!
#npm run snap:serve &
#SNAP_PID=$!

setsid npm run hardhat:node >/tmp/hardhat.log 2>&1 &
HARDHAT_PID=$!

setsid npm run snap:serve >/tmp/snap.log 2>&1 &
SNAP_PID=$!

echo "Hardhat PID: $HARDHAT_PID, Snap PID: $SNAP_PID"
echo "-------------------------------------------"


# ==== receiver address for "NOT a MetaMask internal account" ====
# fixed receiver (you can change this to any random-looking address)
export RECEIVER_ADDR="0x1000000000000000000000000000000000000001"

# build dir is served by your web server as /build/ (client.js already fetches /build/proof.json)
mkdir -p build
echo "{\"to\":\"$RECEIVER_ADDR\"}" > build/receiver.json

# Wait until Hardhat JSON-RPC is reachable (8545)
echo "▶ Waiting for Hardhat node (8545)..."
for i in {1..80}; do
  if curl -fsS -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    http://127.0.0.1:8545 >/dev/null 2>&1; then
    echo "✅ Hardhat node is up."
    break
  fi
  sleep 0.25
done

# Prefund receiver "genesis-like" (Hardhat only)
# 0x3635C9ADC5DEA00000 = 1000 ETH in wei
curl -fsS -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"hardhat_setBalance\",\"params\":[\"$RECEIVER_ADDR\",\"0x3635C9ADC5DEA00000\"]}" \
  http://127.0.0.1:8545 >/dev/null

echo "✅ Receiver ready: $RECEIVER_ADDR (prefunded on Hardhat)"
echo "   build/receiver.json written."
echo "-------------------------------------------"







# Wait until Snap manifest is reachable
echo "▶ Waiting for Snap server (8081)..."
for i in {1..80}; do
  if curl -fsS http://localhost:8081/snap.manifest.json >/dev/null 2>&1; then
    echo "✅ Snap server is up."
    break
  fi
  sleep 0.25
done

if ! curl -fsS http://localhost:8081/snap.manifest.json >/dev/null 2>&1; then
  echo "❌ Snap server did not start (port 8081?)."
  echo "   Try: lsof -t -i :8081 | xargs -r kill -9"
  exit 1
fi


# ==== OIDC 서버 실행 및 토큰 획득 ====
echo "▶ Starting OIDC server..."
rm -f .id_token.txt
npm run dev &
SERVER_PID=$!
echo "OIDC Server started with PID: $SERVER_PID"
echo ""
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!!! PLEASE DO THE FOLLOWING NOW                            !!!"
echo "!!! 1. Open your browser to http://localhost:3000/login    !!!"
echo "!!! 2. Log in with your Google account.                    !!!"
echo "!!! 3. You will be redirected to a '/me' page.             !!!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo ""

# .id_token.txt 파일이 생성될 때까지 대기
echo "▶ Waiting for ID Token file to be created by the server..."
while [ ! -f ".id_token.txt" ]
do
  sleep 1
done

echo "ID Token file found!"
sleep 1 # 종료 대기

# 파일에서 토큰 읽어서 환경변수에 저장
export ID_TOKEN=$(cat .id_token.txt)
echo "ID_TOKEN has been set from file."
echo "-------------------------------------------"

# 토큰 존재 재확인
if [[ -z "${ID_TOKEN:-}" ]]; then
  echo "ERROR: Failed to get ID_TOKEN from server flow."
  exit 1
fi

mkdir -p build circuits

# ==== 0) 회로 파일 존재 확인 / 없으면 샘플 생성 ====
if [[ ! -f "circuits/bind_key_to_idtoken.circom" ]]; then
cat > circuits/bind_key_to_idtoken.circom <<'CIR'

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/babyjub.circom";

template BindKeyToIdToken() {
    signal input sk;   // private
    signal input h;    // private

    signal input Ax;   // public
    signal input Ay;   // public
    signal input comm; // public

    component mul = BabyJubScalarMul();
    mul.e <== sk;
    mul.base[0] <== BabyJub.Base[0];
    mul.base[1] <== BabyJub.Base[1];

    mul.out[0] === Ax;
    mul.out[1] === Ay;

    component H = Poseidon(2);
    H.inputs[0] <== h;
    H.inputs[1] <== sk;
    H.out === comm;
}

component main = BindKeyToIdToken();
CIR
fi

# ==== 1) 파생 ====
step "BIP32 derive (node scripts/derive_bip32.js)" npm run --silent derive


# ==== ZKP Workflow for the new circuit ====
#CIRCUIT_NAME="jwt_verify_main"
CIRCUIT_NAME="bind_key_to_idtoken"
CIRCUIT_PATH="circuits/${CIRCUIT_NAME}.circom"
BUILD_DIR="build"
CIRCUIT_BUILD_PATH="${BUILD_DIR}/${CIRCUIT_NAME}"


# ==== 2) 회로 컴파일 ====
#step "circom compile" circom ${CIRCUIT_PATH} --r1cs --wasm --sym -o ${BUILD_DIR}
step "circom compile" npm run zk:compile


# ==== 2a) 생성된 JS 파일을 CJS 형식으로 수정 (ESM 호환성 문제 해결) ====
step "patch generated js" bash -c "mv ${CIRCUIT_BUILD_PATH}_js/generate_witness.js ${CIRCUIT_BUILD_PATH}_js/generate_witness.cjs && mv ${CIRCUIT_BUILD_PATH}_js/witness_calculator.js ${CIRCUIT_BUILD_PATH}_js/witness_calculator.cjs && sed -i 's/witness_calculator.js/witness_calculator.cjs/g' ${CIRCUIT_BUILD_PATH}_js/generate_witness.cjs"

# ==== 3) Powers of Tau (Power 21) ====
PTAU_FINAL="pot21_final.ptau"
if [[ ! -f "$PTAU_FINAL" ]]; then
  echo "▶ Downloading Powers of Tau file (Power 21)..."
  # This is a very large file (~2.1G).
  wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_21.ptau -O $PTAU_FINAL
  echo "✅ Powers of Tau file downloaded."
else
  echo "▶ Powers of Tau file (Power 21) already exists, skip download."
fi

# ==== 4) proving key / verification key ====
if [[ ! -f "${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey" ]]; then
  step "snarkjs key setup" bash -c "npx snarkjs zkey new ${CIRCUIT_BUILD_PATH}.r1cs ${PTAU_FINAL} ${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey -v && npx snarkjs zkey contribute ${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey ${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey --name='Key Contribution' -v && npx snarkjs zkey export verificationkey ${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey ${BUILD_DIR}/verification_key.json"
else
  echo "▶ zkey already exists, skip"
fi

# ==== 5) 입력 생성 ====
step "build input.json (scripts/make_proof.js)" npm run --silent zk:input

# ==== 6) witness ====
step "generate witness" node ${CIRCUIT_BUILD_PATH}_js/generate_witness.cjs ${CIRCUIT_BUILD_PATH}_js/${CIRCUIT_NAME}.wasm ${BUILD_DIR}/input.json ${BUILD_DIR}/witness.wtns

# ==== 7) prove ====
step "groth16 prove" npx snarkjs groth16 prove ${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey ${BUILD_DIR}/witness.wtns ${BUILD_DIR}/proof.json ${BUILD_DIR}/public.json

# ==== 8) verify ====
step "groth16 verify" npx snarkjs groth16 verify ${BUILD_DIR}/verification_key.json ${BUILD_DIR}/public.json ${BUILD_DIR}/proof.json

echo "✅ ALL DONE"

echo ""
echo "✅ Proof verified. Now test the Snap UI:"
echo "   1) Open the snap site, click Connect"
echo "   2) Then click Say Hello (Snap invoke)"
echo ""
read -r -p "Press ENTER to shut down servers... " _
