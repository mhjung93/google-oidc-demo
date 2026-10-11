#!/usr/bin/env bash
# build/mode3 의 **배포용 산출물만** 묶는다 — 다른 기계(노트북·WSL)에 데모를 올릴 때 회로를 다시 빌드하지 않고 복사하기 위해.
#
#   bash scripts/pack_mode3_build.sh [out.tar.gz]      # 기본 ~/mode3_build_YYYYMMDD.tar.gz
#   (받는 쪽, 저장소 루트에서)  tar -xzf mode3_build_YYYYMMDD.tar.gz && sha256sum -c build/mode3/MANIFEST.sha256
#
# 묶는 것(런타임이 읽는 셋, 약 27MB — lib/mode3_wallet.js 의 WASM_PATH·ZKEY_PATH·VKEY_PATH, cia.js 의 VKEY_PATH):
#   build/mode3/pi_cred_final.zkey   증명 키(지갑)
#   build/mode3/pi_cred_vkey.json    검증 키(CIA·RP·지갑)
#   build/mode3/pi_cred_js/          pi_cred.wasm + witness 생성기
# 묶지 않는 것: pi_cred.r1cs·pi_cred.sym·pi_cred_0000.zkey·witness_test/·commit/ (회로 개발·테스트용), *.ptau(키 생성용 2.3GB).
# 셋이 어긋나면 로그인이 전부 bad_proof 가 되므로 **항상 한 세트로** 옮긴다(docs/MODE3_DEMO.md "처음 한 번" 0 의 경고와 같다).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$HOME/mode3_build_$(date +%Y%m%d).tar.gz}"
FILES=(build/mode3/pi_cred_final.zkey build/mode3/pi_cred_vkey.json build/mode3/pi_cred_js/pi_cred.wasm build/mode3/pi_cred_js/generate_witness.js build/mode3/pi_cred_js/witness_calculator.js)

cd "$ROOT"
for f in "${FILES[@]}"; do
  [ -f "$f" ] || { echo "없음: $f — 먼저 bash scripts/build_mode3_circuit.sh 로 build/mode3 를 만들어야 한다" >&2; exit 1; }
done
# 받는 쪽이 세트가 온전한지 확인할 수 있게 해시 목록을 함께 넣는다
sha256sum "${FILES[@]}" > build/mode3/MANIFEST.sha256
tar -czf "$OUT" "${FILES[@]}" build/mode3/MANIFEST.sha256
echo "묶음: $OUT ($(du -h "$OUT" | cut -f1))"
cat build/mode3/MANIFEST.sha256
echo "받는 쪽(저장소 루트): tar -xzf $(basename "$OUT") && sha256sum -c build/mode3/MANIFEST.sha256 && npx hardhat compile"
