#!/usr/bin/env bash
# Mode 3 Snap 모드 데모 리셋(2026-10-22) — demo_web_reset.sh 와 같은 순서(전부 내림 → 백업 → hardhat 새로 → 배포 → IdP·zkONE·zkTWO)이되
# 지갑 자리에 에이전트(mode3_wallet_agent.js, MODE3_WALLET_SECRETS=snap)와 Snap 서버(snap-mode3, :8082)를 띄운다. 옵션(AUTO_APPROVE·TWO_CHAINS·ADMIN_OPEN·HEIGHT_GRID·DEMO_LOG_DIR)은 그대로.
# 전제: cd snap-mode3 && npm install && npm run build, 브라우저에 MetaMask Flask. 리셋 뒤 MetaMask 안의 옛 등록은 지갑 페이지의 'Snap 초기화' 로 지운다.
WALLET_MODE=snap exec bash "$(dirname "$0")/demo_web_reset.sh" "$@"
