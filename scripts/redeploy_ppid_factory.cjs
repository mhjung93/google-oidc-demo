// v2 스택(PiPkIVerifier / RevocationRegistry / PPIDWalletFactory) 재배포 스크립트였다.
// 2026-09-07(설계 문서 13.1절) 이후 **더 이상 쓰지 않는다.**
//
// 이유. 이 스크립트는 부트스트랩 root를 /idp/revocation_state_v2에서 읽었는데 그 엔드포인트가
// 사라졌고, 여기서 배포하는 세 컨트랙트는 운영 경로에서 v3 판으로 교체됐다. 그대로 두면
// "재배포했는데 아무것도 달라지지 않는" 실패를 만든다 — 데몬과 지갑은 v3 레지스트리를
// 보고 있는데 이 스크립트는 v2 레지스트리를 새로 띄우기 때문이다.
//
// 대체: scripts/deploy_v3_stack.cjs (같은 일을 v3 스택으로 하고, 부트스트랩 root도 v3
// topRoot에서 읽는다).
throw new Error(
  "scripts/redeploy_ppid_factory.cjs는 폐기됐습니다(v2 스택 전용).\n" +
  "  REDEPLOY_CONFIRM=yes npx hardhat run scripts/deploy_v3_stack.cjs --network localhost\n" +
  "를 대신 사용하십시오."
);
