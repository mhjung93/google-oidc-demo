// 이중 트리(v3) 스택 배포 — verifier + RevocationRegistryV3 + PPIDWalletFactoryV3.
// 2026-09-07(설계 문서 13.2절, V4 전환) 이후 **더 이상 쓰지 않는다.**
//
// 이유. RevocationRegistryV3는 `pushRoot(bytes32)`로 IdP가 준 root를 그대로 받는데,
// scripts/revocation_sweep.cjs는 이제 `pushUpdates(Update[])`만 부른다. 이 스크립트로
// 배포하면 게시가 통째로 멈춘다 — sweep이 존재하지 않는 함수를 부르기 때문이다.
// (컨트랙트 자체는 남아 있다. test/PPIDWalletV3*.test.mjs와 가스 기준선이 쓴다.)
//
// 대체: scripts/deploy_v4_stack.cjs
//   REDEPLOY_CONFIRM=yes npx hardhat run scripts/deploy_v4_stack.cjs --network localhost
throw new Error(
  "scripts/deploy_v3_stack.cjs는 폐기됐습니다(V3 레지스트리 전용).\n" +
  "  REDEPLOY_CONFIRM=yes npx hardhat run scripts/deploy_v4_stack.cjs --network localhost\n" +
  "를 대신 사용하십시오."
);
