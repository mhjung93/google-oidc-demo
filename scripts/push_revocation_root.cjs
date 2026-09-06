// IdP의 현재 폐기 root를 RevocationRegistry에 그대로 게시하던 스크립트였다.
// 2026-09-07(설계 문서 13.2절, V4 전환) 이후 **그런 조작 자체가 없다.**
//
// 이유. RevocationRegistryV4는 root를 받지 않는다. 현재 root에서 시작해 검증된 서브트리
// 전이만 접어 올려 새 root를 유도한다 — 그것이 롤백과 쓰레기 root를 원천적으로 막는 방법이다.
// 따라서 "임의의 root를 민다"는 이 스크립트의 기능은 설계상 사라진 것이지, 옮겨간 것이 아니다.
//
// 대체: scripts/revocation_sweep.cjs (prepare -> commit -> pushUpdates 한 사이클).
// 최초 부트스트랩은 scripts/deploy_v4_stack.cjs가 레지스트리 생성자에서 한다.
throw new Error(
  "scripts/push_revocation_root.cjs는 폐기됐습니다. V4 레지스트리는 root를 받지 않고 유도합니다.\n" +
  "  npx hardhat run scripts/revocation_sweep.cjs --network localhost   (게시 한 사이클)\n" +
  "를 사용하십시오."
);
