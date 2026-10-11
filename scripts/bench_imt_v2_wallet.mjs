// v1 전체 재구성 vs v2 증분 동기화를 **HTTP 왕복 포함**으로 재던 벤치였다.
// 2026-09-07(설계 문서 13.1절) 이후 실행할 수 없다.
//
// 이유. 이 벤치는 /idp/revocation_state_v2와 wallet_agent.js의 syncRevocationTreeV2에
// 의존했는데 둘 다 사라졌다. 더 근본적으로는 **비교 자체가 성립하지 않는다**: v3에는 증분
// 동기화 프로토콜이 없다. 지갑이 캐시 없이 매번 자기 샤드 하나를 통째로 받으므로, 잴 것이
// "증분이 전체보다 얼마나 싼가"가 아니라 "캐시 없는 전체가 얼마나 싼가"로 바뀌었다.
//
// 대체:
//   - scripts/bench_wallet_revocation_v3.mjs — v3 지갑 경로(왕복 + 자체 검증 포함)
//   - scripts/bench_imt_v2.mjs — 트리 연산의 O(n) 기준선(왕복 제외). 논문이 인용하는
//     "리프 32,000개 재구성 24,752 ms"가 여기서 나온다. 이건 **그대로 동작한다** —
//     lib/imt_v2.js만 쓰고 IdP에 붙지 않기 때문이다. (그 라이브러리 자체는 죽지 않았다.
//     v3의 서브트리가 전부 createIMTv2 인스턴스다 — 사라진 것은 깊이 20 트리 하나를
//     IdP가 통째로 서빙하던 배선이다.)
throw new Error(
  "scripts/bench_imt_v2_wallet.mjs는 폐기됐습니다(v2 증분 동기화 전용).\n" +
  "  node scripts/bench_wallet_revocation_v3.mjs   (v3 지갑 경로)\n" +
  "  node scripts/bench_imt_v2.mjs                 (v2 O(n) 기준선, 여전히 동작)\n" +
  "를 대신 사용하십시오."
);
