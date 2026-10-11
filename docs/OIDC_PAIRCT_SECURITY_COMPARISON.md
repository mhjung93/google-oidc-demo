# OIDC와 PairCT의 보안·프라이버시 비교

## 1. 목적과 판정 범위

이 문서는 일반적인 OpenID Connect(OIDC) Authorization Code Flow, OIDC의 pairwise subject identifier 사용 구성, PairCT 프로토콜의 목표, 현재 PairCT 데모 구현을 동일한 조건으로 비교한다.

여기서 `불충족`은 항상 취약점을 뜻하지 않는다. OIDC가 의도적으로 RP 정보를 IdP에 제공하는 것처럼 해당 속성이 애초에 프로토콜의 설계 목표가 아닌 경우에는 `설계 범위 밖`으로 구분한다. 반대로 현재 PairCT 구현이 PairCT의 명시적 목표를 만족하지 못하는 경우에는 `불충족`으로 판정한다.

판정 기호는 다음과 같다.

- `충족`: 해당 구조가 속성을 직접 제공한다.
- `부분 충족`: 특정 설정이나 추가 가정에서만 제공한다.
- `불충족`: 해당 프로토콜의 목표이지만 현재 구조가 만족하지 못한다.
- `설계 범위 밖`: 원래 해당 보장을 제공하도록 정의된 프로토콜이 아니다.
- `해당 없음`: 해당 구성요소나 개념이 존재하지 않는다.

## 2. 비교 대상

### 일반 OIDC

표준 Authorization Code Flow를 사용하고 ID Token의 `sub`를 서비스 계정 식별자로 사용하는 일반적인 구성을 의미한다. OIDC에서 RP는 Client이며 IdP는 OpenID Provider(OP)에 해당한다.

### OIDC pairwise `sub`

OIDC의 `subject_type=pairwise` 구성을 의미한다. 이 경우 OP는 sector identifier를 사용해 서로 다른 RP가 받은 `sub`를 직접 상관하기 어렵게 만들 수 있다.

### PairCT 프로토콜 목표

논문에서 제안하는 정상 동작 기준이다. ordinary authentication에서는 IdP가 accessed service를 알지 못하고, RP는 서비스별 PPID로 returning user를 인식하며, 외부 승인을 받은 disputed session에 대해서만 opening을 수행하는 것을 목표로 한다.

### 현재 PairCT 구현

2026년 7월 21일 기준 다음 활성 Mode 2 실행 경로를 의미한다.

- `client.js`
- `server.js`
- `custom_idp.js`
- `wallet_agent.js`
- `idp/login_popup.js`
- `circuits/pi_arid_i.circom`
- `circuits/pi_ppid.circom`
- `circuits/pi_pk_i.circom`
- `contracts/PPIDWallet.sol`

## 3. 종합 비교표

| 비교 조건 | 일반 OIDC | OIDC pairwise `sub` | PairCT 프로토콜 목표 | 현재 PairCT 구현 | 판정 근거 |
|---|---|---|---|---|---|
| IdP-side RP hiding | 설계 범위 밖 | 설계 범위 밖 | 충족 목표 | 불충족 | OIDC OP는 인증 요청의 `client_id`, `redirect_uri` 등으로 RP를 안다. 현재 PairCT도 RP FE가 IdP 팝업을 직접 열고 fragment와 `postMessage`의 `event.origin`을 노출한다. |
| RP-side 실제 신원 비공개 | 부분 충족 | 부분 충족 | 충족 목표 | 충족 | OIDC RP는 최소한 `iss`, `sub`를 받으며 요청 scope에 따라 프로필 정보도 받을 수 있다. PairCT RP FE에는 `uid`와 `salt`가 직접 전달되지 않는다. |
| IdP-scoped identifier의 RP 비공개 | 불충족 | 부분 충족 | 충족 목표 | 충족 | 일반 OIDC의 `sub`는 RP가 직접 받는다. pairwise `sub`도 RP가 받지만 다른 RP의 값과 다르다. 현재 PairCT RP는 IdP의 `uid`를 받지 않는다. |
| Cross-RP unlinkability | 불충족 또는 배포 의존 | 부분 충족 | 충족 목표 | 부분 충족 | 일반 public `sub`는 여러 RP에서 재사용될 수 있다. pairwise `sub`는 sector가 분리된 RP 사이의 상관을 줄인다. PairCT의 Poseidon 기반 PPID는 RP별 `rid`를 포함하지만 현재 IdP·RP FE 전송 경계와 동일 salt 관리 가정이 남는다. |
| Service-local account continuity | 충족 | 충족 | 충족 목표 | 충족 | OIDC는 안정적인 `(iss, sub)`로 returning user를 식별한다. PairCT는 안정적인 PPID를 RP-local account handle로 사용한다. |
| PPID의 `(uid, rid)`별 결정성·유일성 | 해당 없음 | 부분 충족 | 충족 목표 | 부분 충족 | OIDC pairwise `sub`는 OP의 pairwise algorithm에 의존한다. PairCT는 동일 `uid`, `rid`, `salt`에서 같은 PPID를 계산하지만 salt 영속성과 고정성 관리가 데모 상태에 의존한다. |
| IdP의 cross-service 사용자 활동 관찰 방지 | 불충족 | 불충족 | 충족 목표 | 불충족 | pairwise `sub`는 RP끼리의 연결을 줄일 뿐 OP가 어느 RP의 로그인을 처리하는지는 숨기지 않는다. 현재 PairCT IdP 팝업도 RP origin을 알 수 있다. |
| RP 간 사용자 식별자 직접 비교 방지 | 불충족 또는 배포 의존 | 충족 | 충족 목표 | 충족에 가까움 | OIDC pairwise `sub`와 PairCT PPID 모두 서비스별 값을 사용한다. 현재 Poseidon PPID에는 알려진 단순 교차곱 관계가 없다. |
| Offline dictionary attack resilience | 설계 범위 밖 | 설계 범위 밖 | 충족 목표 | 부분 충족 | OIDC `sub`는 OP가 발급하는 식별자이므로 PairCT식 `uid`, `rid` 추측 공격 모델과 다르다. PairCT PPID는 비밀 salt에 의존하지만 로컬 agent token과 salt 저장소 보호가 추가 가정이다. |
| 브라우저 요청–응답 session binding | 충족 | 충족 | 충족 목표 | 부분 충족 | 정상 OIDC는 `state`, `nonce` 및 Authorization Code Flow 검증으로 요청과 응답을 결합한다. 현재 PairCT의 `r_i`는 팝업에서 비교되지만 IdP 서명이나 `pi_i`에는 포함되지 않는다. |
| RP audience binding | 충족 | 충족 | 충족 목표 | 충족 | OIDC ID Token의 `aud`는 Client ID를 포함하고 RP가 검증한다. PairCT RP backend는 자신의 `rid`와 세션 `rp_nonce`로 `arid_i`를 재계산한다. |
| 토큰 위조·필드 변조 방지 | 충족 | 충족 | 충족 목표 | 충족 | OIDC는 서명된 ID Token과 `iss`, `aud`, `exp`, `nonce` 등의 검증을 사용한다. PairCT는 EdDSA-Poseidon으로 `arid_i`, `auid_i`, `r_token`, `max_height`, `chain_id`를 서명한다. |
| 토큰 만료 검증 | 충족 | 충족 | 충족 목표 | 충족 | OIDC는 서명된 `exp`를 검증한다. PairCT RP와 온체인 wallet은 서명된 `max_height`를 검증한다. 현재 PairCT token의 별도 `exp`는 서명되지 않지만 권위 있는 만료값으로 사용되지 않는다. |
| Replay resistance | 충족 | 충족 | 충족 목표 | 부분 충족 | 정상 OIDC는 authorization code의 일회성, `state`, `nonce`, redirect URI 및 token 검증을 사용한다. PairCT는 RP `rp_nonce`를 성공 후 소모하지만 IdP의 `usedNonces`와 RP session store가 메모리 전용이다. |
| IdP 인증과 토큰 발급의 서버 측 결합 | 충족 | 충족 | 충족 목표 | 불충족 | 정상 OIDC OP는 인증·동의 결과에 근거해 authorization code 또는 token을 발급한다. 현재 `/consent_result`는 선행 `/sso_with_credentials` 성공 상태를 IdP 서버 세션으로 확인하지 않는다. |
| 토큰이 RP FE에 노출되지 않는 backend delivery | 충족 가능 | 충족 가능 | Wallet delivery 목표 | 불충족 | Authorization Code Flow는 code를 RP callback으로 보내고 token endpoint 교환을 RP backend에서 수행할 수 있다. 현재 PairCT IdP token은 IdP 팝업에서 RP FE로 먼저 전달된 후 wallet agent와 RP backend로 전달된다. |
| Session-bound wallet key authentication | 해당 없음 | 해당 없음 | 충족 목표 | 충족에 가까움 | 일반 OIDC에는 wallet session key가 없다. PairCT의 `r_token=Poseidon(pk_i,max_height,rp_nonce)`과 `pi_pk_i`는 세션키를 묶지만 wallet agent가 전역 `currentSessionKey` 하나만 사용해 동시 세션 혼선 가능성이 있다. |
| Wallet–IdP account binding | 해당 없음 | 해당 없음 | 충족 목표 | 불충족 | 일반 OIDC는 별도 wallet 주체를 정의하지 않는다. 현재 PairCT는 사전 enrollment 대신 `DEMO_BOUND_UID='12345'`를 하드코딩한다. |
| 동일 salt 사용 강제 | 해당 없음 | 해당 없음 | 배포 정책 필요 | 부분 충족 | OIDC pairwise identifier 생성 비밀은 OP가 관리한다. 현재 PairCT IdP의 `lastAuid`는 동일 salt 사용을 검사하지만 메모리 전용이며 성공한 token 발급 전에 갱신될 수 있다. |
| RP FE와 RP backend의 비공모 가정 불필요 | 충족 | 충족 | 가정 최소화 필요 | 불충족 | 일반 웹 보안 모델에서는 RP FE와 RP backend를 같은 RP 주체로 본다. 현재 PairCT에서는 RP FE가 wallet-agent token, PPID, proof, IdP token을 모두 취급한다. |
| Conditional privacy | 설계 범위 밖 | 설계 범위 밖 | 충족 목표 | 불충족 | OIDC는 정상 인증과 분쟁 opening을 분리하는 프로토콜이 아니다. 현재 PairCT는 ordinary login에서 RP와 PPID가 IdP 측에 노출될 수 있다. |
| Identity-level traceability | 부분 충족 | 부분 충족 | 충족 목표 | 기능상 충족 | OIDC OP는 일반적으로 자신이 발급한 `sub`를 계정과 연결할 수 있지만 표준화된 분쟁 tracing 절차는 아니다. 현재 PairCT는 `r_token`과 RP session record를 이용해 `uid` lookup을 수행한다. |
| Authorized opening | 설계 범위 밖 | 설계 범위 밖 | 충족 목표 | 불충족 | OIDC Core는 PairCT식 외부 승인 opening을 정의하지 않는다. 현재 PairCT의 RP trace API와 IdP lookup API에는 감사자 인증이나 외부 authorization 검증이 없다. |
| IdP key 영속성·rotation | 충족 가능 | 충족 가능 | 충족 필요 | 불충족 | OIDC는 issuer metadata와 JWKS 기반 key rotation을 지원한다. 현재 Custom IdP의 PS·EdDSA 키는 프로세스 시작 시 새로 생성되어 재시작 후 기존 credential 및 온체인 trusted key와 불일치한다. |
| TLS 기반 채널 보호 | 필수 | 필수 | 충족 필요 | 불충족 | 표준 OIDC 운영 endpoint는 TLS 사용을 전제로 한다. 현재 데모는 `http://127.0.0.1` 통신이다. localhost 데모 한계로는 허용할 수 있지만 운영 보장으로 볼 수 없다. |

## 4. 핵심 차이

### 4.1 OIDC가 명확히 더 강한 부분

정상적으로 구현된 Authorization Code Flow는 인증 요청, 사용자 인증, 동의, authorization code, token endpoint 교환을 OP와 RP의 서버 상태로 결합한다. ID Token은 `iss`, `sub`, `aud`, `exp`, 필요 시 `nonce`를 포함하며 RP가 이 값을 검증한다.

현재 PairCT 구현은 암호학적 proof와 token field binding은 강하지만, IdP 웹 세션이 `/sso_with_credentials`와 `/consent_result`를 결합하지 않는다. 따라서 웹 인증 상태 관리에서는 정상 OIDC 구현보다 약하다.

### 4.2 Pairwise OIDC가 제공하지만 한계가 있는 부분

OIDC pairwise `sub`는 서로 다른 sector의 RP가 받은 subject identifier를 직접 비교해 동일 사용자인지 알아내는 것을 어렵게 한다. 그러나 OP는 pairwise identifier를 생성하며 인증 요청의 Client를 알고 있으므로 다음 속성은 제공하지 않는다.

- IdP-side RP hiding
- IdP의 서비스 접근 관찰 방지
- Wallet session key binding
- Conditional privacy with authorized opening

따라서 PairCT의 차별점은 단순히 “pairwise identifier를 제공한다”가 아니라, ordinary authentication에서 IdP의 RP 관찰을 차단하면서 RP-local continuity와 authorized opening을 함께 제공하는 데 있어야 한다.

### 4.3 현재 PairCT 구현이 프로토콜 목표와 다른 부분

현재 실행 경로에서는 RP FE가 IdP 팝업을 직접 열고 `currentSSOProof` 전체를 전송한다. 이에 따라 IdP 측 JavaScript는 RP origin, `rid`, PPID를 관찰할 수 있다. 또한 IdP token도 wallet-controlled context가 아니라 RP FE로 먼저 반환된다.

따라서 현재 구현은 회로 수준의 hidden witness와 웹 통신 수준의 observer를 구분해야 한다.

- `pi_i` 회로에서 `rid`, `rp_nonce`, `salt`, `pk_i`가 private witness인 것은 맞다.
- 그러나 별도 `pi_PPID`, `business.ppid`, URL fragment, `postMessage.event.origin`을 통해 RP와 PPID가 IdP 측에 노출된다.
- 그러므로 “회로가 rid를 숨긴다”는 사실만으로 IdP-side RP hiding을 주장할 수 없다.

## 5. OIDC 대비 PairCT의 연구 기여로 유지할 항목

다음 항목은 일반 OIDC 또는 pairwise OIDC가 직접 제공하지 않으므로 PairCT의 비교 특성으로 사용할 가치가 있다.

1. **IdP-side RP hiding**  
   OIDC에서는 OP가 Client를 알아야 하지만 PairCT는 ordinary authentication 중 accessed service를 IdP로부터 숨기는 것을 목표로 한다.

2. **RP-side IdP identity privacy**  
   OIDC RP는 `sub`를 직접 받지만 PairCT RP는 `uid` 대신 PPID만 받아야 한다.

3. **Cross-RP unlinkability**  
   pairwise OIDC도 이 속성을 부분적으로 제공하므로, PairCT는 이 항목만으로 차별화해서는 안 된다.

4. **Session-bound wallet authentication**  
   일반 OIDC에는 wallet-generated session key와 proof/token 결합이 없다.

5. **Offline dictionary attack resilience**  
   PairCT의 PPID가 공개된 `uid`, `rid` 후보만으로 재계산되지 않아야 한다.

6. **Conditional privacy**  
   ordinary authentication의 비공개성과 disputed session의 제한된 opening을 분리한다.

7. **Identity-level traceability with authorized opening**  
   단순히 IdP가 계정 매핑을 보유하는 것을 넘어, retained RP transcript와 IdP record를 외부 승인 아래 결합해야 한다.

## 6. 결론

일반 OIDC는 인증 상태 결합, audience 검증, token validation 및 운영 키 관리에서 성숙한 표준 구조를 제공한다. 반면 IdP가 RP를 아는 것은 OIDC의 취약점이 아니라 정상 설계의 일부다. Pairwise `sub`는 RP 간 연결 가능성을 줄이지만 IdP의 RP 관찰은 막지 않는다.

PairCT의 연구적 차별점은 OIDC의 기본 인증 안전성을 약화하지 않으면서 다음을 추가하는 데 있다.

```text
IdP-side RP hiding
+ RP-local account continuity
+ wallet session binding
+ cross-RP unlinkability
+ conditional privacy
+ externally authorized opening
```

현재 PairCT 구현은 RP audience binding, proof consistency, token signature, PPID 계산 및 온체인 session-key 검증을 상당 부분 구현했다. 그러나 IdP-side RP hiding, IdP 인증과 consent의 서버 세션 결합, wallet-direct token delivery, durable replay/salt state, authorized opening, key persistence는 아직 충족하지 못한다.

## 7. 기준 문서

- [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Core 1.0 — Subject Identifier Types and Pairwise Identifier Algorithm](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
- [OpenID Connect Core 1.0 — Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
- [OpenID Connect Core 1.0 — ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
