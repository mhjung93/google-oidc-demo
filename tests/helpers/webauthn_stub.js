// 결정적 WebAuthn 스텁(2026-11-17 패스키 모드 계획 R-A) — tests/helpers/ethereum_stub.js 처럼 init script 문자열을 만든다.
// CDP 가상 인증기는 탭(대상)마다 따로라서 승인 팝업(새 창)이 zk 스냅 화면에서 만든 패스키를 볼 수 없다 — 그래서 흐름 시험은 이 스텁으로 한다.
// 같은 secretHex 를 컨텍스트의 모든 페이지에 넣으면 같은 패스키로 동작한다(credential ID 는 secret 에서 정해진다).
//   PRF(input) = HMAC-SHA256(secret, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))  — 실제 hmac-secret 의 입력 처리와 같은 모양
// 호출 수는 페이지가 새로 떠도(IdP 를 다녀온 팝업) 세도록 하네스 함수 window.__webauthnHit(kind, rpId) 로 알린다(있을 때만).
//   kind = 'create' | 'get', rpId = 그 호출의 RP ID(create 는 publicKey.rp.id, get 은 publicKey.rpId — 없으면 null). 하네스는 둘째 인자를 무시해도 된다.
//   셋째 인자(2026-11-19 휴대폰 패스키): 그 호출의 옵션 { kind, hints, transports }(없으면 null). 하네스는 무시해도 된다.
//   요청에 hints:['hybrid'] 가 있으면 휴대폰(다른 기기) 인증기처럼 답한다 — authenticatorAttachment 'cross-platform', transports ['hybrid','internal'], 동기화 표시(BE·BS) 켬.
//   extraSecrets: 더 많은 credential(여러 패스키) — credential 마다 secret 이 하나, credId = SHA-256(secret)[0..16]. 0번이 secretHex.
//     create 는 window.__webauthnCreateIndex(없으면 0)번 secret 으로 만들고, 그 credId 가 excludeCredentials 에 있으면 InvalidStateError.
//     (secret 이 하나뿐이면 excludeCredentials·allowCredentials 를 예전처럼 무시한다.)
//     get 은 allowCredentials 가 있으면 맞는 secret 으로, 맞는 것이 없으면 NotAllowedError. allowCredentials 가 없으면 0번.
//   createStub 옵션: prf=false 면 PRF 를 주지 않는 인증기, cancel=true 면 사용자가 창을 닫은 것처럼 NotAllowedError.
export function buildWebAuthnStub({ secretHex, prf = true, cancel = false, extraSecrets = [] }) {
  for (const h of [secretHex, ...extraSecrets]) if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('secretHex 는 32바이트 16진');
  return `(() => {
  const SECRETS = ${JSON.stringify([secretHex, ...extraSecrets])}.map((hex) => Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16)));
  const PRF = ${prf ? 'true' : 'false'}, CANCEL = ${cancel ? 'true' : 'false'};
  const enc = new TextEncoder();
  const bytes = (v) => v instanceof Uint8Array ? v : v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  const hit = (k, rpId, pk) => { try { if (typeof window.__webauthnHit === 'function') window.__webauthnHit(k, rpId, { kind: k, hints: pk?.hints ?? null, transports: pk?.allowCredentials?.[0]?.transports ?? null }); } catch {} };
  const phone = (pk) => Array.isArray(pk?.hints) && pk.hints.includes('hybrid');
  const authData = () => { const b = new Uint8Array(37); b[32] = 0x01 | 0x04 | 0x08 | 0x10; return b.buffer; };   // UP·UV·BE·BS
  async function credIdOf(secret) { return new Uint8Array(await crypto.subtle.digest('SHA-256', secret)).slice(0, 16).buffer; }
  const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  // get: allowCredentials 가 있으면 id 가 맞는 secret, 맞는 것이 없으면 null(NotAllowedError) — secret 이 하나뿐이면 예전처럼 allowCredentials 를 무시하고 그 credential 을 준다. 없으면 0번. create: window.__webauthnCreateIndex(없으면 0)번.
  async function pickForGet(pk) {
    const allow = pk?.allowCredentials;
    if (SECRETS.length === 1 || !Array.isArray(allow) || !allow.length) return SECRETS[0];
    for (const s of SECRETS) { const id = new Uint8Array(await credIdOf(s)); if (allow.some((c) => sameBytes(bytes(c.id), id))) return s; }
    return null;
  }
  async function prfOf(input, SECRET) {
    const pre = enc.encode('WebAuthn PRF\\0');
    const buf = new Uint8Array(pre.length + bytes(input).length); buf.set(pre, 0); buf.set(bytes(input), pre.length);
    const salt = await crypto.subtle.digest('SHA-256', buf);
    const key = await crypto.subtle.importKey('raw', SECRET, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return crypto.subtle.sign('HMAC', key, salt);
  }
  const cancelled = () => Promise.reject(new DOMException('사용자가 취소했다(스텁)', 'NotAllowedError'));
  navigator.credentials.create = async ({ publicKey }) => {
    hit('create', publicKey?.rp?.id ?? publicKey?.rpId ?? null, publicKey); if (CANCEL) return cancelled();
    const idx = window.__webauthnCreateIndex ?? 0;
    const SECRET = SECRETS[idx];
    if (!SECRET) throw new Error('__webauthnCreateIndex ' + idx + ' 에 해당하는 secret 이 없다(스텁 secret ' + SECRETS.length + '개)');
    const rawId = await credIdOf(SECRET);
    const dup = SECRETS.length > 1 && (publicKey?.excludeCredentials ?? []).some((c) => sameBytes(bytes(c.id), new Uint8Array(rawId)));
    if (dup) return Promise.reject(new DOMException('이미 이 인증기에 있는 credential(스텁)', 'InvalidStateError'));
    const first = publicKey?.extensions?.prf?.eval?.first;
    const out = PRF && first ? { enabled: true, results: { first: await prfOf(first, SECRET) } } : { enabled: PRF };
    if (phone(publicKey)) return { rawId, id: '', type: 'public-key', response: { getTransports: () => ['hybrid', 'internal'], getAuthenticatorData: authData }, authenticatorAttachment: 'cross-platform', getClientExtensionResults: () => ({ prf: out }) };
    return { rawId, id: '', type: 'public-key', response: {}, authenticatorAttachment: 'platform', getClientExtensionResults: () => ({ prf: out }) };
  };
  navigator.credentials.get = async ({ publicKey }) => {
    hit('get', publicKey?.rp?.id ?? publicKey?.rpId ?? null, publicKey); if (CANCEL) return cancelled();
    const SECRET = await pickForGet(publicKey);
    if (!SECRET) return Promise.reject(new DOMException('맞는 credential 이 없다(스텁)', 'NotAllowedError'));
    const first = publicKey?.extensions?.prf?.eval?.first;
    const ext = PRF && first ? { prf: { results: { first: await prfOf(first, SECRET) } } } : {};
    if (phone(publicKey)) return { rawId: await credIdOf(SECRET), id: '', type: 'public-key', response: { authenticatorData: authData() }, authenticatorAttachment: 'cross-platform', getClientExtensionResults: () => ext };
    return { rawId: await credIdOf(SECRET), id: '', type: 'public-key', response: {}, authenticatorAttachment: 'platform', getClientExtensionResults: () => ext };
  };
})();`;
}
