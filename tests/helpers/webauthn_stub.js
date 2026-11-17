// 결정적 WebAuthn 스텁(2026-11-17 패스키 모드 계획 R-A) — tests/helpers/ethereum_stub.js 처럼 init script 문자열을 만든다.
// CDP 가상 인증기는 탭(대상)마다 따로라서 승인 팝업(새 창)이 zk 스냅 화면에서 만든 패스키를 볼 수 없다 — 그래서 흐름 시험은 이 스텁으로 한다.
// 같은 secretHex 를 컨텍스트의 모든 페이지에 넣으면 같은 패스키로 동작한다(credential ID 는 secret 에서 정해진다).
//   PRF(input) = HMAC-SHA256(secret, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))  — 실제 hmac-secret 의 입력 처리와 같은 모양
// 호출 수는 페이지가 새로 떠도(IdP 를 다녀온 팝업) 세도록 하네스 함수 window.__webauthnHit(kind, rpId) 로 알린다(있을 때만).
//   kind = 'create' | 'get', rpId = 그 호출의 RP ID(create 는 publicKey.rp.id, get 은 publicKey.rpId — 없으면 null). 하네스는 둘째 인자를 무시해도 된다.
//   createStub 옵션: prf=false 면 PRF 를 주지 않는 인증기, cancel=true 면 사용자가 창을 닫은 것처럼 NotAllowedError.
export function buildWebAuthnStub({ secretHex, prf = true, cancel = false }) {
  if (!/^[0-9a-f]{64}$/.test(secretHex)) throw new Error('secretHex 는 32바이트 16진');
  return `(() => {
  const SECRET = Uint8Array.from(${JSON.stringify(secretHex)}.match(/../g), (h) => parseInt(h, 16));
  const PRF = ${prf ? 'true' : 'false'}, CANCEL = ${cancel ? 'true' : 'false'};
  const enc = new TextEncoder();
  const bytes = (v) => v instanceof Uint8Array ? v : v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  const hit = (k, rpId) => { try { if (typeof window.__webauthnHit === 'function') window.__webauthnHit(k, rpId); } catch {} };
  async function credId() { return new Uint8Array(await crypto.subtle.digest('SHA-256', SECRET)).slice(0, 16).buffer; }
  async function prfOf(input) {
    const pre = enc.encode('WebAuthn PRF\\0');
    const buf = new Uint8Array(pre.length + bytes(input).length); buf.set(pre, 0); buf.set(bytes(input), pre.length);
    const salt = await crypto.subtle.digest('SHA-256', buf);
    const key = await crypto.subtle.importKey('raw', SECRET, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return crypto.subtle.sign('HMAC', key, salt);
  }
  const cancelled = () => Promise.reject(new DOMException('사용자가 취소했다(스텁)', 'NotAllowedError'));
  navigator.credentials.create = async ({ publicKey }) => {
    hit('create', publicKey?.rp?.id ?? publicKey?.rpId ?? null); if (CANCEL) return cancelled();
    const first = publicKey?.extensions?.prf?.eval?.first;
    const out = PRF && first ? { enabled: true, results: { first: await prfOf(first) } } : { enabled: PRF };
    const rawId = await credId();
    return { rawId, id: '', type: 'public-key', response: {}, authenticatorAttachment: 'platform', getClientExtensionResults: () => ({ prf: out }) };
  };
  navigator.credentials.get = async ({ publicKey }) => {
    hit('get', publicKey?.rp?.id ?? publicKey?.rpId ?? null); if (CANCEL) return cancelled();
    const first = publicKey?.extensions?.prf?.eval?.first;
    const ext = PRF && first ? { prf: { results: { first: await prfOf(first) } } } : {};
    return { rawId: await credId(), id: '', type: 'public-key', response: {}, authenticatorAttachment: 'platform', getClientExtensionResults: () => ext };
  };
})();`;
}
