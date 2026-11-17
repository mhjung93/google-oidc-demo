// Mode 3 패스키 모드(스펙 docs/superpowers/specs/2026-11-17-mode3-passkey-mode-design.md) — 전역 window.Mode3Passkey.
// salt(s_u)는 패스키의 PRF 확장 출력에서 그때그때 유도하고 어디에도 저장하지 않는다(P2·P3).
// strings.js 처럼 전역 스크립트다 — 테스트는 vm.runInThisContext 로 읽는다(tests/test_mode3_passkey_salt.mjs).
(function () {
  const enc = new TextEncoder();
  // 유도식의 두 상수(P2). 바꾸면 모든 사용자의 salt·auid·PPID 가 바뀐다 — 바꾸지 않는다.
  const PRF_INPUT = enc.encode('zkd-s_u-v1');
  const SALT_DOMAIN = 'zkd-passkey-s_u-v1';

  const fail = (reason, message) => { throw Object.assign(new Error(message || reason), { reason }); };
  const toBytes = (v) => (v instanceof Uint8Array ? v : v instanceof ArrayBuffer ? new Uint8Array(v) : ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : null);

  /** PRF 출력(32바이트) → s_u 10진 문자열. s_u = BigInt(SHA-256(utf8(SALT_DOMAIN) ‖ prf)) >> 6 — [0, 2^250) 이고 0 이면 거절한다. */
  async function saltFromPrf(prfFirst) {
    const prf = toBytes(prfFirst);
    if (!prf || prf.byteLength !== 32) fail('passkey_prf_unsupported', 'PRF 출력이 32바이트가 아니다');
    const dom = enc.encode(SALT_DOMAIN);
    const buf = new Uint8Array(dom.length + 32);
    buf.set(dom, 0); buf.set(prf, dom.length);
    const h = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
    let n = 0n;
    for (const b of h) n = (n << 8n) | BigInt(b);
    const s = n >> 6n;
    if (s === 0n) fail('passkey_bad_salt', '유도한 salt 가 0 이다');
    return s.toString();
  }

  // ---- WebAuthn(스펙 §4.1·§4.2) — RP ID 기본은 localhost(에이전트 P6), passkey-web 은 호출자가 rpId 를 준다(2026-11-17 passkey-web R-2). 서버 검증이 없는 데모라 challenge 는 무작위로만 둔다(PRF 만 쓴다). ----
  const DEFAULT_RP_ID = 'localhost';
  const b64url = (bytes) => btoa(String.fromCharCode(...toBytes(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
  function precheck(rpId) {
    if (typeof rpId !== 'string' || !rpId) fail('passkey_wrong_origin', `패스키 RP ID 가 비었거나 문자열이 아니다 (${String(rpId)})`);
    // IP 주소는 RP ID 가 될 수 없다 — WebAuthn 호출 전에 거절한다. 콜론이 하나뿐이고 뒤가 숫자면 IPv6 가 아니라 "이름:포트"(localhost:5100) — 포트를 빼라고 따로 말한다(IPv4:포트는 IP).
    const port = /^([^:[\]]+):(\d+)$/.exec(rpId);
    const isIpv4 = (h) => /^\d+(\.\d+){3}$/.test(h);
    if (port && !isIpv4(port[1])) fail('passkey_wrong_origin', `RP ID(${rpId})에는 포트를 넣지 않는다 — 포트를 빼고 이름만(${port[1]}) 쓴다`);
    if (isIpv4(rpId) || rpId.includes(':')) fail('passkey_wrong_origin', `IP 주소(${rpId})는 패스키 RP ID 가 될 수 없다 — 이름(도메인)으로 연 페이지에서 쓴다`);
    if (location.hostname !== rpId) fail('passkey_wrong_origin', `패스키는 ${rpId} 에서만 쓴다 (지금 ${location.hostname})`);
    if (typeof window.PublicKeyCredential !== 'function' || !window.isSecureContext || !navigator.credentials) fail('passkey_unsupported', 'WebAuthn 을 쓸 수 없는 브라우저·페이지');
  }
  // 브라우저 오류 → 사유. 이미 사유가 붙은 오류는 그대로.
  function mapError(e) {
    if (e?.reason) return e;
    if (e?.name === 'NotAllowedError' || e?.name === 'AbortError') return Object.assign(new Error(e.message || e.name), { reason: 'passkey_cancelled' });
    return Object.assign(new Error(e?.message || String(e)), { reason: 'passkey_unsupported' });
  }

  /** 저장된(또는 고른) 패스키로 PRF 를 계산해 s_u 를 만든다. credentialId 가 없으면 고르기 창(이미 있는 패스키 쓰기). */
  async function derivePrf({ credentialId, rpId = DEFAULT_RP_ID } = {}) {
    precheck(rpId);
    let a;
    try {
      a = await navigator.credentials.get({ publicKey: {
        challenge: rand(32), rpId, userVerification: 'required',
        ...(credentialId ? { allowCredentials: [{ type: 'public-key', id: fromB64url(credentialId) }] } : {}),
        extensions: { prf: { eval: { first: PRF_INPUT } } },
      } });
    } catch (e) { throw mapError(e); }
    if (!a) fail('passkey_cancelled');
    const first = a.getClientExtensionResults?.()?.prf?.results?.first;
    if (!first) fail('passkey_prf_unsupported', '인증기가 PRF 값을 주지 않았다');
    return { credentialId: b64url(a.rawId), s_u: await saltFromPrf(first) };
  }

  /** 새 패스키를 만들고(PRF 켬) 바로 한 번 계산해 같은 값이 나오는지 본다 — 백업 확인의 자리(스펙 §4.2). */
  async function createPasskey({ rpId = DEFAULT_RP_ID, rpName = 'zk 스냅' } = {}) {
    precheck(rpId);
    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey: {
        rp: { id: rpId, name: rpName },
        user: { id: rand(16), name: 'zk-snap', displayName: rpName },
        challenge: rand(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        extensions: { prf: { eval: { first: PRF_INPUT } } },
      } });
    } catch (e) { throw mapError(e); }
    if (!cred) fail('passkey_cancelled');
    const ext = cred.getClientExtensionResults?.() ?? {};
    if (ext.prf?.enabled !== true) fail('passkey_prf_unsupported', '인증기가 PRF 를 켜지 않았다');
    const credentialId = b64url(cred.rawId);
    const atCreate = ext.prf?.results?.first ? await saltFromPrf(ext.prf.results.first) : null;
    const d = await derivePrf({ credentialId, rpId });
    if (atCreate !== null && atCreate !== d.s_u) fail('passkey_unstable', '만들 때와 다시 계산할 때 PRF 값이 다르다');
    return { credentialId, s_u: d.s_u };
  }

  /**
   * 스냅 RPC 와 같은 이름·입출력의 어댑터(스펙 §4.1 표). 비밀이 아닌 상태는 에이전트(/wallet/passkey/*)에서, salt 는 패스키에서 온다.
   * fetchJson(url, init) → { status, body }. confirmBox(title, lines) → Promise<boolean>. promptBox(title, lines, placeholder) → Promise<string|null>.
   * withSalt(fn): fn 이 도는 동안 salt 를 한 번만 만들어 재사용하고 끝나면 버린다(팝업 하나에 패스키 한 번, P3).
   */
  function createPasskeyStore({ fetchJson, confirmBox, promptBox, derive = derivePrf }) {
    let held = null;      // withSalt 중의 { s_u } — 저장소에는 쓰지 않는다
    let depth = 0;
    async function agentState() {
      const r = await fetchJson('/wallet/passkey/state');
      if (r.status !== 200) fail(r.body?.reason ?? 'wallet_error', `passkey state HTTP ${r.status}`);
      return r.body;
    }
    async function salt(st) {
      if (held) return held.s_u;
      const cur = st ?? await agentState();
      if (!cur.passkey?.credentialId) fail('passkey_setup_required');
      // 스펙 §11 P16(10분 보관): 에이전트 메모리에 맡겨 둔 salt 가 있으면 패스키를 묻지 않는다. 없으면(시간 지남·재시작·등록 전) 패스키 → 맡긴다(실패는 무시 — 다음에 또 묻는다).
      const h = await fetchJson('/wallet/passkey/held').catch(() => null);
      let s_u = h?.status === 200 && typeof h.body?.s_u === 'string' ? h.body.s_u : null;
      if (!s_u) {
        const d = await derive({ credentialId: cur.passkey.credentialId });
        if (d.credentialId !== cur.passkey.credentialId) fail('passkey_mismatch', '연결된 패스키와 다른 패스키다');   // R-E
        s_u = d.s_u;
        await fetchJson('/wallet/passkey/hold', { method: 'POST', body: { s_u } }).catch(() => null);
      }
      if (depth > 0) held = { s_u };
      return s_u;
    }
    const requireRegistered = (st) => (st.registration?.uid ? st.registration : fail('not_registered'));
    async function withSalt(fn) {
      depth++;
      try { return await fn(); } finally { depth--; if (depth === 0) held = null; }
    }
    async function call(method, params = {}) {
      switch (method) {
        case 'getPublicInfo': {
          const st = await agentState(); const r = st.registration;
          return { registered: Boolean(r?.uid), pending: false, uid: r?.uid ?? null, auid: r?.auid ?? null, attrs: r?.attrs ?? null, slot: r?.slot ?? null,
            provider: r?.provider ?? null, hasUserCred: Boolean(st.userCred), consents: st.consents ?? {}, hasSalt: Boolean(st.passkey), backedUp: Boolean(st.passkey) };
        }
        case 'getStoredState': {
          const st = await agentState();
          return { version: 'passkey', salt: null, passkey: st.passkey, registration: st.registration, userCred: st.userCred, consents: st.consents ?? {} };
        }
        case 'prepareRegister': {
          const st = await agentState();
          if (st.registration?.uid) fail('already_registered');
          return { s_u: await salt(st) };
        }
        case 'getSalt': case 'showSalt': return { s_u: await salt() };
        case 'consentLogin': {
          const st = await agentState(); const r = requireRegistered(st);
          const s_u = await salt(st);
          const allowAgent = params.allowAgent === true || params.allowAgent === 1 || params.allowAgent === '1' ? '1' : '0';
          const c = await fetchJson('/wallet/passkey/consent', { method: 'POST', body: { origin: params.origin, arid: params.arid ?? null, allowAgent } });
          if (c.status !== 200) fail(c.body?.reason ?? 'wallet_error', `consent HTTP ${c.status}`);
          return { uid: r.uid, s_u, attrs: r.attrs, userCred: st.userCred ?? null };
        }
        case 'consentDisclosure': {
          if (params.relay !== true) return { ok: true };
          // 스냅 창(predicateLines)과 같은 자리 — 패스키 모드에는 스냅이 없어 화면 확인 상자로 묻는다(P8). 술어는 원문을 한 줄로 보인다.
          const lines = [];
          if (params.disclose && Object.keys(params.disclose).length) lines.push(`공개할 조건: ${JSON.stringify(params.disclose)}`);
          if (params.set) lines.push(`집합 소속: ${JSON.stringify(params.set)}`);
          const ok = await confirmBox(lines.length ? '속성 공개 동의' : '출금 확인', [
            params.origin ? `서비스: ${params.origin}` : '서비스: (지갑 페이지)', ...lines, `받는 주소: ${params.to}`, `금액: ${params.value ?? '0'} wei`]);
          return ok ? { ok: true } : { denied: true };
        }
        // 에이전트가 이미 가졌다(스펙 §3.2) — 스냅에 반영할 것이 없다.
        case 'storeRegistration': case 'updateUserCred': return { ok: true };
        case 'syncAttrs': return { ok: true, changed: false };
        case 'consentRevokeSession': return { ok: true };
        case 'selfRevoke': {
          const r = requireRegistered(await agentState());
          const pwd = await promptBox('자기 폐기', [`uid: ${r.uid}`, '자기 폐기는 되돌릴 수 없습니다. 계정 비밀번호를 입력하세요.'], '비밀번호');
          return pwd === null || pwd === '' ? { denied: true } : { uid: r.uid, pwd };
        }
        case 'reset': {
          const ok = await confirmBox('등록 초기화', ['이 스냅 에이전트의 등록·동의 기록을 지웁니다. 패스키 연결은 남습니다 — 다시 등록하면 같은 주소입니다.', '체인·AA 쪽 상태는 지워지지 않습니다.']);
          return ok ? { ok: true } : { denied: true };
        }
        default: fail('passkey_mode', `패스키 모드에는 ${method} 가 없다`);
      }
    }
    return { call, withSalt, agentState };
  }

  window.Mode3Passkey = { PRF_INPUT, SALT_DOMAIN, saltFromPrf, createPasskey, derivePrf, createPasskeyStore, b64url };
})();
