// mode3/user/core/idp.js — IdP 호출(브라우저 fetch, CORS 는 cia.js 가 연다 — Task 6). pk_CIA 는 env 고정(config.pkCia)이 있으면 그것, 없으면 TOFU.
import { DEFAULT_ATTR_SCHEMA, loadSchema } from '../../../lib/mode3_attr_schema.js';
// 기본 스키마·검증 실패 상태의 재수신 간격 — 에이전트의 백그라운드 재시도(ATTR_SCHEMA_RETRY_MS) 자리. 페이지에는 타이머를 두지 않고
// schema() 호출 때 간격이 지났으면 다시 받는다.
export const ATTR_SCHEMA_RETRY_MS = 60_000;
export function createIdp({ ciaUrl, fetch = globalThis.fetch, pinnedPk = null, timeoutMs = 2000, now = Date.now }) {
  const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
  let pkP = null;
  let schemaCache = null;     // { schema, hash, source: 'cia' | 'default' }
  let schemaInvalid = null;   // 마지막으로 받은 스키마의 검증 실패 메시지(받아서 통과하면 null)
  let schemaP = null, schemaTriedAt = 0;
  // 에이전트 fetchAttrSchema 와 같은 규칙: 못 받으면(HTTP 오류·네트워크·타임아웃) 기본 스키마, 받았는데 검증에 실패하면 보관 스키마를
  // 바꾸지 않고 schemaInvalid 에 기록한다(술어 요청은 schema_invalid — 연결 실패와 구분). 진행 중 요청은 하나로 합친다.
  const fetchSchema = () => (schemaP ??= (async () => {
    schemaTriedAt = now();
    const c = new AbortController(); const tm = setTimeout(() => c.abort(), timeoutMs);
    let b;
    try {
      const r = await fetch(`${ciaUrl}/cia/attr_schema`, { signal: c.signal }); if (!r.ok) throw new Error(`HTTP ${r.status}`);
      b = await r.json();
    } catch {
      if (!schemaCache && !schemaInvalid) schemaCache = { ...loadSchema(DEFAULT_ATTR_SCHEMA), source: 'default' };
      return schemaCache;
    } finally { clearTimeout(tm); }
    let loaded;
    try { loaded = loadSchema(b?.schema); } catch (e) { schemaInvalid = e.message; return schemaCache; }
    schemaCache = { schema: loaded.schema, hash: loaded.hash, source: 'cia' }; schemaInvalid = null;
    return schemaCache;
  })().finally(() => { schemaP = null; }));
  return {
    post: (p, body) => fetch(`${ciaUrl}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json),
    publicKeys: () => fetch(`${ciaUrl}/cia/public_keys`).then(json),
    pkCia() {
      return (pkP ??= (async () => {
        if (pinnedPk) return { x: BigInt(pinnedPk.x), y: BigInt(pinnedPk.y) };
        let r; try { r = await fetch(`${ciaUrl}/cia/public_keys`); } catch (e) { throw Object.assign(new Error(e.message), { reason: 'cia_unavailable' }); }
        if (!r.ok) throw Object.assign(new Error(`IdP 에서 pk_CIA 를 받지 못했다 (${r.status})`), { reason: 'cia_unavailable' });
        const k = await r.json(); return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y) };
      })().catch((e) => { pkP = null; throw e; }));
    },
    /** { schema, hash, source:'cia'|'default' } — 첫 수신이 검증 실패면 null. force 면 지금 다시 받는다(응답의 schemaHash 가 다를 때).
     *  기본 스키마이거나 검증 실패 상태면 ATTR_SCHEMA_RETRY_MS 가 지난 뒤의 호출이 다시 받는다. 던지지 않는다. */
    async schema(force = false) {
      const unsettled = !schemaCache || schemaCache.source === 'default' || schemaInvalid !== null;
      if (force || (unsettled && now() - schemaTriedAt >= ATTR_SCHEMA_RETRY_MS) || schemaP) return fetchSchema();
      return schemaCache;
    },
    /** 마지막 수신의 검증 실패 메시지(없으면 null) — user_core 가 술어 요청을 503 schema_invalid 로 막는 데 쓴다. */
    schemaInvalid: () => schemaInvalid,
  };
}
