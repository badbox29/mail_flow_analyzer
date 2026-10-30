/**
 * Mail Flow Analyzer — DNS Resolution Worker
 * ==========================================
 * A Cloudflare Worker that performs DNS-over-HTTPS lookups for the Mail Flow
 * Analyzer, with recursive SPF expansion and RFC 7208 lookup counting that is
 * impractical to do from the browser.
 *
 * WHAT IT DOES
 *   GET  /?domain=example.com                      → SPF + DMARC (+ DKIM if selector given)
 *   GET  /?domain=example.com&selector=selector1   → also resolves that DKIM key
 *   GET  /?domain=example.com&dkim=probe           → probe common DKIM selectors
 *
 *   Returns JSON:
 *   {
 *     domain, spf:{...}, dmarc:{...}, dkim:{...}, generatedAt
 *   }
 *
 * DEPLOYMENT
 *   1. Create a new Worker in the Cloudflare dashboard (or `wrangler init`).
 *   2. Paste this file as the Worker script (or src/index.js with wrangler).
 *   3. Deploy. Note the Worker URL (e.g. https://mfa-dns.<you>.workers.dev).
 *   4. In Mail Flow Analyzer → Settings → DNS, paste that URL and enable DNS lookups.
 *
 *   No bindings, secrets, or KV are required. The Worker is stateless and uses
 *   Cloudflare's edge cache to avoid repeated upstream DNS queries.
 *
 * PRIVACY
 *   The Worker receives the domains being analyzed (to look them up). It stores
 *   nothing. It only queries public DNS via DoH and returns the records.
 *
 * SECURITY / ABUSE
 *   Set an ALLOWED_ORIGINS environment variable (Worker → Settings → Variables)
 *   to a comma-separated list of origins permitted to call this Worker, e.g.
 *       https://yourtool.example.com, https://badbox29.github.io
 *   The Worker echoes back the request's Origin only if it is in the list, which
 *   is how browsers enforce the allowlist. Requests from origins not in the list
 *   are rejected with 403. If ALLOWED_ORIGINS is unset/empty, or contains "*",
 *   the Worker allows any origin (the out-of-the-box default). A simple
 *   per-request recursion guard limits SPF include-chain blowup.
 */
const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query'; // upstream DoH used by the Worker
const SPF_LOOKUP_LIMIT = 10;         // RFC 7208 §4.6.4
const MAX_SPF_RECORDS = 50;          // hard safety cap on total records resolved per request
const COMMON_DKIM_SELECTORS = [
  'selector1', 'selector2',          // Microsoft 365
  'google',                          // Google Workspace
  'k1', 'k2', 'k3',                  // Mailchimp / Mandrill / common
  'dkim', 'default', 'mail', 's1', 's2',
  'mandrill', 'mailjet', 'sendgrid', 'amazonses', 'pm', 'protonmail', 'zoho',
];

export default {
  async fetch(request, env) {
    // Resolve the allowed origin for this request from the ALLOWED_ORIGINS env var
    // (comma-separated). Unset/empty or a "*" entry means allow any origin.
    const allowList = ((env && env.ALLOWED_ORIGINS) || '')
      .split(',').map(o => o.trim().toLowerCase()).filter(Boolean);
    const allowAny = allowList.length === 0 || allowList.includes('*');
    const reqOrigin = request.headers.get('Origin') || '';
    const originAllowed = allowAny || allowList.includes(reqOrigin.toLowerCase());
    // The value echoed back: "*" when open, the exact request origin when allow-listed.
    const allowOriginValue = allowAny ? '*' : reqOrigin;

    const cors = {
      'Access-Control-Allow-Origin': allowOriginValue,
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',
    };

    if (request.method === 'OPTIONS') {
      // Preflight: honor the allowlist so disallowed origins fail CORS cleanly.
      return new Response(null, { status: originAllowed ? 204 : 403, headers: cors });
    }

    // Reject requests from origins not in the allowlist. (Direct hits with no
    // Origin header — e.g. opening the URL in a browser tab or curl — are allowed,
    // since CORS only governs cross-origin browser requests.)
    if (!allowAny && reqOrigin && !originAllowed) {
      return json({ error: 'Origin not allowed.' }, 403, cors);
    }

    const url = new URL(request.url);
    const domain = (url.searchParams.get('domain') || '').trim().toLowerCase().replace(/[^a-z0-9.\-_]/g, '');
    const selector = (url.searchParams.get('selector') || '').trim().toLowerCase().replace(/[^a-z0-9.\-_]/g, '');
    const dkimMode = (url.searchParams.get('dkim') || '').trim().toLowerCase();

    if (!domain || !domain.includes('.')) {
      return json({ error: 'A valid domain parameter is required.' }, 400, cors);
    }

    try {
      const [spf, dmarc, dkim] = await Promise.all([
        resolveSpf(domain),
        resolveDmarc(domain),
        resolveDkim(domain, selector, dkimMode),
      ]);
      return json({ domain, spf, dmarc, dkim, generatedAt: new Date().toISOString() }, 200, cors);
    } catch (e) {
      return json({ domain, error: 'Lookup failed: ' + (e && e.message ? e.message : String(e)) }, 502, cors);
    }
  },
};

// ── DoH query helper ─────────────────────────────────────────────────────────
async function dohQuery(name, type) {
  const u = new URL(DOH_ENDPOINT);
  u.searchParams.set('name', name);
  u.searchParams.set('type', type);
  const resp = await fetch(u.toString(), {
    headers: { 'accept': 'application/dns-json' },
    cf: { cacheTtl: 300, cacheEverything: true },
  });
  if (!resp.ok) throw new Error('DoH ' + type + ' query failed for ' + name + ' (' + resp.status + ')');
  const data = await resp.json();
  // Answer records; join TXT chunks, strip quotes
  const answers = (data.Answer || []).map(a => ({
    type: a.type,
    data: typeof a.data === 'string' ? a.data.replace(/^"|"$/g, '').replace(/"\s+"/g, '') : a.data,
  }));
  return { status: data.Status, answers };
}

async function txtRecords(name) {
  const r = await dohQuery(name, 'TXT');
  return r.answers.filter(a => a.type === 16).map(a => a.data);
}

// ── SPF resolution with recursive lookup counting ────────────────────────────
async function resolveSpf(domain) {
  const txts = await txtRecords(domain);
  const spfRecords = txts.filter(t => /^v=spf1\b/i.test(t.trim()));
  if (spfRecords.length === 0) {
    return { found: false, record: null, lookupCount: 0, withinLimit: true, mechanisms: [], tree: [], notes: ['No SPF record published.'] };
  }
  if (spfRecords.length > 1) {
    return { found: true, record: spfRecords[0], multiple: true, lookupCount: null, withinLimit: false, mechanisms: [], tree: [],
      notes: ['Multiple SPF records found (' + spfRecords.length + '). RFC 7208 requires exactly one; multiple records cause a permerror.'] };
  }
  const root = spfRecords[0];
  const state = { count: 0, recordsResolved: 0, visited: new Set(), notes: [] };
  const tree = await expandSpf(domain, root, state, 0);
  const withinLimit = state.count <= SPF_LOOKUP_LIMIT;
  if (!withinLimit) {
    state.notes.unshift('SPF requires ' + state.count + ' DNS lookups, exceeding the RFC 7208 limit of ' + SPF_LOOKUP_LIMIT +
      '. Receivers will return a permerror, which prevents SPF from passing and typically causes DMARC to fail as well.');
  }
  // 'all' qualifier
  const allMatch = root.match(/([~\-?+])all\b/i);
  return {
    found: true,
    record: root,
    lookupCount: state.count,
    withinLimit,
    allQualifier: allMatch ? allMatch[1] : null,
    tree,
    notes: state.notes,
  };
}

// Recursively expand an SPF record, counting lookup-causing mechanisms.
// Returns a tree node array for display.
async function expandSpf(owner, record, state, depth) {
  const nodes = [];
  if (depth > 12 || state.recordsResolved > MAX_SPF_RECORDS) return nodes;
  const terms = record.trim().split(/\s+/).slice(1); // drop v=spf1
  for (const term of terms) {
    const t = term.trim();
    if (!t) continue;
    const lower = t.toLowerCase();
    // Lookup-causing mechanisms per RFC 7208 §4.6.4
    if (/^include:/i.test(t)) {
      state.count++;
      const inc = t.slice(8);
      const node = { type: 'include', target: inc, lookups: 1, children: [] };
      if (!state.visited.has('inc:' + inc)) {
        state.visited.add('inc:' + inc);
        try {
          const incTxts = await txtRecords(inc);
          const incSpf = incTxts.find(x => /^v=spf1\b/i.test(x.trim()));
          state.recordsResolved++;
          if (incSpf) node.children = await expandSpf(inc, incSpf, state, depth + 1);
          else node.note = 'No SPF record at include target.';
        } catch (e) { node.note = 'Lookup failed.'; }
      } else { node.note = 'Already resolved (cycle avoided).'; }
      nodes.push(node);
    } else if (/^redirect=/i.test(t)) {
      state.count++;
      const rd = t.slice(9);
      const node = { type: 'redirect', target: rd, lookups: 1, children: [] };
      if (!state.visited.has('rd:' + rd)) {
        state.visited.add('rd:' + rd);
        try {
          const rdTxts = await txtRecords(rd);
          const rdSpf = rdTxts.find(x => /^v=spf1\b/i.test(x.trim()));
          state.recordsResolved++;
          if (rdSpf) node.children = await expandSpf(rd, rdSpf, state, depth + 1);
          else node.note = 'No SPF record at redirect target.';
        } catch (e) { node.note = 'Lookup failed.'; }
      } else { node.note = 'Already resolved (cycle avoided).'; }
      nodes.push(node);
    } else if (/^a(:|$)/i.test(lower) || /^mx(:|$)/i.test(lower) || /^ptr(:|$)/i.test(lower) || /^exists:/i.test(lower)) {
      state.count++;
      const mech = lower.split(/[:/]/)[0];
      nodes.push({ type: mech, target: t, lookups: 1 });
    } else if (/^ip4:/i.test(lower) || /^ip6:/i.test(lower)) {
      nodes.push({ type: 'ip', target: t, lookups: 0 });
    } else if (/^[~\-?+]?all$/i.test(lower)) {
      nodes.push({ type: 'all', target: t, lookups: 0 });
    } else {
      nodes.push({ type: 'other', target: t, lookups: 0 });
    }
  }
  return nodes;
}

// ── DMARC resolution ─────────────────────────────────────────────────────────
async function resolveDmarc(domain) {
  const name = '_dmarc.' + domain;
  let txts = [];
  try { txts = await txtRecords(name); } catch (e) { /* treat as none */ }
  const rec = txts.find(t => /^v=dmarc1\b/i.test(t.trim()));
  if (!rec) {
    return { found: false, record: null, policy: null, notes: ['No DMARC record published at ' + name + '.'] };
  }
  const tags = {};
  rec.split(';').forEach(part => {
    const m = part.trim().match(/^(\w+)\s*=\s*(.+)$/);
    if (m) tags[m[1].toLowerCase()] = m[2].trim();
  });
  const notes = [];
  const p = (tags.p || '').toLowerCase();
  if (p === 'reject') notes.push('Policy is p=reject: receivers should reject messages that fail DMARC.');
  else if (p === 'quarantine') notes.push('Policy is p=quarantine: failing messages should be sent to junk/quarantine.');
  else if (p === 'none') notes.push('Policy is p=none: monitoring only — no enforcement action is requested.');
  if (tags.pct && tags.pct !== '100') notes.push('pct=' + tags.pct + ': policy is applied to only ' + tags.pct + '% of messages.');
  if (tags.sp) notes.push('Subdomain policy sp=' + tags.sp + '.');
  return {
    found: true, record: rec, policy: p || null,
    subdomainPolicy: (tags.sp || '').toLowerCase() || null,
    pct: tags.pct || '100',
    rua: tags.rua || null, ruf: tags.ruf || null,
    tags, notes,
  };
}

// ── DKIM resolution (selector from message, or probe common selectors) ────────
async function resolveDkim(domain, selector, mode) {
  const results = [];
  const trySelector = async (sel) => {
    const name = sel + '._domainkey.' + domain;
    try {
      const txts = await txtRecords(name);
      const rec = txts.find(t => /(^|;)\s*(v=dkim1|k=|p=)/i.test(t));
      if (rec) {
        const tags = {};
        rec.split(';').forEach(part => { const m = part.trim().match(/^(\w+)\s*=\s*(.*)$/); if (m) tags[m[1].toLowerCase()] = m[2].trim(); });
        const revoked = tags.p !== undefined && tags.p === '';
        results.push({ selector: sel, found: true, record: rec, revoked,
          keyType: tags.k || 'rsa', hasKey: !!(tags.p && tags.p.length), note: revoked ? 'Key published but empty (p=) — selector revoked.' : null });
        return true;
      }
    } catch (e) { /* not found */ }
    return false;
  };

  if (selector) {
    await trySelector(selector);
    if (results.length) return { mode: 'selector', selectorsFound: results.length, keys: results };
    return { mode: 'selector', selectorsFound: 0, keys: [], notes: ['No DKIM key found at ' + selector + '._domainkey.' + domain + '.'] };
  }

  if (mode === 'probe') {
    // Probe common selectors in parallel (bounded)
    await Promise.all(COMMON_DKIM_SELECTORS.map(trySelector));
    if (results.length) return { mode: 'probe', selectorsFound: results.length, keys: results,
      notes: ['Found by probing common selectors. This is not exhaustive — a domain may use selectors not in the probe list.'] };
    return { mode: 'probe', selectorsFound: 0, keys: [],
      notes: ['No DKIM keys found among common selectors. The domain may use a custom selector, or may not publish DKIM.'] };
  }

  return { mode: 'none', selectorsFound: 0, keys: [], notes: ['DKIM lookup skipped (no selector provided and probing not requested).'] };
}

// ── util ─────────────────────────────────────────────────────────────────────
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj, null, 2), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...(cors || {}) },
  });
}
