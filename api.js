// Zaffa — tiny client for the Supabase functions.
// If config.js is not filled yet, a local DEMO mode is used (nothing is saved).
(function () {
  const C = window.ZAFFA || {};
  const DEMO = !C.SUPABASE_URL || C.SUPABASE_URL.includes('YOUR-PROJECT');

  async function realRpc(fn, args) {
    const r = await fetch(C.SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/rpc/' + fn, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: C.SUPABASE_ANON_KEY,
        // old-style anon keys are JWTs (eyJ...) and go in Authorization too; new publishable keys only need apikey
        ...(String(C.SUPABASE_ANON_KEY).startsWith('eyJ') ? { Authorization: 'Bearer ' + C.SUPABASE_ANON_KEY } : {})
      },
      body: JSON.stringify(args || {})
    });
    const t = await r.text();
    let j = null;
    try { j = t ? JSON.parse(t) : null; } catch (e) { j = t; }
    if (!r.ok) throw new Error((j && j.message) || t || ('HTTP ' + r.status));
    return j;
  }

  // ---------- HMAC used by the rotating barcode ----------
  async function hmacHex(secret, msg) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  async function qrPayload(token, secret, step) {
    step = step == null ? Math.floor(Date.now() / 30000) : step;
    const sig = (await hmacHex(secret, token + '.' + step)).slice(0, 20);
    return 'ZF1.' + token + '.' + step + '.' + sig;
  }

  // ---------- DEMO store (in memory, same behaviour as the database) ----------
  const rnd = n => Array.from(crypto.getRandomValues(new Uint8Array(n))).map(b => b.toString(16).padStart(2, '0')).join('');
  const demo = {
    title: 'زفاف خالد ومدى', scan_key: 'demo-scan', password: 'demo',
    guests: [
      { name: 'نورة الدوسري', phone: '0551234567', max: 2 },
      { name: 'هيا القحطاني', phone: '0569876543', max: 1 },
      { name: 'ريم الشمري', phone: '0503334444', max: 0 }
    ].map((g, i) => ({ id: 'g' + i, ...g, token: i === 0 ? 'demo' : rnd(9), secret: rnd(16), status: 'pending', companions: 0, responded_at: null, sent_at: null, checked_in_at: null }))
  };
  const pub = g => ({ id: g.id, name: g.name, phone: g.phone, max: g.max, token: g.token, status: g.status, companions: g.companions, responded_at: g.responded_at, sent_at: g.sent_at, checked_in_at: g.checked_in_at });
  const auth = p => { if (p.p_password !== demo.password) throw new Error('unauthorized'); };
  const inv = g => g ? { name: g.name, max: g.max, status: g.status, companions: g.companions, checked_in: !!g.checked_in_at, secret: g.status === 'accepted' ? g.secret : null } : null;
  const byToken = t => demo.guests.find(g => g.token === t);
  const now = () => new Date().toISOString();

  async function demoRpc(fn, a) {
    await new Promise(r => setTimeout(r, 150));
    switch (fn) {
      case 'invite_get': return inv(byToken(a.p_token));
      case 'invite_respond': {
        const g = byToken(a.p_token); if (!g) return null;
        if (!g.checked_in_at) { g.status = a.p_attend ? 'accepted' : 'declined'; g.companions = a.p_attend ? Math.max(0, Math.min(a.p_companions || 0, g.max)) : 0; g.responded_at = now(); }
        return inv(g);
      }
      case 'scan_check': {
        if (a.p_scan_key !== demo.scan_key) return { result: 'bad_key' };
        const [v, token, step, sig] = String(a.p_payload).split('.');
        const g = byToken(token);
        if (v !== 'ZF1' || !g) return { result: 'invalid' };
        if (sig !== (await hmacHex(g.secret, token + '.' + step)).slice(0, 20)) return { result: 'invalid' };
        if (Math.abs(+step - Math.floor(Date.now() / 30000)) > 2) return { result: 'expired', name: g.name };
        if (g.status !== 'accepted') return { result: 'not_accepted', name: g.name };
        if (g.checked_in_at) return { result: 'used', name: g.name, at: g.checked_in_at };
        g.checked_in_at = now(); return { result: 'ok', name: g.name, people: 1 + g.companions };
      }
      case 'scan_stats': {
        const acc = demo.guests.filter(g => g.status === 'accepted');
        return { title: demo.title, expected: acc.reduce((s, g) => s + 1 + g.companions, 0), inside: demo.guests.filter(g => g.checked_in_at).reduce((s, g) => s + 1 + g.companions, 0) };
      }
      case 'admin_list': auth(a); return { title: demo.title, scan_key: demo.scan_key, guests: demo.guests.map(pub) };
      case 'admin_add': auth(a); {
        let n = 0;
        (a.p_guests || []).forEach(x => { if (!String(x.name || '').trim()) return; n++; demo.guests.push({ id: 'g' + rnd(4), name: String(x.name).trim(), phone: String(x.phone || '').trim() || null, max: Math.max(0, Math.min(20, +x.max || 0)), token: rnd(9), secret: rnd(16), status: 'pending', companions: 0, responded_at: null, sent_at: null, checked_in_at: null }); });
        return n;
      }
      case 'admin_update': auth(a); { const g = demo.guests.find(x => x.id === a.p_id); if (g) { g.name = a.p_name; g.phone = a.p_phone || null; g.max = Math.max(0, Math.min(20, +a.p_max || 0)); g.companions = Math.min(g.companions, g.max); } return null; }
      case 'admin_delete': auth(a); demo.guests = demo.guests.filter(x => x.id !== a.p_id); return null;
      case 'admin_mark_sent': auth(a); { const g = demo.guests.find(x => x.id === a.p_id); if (g) g.sent_at = now(); return null; }
      case 'admin_reset': auth(a); { const g = demo.guests.find(x => x.id === a.p_id); if (g) Object.assign(g, { status: 'pending', companions: 0, responded_at: null, checked_in_at: null }); return null; }
    }
    throw new Error('unknown function ' + fn);
  }

  window.Zaffa = {
    DEMO,
    rpc: (fn, args) => (DEMO ? demoRpc(fn, args) : realRpc(fn, args)),
    qrPayload,
    slug: C.EVENT_SLUG || 'khalid-mada',
    AR: n => String(n).replace(/\d/g, d => '٠١٢٣٤٥٦٧٨٩'[d]),
    phoneIntl(p) {
      let d = String(p || '').replace(/\D/g, '');
      if (d.startsWith('00')) d = d.slice(2);
      if (d.startsWith('05') && d.length === 10) d = '966' + d.slice(1);
      else if (d.startsWith('5') && d.length === 9) d = '966' + d;
      return d;
    },
    demoStore: demo
  };
})();
