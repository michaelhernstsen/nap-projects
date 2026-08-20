/**
 * NAP Projects — login + 2FA + projekt-/opgavestyring (Notion-stil tabel)
 *
 * Samme auth-kerne som nap-homehub/nap-dashboard (individuelle konti,
 * obligatorisk TOTP, HMAC-signerede sessions, PBKDF2-hashede kodeord).
 * Se nap-dashboard-repo/web/dashboard-worker.js for det oprindelige
 * forbillede - koden herunder er bevidst identisk i den del.
 *
 * v1-omfang (se README): projekter + opgaver grupperet under dem, med
 * faste felter (status/prioritet/ansvarlig/forfaldsdato/tags/blocked-by).
 * IKKE bygget endnu: brugerdefinerede felter, flere gemte visninger,
 * avanceret filter-builder. Kan tilfoejes senere uden at aendre skemaet
 * fundamentalt (task_deps/task_tags er allerede relationelle).
 *
 * Ruter:
 *   GET/POST /setup, /login, /2fa-setup, /2fa-verify, /account/password, /logout
 *   GET      /admin/users       Brugeradministration (kraever is_admin)
 *   GET      /qrcode.js         Vendoret QR-generator
 *   GET/POST /api/projects, /api/projects/:id
 *   GET/POST /api/tasks, /api/tasks/:id
 *   GET      /api/users         Team til ansvarlig-dropdown
 *   GET/POST /api/tags
 *   GET      /api/me
 *   GET      /*                 App-shell fra ./public (kraever session)
 *
 * Secrets: SETUP_KEY, SESSION_SECRET
 * Bindings: DB (D1 nap-projects), ASSETS
 */

const SESSION_DAGE = 30;
const MAX_FORSOEG = 8;
const SPAERRE_MIN = 15;
const PREAUTH_MIN = 10;

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });

/* ------------------------------------------------------------------ */
/* Auth-kerne - identisk med nap-homehub/nap-dashboard                 */
/* ------------------------------------------------------------------ */

const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

async function hmac(secret, data){
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
}

function sikkerLig(a, b){
  const A = new TextEncoder().encode(a), B = new TextEncoder().encode(b);
  if(A.length !== B.length) return false;
  let d = 0;
  for(let i=0;i<A.length;i++) d |= A[i] ^ B[i];
  return d === 0;
}

async function lavToken(env, uid){
  const udloeb = Date.now() + SESSION_DAGE*864e5;
  const payload = `${uid}:${udloeb}`;
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

async function gyldigToken(env, token){
  if(!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const forventet = await hmac(env.SESSION_SECRET, payload);
  if(!sikkerLig(sig, forventet)) return null;
  const [uidStr, expStr] = payload.split(':');
  const uid = Number(uidStr), udloeb = Number(expStr);
  if(!uid || !(udloeb > Date.now())) return null;
  return { uid, udloeb };
}

async function lavPreauthToken(env, purpose, uid, ekstra){
  const udloeb = Date.now() + PREAUTH_MIN*60000;
  const payload = `${purpose}:${uid}:${udloeb}:${ekstra || ''}`;
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

async function gyldigPreauthToken(env, token, forventetPurpose){
  if(!token || !token.includes('.')) return null;
  const dot = token.lastIndexOf('.');
  const payload = token.slice(0, dot), sig = token.slice(dot+1);
  const forventet = await hmac(env.SESSION_SECRET, payload);
  if(!sikkerLig(sig, forventet)) return null;
  const [purpose, uidStr, expStr, ekstra] = payload.split(':');
  if(purpose !== forventetPurpose) return null;
  const uid = Number(uidStr), udloeb = Number(expStr);
  if(!uid || !(udloeb > Date.now())) return null;
  return { uid, ekstra: ekstra || null };
}

const SESSION_COOKIE = (navn, vaerdi, maxAgeSek) =>
  `${navn}=${encodeURIComponent(vaerdi)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSek}`;
const RYD_COOKIE = navn => `${navn}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;

const PBKDF2_ITERATIONER = 50000;
const b64enc = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64dec = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));

async function hashKode(kode, saltB64){
  const salt = saltB64 ? b64dec(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const noegle = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(kode), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name:'PBKDF2', hash:'SHA-256', salt, iterations:PBKDF2_ITERATIONER }, noegle, 256);
  return { hash: b64enc(bits), salt: b64enc(salt) };
}

async function verificerKode(kode, hashB64, saltB64){
  const { hash } = await hashKode(kode, saltB64);
  return sikkerLig(hash, hashB64);
}

function tilfaeldigKode(laengde){
  const alfabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(laengde));
  return Array.from(bytes, b => alfabet[b % alfabet.length]).join('');
}

const B32_ALFABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes){
  let bits = 0, value = 0, out = '';
  for(const b of bytes){
    value = (value << 8) | b; bits += 8;
    while(bits >= 5){ out += B32_ALFABET[(value >>> (bits-5)) & 31]; bits -= 5; }
  }
  if(bits > 0) out += B32_ALFABET[(value << (5-bits)) & 31];
  return out;
}

function base32Decode(str){
  str = str.replace(/=+$/,'').toUpperCase();
  let bits = 0, value = 0; const out = [];
  for(const c of str){
    const idx = B32_ALFABET.indexOf(c);
    if(idx === -1) continue;
    value = (value << 5) | idx; bits += 5;
    if(bits >= 8){ out.push((value >>> (bits-8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

function nyTotpHemmelighed(){
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

async function hotp(secretBytes, counter){
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2**32));
  view.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey(
    'raw', secretBytes, { name:'HMAC', hash:'SHA-1' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const offset = mac[mac.length-1] & 0xf;
  const bin = ((mac[offset]&0x7f)<<24) | ((mac[offset+1]&0xff)<<16)
            | ((mac[offset+2]&0xff)<<8) | (mac[offset+3]&0xff);
  return String(bin % 1000000).padStart(6,'0');
}

async function totpVerificer(secretBase32, kode, sidsteStep){
  const secretBytes = base32Decode(secretBase32);
  const nuStep = Math.floor(Date.now()/1000/30);
  for(const delta of [0,-1,1]){
    const step = nuStep + delta;
    if(sidsteStep != null && step <= sidsteStep) continue;
    const forventet = await hotp(secretBytes, step);
    if(sikkerLig(String(kode||''), forventet)) return step;
  }
  return null;
}

function laesCookie(req, navn){
  const c = req.headers.get('cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + navn + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}

async function tjekSpaerre(db, ip){
  try{
    const r = await db.prepare(
      `SELECT antal, foerste FROM login_forsoeg WHERE ip = ?`).bind(ip).first();
    if(!r) return { spaerret:false, antal:0 };
    const alder = (Date.now() - new Date(r.foerste).getTime())/60000;
    if(alder > SPAERRE_MIN){
      await db.prepare(`DELETE FROM login_forsoeg WHERE ip = ?`).bind(ip).run();
      return { spaerret:false, antal:0 };
    }
    return { spaerret: r.antal >= MAX_FORSOEG, antal: r.antal };
  }catch(e){ return { spaerret:false, antal:0 }; }
}
async function taelForsoeg(db, ip){
  try{
    await db.prepare(
      `INSERT INTO login_forsoeg (ip, antal, foerste) VALUES (?, 1, datetime('now'))
       ON CONFLICT(ip) DO UPDATE SET antal = antal + 1`).bind(ip).run();
  }catch(e){}
}
async function nulstilForsoeg(db, ip){
  try{ await db.prepare(`DELETE FROM login_forsoeg WHERE ip = ?`).bind(ip).run(); }
  catch(e){}
}

async function brugerAntal(db){ return (await db.prepare(`SELECT COUNT(*) n FROM users`).first()).n; }
async function brugerVedNavn(db, username){ return db.prepare(`SELECT * FROM users WHERE username = ?`).bind(username).first(); }
async function brugerVedId(db, id){ return db.prepare(`SELECT * FROM users WHERE id = ?`).bind(id).first(); }
async function hentBrugerListe(db){
  const r = await db.prepare(`SELECT id, username, totp_secret, is_admin, created_at FROM users ORDER BY created_at`).all();
  return r.results || [];
}
async function opretBruger(db, { username, password, isAdmin, mustChange }){
  const { hash, salt } = await hashKode(password);
  await db.prepare(`INSERT INTO users
      (username, password_hash, password_salt, is_admin, must_change_password, created_at)
    VALUES (?,?,?,?,?,datetime('now'))`)
    .bind(username, hash, salt, isAdmin ? 1 : 0, mustChange ? 1 : 0).run();
}

function naesteTrinEfterKode(bruger){
  if(bruger.must_change_password) return { purpose:'changepw', sti:'/account/password' };
  if(!bruger.totp_secret) return { purpose:'enroll', sti:'/2fa-setup' };
  return { purpose:'totp', sti:'/2fa-verify' };
}

const esc = s => String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

/* ------------------------------------------------------------------ */
/* Auth-sider - samme visuelle "chrome" som resten af NAP's vaerktoejer */
/* ------------------------------------------------------------------ */

const authCSS = `
:root{color-scheme:light}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#f7f7f5;color:#1a1a18;
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.box{background:#fff;border:1px solid #e3e3df;border-radius:12px;padding:32px;
  width:100%;max-width:420px;margin:20px}
h1{font-size:18px;margin:0 0 4px}
p.s{color:#6b6b66;font-size:13px;margin:0 0 22px}
label{display:block;font-size:12px;color:#6b6b66;margin-bottom:6px;margin-top:12px}
label:first-of-type{margin-top:0}
input{width:100%;padding:10px 12px;border:1px solid #e3e3df;border-radius:8px;
  font-size:15px;background:#fff;color:#1a1a18}
input:focus{outline:2px solid #1856a8;outline-offset:-1px;border-color:#1856a8}
button{width:100%;margin-top:14px;padding:11px;border:none;border-radius:8px;
  background:#1a1a18;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#333}
.fejl{background:#fdecea;border:1px solid #f2c9c5;color:#b3261e;border-radius:8px;
  padding:10px 12px;font-size:13px;margin-bottom:16px}
.ok{background:#e6f5ec;border:1px solid #c9e8d6;color:#0d7a4a;border-radius:8px;
  padding:10px 12px;font-size:13px;margin-bottom:16px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;
  background:#f7f7f5;border:1px solid #e3e3df;border-radius:8px;padding:10px 12px;
  word-break:break-all;user-select:all;letter-spacing:.03em}
a{color:#1856a8}
.qrwrap{display:flex;justify-content:center;margin:16px 0}
.qrwrap svg{width:220px;height:220px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e3e3df}
.pill{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;font-weight:650}
.pill.g{background:#e6f5ec;color:#0d7a4a}.pill.m{background:#f0f1f4;color:#6a6f7a}
form.rowform{display:inline}
.btn2{width:auto;margin-top:0;padding:5px 10px;font-size:12px;font-weight:500;
  background:#fff;color:#1a1a18;border:1px solid #e3e3df}
.btn2:hover{background:#f0f1f4}
`;

const authSide = (titel, undertekst, indhold, bredde) => `<!DOCTYPE html><html lang="da"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(titel)} — NAP Projects</title>
<style>${authCSS}${bredde ? `.box{max-width:${bredde}px}` : ''}</style></head><body>
<div class="box"><h1>${esc(titel)}</h1>${undertekst ? `<p class="s">${undertekst}</p>` : ''}
${indhold}</div></body></html>`;

const loginSide = (fejl) => authSide('NAP Projects', 'Log ind for at fortsætte', `
  ${fejl ? `<div class="fejl">${esc(fejl)}</div>` : ''}
  <form method="POST" action="/login">
    <label for="u">Brugernavn</label>
    <input id="u" name="username" autocomplete="username" autofocus required>
    <label for="p">Adgangskode</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Log ind</button>
  </form>`);

const setupSide = (fejl) => authSide('Opsætning', 'Opret den første (admin-)konto', `
  ${fejl ? `<div class="fejl">${esc(fejl)}</div>` : ''}
  <form method="POST" action="/setup">
    <label for="k">Opsætningsnøgle</label>
    <input id="k" name="setupKey" type="password" autofocus required>
    <label for="u">Brugernavn</label>
    <input id="u" name="username" autocomplete="username" required>
    <label for="p">Adgangskode</label>
    <input id="p" name="password" type="password" autocomplete="new-password" required minlength="10">
    <label for="p2">Gentag adgangskode</label>
    <input id="p2" name="password2" type="password" autocomplete="new-password" required minlength="10">
    <button type="submit">Opret konto</button>
  </form>`);

const setupFaerdigSide = () => authSide('Opsætning er allerede fuldført',
  'Der findes allerede mindst én konto. Bed en administrator om en konto via "Administrer brugere".',
  '<p class="s"><a href="/login">Til login</a></p>');

const totpSetupSide = (brugernavn, secret, fejl) => {
  const label = encodeURIComponent(`NAP Projects:${brugernavn}`);
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent('NAP Projects')}`
    + `&algorithm=SHA1&digits=6&period=30`;
  const gruppe = secret.replace(/(.{4})/g,'$1 ').trim();
  return authSide('Sæt 2FA op', 'Obligatorisk - scan koden med en authenticator-app', `
    ${fejl ? `<div class="fejl">${esc(fejl)}</div>` : ''}
    <div class="qrwrap"><div id="qr"></div></div>
    <p class="s" style="text-align:center;margin:-8px 0 14px">Eller indtast manuelt:</p>
    <div class="mono">${esc(gruppe)}</div>
    <form method="POST" action="/2fa-setup" style="margin-top:18px">
      <label for="kode">6-cifret kode fra appen</label>
      <input id="kode" name="kode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus required
        autocomplete="one-time-code">
      <button type="submit">Bekræft og fortsæt</button>
    </form>
    <script src="/qrcode.js"></script>
    <script>
      var qr = qrcode(0, 'M');
      qr.addData(${JSON.stringify(uri)});
      qr.make();
      document.getElementById('qr').innerHTML = qr.createSvgTag({ scalable: true });
    </script>`);
};

const totpVerifySide = (fejl) => authSide('Bekræft med 2FA', 'Indtast koden fra din authenticator-app', `
  ${fejl ? `<div class="fejl">${esc(fejl)}</div>` : ''}
  <form method="POST" action="/2fa-verify">
    <label for="kode">6-cifret kode</label>
    <input id="kode" name="kode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus required
      autocomplete="one-time-code">
    <button type="submit">Log ind</button>
  </form>`);

const changePasswordSide = (tvunget, fejl, ok) => authSide('Skift adgangskode',
  tvunget ? 'Du skal sætte en ny adgangskode før du kan fortsætte' : 'Opdatér din egen adgangskode', `
  ${fejl ? `<div class="fejl">${esc(fejl)}</div>` : ''}
  ${ok ? `<div class="ok">Adgangskode ændret.</div>` : ''}
  <form method="POST" action="/account/password">
    ${tvunget ? '' : `
    <label for="nuv">Nuværende adgangskode</label>
    <input id="nuv" name="nuvaerende" type="password" autocomplete="current-password" required>`}
    <label for="ny">Ny adgangskode</label>
    <input id="ny" name="ny" type="password" autocomplete="new-password" required minlength="10" autofocus>
    <label for="ny2">Gentag ny adgangskode</label>
    <input id="ny2" name="ny2" type="password" autocomplete="new-password" required minlength="10">
    <button type="submit">Skift adgangskode</button>
  </form>
  ${tvunget ? '' : '<p class="s" style="margin-top:14px"><a href="/">Til projekter</a></p>'}`);

const adminUsersSide = (brugere, nyKode, fejl) => authSide('Administrer brugere', null, `
  ${fejl ? `<div class="fejl">${esc(fejl)}</div>` : ''}
  ${nyKode ? `<div class="ok">Bruger oprettet. Midlertidig adgangskode (vises kun denne ene gang):<br>
    <div class="mono" style="margin-top:6px">${esc(nyKode)}</div></div>` : ''}
  <table><thead><tr><th>Bruger</th><th>2FA</th><th>Admin</th><th></th></tr></thead><tbody>
  ${brugere.map(b => `<tr><td>${esc(b.username)}</td>
    <td>${b.totp_secret ? '<span class="pill g">sat op</span>' : '<span class="pill m">mangler</span>'}</td>
    <td>${b.is_admin ? '<span class="pill g">ja</span>' : '–'}</td>
    <td>
      <form class="rowform" method="POST" action="/admin/users">
        <input type="hidden" name="action" value="reset2fa"><input type="hidden" name="id" value="${b.id}">
        <button class="btn2" type="submit">Nulstil 2FA</button>
      </form>
      <form class="rowform" method="POST" action="/admin/users">
        <input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="${b.id}">
        <button class="btn2" type="submit">Slet</button>
      </form>
    </td></tr>`).join('')}
  </tbody></table>
  <form method="POST" action="/admin/users" style="margin-top:20px">
    <input type="hidden" name="action" value="create">
    <label for="nu">Nyt brugernavn</label>
    <input id="nu" name="username" autocomplete="off" required>
    <button type="submit">Opret bruger (midlertidig kode genereres)</button>
  </form>
  <p class="s" style="margin-top:14px"><a href="/">Til projekter</a></p>`, 520);

const html = (body, status = 200, extra = {}) => {
  const headers = new Headers({
    'content-type':'text/html; charset=utf-8', 'cache-control':'no-store',
    'x-frame-options':'DENY', 'referrer-policy':'no-referrer',
  });
  for(const [k, v] of Object.entries(extra)){
    if(k.toLowerCase() === 'set-cookie' && Array.isArray(v)) v.forEach(c => headers.append('set-cookie', c));
    else headers.set(k, v);
  }
  return new Response(body, { status, headers });
};

/* ------------------------------------------------------------------ */
/* Data - projekter/opgaver                                            */
/* ------------------------------------------------------------------ */

/**
 * Rydder alt der peger paa en opgave - tags, blocked-by-relationer, kommentarer
 * og vedhaeftede filer (baade D1-raekken og selve objektet i R2). Bruges baade
 * ved sletning af en enkelt opgave og ved sletning af et helt projekt.
 */
async function ryddTaskRelationer(env, taskId){
  const filer = await env.DB.prepare(`SELECT r2_key FROM task_attachments WHERE task_id=?`).bind(taskId).all();
  for(const f of (filer.results || [])){
    try{ await env.FILES.delete(f.r2_key); }catch(e){}
  }
  await env.DB.prepare(`DELETE FROM task_attachments WHERE task_id=?`).bind(taskId).run();
  await env.DB.prepare(`DELETE FROM task_tags WHERE task_id=?`).bind(taskId).run();
  await env.DB.prepare(`DELETE FROM task_deps WHERE task_id=? OR depends_on_task_id=?`).bind(taskId, taskId).run();
  await env.DB.prepare(`DELETE FROM task_comments WHERE task_id=?`).bind(taskId).run();
}

async function hentAlt(db){
  const [projekter, opgaver, brugere, tags, taskTags, deps] = await Promise.all([
    db.prepare(`SELECT id, name, icon, start_date, due_date, effort, archived, position, description
      FROM projects ORDER BY position, id`).all(),
    db.prepare(`SELECT id, project_id, name, status, priority, assignee_id, due_date, position, description, parent_task_id
      FROM tasks ORDER BY position, id`).all(),
    db.prepare(`SELECT id, username FROM users ORDER BY username`).all(),
    db.prepare(`SELECT id, name, color FROM tags ORDER BY name`).all(),
    db.prepare(`SELECT task_id, tag_id FROM task_tags`).all(),
    db.prepare(`SELECT task_id, depends_on_task_id FROM task_deps`).all(),
  ]);
  const tagsPrTask = {};
  for(const r of taskTags.results || []){ (tagsPrTask[r.task_id] ||= []).push(r.tag_id); }
  const blockedByPrTask = {};
  const blockerPrTask = {};
  for(const r of deps.results || []){
    (blockedByPrTask[r.task_id] ||= []).push(r.depends_on_task_id);
    (blockerPrTask[r.depends_on_task_id] ||= []).push(r.task_id);
  }
  const opg = (opgaver.results || []).map(t => ({
    ...t,
    tags: tagsPrTask[t.id] || [],
    blocked_by: blockedByPrTask[t.id] || [],
    blocking: blockerPrTask[t.id] || [],
  }));
  return {
    projects: projekter.results || [],
    tasks: opg,
    users: brugere.results || [],
    tags: tags.results || [],
  };
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

export default {
  async fetch(req, env, ctx){
    const url = new URL(req.url);
    const ip = req.headers.get('cf-connecting-ip') || 'ukendt';

    if(!env.SESSION_SECRET){
      return html('<h1>Ikke konfigureret</h1><p>Secret SESSION_SECRET mangler.</p>', 500);
    }

    if(url.pathname === '/qrcode.js'){
      const res = await env.ASSETS.fetch(req);
      return new Response(res.body, { status:res.status,
        headers:{ 'content-type':'application/javascript; charset=utf-8', 'cache-control':'public, max-age=86400' } });
    }

    if(url.pathname === '/setup'){
      if(await brugerAntal(env.DB) > 0) return html(setupFaerdigSide(), 403);
      if(req.method === 'POST'){
        const form = await req.formData();
        const setupKey = String(form.get('setupKey') || '');
        const username = String(form.get('username') || '').trim();
        const password = String(form.get('password') || '');
        const password2 = String(form.get('password2') || '');
        if(!env.SETUP_KEY || !sikkerLig(setupKey, env.SETUP_KEY))
          return html(setupSide('Forkert opsætningsnøgle.'), 401);
        if(!username) return html(setupSide('Brugernavn mangler.'), 400);
        if(password.length < 10 || password !== password2)
          return html(setupSide('Adgangskoderne matcher ikke, eller er under 10 tegn.'), 400);
        await opretBruger(env.DB, { username, password, isAdmin:true, mustChange:false });
        const bruger = await brugerVedNavn(env.DB, username);
        const trin = naesteTrinEfterKode(bruger);
        const secret = trin.purpose === 'enroll' ? nyTotpHemmelighed() : '';
        const preauth = await lavPreauthToken(env, trin.purpose, bruger.id, secret);
        return html('<meta http-equiv="refresh" content="0;url=' + trin.sti + '">', 302, {
          'set-cookie': SESSION_COOKIE('napp_preauth', preauth, PREAUTH_MIN*60), 'location': trin.sti,
        });
      }
      return html(setupSide(null));
    }

    if(url.pathname === '/login'){
      if(req.method === 'POST'){
        const sp = await tjekSpaerre(env.DB, ip);
        if(sp.spaerret)
          return html(loginSide(`For mange forsoeg. Proev igen om ${SPAERRE_MIN} minutter.`), 429);
        const form = await req.formData();
        const username = String(form.get('username') || '').trim();
        const password = String(form.get('password') || '');
        const bruger = username ? await brugerVedNavn(env.DB, username) : null;
        const korrekt = bruger && await verificerKode(password, bruger.password_hash, bruger.password_salt);
        if(korrekt){
          await nulstilForsoeg(env.DB, ip);
          const trin = naesteTrinEfterKode(bruger);
          const secret = trin.purpose === 'enroll' ? nyTotpHemmelighed() : '';
          const preauth = await lavPreauthToken(env, trin.purpose, bruger.id, secret);
          return html('<meta http-equiv="refresh" content="0;url=' + trin.sti + '">', 302, {
            'set-cookie': SESSION_COOKIE('napp_preauth', preauth, PREAUTH_MIN*60), 'location': trin.sti,
          });
        }
        await taelForsoeg(env.DB, ip);
        return html(loginSide('Forkert brugernavn eller adgangskode.'), 401);
      }
      return html(loginSide(null));
    }

    if(url.pathname === '/2fa-setup'){
      const pre = await gyldigPreauthToken(env, laesCookie(req, 'napp_preauth'), 'enroll');
      if(!pre) return html(loginSide(null), 401);
      const bruger = await brugerVedId(env.DB, pre.uid);
      if(!bruger) return html(loginSide(null), 401);
      if(req.method === 'POST'){
        const sp = await tjekSpaerre(env.DB, ip);
        if(sp.spaerret)
          return html(totpSetupSide(bruger.username, pre.ekstra,
            `For mange forsoeg. Proev igen om ${SPAERRE_MIN} minutter.`), 429);
        const form = await req.formData();
        const kode = String(form.get('kode') || '');
        const step = await totpVerificer(pre.ekstra, kode, null);
        if(step == null){
          await taelForsoeg(env.DB, ip);
          return html(totpSetupSide(bruger.username, pre.ekstra, 'Forkert kode.'), 401);
        }
        await nulstilForsoeg(env.DB, ip);
        await env.DB.prepare(`UPDATE users SET totp_secret=?, last_totp_step=? WHERE id=?`)
          .bind(pre.ekstra, step, bruger.id).run();
        const token = await lavToken(env, bruger.id);
        return html('<meta http-equiv="refresh" content="0;url=/">', 302, {
          'set-cookie': [SESSION_COOKIE('napp_session', token, SESSION_DAGE*86400), RYD_COOKIE('napp_preauth')],
          'location': '/',
        });
      }
      return html(totpSetupSide(bruger.username, pre.ekstra, null));
    }

    if(url.pathname === '/2fa-verify'){
      const pre = await gyldigPreauthToken(env, laesCookie(req, 'napp_preauth'), 'totp');
      if(!pre) return html(loginSide(null), 401);
      const bruger = await brugerVedId(env.DB, pre.uid);
      if(!bruger) return html(loginSide(null), 401);
      if(req.method === 'POST'){
        const sp = await tjekSpaerre(env.DB, ip);
        if(sp.spaerret)
          return html(totpVerifySide(`For mange forsoeg. Proev igen om ${SPAERRE_MIN} minutter.`), 429);
        const form = await req.formData();
        const kode = String(form.get('kode') || '');
        const step = await totpVerificer(bruger.totp_secret, kode, bruger.last_totp_step);
        if(step == null){
          await taelForsoeg(env.DB, ip);
          return html(totpVerifySide('Forkert eller allerede brugt kode.'), 401);
        }
        await nulstilForsoeg(env.DB, ip);
        await env.DB.prepare(`UPDATE users SET last_totp_step=? WHERE id=?`).bind(step, bruger.id).run();
        const token = await lavToken(env, bruger.id);
        return html('<meta http-equiv="refresh" content="0;url=/">', 302, {
          'set-cookie': [SESSION_COOKIE('napp_session', token, SESSION_DAGE*86400), RYD_COOKIE('napp_preauth')],
          'location': '/',
        });
      }
      return html(totpVerifySide(null));
    }

    if(url.pathname === '/account/password'){
      const pre = await gyldigPreauthToken(env, laesCookie(req, 'napp_preauth'), 'changepw');
      const session = pre ? null : await gyldigToken(env, laesCookie(req, 'napp_session'));
      if(!pre && !session) return html(loginSide(null), 401);
      const bruger = await brugerVedId(env.DB, pre ? pre.uid : session.uid);
      if(!bruger) return html(loginSide(null), 401);
      if(req.method === 'POST'){
        const form = await req.formData();
        const ny = String(form.get('ny') || ''), ny2 = String(form.get('ny2') || '');
        if(!pre){
          const nuvaerende = String(form.get('nuvaerende') || '');
          if(!await verificerKode(nuvaerende, bruger.password_hash, bruger.password_salt))
            return html(changePasswordSide(false, 'Forkert nuværende adgangskode.'), 401);
        }
        if(ny.length < 10 || ny !== ny2)
          return html(changePasswordSide(!!pre, 'Adgangskoderne matcher ikke, eller er under 10 tegn.'), 400);
        const { hash, salt } = await hashKode(ny);
        await env.DB.prepare(`UPDATE users SET password_hash=?, password_salt=?, must_change_password=0 WHERE id=?`)
          .bind(hash, salt, bruger.id).run();
        if(pre){
          const opdateret = await brugerVedId(env.DB, bruger.id);
          const trin = naesteTrinEfterKode(opdateret);
          const secret = trin.purpose === 'enroll' ? nyTotpHemmelighed() : '';
          const nyPreauth = await lavPreauthToken(env, trin.purpose, bruger.id, secret);
          return html('<meta http-equiv="refresh" content="0;url=' + trin.sti + '">', 302, {
            'set-cookie': SESSION_COOKIE('napp_preauth', nyPreauth, PREAUTH_MIN*60), 'location': trin.sti,
          });
        }
        return html(changePasswordSide(false, null, true));
      }
      return html(changePasswordSide(!!pre, null));
    }

    if(url.pathname === '/logout'){
      return html('<meta http-equiv="refresh" content="0;url=/login">', 302, {
        'set-cookie': [RYD_COOKIE('napp_session'), RYD_COOKIE('napp_preauth')],
        'location': '/login',
      });
    }

    /* --- Alt herunder kraever gyldig session ----------------------- */
    const okToken = await gyldigToken(env, laesCookie(req, 'napp_session'));
    if(!okToken){
      if(url.pathname.startsWith('/api/')) return json({ error:'ikke logget ind' }, 401);
      return html(loginSide(null), 401);
    }
    const mig = await brugerVedId(env.DB, okToken.uid);
    if(!mig) return html(loginSide(null), 401);

    if(url.pathname === '/admin/users'){
      if(!mig.is_admin) return html('<h1>Ikke tilladt</h1>', 403);
      if(req.method === 'POST'){
        const form = await req.formData();
        const action = String(form.get('action') || '');
        if(action === 'create'){
          const username = String(form.get('username') || '').trim();
          if(!username) return html(adminUsersSide(await hentBrugerListe(env.DB), null, 'Brugernavn mangler.'));
          if(await brugerVedNavn(env.DB, username))
            return html(adminUsersSide(await hentBrugerListe(env.DB), null, 'Brugernavnet er allerede i brug.'));
          const kode = tilfaeldigKode(14);
          await opretBruger(env.DB, { username, password:kode, isAdmin:false, mustChange:true });
          return html(adminUsersSide(await hentBrugerListe(env.DB), kode, null));
        }
        if(action === 'delete'){
          const id = Number(form.get('id'));
          if(id === mig.id)
            return html(adminUsersSide(await hentBrugerListe(env.DB), null, 'Du kan ikke slette din egen konto.'));
          await env.DB.prepare(`DELETE FROM users WHERE id=?`).bind(id).run();
          await env.DB.prepare(`UPDATE tasks SET assignee_id=NULL WHERE assignee_id=?`).bind(id).run();
          return html(adminUsersSide(await hentBrugerListe(env.DB), null, null));
        }
        if(action === 'reset2fa'){
          const id = Number(form.get('id'));
          await env.DB.prepare(`UPDATE users SET totp_secret=NULL, last_totp_step=NULL WHERE id=?`).bind(id).run();
          return html(adminUsersSide(await hentBrugerListe(env.DB), null, null));
        }
      }
      return html(adminUsersSide(await hentBrugerListe(env.DB), null, null));
    }

    if(url.pathname === '/api/me') return json({ id: mig.id, username: mig.username, isAdmin: !!mig.is_admin });

    if(url.pathname === '/api/all' && req.method === 'GET'){
      return json(await hentAlt(env.DB));
    }

    if(url.pathname === '/api/projects' && req.method === 'POST'){
      const b = await req.json();
      const r = await env.DB.prepare(`INSERT INTO projects (name, icon, start_date, due_date, effort, created_at, created_by)
        VALUES (?,?,?,?,?,datetime('now'),?)`)
        .bind(String(b.name||'Nyt projekt'), String(b.icon||'📁'), b.start_date||null, b.due_date||null, b.effort||null, mig.id).run();
      return json({ id: r.meta.last_row_id });
    }
    if(url.pathname.match(/^\/api\/projects\/\d+$/) && (req.method === 'PATCH' || req.method === 'DELETE')){
      const id = Number(url.pathname.split('/').pop());
      if(req.method === 'DELETE'){
        const taskIds = (await env.DB.prepare(`SELECT id FROM tasks WHERE project_id=?`).bind(id).all())
          .results.map(r => r.id);
        for(const tid of taskIds){
          await ryddTaskRelationer(env, tid);
        }
        await env.DB.prepare(`DELETE FROM tasks WHERE project_id=?`).bind(id).run();
        await env.DB.prepare(`DELETE FROM projects WHERE id=?`).bind(id).run();
        return json({ ok:true });
      }
      const b = await req.json();
      const felter = ['name','icon','start_date','due_date','effort','archived','position','description'];
      const sat = felter.filter(f => f in b);
      if(sat.length){
        await env.DB.prepare(`UPDATE projects SET ${sat.map(f=>`${f}=?`).join(',')} WHERE id=?`)
          .bind(...sat.map(f=>b[f]), id).run();
      }
      return json({ ok:true });
    }

    if(url.pathname === '/api/tasks' && req.method === 'POST'){
      const b = await req.json();
      const r = await env.DB.prepare(`INSERT INTO tasks (project_id, name, status, priority, assignee_id, due_date, parent_task_id, created_at, created_by)
        VALUES (?,?,?,?,?,?,?,datetime('now'),?)`)
        .bind(Number(b.project_id), String(b.name||'Ny opgave'), b.status||'Not started', b.priority||null,
              b.assignee_id||null, b.due_date||null, b.parent_task_id||null, mig.id).run();
      return json({ id: r.meta.last_row_id });
    }
    if(url.pathname.match(/^\/api\/tasks\/\d+\/comments$/)){
      const taskId = Number(url.pathname.split('/')[3]);
      if(req.method === 'POST'){
        const b = await req.json();
        const body = String(b.body||'').trim();
        if(!body) return json({ error:'tom kommentar' }, 400);
        const r = await env.DB.prepare(`INSERT INTO task_comments (task_id, user_id, body, created_at)
          VALUES (?,?,?,datetime('now'))`).bind(taskId, mig.id, body).run();
        return json({ id: r.meta.last_row_id });
      }
      const r = await env.DB.prepare(`SELECT id, task_id, user_id, body, created_at
        FROM task_comments WHERE task_id=? ORDER BY id`).bind(taskId).all();
      return json(r.results || []);
    }

    /* --- Vedhaeftede filer (R2) ------------------------------------ */
    if(url.pathname.match(/^\/api\/tasks\/\d+\/attachments$/)){
      const taskId = Number(url.pathname.split('/')[3]);
      if(req.method === 'POST'){
        const form = await req.formData();
        const file = form.get('file');
        if(!file || typeof file === 'string') return json({ error:'ingen fil' }, 400);
        const key = 'task-' + taskId + '/' + crypto.randomUUID() + '-' + file.name;
        await env.FILES.put(key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
        const r = await env.DB.prepare(`INSERT INTO task_attachments (task_id, filename, size, content_type, r2_key, uploaded_by, uploaded_at)
          VALUES (?,?,?,?,?,?,datetime('now'))`)
          .bind(taskId, file.name, file.size, file.type || null, key, mig.id).run();
        return json({ id: r.meta.last_row_id });
      }
      const r = await env.DB.prepare(`SELECT id, task_id, filename, size, content_type, uploaded_by, uploaded_at
        FROM task_attachments WHERE task_id=? ORDER BY id`).bind(taskId).all();
      return json(r.results || []);
    }
    if(url.pathname.match(/^\/api\/attachments\/\d+\/download$/)){
      const id = Number(url.pathname.split('/')[3]);
      const row = await env.DB.prepare(`SELECT * FROM task_attachments WHERE id=?`).bind(id).first();
      if(!row) return html('<h1>404</h1>', 404);
      const obj = await env.FILES.get(row.r2_key);
      if(!obj) return html('<h1>404</h1>', 404);
      const headers = new Headers();
      headers.set('content-type', row.content_type || 'application/octet-stream');
      headers.set('content-disposition', 'attachment; filename="' + String(row.filename).replace(/"/g,'') + '"');
      headers.set('cache-control', 'private, max-age=3600');
      return new Response(obj.body, { headers });
    }
    if(url.pathname.match(/^\/api\/attachments\/\d+$/) && req.method === 'DELETE'){
      const id = Number(url.pathname.split('/').pop());
      const row = await env.DB.prepare(`SELECT r2_key FROM task_attachments WHERE id=?`).bind(id).first();
      if(row){ try{ await env.FILES.delete(row.r2_key); }catch(e){} }
      await env.DB.prepare(`DELETE FROM task_attachments WHERE id=?`).bind(id).run();
      return json({ ok:true });
    }

    if(url.pathname.match(/^\/api\/tasks\/\d+$/) && (req.method === 'PATCH' || req.method === 'DELETE')){
      const id = Number(url.pathname.split('/').pop());
      if(req.method === 'DELETE'){
        await ryddTaskRelationer(env, id);
        await env.DB.prepare(`UPDATE tasks SET parent_task_id=NULL WHERE parent_task_id=?`).bind(id).run();
        await env.DB.prepare(`DELETE FROM tasks WHERE id=?`).bind(id).run();
        return json({ ok:true });
      }
      const b = await req.json();
      const felter = ['project_id','name','status','priority','assignee_id','due_date','position','description','parent_task_id'];
      const sat = felter.filter(f => f in b);
      if(sat.length){
        await env.DB.prepare(`UPDATE tasks SET ${sat.map(f=>`${f}=?`).join(',')} WHERE id=?`)
          .bind(...sat.map(f=>b[f]), id).run();
      }
      if(Array.isArray(b.tags)){
        await env.DB.prepare(`DELETE FROM task_tags WHERE task_id=?`).bind(id).run();
        for(const tagId of b.tags){
          await env.DB.prepare(`INSERT OR IGNORE INTO task_tags (task_id, tag_id) VALUES (?,?)`).bind(id, tagId).run();
        }
      }
      if(Array.isArray(b.blocked_by)){
        await env.DB.prepare(`DELETE FROM task_deps WHERE task_id=?`).bind(id).run();
        for(const depId of b.blocked_by){
          if(depId !== id)
            await env.DB.prepare(`INSERT OR IGNORE INTO task_deps (task_id, depends_on_task_id) VALUES (?,?)`).bind(id, depId).run();
        }
      }
      return json({ ok:true });
    }

    if(url.pathname === '/api/tags' && req.method === 'POST'){
      const b = await req.json();
      const navn = String(b.name||'').trim();
      if(!navn) return json({ error:'navn mangler' }, 400);
      const r = await env.DB.prepare(`INSERT INTO tags (name, color) VALUES (?,?)
        ON CONFLICT(name) DO UPDATE SET name=excluded.name RETURNING id`).bind(navn, b.color||'gray').first();
      return json({ id: r.id });
    }

    if(url.pathname === '/api/users' && req.method === 'GET'){
      const r = await env.DB.prepare(`SELECT id, username FROM users ORDER BY username`).all();
      return json(r.results || []);
    }

    /* --- Statiske filer / app-shell -------------------------------- */
    const res = await env.ASSETS.fetch(req);
    const h = new Headers(res.headers);
    h.set('x-frame-options','DENY'); h.set('referrer-policy','no-referrer'); h.set('cache-control','no-store');
    return new Response(res.body, { status:res.status, headers:h });
  },
};
