"use strict";
/* Mon patrimoine, appli iPhone.
   - Les chiffres arrivent dans un fichier chiffré (AES-256-GCM) déposé dans Dropbox par le PC.
   - Sur le téléphone, seule la version chiffrée est gardée. En clair, les données n'existent qu'en mémoire.
   - Aucun envoi vers un autre site que Dropbox (lecture seule du fichier). */
const MPC = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder(), ITER = 600000;
  const b64 = u8 => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const aad = (iter, salt) => enc.encode(`MPv1|${iter}|${salt}`);
  const importKey = raw => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  async function deriveRaw(pass, salt, iter) {
    const base = await crypto.subtle.importKey("raw", enc.encode(pass.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, base, 256));
  }
  async function seal(raw, obj, salt, iter) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(iter, salt) }, await importKey(raw), enc.encode(JSON.stringify(obj))));
    return JSON.stringify({ v: 1, kdf: "PBKDF2-SHA256", iter, salt, iv: b64(iv), ct: b64(ct) });
  }
  async function open(raw, text) {
    const h = JSON.parse(text);
    if (h.v !== 1 || !Number.isInteger(h.iter) || h.iter < 300000 || h.iter > 5000000) throw new Error("format");
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(h.iv), additionalData: aad(h.iter, h.salt) }, await importKey(raw), unb64(h.ct));
    return JSON.parse(dec.decode(pt));
  }
  function phrase() {   // 4 mots de 3 syllabes : environ 80 bits, faciles à taper
    const C = "bdfgklmnprstvz", V = "aeiou", r = n => { const a = new Uint32Array(1); let x; do { crypto.getRandomValues(a); x = a[0]; } while (x >= 4294967296 - (4294967296 % n)); return x % n; };
    return Array.from({ length: 4 }, () => Array.from({ length: 3 }, () => C[r(C.length)] + V[r(V.length)]).join("")).join("-");
  }
  return { b64, unb64, ITER, deriveRaw, seal, open, phrase };
})();

/* ---------- stockage local (IndexedDB, avec repli en mémoire) ---------- */
const mem = new Map();
const kv = (() => {
  let db = null;
  const open = () => db ? Promise.resolve(db) : new Promise((res, rej) => {
    try {
      const r = indexedDB.open("mp-tel", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("kv");
      r.onsuccess = () => { db = r.result; res(db); };
      r.onerror = () => rej(r.error);
    } catch (e) { rej(e); }
  });
  const tx = async (mode, fn) => { const d = await open(); return new Promise((res, rej) => { const t = d.transaction("kv", mode), s = t.objectStore("kv"), q = fn(s); t.oncomplete = () => res(q && q.result); t.onerror = () => rej(t.error); }); };
  return {
    async get(k) { try { return await tx("readonly", s => s.get(k)); } catch (e) { return mem.get(k); } },
    async set(k, v) { try { await tx("readwrite", s => s.put(v, k)); } catch (e) { mem.set(k, v); } },
    async clear() { mem.clear(); try { await tx("readwrite", s => s.clear()); } catch (e) { /* rien */ } },
  };
})();

/* ---------- outils ---------- */
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = n => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, "’");
const MONTHS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];
const dstr = iso => { const [y, m, d] = iso.split("-"); return `${+d} ${MONTHS[+m - 1]} ${y}`; };
const isoOf = d => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const todayIso = () => isoOf(new Date());
const daysBetween = (a, b) => Math.round((Date.parse(b + "T00:00:00Z") - Date.parse(a + "T00:00:00Z")) / 864e5);
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.hidden = false; clearTimeout(toast.h); toast.h = setTimeout(() => { t.hidden = true; }, 4000); }
const ICONS = {
  home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>', week: '<rect x="3" y="5" width="18" height="16" rx="3"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  goal: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/>', gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
};
const icon = n => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[n]}</svg>`;

/* ---------- état ---------- */
const MAX_FAILS = 10, AUTO_LOCK_MS = 60000, IDLE_MS = 180000, STALE_COPY_DAYS = 8;
let S = { key: null, pass: "", data: null, at: "", tab: "home", saving: null, busy: false, wipeAsk: false, setup: null };
let hiddenAt = 0, idleTimer = null;

function setSaving() { if (S.saving === null && S.data) S.saving = S.data.settings.monthly_saving; }
function applyWidths() { document.querySelectorAll("[data-w]").forEach(e => { e.style.width = e.dataset.w + "%"; }); }
function show(html) { $("#app").innerHTML = html; applyWidths(); }
function resetIdle() { clearTimeout(idleTimer); if (S.key) idleTimer = setTimeout(lock, IDLE_MS); }

/* ---------- verrouillage ---------- */
function lock() {
  if (S.key) S.key.fill(0);
  S.key = null; S.pass = ""; S.data = null; S.saving = null; S.wipeAsk = false;
  clearTimeout(idleTimer);
  screenLock();
}
async function wipe() {
  lock(); await kv.clear();
  screenSetup();
}
document.addEventListener("visibilitychange", () => {
  const c = $("#cover");
  if (document.hidden) { c.textContent = "Mon patrimoine"; c.hidden = false; hiddenAt = Date.now(); }
  else { c.hidden = true; if (S.key && hiddenAt && Date.now() - hiddenAt > AUTO_LOCK_MS) lock(); else resetIdle(); }
});
window.addEventListener("pagehide", () => { if (S.key) { $("#cover").textContent = "Mon patrimoine"; $("#cover").hidden = false; } });
["pointerdown", "keydown", "scroll"].forEach(ev => document.addEventListener(ev, resetIdle, { passive: true }));

/* ---------- Dropbox (lecture seule du fichier chiffré) ---------- */
const DBX_TOKEN = "https://api.dropboxapi.com/oauth2/token";
const b64u = u8 => MPC.b64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function pkce() {
  const v = b64u(crypto.getRandomValues(new Uint8Array(48)));
  const ch = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v))));
  return { v, ch };
}
async function tokenCall(params) {
  const r = await fetch(DBX_TOKEN, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params), credentials: "omit", referrerPolicy: "no-referrer" });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error_description || j.error || "Dropbox a refusé");
  return j;
}
async function downloadBlob(accessToken) {
  const r = await fetch("https://content.dropboxapi.com/2/files/download", { method: "POST", credentials: "omit", referrerPolicy: "no-referrer",
    headers: { Authorization: "Bearer " + accessToken, "Dropbox-API-Arg": JSON.stringify({ path: "/patrimoine.enc" }) } });
  if (r.status === 409) { const d = (await r.text().catch(() => "")).slice(0, 140); let ls = ""; try { const q = await fetch("https://api.dropboxapi.com/2/files/list_folder", { method: "POST", credentials: "omit", referrerPolicy: "no-referrer", headers: { Authorization: "Bearer " + accessToken, "Content-Type": "application/json" }, body: JSON.stringify({ path: "", limit: 20 }) }); const qj = await q.json(); ls = q.ok ? " Contenu: " + (qj.entries.map(x => x.name).join(", ") || "vide") : " Liste: " + JSON.stringify(qj).slice(0, 100); } catch (e) { ls = " Liste impossible"; } throw new Error("Introuvable (" + d.slice(0, 60) + ")." + ls); }
  if (!r.ok) throw new Error("Dropbox : erreur " + r.status);
  const t = await r.text();
  if (t.length > 3_000_000) throw new Error("fichier trop gros");
  return t;
}

/* ---------- ouverture d'un fichier chiffré ---------- */
async function keyFor(header, pass) {
  if (S.key && S.hdr && S.hdr.salt === header.salt && S.hdr.iter === header.iter) return S.key;
  return MPC.deriveRaw(pass, MPC.unb64(header.salt), header.iter);
}
async function openBlob(text, pass, minGen) {
  const header = JSON.parse(text), raw = await keyFor(header, pass);
  const payload = await MPC.open(raw, text);          // échoue si phrase fausse ou fichier modifié
  if (!payload || typeof payload.gen !== "number" || !payload.data) throw new Error("contenu inattendu");
  if (payload.gen < minGen) throw new Error("ancien");   // protège contre un vieux fichier remis en place
  return { raw, header, payload };
}
function adopt(o) { if (S.key && S.key !== o.raw) S.key.fill(0); S.key = o.raw; S.hdr = { salt: o.header.salt, iter: o.header.iter }; S.data = o.payload.data; S.at = o.payload.at; S.saving = null; setSaving(); }

/* ---------- synchronisation (à l'ouverture et à la demande) ---------- */
async function syncNow(manual) {
  if (S.busy || !S.key) return;
  S.busy = true; if (S.tab === "settings") render();
  try {
    const sealed = await kv.get("tok"), appkey = await kv.get("appkey");
    if (!sealed || !appkey) throw new Error("Dropbox n'est pas connecté.");
    const rt = (await MPC.open(S.key, sealed)).rt;
    const at = (await tokenCall({ grant_type: "refresh_token", refresh_token: rt, client_id: appkey })).access_token;
    const text = await downloadBlob(at);
    const old = await kv.get("blob");
    if (text === old) { await kv.set("last", new Date().toISOString()); if (manual) toast("Déjà à jour."); return; }
    const o = await openBlob(text, S.pass, (await kv.get("gen")) || 0);
    const rekey = !S.hdr || o.header.salt !== S.hdr.salt;
    adopt(o);
    await kv.set("blob", text); await kv.set("gen", o.payload.gen); await kv.set("last", new Date().toISOString());
    if (rekey) await kv.set("tok", await MPC.seal(S.key, { rt }, o.header.salt, o.header.iter));
    toast("Données mises à jour.");
  } catch (e) {
    toast(e.message === "ancien" ? "Fichier plus ancien que le tien : refusé." : /decrypt|operation|OperationError/i.test(String(e)) ? "Le fichier Dropbox ne s'ouvre pas avec ta phrase de passe." : (navigator.onLine ? e.message : "Pas de réseau : données du dernier envoi."));
  } finally { S.busy = false; if (S.key) render(); }
}

/* ---------- écrans : première configuration ---------- */
function screenSetup(step) {
  S.setup = S.setup || { appkey: "kg69yxxh9yua5rm", ver: "" };
  show(`<div class="page"><div><div class="eyebrow">Première ouverture</div><h1>Mon patrimoine</h1></div>
    <div class="note">Cette appli lit une copie chiffrée de tes chiffres dans ton Dropbox. Rien d'autre n'est envoyé nulle part. Il te faut la clé de ton appli Dropbox et la phrase de passe choisie sur le PC.</div>
    <form class="card" id="setupForm" autocomplete="on">
      <p class="muted">Clé Dropbox intégrée à l'appli.</p>
      <input class="sr" type="text" name="username" autocomplete="username" value="MonPatrimoine" tabindex="-1" aria-hidden="true">
      <label class="field">Phrase de passe<input id="sPass" type="password" name="password" autocomplete="new-password" autocapitalize="off" required></label>
      ${S.setup.url ? `<a class="btn primary btnlink" href="${esc(S.setup.url)}" target="_blank" rel="noopener noreferrer">1. Autoriser dans Dropbox</a>
        <label class="field">2. Colle ici le code donné par Dropbox<input id="sCode" type="text" autocapitalize="off" autocorrect="off" spellcheck="false" required></label>
        <button class="btn primary" type="submit">3. Terminer</button>` : `<button class="btn primary" type="submit">Continuer</button>`}
    </form></div>`);
}
async function setupSubmit() {
  const appkey = "kg69yxxh9yua5rm", pass = $("#sPass").value;
  if (pass.length < 16) { toast("Phrase de passe trop courte (16 caractères minimum)."); return; }
  if (!S.setup.url) {
    const p = await pkce();
    S.setup = { appkey, ver: p.v, pass, url: `https://www.dropbox.com/oauth2/authorize?client_id=${encodeURIComponent(appkey)}&response_type=code&code_challenge=${p.ch}&code_challenge_method=S256&token_access_type=offline&scope=files.content.read%20files.metadata.read` };
    await kv.set("pkce", { appkey, ver: p.v, url: S.setup.url });
    screenSetup(); $("#sPass").value = pass; return;
  }
  const code = $("#sCode").value.trim();
  toast("Connexion en cours…");
  try {
    const t = await tokenCall({ grant_type: "authorization_code", code, code_verifier: S.setup.ver, client_id: S.setup.appkey });
    if (t.scope && !/files\.content\.read/.test(t.scope)) throw new Error("Droits Dropbox insuffisants.");
    const text = await downloadBlob(t.access_token);
    const o = await openBlob(text, pass, 0);
    S.pass = pass; adopt(o);
    await kv.set("appkey", S.setup.appkey); await kv.set("blob", text); await kv.set("gen", o.payload.gen); await kv.set("fails", 0);
    await kv.set("tok", await MPC.seal(S.key, { rt: t.refresh_token }, o.header.salt, o.header.iter)); await kv.set("last", new Date().toISOString());
    S.setup = null; S.tab = "home"; render(); resetIdle();
    toast("Prêt. Pense à ajouter l'appli à l'écran d'accueil.");
  } catch (e) { toast(/decrypt|operation|OperationError/i.test(String(e)) ? "Phrase de passe incorrecte pour ce fichier." : e.message); }
}

/* ---------- écran : verrouillé ---------- */
let lockedUntil = 0;
function screenLock() {
  show(`<div class="page"><div><div class="eyebrow">Verrouillé</div><h1>Mon patrimoine</h1></div>
    <form class="card" id="lockForm" autocomplete="on">
      <input class="sr" type="text" name="username" autocomplete="username" value="MonPatrimoine" tabindex="-1" aria-hidden="true">
      <label class="field">Phrase de passe<input id="lPass" type="password" name="password" autocomplete="current-password" autocapitalize="off" required></label>
      <button class="btn primary" id="lBtn" type="submit">Ouvrir</button>
      <span class="small muted" id="lMsg"></span></form></div>`);
  const i = $("#lPass"); if (i) i.focus();
}
async function unlockSubmit() {
  const wait = lockedUntil - Date.now();
  if (wait > 0) { $("#lMsg").textContent = `Attends ${Math.ceil(wait / 1000)} s avant de réessayer.`; return; }
  const pass = $("#lPass").value, btn = $("#lBtn"); btn.disabled = true; $("#lMsg").textContent = "Déverrouillage…";
  try {
    const blob = await kv.get("blob");
    if (!blob) { await wipe(); return; }
    const o = await openBlob(blob, pass, (await kv.get("gen")) || 0);
    S.pass = pass; adopt(o); await kv.set("fails", 0);
    S.tab = "home"; render(); resetIdle(); syncNow(false);
  } catch (e) {
    const fails = ((await kv.get("fails")) || 0) + 1; await kv.set("fails", fails);
    if (fails >= MAX_FAILS) { await wipe(); toast("Trop d'essais : les données de cet iPhone ont été effacées."); return; }
    lockedUntil = Date.now() + Math.min(30000, fails * fails * 500);
    btn.disabled = false; $("#lPass").value = "";
    $("#lMsg").textContent = `Phrase incorrecte (${fails}/${MAX_FAILS}). Après ${MAX_FAILS} erreurs, les données de cet iPhone sont effacées.`;
  }
}

/* ---------- écrans de l'appli ---------- */
const OFF_BUDGET = ["Logement", "Impôts et assurances"], BIG_TX = 200;
function weekRange() { const d = new Date(), wd = (d.getDay() + 6) % 7, a = new Date(d.getFullYear(), d.getMonth(), d.getDate() - wd), b = new Date(a.getFullYear(), a.getMonth(), a.getDate() + 6); return { from: isoOf(a), to: isoOf(b), a, b }; }
const longDate = months => { const d = new Date(); d.setMonth(d.getMonth() + Math.ceil(months)); return d.toLocaleDateString("fr-CH", { month: "long", year: "numeric" }); };
function deltaSince(days) {
  const h = S.data.history, t = todayIso(); let base = null;
  for (const [d, v] of h) { if (daysBetween(d, t) >= days) base = v; }
  return base === null ? null : S.data.totals.total - base;
}
function chip(label, d) { return d === null ? "" : `<span class="small ${d >= 0 ? "up" : "down"}">${label} ${d >= 0 ? "+" : "−"}${fmt(Math.abs(d))} CHF</span>`; }
function banner(text) { return `<div class="banner">${icon("clock")}<span>${esc(text)}</span></div>`; }

function viewHome() {
  const D = S.data, t = D.totals, copyAge = daysBetween((S.at || D.today).slice(0, 10), todayIso());
  const warn = copyAge >= STALE_COPY_DAYS ? banner(`Dernière copie du PC il y a ${copyAge} jours : ouvre l'appli sur ton PC pour la renouveler.`)
    : D.stale_days !== null && D.stale_days >= 5 ? banner(`Les soldes du PC datent de ${D.stale_days} jours : télécharge tes exports.`) : "";
  const g = D.goals[0];
  const goalCard = g ? `<div class="card"><div class="rowline"><h2>${esc(g.name)}</h2><span class="up">${Math.min(100, g.now / g.target * 100).toFixed(1)} %</span></div>
    <div class="bar"><span data-w="${Math.min(100, g.now / g.target * 100)}"></span></div>
    <span class="small muted">${fmt(g.now)} sur ${fmt(g.target)} CHF · il manque ${fmt(Math.max(g.target - g.now, 0))} CHF</span></div>` : "";
  const rows = [["Épargne Raiffeisen", t.savings, "k1"], ["Pilier 3a", t.p3a, "k2"], ["Placements Yuh", t.invest, "k3"], ["Liquidités", t.liquid, "k4"]];
  return `<div class="page"><div><div class="eyebrow">${new Date().toLocaleDateString("fr-CH", { weekday: "long", day: "numeric", month: "long" })}</div><h1>Mon patrimoine</h1></div>${warn}
    <div class="card"><span class="small muted w600">Patrimoine total</span><div class="big">${fmt(t.total)}<small>CHF</small></div>
      <div class="chips">${chip("7 jours", deltaSince(7))}${chip("30 jours", deltaSince(30))}</div></div>
    ${goalCard}
    <div class="card"><h2>Répartition</h2><div class="stack gap12">${rows.map(([n, v, k]) => `<div class="stack"><div class="rowline"><span>${n}</span><span>${fmt(v)}</span></div><div class="thin"><span class="${k}" data-w="${t.total ? Math.max(v / t.total * 100, 0) : 0}"></span></div></div>`).join("")}</div></div></div>`;
}
function viewWeek() {
  const D = S.data, { from, to, a, b } = weekRange(), bud = D.settings.weekly_budget;
  let spent = 0; const cur = [], off = [];
  D.tx.filter(x => x.d >= from && x.d <= to).forEach(x => { if (OFF_BUDGET.includes(x.c) || x.a >= BIG_TX) off.push(x); else { spent += x.a; cur.push(x); } });
  spent = Math.max(spent, 0);
  const left = bud - spent, frac = Math.min(spent / bud, 1), C = 2 * Math.PI * 64, over = left < 0;
  const latest = D.tx.length ? D.tx.map(x => x.d).sort().pop() : null;
  const old = !latest || daysBetween(latest, todayIso()) > 4 ? banner("Les dépenses du PC ne vont pas jusqu'à aujourd'hui : importe un export récent sur le PC.") : "";
  const fd = d => { const [y, m, dd] = d.split("-"); return `${+dd} ${MONTHS[+m - 1]}`; };
  return `<div class="page"><div><div class="eyebrow">Du ${fd(from)} au ${fd(to)}</div><h1>Cette semaine</h1></div>${old}
    <div class="card"><div class="ring"><svg viewBox="0 0 160 160" role="img" aria-label="${over ? "Dépassé de " + fmt(-left) : "Reste " + fmt(left)} CHF sur ${fmt(bud)}">
      <circle class="tr" cx="80" cy="80" r="64"/><circle class="fg ${over ? "over" : ""}" cx="80" cy="80" r="64" stroke-dasharray="${(frac * C).toFixed(1)} ${C.toFixed(1)}" transform="rotate(-90 80 80)"/>
      <text x="80" y="80" text-anchor="middle" font-size="30" font-weight="800">${fmt(Math.abs(left))}</text><text class="sub" x="80" y="102" text-anchor="middle" font-size="13" font-weight="600">${over ? "CHF de trop" : "CHF restants"}</text></svg>
      <div class="nums"><div><span class="small muted">Dépensé</span><b>${fmt(spent)} CHF</b></div><div><span class="small muted">Budget de la semaine</span><b>${fmt(bud)} CHF</b></div></div></div></div>
    <div class="card list"><h2>Dépenses courantes</h2>${cur.length ? cur.sort((x, y) => y.d.localeCompare(x.d)).map(x => `<div class="item"><div><div class="t">${esc(x.l)}</div><div class="s">${esc(x.c)} · ${fd(x.d)}</div></div><span class="v">−${fmt(x.a)}</span></div>`).join("") : `<span class="small muted">Rien cette semaine.</span>`}</div>
    ${off.length ? `<div class="note"><b>Hors budget courant</b><br>${off.map(x => `${esc(x.l)} ${fmt(x.a)}`).join(" · ")}</div>` : ""}</div>`;
}
function projRows(sv) {
  const D = S.data, price = D.settings.purchase_price, need = price * 0.23, have = D.totals.total;
  const items = [{ n: `Achat à ${fmt(price)} CHF`, miss: Math.max(need - have, 0) }, ...D.goals.map(g => ({ n: g.name, miss: Math.max(g.target - g.now, 0) }))];
  return items.map((i, k) => `<div class="item ${k === 0 ? "hl" : ""}"><div><div class="t">${esc(i.n)}</div><div class="s">${i.miss > 0 ? "il manque " + fmt(i.miss) + " CHF" : "déjà atteint"}</div></div><span class="v">${i.miss > 0 ? longDate(i.miss / sv) : "maintenant"}</span></div>`).join("");
}
function viewGoal() {
  const D = S.data, price = D.settings.purchase_price, need = price * 0.23, have = D.totals.total;
  const sv = S.saving;
  return `<div class="page"><div><div class="eyebrow">Appartement, ${fmt(price)} CHF</div><h1>Objectif</h1></div>
    <div class="card"><div class="rowline"><span class="big t34">${fmt(have)}</span><span class="muted">sur ${fmt(need)} CHF nécessaires</span></div>
      <div class="bar"><span data-w="${Math.min(100, have / need * 100)}"></span></div>
      <span class="small muted">20 % de fonds propres et environ 3 % de frais. Il manque ${fmt(Math.max(need - have, 0))} CHF. Ton 3a est compté (utilisable pour une résidence principale).</span></div>
    <div class="card"><h2>Et si j'épargne…</h2><div class="rowline"><span class="big t26" id="svOut">${fmt(sv)}</span><span class="muted">CHF par mois</span></div>
      <input type="range" id="sv" min="200" max="4000" step="50" value="${sv}" aria-label="Épargne par mois"></div>
    <div class="card list"><h2>Date estimée</h2><div id="projRows">${projRows(sv)}</div></div>
    <p class="small muted nomargin">Estimation sans les gains ou pertes de la bourse. La banque décide selon ton revenu.</p></div>`;
}
function viewSettings() {
  const at = S.at ? new Date(S.at).toLocaleString("fr-CH", { dateStyle: "medium", timeStyle: "short" }) : "—";
  return `<div class="page"><div><div class="eyebrow">Synchronisation et sécurité</div><h1>Réglages</h1></div>
    <div class="card"><h2>Données</h2><span class="small">Copie du PC : ${esc(at)}</span>
      <div class="actions"><button class="btn primary" data-act="sync" ${S.busy ? "disabled" : ""}>${S.busy ? "Synchronisation…" : "Synchroniser maintenant"}</button><button class="btn" data-act="lock">Verrouiller</button></div></div>
    <div class="note">Sur cet iPhone, les chiffres sont gardés chiffrés. Ils ne sont lisibles qu'après ta phrase de passe, et seulement en mémoire. L'appli se verrouille après 1 minute en arrière-plan. Dropbox ne voit qu'un fichier illisible.</div>
    <div class="card"><h2>Effacer cet iPhone</h2><span class="small muted">Supprime les données, la connexion Dropbox et la clé de cet appareil. Ton PC et ton Dropbox ne sont pas touchés.</span>
      <div class="actions">${S.wipeAsk ? `<button class="btn danger" data-act="wipe-yes">Oui, tout effacer</button><button class="btn" data-act="wipe-no">Annuler</button>` : `<button class="btn danger" data-act="wipe-ask">Effacer</button>`}</div></div></div>`;
}
const TABS = [["home", "Accueil", "home", viewHome], ["week", "Semaine", "week", viewWeek], ["goal", "Objectif", "goal", viewGoal], ["settings", "Réglages", "gear", viewSettings]];
function render() {
  if (!S.data) return;
  const tab = TABS.find(t => t[0] === S.tab) || TABS[0];
  const scroll = window.scrollY;
  show(tab[3]() + `<nav aria-label="Navigation">${TABS.map(t => `<button data-act="tab" data-tab="${t[0]}" ${t[0] === tab[0] ? 'aria-current="page"' : ""}>${icon(t[2])}${t[1]}</button>`).join("")}</nav>`);
  window.scrollTo(0, scroll);
}

/* ---------- événements ---------- */
document.addEventListener("click", async e => {
  const el = e.target.closest("[data-act]"); if (!el) return;
  const a = el.dataset.act;
  if (a === "tab") { S.tab = el.dataset.tab; S.wipeAsk = false; render(); window.scrollTo(0, 0); }
  else if (a === "sync") syncNow(true);
  else if (a === "lock") lock();
  else if (a === "wipe-ask") { S.wipeAsk = true; render(); }
  else if (a === "wipe-no") { S.wipeAsk = false; render(); }
  else if (a === "wipe-yes") await wipe();
});
document.addEventListener("input", e => {
  if (e.target.id !== "sv" || !S.data) return;
  S.saving = +e.target.value; $("#svOut").textContent = fmt(S.saving); $("#projRows").innerHTML = projRows(S.saving);
});
document.addEventListener("submit", e => {
  e.preventDefault();
  if (e.target.id === "setupForm") setupSubmit();
  else if (e.target.id === "lockForm") unlockSubmit();
});

/* ---------- démarrage ---------- */
(async function start() {
  if ("serviceWorker" in navigator) { try { await navigator.serviceWorker.register("sw.js"); } catch (e) { /* hors ligne non garanti */ } }
  const blob = await kv.get("blob");
  if (blob) screenLock();
  else { const p = await kv.get("pkce"); if (p) S.setup = { ...p }; screenSetup(); }
})();
