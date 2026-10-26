// Lanseringskollen – skanner (Cloudflare Worker)
//
// Läser en publik webbsida PASSIVT, precis som en vanlig besökare,
// och letar efter vanliga kvalitetsbrister i AI-byggda appar.
// Den försöker aldrig logga in, gissa adresser eller ta sig in i databaser.
//
// Anrop: GET https://<din-worker>.workers.dev/?url=https://din-app.se

// Vilka sajter som får anropa skannern. Byt till din egen adress när sidan är live,
// t.ex. ["https://roleadmin.github.io"]. "*" betyder alla.
const ALLOWED_ORIGINS = ["*"];

const TIMEOUT_MS = 8000;
const MAX_BYTES = 3_000_000;
const MAX_SCRIPTS = 8;

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "GET") return json({ error: "Endast GET stöds." }, 405, cors);

    const target = new URL(request.url).searchParams.get("url");
    let url;
    try {
      url = validateTarget(target);
    } catch (e) {
      return json({ error: e.message }, 400, cors);
    }

    try {
      const page = await collect(url);
      return json(analyze(page), 200, cors);
    } catch (e) {
      return json({ error: "Kunde inte läsa sidan: " + (e.message || "okänt fel") }, 502, cors);
    }
  },
};

// ---------- Säkerhet för själva skannern ----------

export function validateTarget(raw) {
  if (!raw) throw new Error("Ange en adress, t.ex. https://min-app.se");
  let s = raw.trim();
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u;
  try { u = new URL(s); } catch { throw new Error("Adressen ser inte ut som en webbadress."); }
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Endast http och https stöds.");
  if (u.port && !["80", "443"].includes(u.port)) throw new Error("Endast vanliga webbportar stöds.");
  if (u.username || u.password) throw new Error("Adresser med inloggningsuppgifter stöds inte.");
  const h = u.hostname.toLowerCase();
  const blocked =
    h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith("[") || h.includes(":") || !h.includes(".");
  if (blocked) throw new Error("Ange ett vanligt domännamn, inte en IP-adress eller intern adress.");
  return u;
}

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes("*") ? "*" : (ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0]);
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
}

// ---------- Hämta sidan ----------

async function get(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, {
      redirect: opts.redirect || "follow",
      signal: ctrl.signal,
      headers: { "User-Agent": "Lanseringskollen/1.0 (+passiv kvalitetskontroll)", "Accept": opts.accept || "*/*" },
    });
  } finally {
    clearTimeout(t);
  }
}

async function readText(res) {
  const text = await res.text();
  return text.length > MAX_BYTES ? text.slice(0, MAX_BYTES) : text;
}

async function collect(url) {
  const res = await get(url.href, { accept: "text/html,*/*" });
  const finalUrl = new URL(res.url || url.href);
  const headers = {};
  res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
  let setCookies = [];
  if (typeof res.headers.getSetCookie === "function") setCookies = res.headers.getSetCookie();
  else if (typeof res.headers.getAll === "function") setCookies = res.headers.getAll("Set-Cookie");
  else if (headers["set-cookie"]) setCookies = [headers["set-cookie"]];
  const html = await readText(res);

  // Leder http:// vidare till https://?
  let httpRedirectsToHttps = null;
  if (finalUrl.protocol === "https:") {
    try {
      const plain = await get("http://" + finalUrl.host + "/", { redirect: "manual" });
      const loc = plain.headers.get("Location") || "";
      httpRedirectsToHttps = plain.status >= 300 && plain.status < 400 && loc.startsWith("https://");
    } catch { httpRedirectsToHttps = null; }
  }

  // Hämta sajtens egna JavaScript-filer (där AI-verktyg brukar lägga koden).
  const scripts = [];
  const srcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map(m => m[1]);
  for (const src of srcs) {
    if (scripts.length >= MAX_SCRIPTS) break;
    let su;
    try { su = new URL(src, finalUrl); } catch { continue; }
    if (su.origin !== finalUrl.origin) continue;
    try {
      const r = await get(su.href);
      if (r.ok) scripts.push({ url: su.pathname, text: await readText(r) });
    } catch { /* hoppa över */ }
  }

  return { url: url.href, finalUrl: finalUrl.href, status: res.status, headers, setCookies, html, scripts, httpRedirectsToHttps };
}

// ---------- Analys (ren funktion, går att testa utan nätverk) ----------

const TRACKERS = [
  ["Google Analytics / Tag Manager", /googletagmanager\.com|google-analytics\.com|gtag\(\s*['"]config/i],
  ["Meta Pixel", /connect\.facebook\.net\/[^"']*fbevents|fbq\(\s*['"]init/i],
  ["Hotjar", /static\.hotjar\.com|hotjar\.com\/c\/hotjar/i],
  ["Microsoft Clarity", /clarity\.ms\/tag/i],
  ["TikTok Pixel", /analytics\.tiktok\.com/i],
  ["LinkedIn Insight", /snap\.licdn\.com/i],
];

const CONSENT = /cookiebot|onetrust|cookieyes|usercentrics|iubenda|cookie-?consent|cookiehub|klaro|complianz|consentmanager|termly/i;

const SECRETS = [
  ["OpenAI-nyckel", /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g],
  ["Anthropic-nyckel", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ["Stripe hemlig nyckel", /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g],
  ["AWS-nyckel", /\bAKIA[0-9A-Z]{16}\b/g],
  ["GitHub-token", /\bgh[pousr]_[A-Za-z0-9]{30,}/g],
  ["SendGrid-nyckel", /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g],
  ["Resend-nyckel", /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{12,}/g],
  ["Privat nyckel", /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g],
];

function mask(s) {
  return s.length <= 12 ? s.slice(0, 4) + "…" : s.slice(0, 8) + "…" + s.slice(-4);
}

function decodeJwtPayload(tok) {
  try {
    const part = tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = part + "=".repeat((4 - (part.length % 4)) % 4);
    return JSON.parse(atob(pad));
  } catch { return null; }
}

export function analyze(p) {
  const checks = [];
  const add = (id, sev, status, title, detail, manual) => checks.push({ id, sev, status, title, detail, manual: manual || null });
  const h = p.headers || {};
  const https = new URL(p.finalUrl).protocol === "https:";
  const sources = [{ url: "sidans HTML", text: p.html || "" }, ...(p.scripts || [])];
  const all = sources.map(s => s.text).join("\n");

  // 1. HTTPS
  if (https) add("https", "crit", "pass", "Sidan använder HTTPS", "Anslutningen är krypterad.");
  else add("https", "crit", "fail", "Sidan använder inte HTTPS", "Allt som skickas, även lösenord, kan läsas av andra på samma nätverk. Slå på HTTPS hos din hosting.");

  if (https && p.httpRedirectsToHttps === false)
    add("redirect", "warn", "fail", "http:// skickas inte vidare till https://", "Den som skriver adressen utan https hamnar på en okrypterad sida. Slå på \"Force HTTPS\" eller liknande hos din hosting.");
  else if (https && p.httpRedirectsToHttps)
    add("redirect", "warn", "pass", "http:// skickas vidare till https://", "Besökare hamnar alltid på den krypterade versionen.");

  // 2. Säkerhetsrubriker
  const csp = h["content-security-policy"] || "";
  add("hsts", "warn", h["strict-transport-security"] ? "pass" : "fail", "HSTS (tvingar webbläsaren att alltid använda HTTPS)",
    h["strict-transport-security"] ? "Rubriken finns." : "Saknas. Be ditt AI-verktyg lägga till rubriken Strict-Transport-Security.");
  add("csp", "nice", csp ? "pass" : "fail", "Content Security Policy (begränsar vilka skript som får köras)",
    csp ? "Rubriken finns." : "Saknas. Skyddar mot att främmande kod körs på din sida. Be ditt AI-verktyg föreslå en grundläggande policy.");
  add("nosniff", "nice", /nosniff/i.test(h["x-content-type-options"] || "") ? "pass" : "fail", "Skydd mot felaktig filtolkning (X-Content-Type-Options)",
    /nosniff/i.test(h["x-content-type-options"] || "") ? "Rubriken finns." : "Saknas. Lägg till X-Content-Type-Options: nosniff.");
  const frameOk = /deny|sameorigin/i.test(h["x-frame-options"] || "") || /frame-ancestors/i.test(csp);
  add("frame", "nice", frameOk ? "pass" : "fail", "Skydd mot att sidan bäddas in av andra (clickjacking)",
    frameOk ? "Skyddet finns." : "Saknas. Någon kan bädda in din sida i sin egen och lura användare att klicka. Lägg till X-Frame-Options: DENY.");

  // 3. Spårare och samtycke
  const found = TRACKERS.filter(([, re]) => re.test(all)).map(([n]) => n);
  const hasConsent = CONSENT.test(all);
  if (found.length && !hasConsent)
    add("trackers", "crit", "fail", "Spårning utan synlig samtyckeslösning", `Hittade: ${found.join(", ")}. Ingen känd cookie-banner hittades. Spårning får inte starta innan besökaren sagt ja.`, "cookieConsent");
  else if (found.length)
    add("trackers", "warn", "info", "Spårning och cookie-banner hittades", `Hittade: ${found.join(", ")}. Kontrollera manuellt att spårningen startar först efter att besökaren sagt ja.`, "cookieConsent");
  else
    add("trackers", "warn", "pass", "Ingen känd spårning hittades", "Inga vanliga analys- eller annonsskript syntes i sidans kod. Skript som laddas senare kan missas.");

  // 4. Cookies vid första besöket
  const names = (p.setCookies || []).map(c => c.split("=")[0].trim()).filter(Boolean);
  const trackingCookies = names.filter(n => /^(_ga|_gid|_gat|_fbp|_fbc|_hj|_clck|_clsk|_ttp|li_)/i.test(n));
  if (trackingCookies.length)
    add("cookies", "crit", "fail", "Spårningscookies sätts direkt", `Servern sätter ${trackingCookies.join(", ")} innan besökaren hunnit svara. Det kräver samtycke först.`);
  else if (names.length)
    add("cookies", "nice", "info", `${names.length} cookie${names.length > 1 ? "s" : ""} sätts vid första besöket`, `Namn: ${names.join(", ")}. Är de nödvändiga för att sidan ska fungera behövs inget samtycke.`);
  else
    add("cookies", "nice", "pass", "Inga cookies sätts av servern vid första besöket", "Cookies som sätts av JavaScript efteråt syns inte i den här kontrollen.");

  // 5. Läckta nycklar
  const leaks = [];
  for (const s of sources) {
    for (const [name, re] of SECRETS) {
      for (const m of s.text.matchAll(re)) {
        // Riktiga nycklar blandar siffror och bokstäver. Filtrerar bort CSS-klasser som "sk-loading-spinner".
        if (name.endsWith("-nyckel") && name !== "Privat nyckel" && !(/\d/.test(m[0]) && /[A-Za-z]{2}/.test(m[0]) && /[A-Z]/.test(m[0]))) continue;
        leaks.push(`${name} (${mask(m[0])}) i ${s.url}`);
      }
    }
  }
  let supaAnon = false;
  for (const s of sources) {
    for (const m of s.text.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
      const pl = decodeJwtPayload(m[0]);
      if (pl && pl.role === "service_role") leaks.push(`Supabase service_role-nyckel (${mask(m[0])}) i ${s.url}`);
      else if (pl && pl.role === "anon") supaAnon = true;
    }
  }
  const uniq = [...new Set(leaks)];
  if (uniq.length)
    add("secrets", "crit", "fail", "Hemliga nycklar syns i koden", `Hittade ${uniq.length}: ${uniq.slice(0, 5).join("; ")}. Alla som besöker sidan kan läsa dem. Byt nycklarna direkt och flytta dem till servern.`);
  else
    add("secrets", "crit", "pass", "Inga kända hemliga nycklar hittades", `Kontrollerade sidan och ${(p.scripts || []).length} JavaScript-fil${(p.scripts || []).length === 1 ? "" : "er"}. Okända nyckeltyper kan missas.`);

  if (supaAnon)
    add("supabase", "crit", "info", "Appen använder Supabase", "Den publika anon-nyckeln är normal att se. Men då är databasens åtkomstregler (Row Level Security) det enda som skyddar datan. Svara på frågan om det nedan.", "rls");

  // 6. Källkartor
  const maps = sources.some(s => /\/\/# sourceMappingURL=(?!data:)/.test(s.text));
  if (maps) add("sourcemaps", "nice", "fail", "Källkoden går att läsa i läsbar form", "Sidan pekar på källkartor (source maps). Det gör det lättare för andra att studera din kod. Stäng av dem i produktionsbygget.");

  // 7. Integritetspolicy
  const policy = /<a[^>]+href=["'][^"']*(integritet|privacy|personuppgift|dataskydd|gdpr)[^"']*["']|>\s*(integritetspolicy|privacy policy|personuppgiftspolicy|dataskyddspolicy)\s*</i.test(p.html || "");
  add("policy", "crit", policy ? "pass" : "fail", policy ? "Länk till integritetspolicy hittades" : "Ingen länk till integritetspolicy hittades",
    policy ? "Kontrollera att den förklarar vad du sparar, varför och hur länge." : "Samlar appen in personuppgifter behöver användaren kunna läsa hur de hanteras. Om länken bara visas efter inloggning, kontrollera det manuellt.");

  return { url: p.url, finalUrl: p.finalUrl, status: p.status, scannedAt: new Date().toISOString(), scripts: (p.scripts || []).length, checks };
}
