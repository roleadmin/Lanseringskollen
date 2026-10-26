# Lanseringskollen

Gratis kvalitetskoll på svenska för appar byggda med AI-verktyg som Lovable, Claude Code och Bolt.

Klistra in länken till din app. Skannern kollar det som syns utifrån, sedan svarar du på de punkter som kräver insyn, och får en samlad rapport med åtgärdslista.

## Vad skannern kollar automatiskt
- HTTPS, och att `http://` skickas vidare till `https://`
- Säkerhetsrubriker: HSTS, Content Security Policy, X-Content-Type-Options, skydd mot inbäddning
- Spårningsskript (Google Analytics, Meta Pixel, Hotjar m.fl.) och om en cookie-banner finns
- Spårningscookies som sätts direkt vid första besöket
- Läckta hemliga nycklar i sidans JavaScript (OpenAI, Anthropic, Stripe, AWS, GitHub, Supabase service_role m.fl.)
- Om appen använder Supabase (då lyfts frågan om Row Level Security fram)
- Källkartor (source maps) i produktion
- Länk till integritetspolicy

Skannern läser **bara** det som en vanlig besökare kan se. Den loggar aldrig in, gissar inga adresser och försöker aldrig ta sig in i någon databas.

## Filer
- `index.html`: själva sidan. Ingen databas, inga cookies. Svaren sparas bara i besökarens webbläsare.
- `worker/worker.js`: skannern, en Cloudflare Worker (gratis upp till 100 000 anrop per dag).

## Installera skannern (görs en gång, går från mobilen)
1. Skapa ett gratis konto på [dash.cloudflare.com](https://dash.cloudflare.com).
2. Gå till **Workers & Pages** → **Create** → **Create Worker**. Döp den till `lanseringskollen` och tryck **Deploy**.
3. Tryck **Edit code**, ta bort allt och klistra in innehållet i `worker/worker.js`. Tryck **Deploy**.
4. Kopiera adressen, t.ex. `https://lanseringskollen.DITTNAMN.workers.dev`.
5. Öppna `index.html` och fyll i adressen på raden `const WORKER_URL = "";`.
6. I `worker/worker.js`, byt `ALLOWED_ORIGINS = ["*"]` till `["https://roleadmin.github.io"]` så att bara din sida kan använda skannern. Deploya igen.

## Publicera sidan
GitHub Pages: **Settings** → **Pages** → **Branch: main**, mapp `/ (root)` → **Save**. Sidan hamnar på `https://roleadmin.github.io/Lanseringskollen/`.

## Ansvarsfriskrivning
Detta är en kvalitetskontroll, inte en säkerhetsgranskning eller juridisk rådgivning.
