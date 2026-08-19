# nap-projects

Projekt- og opgavestyring for teamet, Notion-inspireret tabelvisning:
projekter grupperet, opgaver med status/ansvarlig/forfaldsdato/prioritet/
tags/blocked-by. Individuelle brugerkonti med obligatorisk 2FA, samme
auth-mønster som nap-dashboard og nap-homehub.

## Status / v1-omfang

Bygget: projekter, opgaver, faste felter (status/prioritet/ansvarlig/dato/
tags/blocked-by-relationer), sortering og fritekstsøgning.

Ikke bygget endnu: brugerdefinerede felter, flere gemte visninger (board/
kalender), avanceret filter-builder, SSO fra nap-homehub.

## Lokal preview

```bash
npx wrangler dev
```

## Deploy

Cloudflare Workers Builds, auto-deploy ved push til `main` (samme opsætning
som de andre NAP-repos).
