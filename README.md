# Sentinel AI

Auditor de código e dependências. Cola um `package.json`, `requirements.txt`, ZIP do projeto ou URL pública do GitHub. O app consulta a API real do [OSV.dev](https://osv.dev), cruza com SAST/segredos, Docker, typosquat e versões latest do npm, e grava o histórico no Supabase (ou localmente).

## O que entra no scan

- npm / yarn / pnpm / bun, PyPI (requirements, pyproject, poetry, Pipfile), Go, Cargo, Composer, RubyGems, Maven, Pub, GitHub Actions
- API pública `https://api.osv.dev/v1/querybatch`
- Regras SAST (eval, SQL concat, innerHTML, pickle, CORS, SSRF…)
- Segredos (AWS, GitHub, Stripe, PEM, connection strings)
- Dockerfile (`FROM latest`, `curl | sh`, root, ENV com senha)
- Pacotes npm desatualizados e nomes parecidos com pacotes populares
- Export Markdown, SARIF, CycloneDX SBOM e JSON

## Supabase

Projeto: `pewhzyjibtfnnvevizpm`

No SQL Editor, rode [`supabase/schema.sql`](supabase/schema.sql) uma vez para criar a tabela `scans`. Sem isso o histórico fica só no navegador.

## Netlify

Build: `npm run build` · publish: `dist` · `NETLIFY=true` ativa o preset Nitro da Netlify.

## Local

```bash
npm install
npm run dev
```
