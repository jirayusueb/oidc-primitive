playbook: Feature (compressed; brainstorm/draft/review skipped, user gave concrete spec + reference)
todo: docs site + use cases + flows + DESIGN.md done (b611ad0786 pushed); DEPLOYED https://oidc-primitive.vercel.app (prod, verified landing + pele diagram + og.png); npm publish waiting npm login; DriftReference agent running on 20 reference pages (redeploy after its commit)
decisions: package name unscoped `oidc-primitive` (user); buildPath code (user); host-checklist + ROADMAP imported into MDX, not copied (user edits them concurrently)
open gate: npm login only (user opens npmjs.com link f7accd50)

- rename better-oidc -> oidc-primitive | tests 92/93, smoke ok | next: scaffold docs
- pre-existing failure: metadata.test.ts expects ES256, src now RS256 (user's uncommitted change)
- PRODUCT.md written apps/docs | next: concept-seed direction
- spawned GuidePages, ReferencePages | next: theme + logo while they run
- commit 54d2a8f on feat/core-primitives; gh repo jirayusueb/oidc-primitive public, main + feat/core-primitives pushed | next: vercel link --project oidc-primitive, pull, build --prod, deploy --prebuilt --prod from apps/docs
- infographics (gpt-image-2) + Pele sequence diagram added; commit 904df7e pushed | next: vercel deploy
- user is migrating build to tsdown + vitest uncommitted; rebuilt dist with tsdown so pre-commit type-check passes
- vercel link/pull/build/deploy --prebuilt --prod in apps/docs; project oidc-primitive; prod URL matches configured site | redeploy: bun run build + vercel deploy --prebuilt --prod
