---
title: Choose your use case
description: Which pages and modules fit sign-in, API protection, machine-to-machine access, multi-tenant SaaS, and MCP servers.
---

`oidc-primitive` is one package. What changes per use case is which endpoints you build and which modules you lean on.

| You are building | Read | Modules that carry it |
| --- | --- | --- |
| Sign-in for your web or mobile app | [Authorization code flow](/guide/authorization-code-flow/) | `Pkce`, `RedirectUri`, `Token`, `TokenSigner`, `IdToken` |
| A protected API behind those tokens | [Resource servers](/guide/resource-servers/) | `AccessTokenVerifier`, `Bearer`, `ResourceMetadata` |
| Machine-to-machine access | [Client credentials](/guide/client-credentials/) | `ClientSecret`, `ClientAssertion`, `TokenSigner` |
| A SaaS that serves many tenants | [Multi-tenant](/guide/multi-tenant/) | `Metadata`, `Keys`, `TokenSigner`, `AccessTokenVerifier` |
| An MCP server or its authorization server | [MCP authorization](/guide/mcp-authorization-server/) | `Pkce`, `Resource`, `ResourceMetadata`, `Metadata` |

## What is deliberately not a use case

- A client library. Your users' apps that log in are served by [oauth4webapi](https://github.com/panva/oauth4webapi) or [openid-client](https://github.com/panva/openid-client).
- A hosted identity provider with a login UI. There is no UI in the package; the host renders login, consent and errors.
- FAPI 2.0 profiles. On the roadmap for v1.2; see [Roadmap](/roadmap/).

Every use case keeps the same split: your app owns routes, storage, sessions and UI. The [Host checklist](/guide/host-checklist/) lists those duties per endpoint.
