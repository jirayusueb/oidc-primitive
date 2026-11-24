---
title: MCP authorization
description: What an MCP server or authorization server needs from OAuth 2.1, and which parts the package covers today.
---

The Model Context Protocol rides on OAuth 2.1: an MCP server that requires authorization is a resource server, and the OAuth server behind it is an authorization server ([MCP Authorization, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)). MCP restates the OAuth 2.1 rules and adds a few of its own.

## What the package covers today

- **PKCE with S256, required for public clients.** `Pkce.challenge` at the client, `Pkce.validateMethod` and `Pkce.verify` at your authorization endpoint. The library accepts only S256, which is what MCP requires.
- **Resource indicators.** The MCP server's URL identifies the resource. `Resource.audience` puts it in the access token's `aud` ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)), so a token for one MCP server does not work on another.
- **Protected resource metadata.** `ResourceMetadata.make` and `ResourceMetadata.wellKnownUrl` build the `/.well-known/oauth-protected-resource` document ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) that tells MCP clients which authorization server to use.
- **Authorization server metadata.** `Metadata.authorizationServer` with OAuth 2.1 defaults for `/.well-known/oauth-authorization-server`.
- **Token verification at the MCP server.** `AccessTokenVerifier` bound to the issuer and to the MCP server's own URL as audience.

## What is not in the package yet

These are v1.1 roadmap items, each with its own design decision:

- **Client ID metadata document.** MCP 2026-07-28 lets an OAuth client publish its metadata at its own `client_id` URL ([draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03)). A `ClientMetadataDocument` module is planned.
- **PAR.** Pushed authorization requests with `request_uri` lifetimes under 600 seconds ([RFC 9126](https://www.rfc-editor.org/rfc/rfc9126)).
- **DPoP.** Proof-of-possession binding for tokens ([RFC 9449](https://www.rfc-editor.org/info/rfc9449)).

## Shape of an MCP authorization server

Your host code keeps its normal shape. The authorization server is an OAuth 2.1 authorization server: authorization endpoint with PKCE, token endpoint with client authentication, discovery, a JWKS. The MCP-specific part is mostly metadata and audience discipline.

```ts
import { Metadata, OAuthResponse, ResourceMetadata } from 'oidc-primitive';

const protectedResource = ResourceMetadata.make({
	resource: 'https://mcp.example.com',
	authorizationServers: ['https://auth.example.com'],
	scopesSupported: ['read', 'write'],
});

if (get && path === '/.well-known/oauth-protected-resource') return OAuthResponse.json(protectedResource);
```

Write the audience as the MCP server URL everywhere: in `Resource.audience` at the token endpoint, and in the `AccessTokenVerifier` the MCP server uses. See [Authorization code flow](/guide/authorization-code-flow/) for the endpoints, [Resource servers](/guide/resource-servers/) for the MCP server side, and the [roadmap](/roadmap/) for the planned MCP modules.
