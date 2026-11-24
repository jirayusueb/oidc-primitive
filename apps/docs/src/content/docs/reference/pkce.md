---
title: Pkce
description: Validate PKCE challenges and verifiers, accept only S256, and reject downgrade attempts.
---

`Pkce` enforces [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) with the [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) tightening. Only `S256` is accepted. A verifier sent without a stored challenge is rejected. See [authorization requests](/guide/authorization-requests/).

## Import

```ts
import { Pkce } from 'oidc-primitive';
```

## isVerifier

```ts title="signature"
const isVerifier: (value: unknown) => value is string;
```

True for a string of 43 to 128 characters from `A-Z a-z 0-9 - . _ ~` ([RFC 7636 section 4.1](https://www.rfc-editor.org/rfc/rfc7636#section-4.1)).

## isChallenge

```ts title="signature"
const isChallenge: (value: unknown) => value is string;
```

True for a string of exactly 43 characters from `A-Z a-z 0-9 - _`. That is the length of a base64url SHA-256 digest ([RFC 7636 section 4.2](https://www.rfc-editor.org/rfc/rfc7636#section-4.2)). Check the `code_challenge` of an authorization request with it.

## challenge

```ts title="signature"
const challenge: (verifier: string) => Promise<string>;
```

Returns `BASE64URL(SHA256(verifier))`. Throws `OAuthError.InvalidRequest` (`code_verifier is malformed`) when `verifier` fails `isVerifier`. Most servers never call this. It is useful in tests and clients.

## checkMethod

```ts title="signature"
const checkMethod: (method: string | null | undefined) => void;
```

Returns normally only for `'S256'`. Throws `OAuthError.InvalidRequest` (`code_challenge_method must be S256`) for anything else, including `plain` and an absent method (absent means `plain` in RFC 7636).

```ts
const params = new URL(request.url).searchParams;
Pkce.checkMethod(params.get('code_challenge_method'));
if (!Pkce.isChallenge(params.get('code_challenge'))) {
  throw new OAuthError.InvalidRequest('code_challenge is malformed');
}
```

## VerifyOptions

```ts title="signature"
interface VerifyOptions {
  readonly required?: boolean;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `required` | `boolean` | `true` | When true, a request with neither verifier nor stored challenge is rejected. Exemptions are host policy ([RFC 9700 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1)). |

## verify

```ts title="signature"
const verify: (
  verifier: string | null | undefined,
  storedChallenge: string | null | undefined,
  options?: VerifyOptions,
) => Promise<void>;
```

Verifies the token request's `code_verifier` against the `code_challenge` stored with the authorization code. The comparison is constant-time. Resolves with no value on success. Throws `OAuthError.InvalidGrant`:

| Message | When |
| --- | --- |
| `PKCE is required` | Neither value is present and `required` is true. |
| `code_verifier sent without a code_challenge` | A verifier but no stored challenge (downgrade, [RFC 9700 section 4.8.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.8.2)). |
| `code_verifier is required` | A stored challenge but no verifier. |
| `code_verifier is malformed` | The verifier fails `isVerifier`. |
| `code_verifier does not match` | The challenge differs. |

```ts
const form = await request.formData();
await Pkce.verify(form.get('code_verifier')?.toString(), storedChallenge);
```

## Spec

- [RFC 7636 section 4.1](https://www.rfc-editor.org/rfc/rfc7636#section-4.1): verifier syntax.
- [RFC 7636 section 4.2](https://www.rfc-editor.org/rfc/rfc7636#section-4.2): S256 challenge. The tests use the Appendix B vector.
- [RFC 9700 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1): S256 only.
- [RFC 9700 section 4.8.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.8.2): PKCE downgrade.
