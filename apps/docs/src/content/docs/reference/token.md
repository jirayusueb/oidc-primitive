---
title: Token
description: Generate, hash and compare opaque credentials such as authorization codes, refresh tokens and client secrets.
---

`Token` handles opaque credentials: authorization codes, refresh tokens, opaque access tokens and client secrets ([RFC 6749 section 10.10](https://www.rfc-editor.org/rfc/rfc6749#section-10.10)). Generate with `generate`, store only `hash(value)`, and compare with `matchesHash`. Values come back as [Redacted](/reference/redacted/). See [tokens and keys](/guide/tokens-and-keys/).

## Import

```ts
import { Token } from 'oidc-primitive';
```

## generate

```ts title="signature"
const generate: (bytes?: number) => Redacted<string>;
```

| Parameter | Type | Default | Meaning |
| --- | --- | --- | --- |
| `bytes` | `number` | `32` | Random bytes before base64url encoding. Minimum 16. |

Returns a random base64url credential. Throws `RangeError` (`Token.generate needs at least 16 bytes`) when `bytes` is below 16 or not an integer.

```ts
const code = Token.generate();
const stored = await Token.hash(code);
```

## hash

```ts title="signature"
const hash: (value: string | Redacted<string>) => Promise<string>;
```

SHA-256 of the credential, base64url. Use it as the storage key.

## equals

```ts title="signature"
const equals: (a: string | Redacted<string>, b: string | Redacted<string>) => Promise<boolean>;
```

Constant-time comparison of two credentials.

## matchesHash

```ts title="signature"
const matchesHash: (presented: string | Redacted<string>, storedHash: string) => Promise<boolean>;
```

Constant-time check of a presented credential against a stored `hash`.

```ts
const form = await request.formData();
const presented = form.get('code')?.toString() ?? '';
const found = await Token.matchesHash(presented, stored);
```

## Spec

- [RFC 6749 section 10.10](https://www.rfc-editor.org/rfc/rfc6749#section-10.10): credential guessing attacks and entropy.
