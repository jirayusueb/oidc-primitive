---
title: Redacted
description: A wrapper that keeps a credential out of logs, JSON output and console output.
---

`Redacted` wraps a credential so it prints as `<redacted>` in strings, JSON and console output. [OpaqueToken.generate](/reference/opaque-token/#generate) and [ClientSecret.parseBasic](/reference/client-secret/#parsebasic) return it. [OAuthResponse.json](/reference/oauth-response/#json) unwraps it on purpose when the value must reach the client. This is a library safeguard against accidental logging, not a protocol rule.

## Import

```ts
import { Redacted } from 'oidc-primitive';
```

The namespace contains the class of the same name: the type is `Redacted.Redacted<string>`.

## Redacted

```ts title="signature"
class Redacted<T = string> {
  private constructor(value: T);
  static make<T>(value: T): Redacted<T>;
  static value<T>(redacted: Redacted<T>): T;
  toString(): string;
  toJSON(): string;
}
```

The constructor is private. `toString()`, `toJSON()` and Node or Bun `util.inspect` output all return `<redacted>`.

## make

```ts title="signature"
const make: <T>(value: T) => Redacted<T>;
```

Wraps a credential.

```ts
const secret = Redacted.make('s3cr3t');
console.log(`${secret}`);
```

The call above prints `<redacted>`.

## value

```ts title="signature"
const value: <T>(redacted: Redacted<T>) => T;
```

Reads the wrapped credential. Call it only where the raw value must leave the process.

```ts
const raw: string = Redacted.value(Redacted.make('s3cr3t'));
```

## Spec

None. The behavior is a library safeguard. Its tests check that `String`, `JSON.stringify` and console inspection never reveal the value.
