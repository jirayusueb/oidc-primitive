---
title: Scope
description: Parse, format and check scope strings, with branded types that keep scope names literal.
---

`Scope` handles the space-delimited `scope` value defined in [RFC 6749 section 3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3). A malformed string is `OAuthError.InvalidScope`. Wire values stay plain strings. The branded `Scope` type only marks that a name was validated.

## Import

```ts
import { Scope } from 'oidc-primitive';
```

The namespace contains a type of the same name: use `Scope.Scope`.

## Scope

```ts title="signature"
type Scope<Name extends string = string> = Name & { readonly [brand]: 'Scope' };
```

A validated scope token.

## isScope

```ts title="signature"
const isScope: (value: unknown) => value is Scope;
```

True for a non-empty string made only of characters `%x21`, `%x23-5B` and `%x5D-7E`. That excludes space, double quote and backslash.

## make

```ts title="signature"
const make: <const Name extends string>(name: Name) => Scope<Name>;
```

Declares a scope and keeps its literal name in the type. Throws `TypeError` (`"<name>" is not a valid scope token`) for an invalid token.

```ts
const read = Scope.make('read');
```

## parse

```ts title="signature"
const parse: (value: string | null | undefined) => Scope[];
```

Splits a space-delimited string. `null`, `undefined` and `''` return `[]`. Duplicates are dropped and order is kept. Throws `OAuthError.InvalidScope` (`scope is malformed`) when any part is not a valid token, which includes empty parts from double spaces.

```ts
const requested = Scope.parse(new URL(request.url).searchParams.get('scope'));
```

## format

```ts title="signature"
const format: (scopes: Iterable<string>) => string;
```

Joins scopes with a single space after removing duplicates. It does not validate.

```ts
const value = Scope.format(['openid', 'email', 'openid']);
```

## Requirement

```ts title="signature"
interface Requirement<S extends string = string> {
  readonly allOf?: ReadonlyArray<S>;
  readonly anyOf?: ReadonlyArray<S>;
}
```

Every `allOf` scope, and, when `anyOf` is non-empty, at least one `anyOf` scope.

## satisfies

```ts title="signature"
const satisfies: (granted: Iterable<string>, requirement: Requirement) => boolean;
```

True when `granted` meets `requirement`. An empty requirement is always satisfied.

```ts
const ok = Scope.satisfies(['read', 'profile'], { allOf: ['read'], anyOf: ['profile', 'email'] });
```

## filter

```ts title="signature"
const filter: <const S extends string>(granted: Iterable<string>, declared: ReadonlyArray<S>) => S[];
```

Returns the `declared` scopes that appear in `granted`, in `declared` order. The result is typed by the declaration.

```ts
const known = Scope.filter(['read', 'unknown'], ['read', 'write']);
```

## Spec

- [RFC 6749 section 3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3): scope syntax.
