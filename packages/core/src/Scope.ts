import { InvalidScope } from './OAuthError.ts';

declare const brand: unique symbol;

/** A validated scope token. Wire values remain strings. */
export type Scope<Name extends string = string> = Name & { readonly [brand]: 'Scope' };

/** RFC 6749 s3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). */
const token = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export const isScope = (value: unknown): value is Scope => typeof value === 'string' && token.test(value);

/** Declare a scope, keeping its literal name in the type. */
export const make = <const Name extends string>(name: Name): Scope<Name> => {
	if (!isScope(name)) throw new TypeError(`"${name}" is not a valid scope token`);
	return name as Scope<Name>;
};

/** Parse a space-delimited scope string. Duplicates are dropped; order is kept. */
export const parse = (value: string | null | undefined): Scope[] => {
	if (value === null || value === undefined || value === '') return [];
	const out: Scope[] = [];
	for (const part of value.split(' ')) {
		if (!isScope(part)) throw new InvalidScope('scope is malformed');
		if (!out.includes(part)) out.push(part);
	}
	return out;
};

export const format = (scopes: Iterable<string>): string => [...new Set(scopes)].join(' ');

/** Every `allOf` scope and, when given, at least one `anyOf` scope. */
export interface Requirement<S extends string = string> {
	readonly allOf?: ReadonlyArray<S>;
	readonly anyOf?: ReadonlyArray<S>;
}

export const satisfies = (granted: Iterable<string>, requirement: Requirement): boolean => {
	const set = new Set(granted);
	const all = requirement.allOf ?? [];
	const any = requirement.anyOf ?? [];
	return all.every((s) => set.has(s)) && (any.length === 0 || any.some((s) => set.has(s)));
};

/** The scopes from `granted` that appear in `declared`, typed by the declaration. */
export const filter = <const S extends string>(granted: Iterable<string>, declared: ReadonlyArray<S>): S[] => {
	const set = new Set(granted);
	return declared.filter((s) => set.has(s));
};
