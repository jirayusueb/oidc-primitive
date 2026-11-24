const placeholder = '<redacted>';

/** A credential that prints as `<redacted>` in strings, JSON and console output. */
export class Redacted<T = string> {
	readonly #value: T;

	private constructor(value: T) {
		this.#value = value;
	}

	/** Wrap a credential. */
	static make<T>(value: T): Redacted<T> {
		return new Redacted(value);
	}

	/** Read the wrapped credential. Call only where the raw value must leave the process. */
	static value<T>(redacted: Redacted<T>): T {
		return redacted.#value;
	}

	toString(): string {
		return placeholder;
	}

	toJSON(): string {
		return placeholder;
	}
}

// Node and Bun console output; a computed class member would break isolatedDeclarations.
Object.defineProperty(Redacted.prototype, Symbol.for('nodejs.util.inspect.custom'), {
	value: (): string => placeholder,
});

/** Wrap a credential. */
export const make = <T>(value: T): Redacted<T> => Redacted.make(value);

/** Read the wrapped credential. */
export const value = <T>(redacted: Redacted<T>): T => Redacted.value(redacted);

/** Unwrap when `input` is `Redacted`, otherwise return it unchanged. */
export const unwrap = <T>(input: T | Redacted<T>): T =>
	input instanceof Redacted ? Redacted.value(input) : input;
