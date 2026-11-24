import { Redacted } from '../redacted.ts';

/** Unwrap when `input` is `Redacted`, otherwise return it unchanged. */
export const unwrap = <T>(input: T | Redacted<T>): T =>
	input instanceof Redacted ? Redacted.value(input) : input;
