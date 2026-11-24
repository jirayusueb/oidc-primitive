import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { Redacted, Token } from '../src/index.ts';

describe('RFC 6749 s10.10 credential generation', () => {
	it('generates distinct 256-bit base64url tokens', () => {
		const a = Redacted.value(Token.generate());
		const b = Redacted.value(Token.generate());
		assert.match(a, /^[A-Za-z0-9_-]{43}$/);
		assert.notEqual(a, b);
		assert.throws(() => Token.generate(8), RangeError);
	});

	it('hashes and compares credentials', async () => {
		const token = Token.generate();
		const stored = await Token.hash(token);
		assert.equal(await Token.matchesHash(token, stored), true);
		assert.equal(await Token.matchesHash('other', stored), false);
		assert.equal(await Token.equals(token, Redacted.value(token)), true);
	});
});
