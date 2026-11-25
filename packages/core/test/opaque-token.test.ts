import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { OpaqueToken, Redacted } from '../src/index.ts';

describe('RFC 6749 s10.10 credential generation', () => {
	it('generates distinct 256-bit base64url tokens', () => {
		const a = Redacted.value(OpaqueToken.generate());
		const b = Redacted.value(OpaqueToken.generate());
		assert.match(a, /^[A-Za-z0-9_-]{43}$/);
		assert.notEqual(a, b);
		assert.throws(() => OpaqueToken.generate(8), RangeError);
	});

	it('hashes and compares credentials', async () => {
		const token = OpaqueToken.generate();
		const stored = await OpaqueToken.hash(token);
		assert.equal(await OpaqueToken.matchesHash(token, stored), true);
		assert.equal(await OpaqueToken.matchesHash('other', stored), false);
		assert.equal(await OpaqueToken.equals(token, Redacted.value(token)), true);
	});
});
