import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { inspect } from 'node:util';
import { Redacted } from '../src/index.ts';

describe('RFC 6749 s10.10 Redacted keeps credentials out of output', () => {
	it('prints a placeholder everywhere and reads on request', () => {
		const secret = Redacted.make('s3cr3t');
		for (const out of [String(secret), `${secret}`, JSON.stringify({ secret }), inspect(secret)]) {
			assert.equal(out.includes('s3cr3t'), false, out);
		}
		assert.equal(Redacted.value(secret), 's3cr3t');
	});

	it('does not export unwrap', () => {
		assert.equal('unwrap' in Redacted, false);
	});
});
