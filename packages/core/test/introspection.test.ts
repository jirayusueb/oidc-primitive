import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { Introspection } from '../src/index.ts';

describe('RFC 7662 s2.2 introspection response', () => {
	it('inactive is exactly { active: false }', () => {
		assert.deepEqual(Introspection.inactive(), { active: false });
	});

	it('active maps known fields, passes extras, and cannot be overridden', () => {
		const body = Introspection.active({ scope: 'a b', client_id: 'c', exp: 9, sub: 'u', aud: ['r'], tenant: 't', active: false });
		assert.deepEqual(body, { scope: 'a b', client_id: 'c', exp: 9, sub: 'u', aud: ['r'], tenant: 't', active: true });
	});
});
