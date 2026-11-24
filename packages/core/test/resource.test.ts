import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { OAuthError, Resource } from '../src/index.ts';

describe('RFC 8707 s2 resource indicators', () => {
	it('uses the issuer when no resource was requested', () => {
		assert.equal(Resource.audience([], 'https://as.example'), 'https://as.example');
	});

	it('validate returns nothing and throws InvalidTarget', () => {
		assert.equal(Resource.validate('https://api.example/v1'), undefined);
	});

	it('accepts one absolute resource and rejects several or fragments', () => {
		assert.equal(Resource.audience(['https://api.example'], 'https://as.example'), 'https://api.example');
		assert.throws(
			() => Resource.audience(['https://a.example', 'https://b.example'], 'https://as.example'),
			OAuthError.InvalidTarget,
		);
		assert.throws(() => Resource.validate('https://api.example#x'), OAuthError.InvalidTarget);
		assert.throws(() => Resource.validate('api'), OAuthError.InvalidTarget);
	});
});
