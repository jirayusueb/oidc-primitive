import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { OAuthError, Resource, Scope } from '../src/index.ts';

describe('RFC 6749 s3.3 scope', () => {
	it('parses space-delimited tokens, dropping duplicates', () => {
		assert.deepEqual(Scope.parse('openid email openid'), ['openid', 'email']);
		assert.deepEqual(Scope.parse(undefined), []);
		assert.equal(Scope.format(['openid', 'email', 'openid']), 'openid email');
	});

	it('rejects malformed tokens', () => {
		assert.throws(() => Scope.parse('openid  email'), OAuthError.InvalidScope);
		assert.throws(() => Scope.parse('a"b'), OAuthError.InvalidScope);
		assert.throws(() => Scope.make('a b'), TypeError);
	});

	it('checks allOf and anyOf requirements', () => {
		assert.equal(Scope.satisfies(['read', 'write'], { allOf: ['read'] }), true);
		assert.equal(Scope.satisfies(['read'], { allOf: ['read', 'write'] }), false);
		assert.equal(Scope.satisfies(['admin'], { anyOf: ['write', 'admin'] }), true);
		assert.equal(Scope.satisfies(['read'], { allOf: ['read'], anyOf: ['write'] }), false);
	});

	it('filters granted scopes to declared ones without rejecting the rest', () => {
		const read = Scope.make('read');
		const write = Scope.make('write');
		assert.deepEqual(Scope.filter(['read', 'other'], [read, write]), ['read']);
	});
});

describe('RFC 8707 s2 resource indicators', () => {
	it('uses the issuer when no resource was requested', () => {
		assert.equal(Resource.audience([], 'https://as.example'), 'https://as.example');
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
