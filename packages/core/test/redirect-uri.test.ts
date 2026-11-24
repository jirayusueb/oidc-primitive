import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { OAuthError, RedirectUri } from '../src/index.ts';

describe('RFC 9700 s4.1.3 exact redirect matching', () => {
	const registered = ['https://app.example/cb', 'http://127.0.0.1/cb', 'http://[::1]/cb'];

	it('matches identical strings only', () => {
		assert.equal(RedirectUri.matches('https://app.example/cb', registered), true);
		for (const uri of [
			'https://app.example/cb/',
			'https://app.example/cb?x=1',
			'https://APP.example/cb',
			'https://app.example:443/cb',
			'https://evil.example/cb',
			'http://app.example/cb',
		]) {
			assert.equal(RedirectUri.matches(uri, registered), false, uri);
		}
	});

	it('lets the loopback port vary (RFC 8252 s7.3)', () => {
		assert.equal(RedirectUri.match('http://127.0.0.1:51004/cb', registered), 'http://127.0.0.1/cb');
		assert.equal(RedirectUri.matches('http://[::1]:8080/cb', registered), true);
		assert.equal(RedirectUri.matches('http://127.0.0.1:51004/other', registered), false);
		assert.equal(RedirectUri.matches('http://localhost:51004/cb', ['http://localhost/cb']), false);
	});
});

describe('RFC 6749 s3.1.2 and RFC 8252 s7 registration rules', () => {
	it('rejects fragments, plain http and dangerous schemes', () => {
		assert.throws(() => RedirectUri.validate('https://app.example/cb#x'), OAuthError.InvalidRedirectUri);
		assert.throws(() => RedirectUri.validate('http://app.example/cb'), OAuthError.InvalidRedirectUri);
		assert.throws(() => RedirectUri.validate('/relative'), OAuthError.InvalidRedirectUri);
		assert.throws(
			() => RedirectUri.validate('javascript:alert(1)', { applicationType: 'native' }),
			OAuthError.InvalidRedirectUri,
		);
		assert.throws(() => RedirectUri.validate('com.example.app:/cb'), OAuthError.InvalidRedirectUri);
	});

	it('rejects http://localhost for every client (RFC 8252 s8.3)', () => {
		assert.throws(() => RedirectUri.validate('http://localhost:3000/cb'), OAuthError.InvalidRedirectUri);
		assert.throws(() => RedirectUri.validate('http://localhost/cb', { applicationType: 'native' }), OAuthError.InvalidRedirectUri);
	});

	it('accepts https, loopback http and native private-use schemes', () => {
		RedirectUri.validate('https://app.example/cb');
		RedirectUri.validate('http://127.0.0.1:3000/cb');
		RedirectUri.validate('http://[::1]:3000/cb');
		RedirectUri.validate('com.example.app:/cb', { applicationType: 'native' });
	});
});
