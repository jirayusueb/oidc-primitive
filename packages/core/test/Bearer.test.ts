import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Bearer, OAuthError } from '../src/index.ts';
const { InvalidToken } = OAuthError;

const headers = (authorization?: string): Headers =>
	new Headers(authorization === undefined ? {} : { Authorization: authorization });

describe('RFC 6750 s2.1 Authorization header', () => {
	it('extracts a b64token', () => {
		assert.equal(Bearer.extract(headers('Bearer abc.DEF-_~+/=')), 'abc.DEF-_~+/=');
		assert.equal(Bearer.extract(headers('bearer abc')), 'abc');
	});

	it('returns undefined when absent or another scheme; never reads the query', () => {
		assert.equal(Bearer.extract(headers()), undefined);
		assert.equal(Bearer.extract(headers('Basic Zm9vOmJhcg==')), undefined);
	});

	it('throws InvalidToken when malformed', () => {
		for (const bad of ['Bearer', 'Bearer ', 'Bearer a b', 'Bearer a$b', 'Bearer =']) {
			assert.throws(() => Bearer.extract(headers(bad)), InvalidToken);
		}
	});
});

describe('RFC 6750 s3 challenge', () => {
	it('formats quoted params', () => {
		assert.equal(
			Bearer.challenge({ realm: 'api', error: 'invalid_token', resource_metadata: 'https://rs/.well-known/oauth-protected-resource' }),
			'Bearer realm="api", error="invalid_token", resource_metadata="https://rs/.well-known/oauth-protected-resource"',
		);
		assert.equal(Bearer.challenge(), 'Bearer');
	});

	it('rejects characters outside s3', () => {
		assert.throws(() => Bearer.challenge({ error_description: 'a"b' }), TypeError);
	});
});
