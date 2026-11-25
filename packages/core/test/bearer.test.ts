import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { Bearer, OAuthError } from '../src/index.ts';
const { InvalidToken } = OAuthError;

const headers = (authorization?: string): Headers =>
	new Headers(authorization === undefined ? {} : { Authorization: authorization });

describe('RFC 6750 s2.1 Authorization header', () => {
	it('extracts a b64token', () => {
		assert.equal(Bearer.parse(headers('Bearer abc.DEF-_~+/=')), 'abc.DEF-_~+/=');
		assert.equal(Bearer.parse(headers('bearer abc')), 'abc');
	});

	it('returns undefined when absent or another scheme; never reads the query', () => {
		assert.equal(Bearer.parse(headers()), undefined);
		assert.equal(Bearer.parse(headers('Basic Zm9vOmJhcg==')), undefined);
	});

	it('throws InvalidToken when malformed', () => {
		for (const bad of ['Bearer', 'Bearer ', 'Bearer a b', 'Bearer a$b', 'Bearer =']) {
			assert.throws(() => Bearer.parse(headers(bad)), InvalidToken);
		}
	});
});

describe('RFC 6750 s3 challenge', () => {
	it('formats quoted params', () => {
		assert.equal(
			Bearer.challenge({ realm: 'api', error: 'invalid_token', resourceMetadata: 'https://rs/.well-known/oauth-protected-resource' }),
			'Bearer realm="api", error="invalid_token", resource_metadata="https://rs/.well-known/oauth-protected-resource"',
		);
		assert.equal(Bearer.challenge(), 'Bearer');
	});

	it('serializes scope and error_description to wire names', () => {
		assert.equal(
			Bearer.challenge({ error: 'insufficient_scope', errorDescription: 'need more', scope: 'a b' }),
			'Bearer error="insufficient_scope", error_description="need more", scope="a b"',
		);
	});

	it('rejects characters outside s3', () => {
		assert.throws(() => Bearer.challenge({ errorDescription: 'a"b' }), TypeError);
	});
});
