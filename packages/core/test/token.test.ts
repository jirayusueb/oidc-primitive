import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { inspect } from 'node:util';
import { ClientSecret, OAuthError, Redacted, Token } from '../src/index.ts';

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

describe('Redacted keeps credentials out of output', () => {
	it('prints a placeholder everywhere and unwraps on request', () => {
		const secret = Redacted.make('s3cr3t');
		for (const out of [String(secret), `${secret}`, JSON.stringify({ secret }), inspect(secret)]) {
			assert.equal(out.includes('s3cr3t'), false, out);
		}
		assert.equal(Redacted.value(secret), 's3cr3t');
	});
});

describe('RFC 6749 s2.3.1 client_secret_basic', () => {
	const basic = (value: string) => `Basic ${btoa(value)}`;

	it('form-decodes id and secret', () => {
		const parsed = ClientSecret.parseBasic(basic('my%20client:p%3Ass+w'));
		assert.equal(parsed?.clientId, 'my client');
		assert.equal(parsed && Redacted.value(parsed.clientSecret), 'p:ss w');
	});

	it('ignores absent headers and other schemes, rejects malformed ones', () => {
		assert.equal(ClientSecret.parseBasic(null), undefined);
		assert.equal(ClientSecret.parseBasic('Bearer abc'), undefined);
		assert.throws(() => ClientSecret.parseBasic('Basic !!!'), OAuthError.InvalidClient);
		assert.throws(() => ClientSecret.parseBasic(basic('no-colon')), OAuthError.InvalidClient);
		assert.throws(() => ClientSecret.parseBasic(basic(':secret')), OAuthError.InvalidClient);
	});
});

describe('RFC 6749 s5.2 and s4.1.2.1 error responses', () => {
	it('builds a no-store JSON error', async () => {
		const res = new OAuthError.InvalidGrant('code expired').toResponse();
		assert.equal(res.status, 400);
		assert.equal(res.headers.get('cache-control'), 'no-store');
		assert.deepEqual(await res.json(), { error: 'invalid_grant', error_description: 'code expired' });
	});

	it('answers invalid_client with 401 and a Basic challenge', () => {
		const res = new OAuthError.InvalidClient().toResponse();
		assert.equal(res.status, 401);
		assert.match(res.headers.get('www-authenticate') ?? '', /^Basic /);
	});

	it('answers invalid_token and insufficient_scope with Bearer challenges (RFC 6750 s3)', () => {
		assert.equal(
			new OAuthError.InvalidToken('expired').toResponse().headers.get('www-authenticate'),
			'Bearer error="invalid_token", error_description="expired"',
		);
		const res = new OAuthError.InsufficientScope('read write').toResponse();
		assert.equal(res.status, 403);
		assert.equal(res.headers.get('www-authenticate'), 'Bearer error="insufficient_scope", scope="read write"');
	});

	it('redirects with error, state and iss (RFC 9207 s2)', () => {
		const res = new OAuthError.AccessDenied().toRedirect('https://app.example/cb?x=1', {
			state: 'xyz',
			issuer: 'https://as.example',
		});
		assert.equal(res.status, 303);
		const location = new URL(res.headers.get('location') ?? '');
		assert.equal(location.searchParams.get('x'), '1');
		assert.equal(location.searchParams.get('error'), 'access_denied');
		assert.equal(location.searchParams.get('state'), 'xyz');
		assert.equal(location.searchParams.get('iss'), 'https://as.example');
	});

	it('supports extension codes and tags', () => {
		const err = OAuthError.make('use_dpop_nonce', { status: 401 });
		assert.equal(err.code, 'use_dpop_nonce');
		assert.equal(new OAuthError.InvalidGrant()._tag, 'InvalidGrant');
		assert.ok(new OAuthError.InvalidGrant() instanceof OAuthError.OAuthError);
	});
});
