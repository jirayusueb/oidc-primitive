import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { describe, it } from 'vitest';
import {
	AccessToken,
	AccessTokenVerifier,
	Bearer,
	ClientAssertion,
	ClientSecret,
	IdToken,
	Keys,
	OAuthError,
	Pkce,
} from '../src/index.ts';

describe('RFC 6749 s5.2 and s4.1.2.1 error responses', () => {
	it('builds a no-store JSON error', async () => {
		const res = new OAuthError.InvalidGrant('code expired').toResponse();
		assert.equal(res.status, 400);
		assert.equal(res.headers.get('cache-control'), 'no-store');
		assert.deepEqual(await res.json(), {
			error: 'invalid_grant',
			error_description: 'code expired',
		});
	});

	it('answers invalid_client with 401, and a Basic challenge only for the Basic scheme', () => {
		const res = new OAuthError.InvalidClient('bad', { scheme: 'Basic' }).toResponse();
		assert.equal(res.status, 401);
		assert.equal(res.headers.get('www-authenticate'), 'Basic realm="token"');
		const other = new OAuthError.InvalidClient().toResponse();
		assert.equal(other.status, 401);
		assert.equal(other.headers.get('www-authenticate'), null);
	});

	it('answers invalid_token and insufficient_scope with Bearer challenges (RFC 6750 s3)', () => {
		assert.equal(
			new OAuthError.InvalidToken('expired').toResponse().headers.get('www-authenticate'),
			'Bearer error="invalid_token", error_description="expired"',
		);
		const res = new OAuthError.InsufficientScope('read write').toResponse();
		assert.equal(res.status, 403);
		assert.equal(
			res.headers.get('www-authenticate'),
			'Bearer error="insufficient_scope", scope="read write"',
		);
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
		const err = OAuthError.fromCode('use_dpop_nonce', { status: 401 });
		assert.equal(err.code, 'use_dpop_nonce');
		assert.equal(new OAuthError.InvalidGrant()._tag, 'InvalidGrant');
		assert.ok(new OAuthError.InvalidGrant() instanceof OAuthError.OAuthError);
	});
});

describe('RFC 6750 s3.1 MissingToken', () => {
	it('answers 401 with a bare Bearer challenge and no error code', async () => {
		const error: OAuthError.OAuthError = new OAuthError.MissingToken();
		const res = error.toResponse();
		assert.equal(res.status, 401);
		assert.equal(res.headers.get('www-authenticate'), 'Bearer');
		assert.equal('error' in error.toJSON(), false);
		assert.throws(
			() => error.toRedirect('https://app.example/cb', { issuer: 'https://as.example' }),
			TypeError,
		);
	});

	it('is not an InvalidToken', () => {
		assert.equal(new OAuthError.MissingToken() instanceof OAuthError.InvalidToken, false);
		assert.ok(new OAuthError.MissingToken() instanceof OAuthError.OAuthError);
	});
});

describe('RFC 6749 s5.2 and RFC 6750 s3.1 OAuthError.fromCode', () => {
	const codes = [
		'invalid_redirect_uri',
		'invalid_request',
		'invalid_client',
		'invalid_grant',
		'unauthorized_client',
		'unsupported_grant_type',
		'unsupported_response_type',
		'invalid_scope',
		'invalid_target',
		'access_denied',
		'login_required',
		'consent_required',
		'interaction_required',
		'account_selection_required',
		'request_not_supported',
		'request_uri_not_supported',
		'registration_not_supported',
		'invalid_token',
		'insufficient_scope',
		'server_error',
		'temporarily_unavailable',
	] as const;

	it('returns the subclass for every registered code', () => {
		for (const code of codes) {
			const error = OAuthError.fromCode(code, { description: 'd' });
			assert.equal(error.code, code);
			assert.notEqual(error._tag, 'OAuthError', code);
			assert.equal(error.description, 'd');
		}
	});

	it('keeps status and challenge of the subclass', () => {
		const invalidToken = OAuthError.fromCode('invalid_token');
		assert.equal(invalidToken.status, 401);
		assert.match(invalidToken.toResponse().headers.get('www-authenticate') ?? '', /^Bearer /);
		const scope = OAuthError.fromCode('insufficient_scope');
		assert.equal(scope.status, 403);
		assert.match(scope.toResponse().headers.get('www-authenticate') ?? '', /^Bearer /);
		assert.equal(OAuthError.fromCode('temporarily_unavailable').status, 503);
		assert.equal(OAuthError.fromCode('invalid_client').status, 401);
	});

	it('builds a base error for an unknown extension code', () => {
		const error = OAuthError.fromCode('use_dpop_nonce', { status: 401 });
		assert.equal(error._tag, 'OAuthError');
		assert.equal(error.status, 401);
		assert.equal(OAuthError.fromCode('toString')._tag, 'OAuthError');
	});
});

describe('RFC 6750 s3 challenge safety', () => {
	it('drops an unsafe description from the Bearer challenge instead of throwing', () => {
		const res = new OAuthError.InvalidToken('café "x"').toResponse();
		assert.equal(res.status, 401);
		assert.equal(res.headers.get('www-authenticate'), 'Bearer error="invalid_token"');
	});
});

describe('RFC 6749 s10.3 and s10.10 errors carry no secret input (design G5)', () => {
	it('never echoes the credential a primitive rejected', async () => {
		const secret = 's3cr3tTokenValue0123456789abcdefghijklmnopq';
		const issuer = 'https://op.example';
		const { publicKey } = await Keys.generate('ES256');
		const rejected: unknown[] = await Promise.all([
			AccessToken.verify(secret, { issuer, audience: 'https://rs', keys: publicKey }).catch(
				(e: unknown) => e,
			),
			ClientAssertion.verify(secret, { issuer, clientId: 'c', keys: publicKey }).catch(
				(e: unknown) => e,
			),
			IdToken.verify(secret, { issuer, audience: 'c', keys: publicKey }).catch((e: unknown) => e),
			Pkce.verify(secret, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM').catch((e: unknown) => e),
			AccessTokenVerifier.make({ issuer, audience: 'https://rs', keys: publicKey })
				.verifyHeaders(new Headers({ Authorization: `Bearer ${secret}` }))
				.catch((e: unknown) => e),
			Promise.resolve()
				.then(() => Bearer.parse(new Headers({ Authorization: `Bearer ${secret} x` })))
				.catch((e: unknown) => e),
			Promise.resolve()
				.then(() => ClientSecret.parseBasic(`Basic ${secret}`))
				.catch((e: unknown) => e),
		]);
		assert.equal(rejected.length, 7);
		for (const error of rejected) {
			assert.ok(error instanceof OAuthError.OAuthError);
			const body = await error.toResponse().text();
			for (const out of [String(error), `${error}`, JSON.stringify(error), inspect(error), body]) {
				assert.equal(out.includes(secret), false, out);
			}
		}
	});
});
