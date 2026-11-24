import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { Metadata } from '../src/index.ts';

const endpoints = { authorization: 'https://as.example/authorize', token: 'https://as.example/token', jwks: 'https://as.example/jwks' };

describe('RFC 8414 s2 and OIDC Discovery s3 metadata', () => {
	it('applies secure defaults and omits unset endpoints', () => {
		const doc = Metadata.authorizationServer({ issuer: 'https://as.example', endpoints, scopes: ['openid'] });
		assert.equal(doc.issuer, 'https://as.example');
		assert.equal(doc.token_endpoint, endpoints.token);
		assert.equal(doc.jwks_uri, endpoints.jwks);
		assert.deepEqual(doc.response_types_supported, ['code']);
		assert.deepEqual(doc.response_modes_supported, ['query']);
		assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
		assert.equal(doc.authorization_response_iss_parameter_supported, true);
		assert.deepEqual(doc.grant_types_supported, ['authorization_code', 'refresh_token']);
		assert.deepEqual(doc.token_endpoint_auth_methods_supported, ['client_secret_basic', 'client_secret_post', 'private_key_jwt']);
		assert.deepEqual(doc.id_token_signing_alg_values_supported, ['RS256']);
		assert.deepEqual(doc.subject_types_supported, ['public']);
		assert.equal((doc.token_endpoint_auth_signing_alg_values_supported as string[]).includes('HS256'), false);
		assert.equal('userinfo_endpoint' in doc, false);
	});

	it('rejects symmetric token endpoint signing algs', () => {
		assert.throws(() => Metadata.authorizationServer({ issuer: 'https://as.example', endpoints, tokenEndpointAuthSigningAlgs: ['HS256'] }), TypeError);
	});

	it('validates the issuer', () => {
		for (const issuer of ['http://as.example', 'https://as.example?x=1', 'https://as.example#f', 'https://as.example?', 'nope']) {
			assert.throws(() => Metadata.authorizationServer({ issuer, endpoints }), TypeError, issuer);
		}
		Metadata.authorizationServer({ issuer: 'http://localhost:3000', endpoints });
		Metadata.authorizationServer({ issuer: 'http://127.0.0.1:3000', endpoints });
	});

	it('builds both well-known URLs for an issuer with a path', () => {
		assert.deepEqual(Metadata.wellKnownUrls('https://as.example/tenant/a'), {
			openidConfiguration: 'https://as.example/tenant/a/.well-known/openid-configuration',
			oauthAuthorizationServer: 'https://as.example/.well-known/oauth-authorization-server/tenant/a',
		});
		assert.deepEqual(Metadata.wellKnownUrls('https://as.example'), {
			openidConfiguration: 'https://as.example/.well-known/openid-configuration',
			oauthAuthorizationServer: 'https://as.example/.well-known/oauth-authorization-server',
		});
	});
});
