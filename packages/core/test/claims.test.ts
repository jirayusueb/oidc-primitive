import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { Claims, OAuthError } from '../src/index.ts';
const { InvalidRequest } = OAuthError;

describe('OIDC Core s5.4 scope claims', () => {
	it('maps standard scopes to the exact claim lists', () => {
		assert.deepEqual(Claims.forScopes(['email']), ['email', 'email_verified']);
		assert.deepEqual(Claims.forScopes(['address']), ['address']);
		assert.deepEqual(Claims.forScopes(['phone']), ['phone_number', 'phone_number_verified']);
		assert.deepEqual(Claims.forScopes(['profile']), [
			'name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile',
			'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at',
		]);
		assert.deepEqual(Claims.forScopes(['openid', 'custom', '__proto__']), []);
	});
});

describe('OIDC Core s5.5 claims request', () => {
	it('parses userinfo and id_token maps', () => {
		const request = Claims.parseRequest('{"userinfo":{"email":null,"name":{"essential":true}},"id_token":{"auth_time":null}}');
		assert.deepEqual(Object.keys(request.userinfo ?? {}), ['email', 'name']);
		assert.deepEqual(Object.keys(request.id_token ?? {}), ['auth_time']);
		assert.deepEqual(Claims.parseRequest(undefined), {});
		assert.deepEqual(Claims.parseRequest(null), {});
	});

	it('rejects malformed JSON and wrong shapes', () => {
		for (const bad of ['{', '[]', '"x"', '{"userinfo":[]}', '{"userinfo":{"email":true}}', '{"id_token":"x"}']) {
			assert.throws(() => Claims.parseRequest(bad), InvalidRequest, bad);
		}
	});

	it('selects by scope or request for the target, always keeping sub', () => {
		const all = { sub: 'u', email: 'a@b', name: 'N', phone_number: '1', auth_time: 5 };
		const request = Claims.parseRequest('{"userinfo":{"phone_number":null},"id_token":{"auth_time":null}}');
		assert.deepEqual(Claims.select(all, { scopes: ['email'], target: 'userinfo' }), { sub: 'u', email: 'a@b' });
		assert.deepEqual(Claims.select(all, { scopes: ['openid'], request, target: 'userinfo' }), { sub: 'u', phone_number: '1' });
		assert.deepEqual(Claims.select(all, { scopes: [], request, target: 'id_token' }), { sub: 'u', auth_time: 5 });
	});
});
