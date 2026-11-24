import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { ClientSecret, OAuthError, Redacted } from '../src/index.ts';

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

	it('fails with a Basic challenge (RFC 6749 s5.2)', () => {
		const error = (() => {
			try {
				ClientSecret.parseBasic('Basic !!!');
			} catch (e) {
				return e;
			}
		})();
		assert.ok(error instanceof OAuthError.InvalidClient);
		assert.equal(error.toResponse().headers.get('www-authenticate'), 'Basic realm="token"');
	});
});
