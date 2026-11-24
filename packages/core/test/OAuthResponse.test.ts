import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import * as OAuthResponse from '../src/OAuthResponse.ts';
import * as Redacted from '../src/Redacted.ts';

describe('RFC 6749 s5.1 responses', () => {
	it('json is no-store and unwraps Redacted only for the response', async () => {
		const token = Redacted.make('at-123');
		const res = OAuthResponse.json({ access_token: token, token_type: 'Bearer' });
		assert.equal(res.status, 200);
		assert.equal(res.headers.get('Cache-Control'), 'no-store');
		assert.match(res.headers.get('Content-Type') ?? '', /^application\/json/);
		assert.deepEqual(await res.json(), { access_token: 'at-123', token_type: 'Bearer' });
		assert.equal(JSON.stringify({ access_token: token }), '{"access_token":"<redacted>"}');
	});

	it('json honours status and extra headers', () => {
		const res = OAuthResponse.json({}, { status: 201, headers: { 'X-A': '1' } });
		assert.equal(res.status, 201);
		assert.equal(res.headers.get('X-A'), '1');
		assert.equal(res.headers.get('Cache-Control'), 'no-store');
	});

	it('redirect is 303 with params and iss (RFC 9207)', () => {
		const res = OAuthResponse.redirect('https://app.example/cb', { code: Redacted.make('c1'), state: 's' }, { issuer: 'https://as.example' });
		assert.equal(res.status, 303);
		const url = new URL(res.headers.get('Location') ?? '');
		assert.equal(url.searchParams.get('code'), 'c1');
		assert.equal(url.searchParams.get('state'), 's');
		assert.equal(url.searchParams.get('iss'), 'https://as.example');
	});
});
