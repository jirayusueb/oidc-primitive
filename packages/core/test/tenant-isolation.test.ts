import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { SignJWT } from 'jose';
import { AccessTokenVerifier, ClientAssertion, IdToken, Keys, OAuthError, TokenSigner } from '../src/index.ts';

// Path issuers on one host: the case where only the issuer string separates tenants.
const tenant = async (issuer: string) => {
	const { publicKey, privateKey } = await Keys.generate('ES256');
	return { issuer, publicKey, signer: TokenSigner.make({ issuer, key: privateKey, kid: 'k1', alg: 'ES256' }) };
};
const a = await tenant('https://as.example/tenant/a');
const b = await tenant('https://as.example/tenant/b');
const audience = 'https://rs.example';
const clientId = 'shared-client';

describe('a tenant A credential fails at tenant B', () => {
	const accessToken = () => a.signer.signAccessToken({ sub: 'u', aud: audience, client_id: clientId, scope: 'read' });
	const atB = (keys: CryptoKey) => AccessTokenVerifier.make({ issuer: b.issuer, audience, keys });

	it('access token at AccessTokenVerifier', async () => {
		const jwt = await accessToken();
		await AccessTokenVerifier.make({ issuer: a.issuer, audience, keys: a.publicKey }).verify(jwt);
		await assert.rejects(atB(b.publicKey).verify(jwt), OAuthError.InvalidToken);
		// Same key in both tenants (misconfiguration): the issuer check alone must still reject.
		await assert.rejects(atB(a.publicKey).verify(jwt), OAuthError.InvalidToken);
	});

	it('ID token at IdToken.verify, also with allowExpired', async () => {
		const jwt = await a.signer.signIdToken({ sub: 'u', aud: clientId });
		await IdToken.verify(jwt, { issuer: a.issuer, audience: clientId, keys: a.publicKey });
		for (const keys of [b.publicKey, a.publicKey]) {
			await assert.rejects(
				IdToken.verify(jwt, { issuer: b.issuer, audience: clientId, keys, allowExpired: true }),
				OAuthError.InvalidRequest,
			);
		}
	});

	it('client assertion at ClientAssertion.verify, for a client registered in both with one key', async () => {
		const { publicKey, privateKey } = await Keys.generate('ES256');
		const jwt = await new SignJWT({ jti: 'j1' })
			.setProtectedHeader({ alg: 'ES256' })
			.setIssuer(clientId)
			.setSubject(clientId)
			.setAudience(a.issuer)
			.setIssuedAt()
			.setExpirationTime('5m')
			.sign(privateKey);
		await ClientAssertion.verify(jwt, { issuer: a.issuer, clientId, keys: publicKey });
		await assert.rejects(
			ClientAssertion.verify(jwt, { issuer: b.issuer, clientId, keys: publicKey }),
			OAuthError.InvalidClient,
		);
	});
});
