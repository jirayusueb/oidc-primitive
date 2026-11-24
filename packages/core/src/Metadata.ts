export interface Endpoints {
	readonly authorization: string;
	readonly token: string;
	readonly jwks: string;
	readonly userinfo?: string;
	readonly introspection?: string;
	readonly revocation?: string;
	readonly registration?: string;
	readonly endSession?: string;
}

export interface AuthorizationServerOptions {
	readonly issuer: string;
	readonly endpoints: Endpoints;
	readonly scopes?: readonly string[];
	readonly grantTypes?: readonly string[];
	readonly tokenEndpointAuthMethods?: readonly string[];
	readonly tokenEndpointAuthSigningAlgs?: readonly string[];
	readonly idTokenSigningAlgs?: readonly string[];
	readonly claims?: readonly string[];
	readonly subjectTypes?: readonly string[];
	/** OIDC Core s5.5 `claims` request parameter; default false. */
	readonly claimsParameterSupported?: boolean;
}

const asymmetric = ['ES256', 'EdDSA', 'PS256', 'RS256', 'ES384', 'ES512', 'PS384', 'PS512', 'RS384', 'RS512'];

const parseIssuer = (issuer: string): URL => {
	let url: URL;
	try {
		url = new URL(issuer);
	} catch {
		throw new TypeError('Issuer must be an absolute URL');
	}
	const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
	if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
		throw new TypeError('Issuer must use https (http only for localhost)');
	}
	if (url.search || url.hash || issuer.includes('?') || issuer.includes('#')) {
		throw new TypeError('Issuer must not have a query or fragment (RFC 8414 s2)');
	}
	return url;
};

/** RFC 8414 s2 and OIDC Discovery s3 document in snake_case. */
export const authorizationServer = (options: AuthorizationServerOptions): Record<string, unknown> => {
	const { issuer, endpoints: e } = options;
	parseIssuer(issuer);
	const authMethods = options.tokenEndpointAuthMethods ?? ['client_secret_basic', 'client_secret_post', 'private_key_jwt'];
	const signingAlgs = options.tokenEndpointAuthSigningAlgs ?? asymmetric;
	if (signingAlgs.some((alg) => !asymmetric.includes(alg))) {
		throw new TypeError('token_endpoint_auth_signing_alg_values_supported must be asymmetric');
	}
	const doc: Record<string, unknown> = {
		issuer,
		authorization_endpoint: e.authorization,
		token_endpoint: e.token,
		jwks_uri: e.jwks,
		userinfo_endpoint: e.userinfo,
		introspection_endpoint: e.introspection,
		revocation_endpoint: e.revocation,
		registration_endpoint: e.registration,
		end_session_endpoint: e.endSession,
		scopes_supported: options.scopes,
		response_types_supported: ['code'],
		response_modes_supported: ['query'],
		grant_types_supported: options.grantTypes ?? ['authorization_code', 'refresh_token'],
		subject_types_supported: options.subjectTypes ?? ['public'],
		// OIDC Discovery s3: RS256 MUST be listed, so it is the default.
		id_token_signing_alg_values_supported: options.idTokenSigningAlgs ?? ['RS256'],
		token_endpoint_auth_methods_supported: authMethods,
		token_endpoint_auth_signing_alg_values_supported: authMethods.includes('private_key_jwt') ? signingAlgs : undefined,
		claims_supported: options.claims,
		code_challenge_methods_supported: ['S256'],
		authorization_response_iss_parameter_supported: true,
		claims_parameter_supported: options.claimsParameterSupported ?? false,
		// OIDC Discovery s3 defaults these to true when absent; request objects are not supported.
		request_parameter_supported: false,
		request_uri_parameter_supported: false,
	};
	for (const key of Object.keys(doc)) if (doc[key] === undefined) delete doc[key];
	return doc;
};

/** OIDC Discovery s4 and RFC 8414 s3.1 (well-known segment inserted between host and path). */
export const wellKnownUrls = (issuer: string): { openidConfiguration: string; oauthAuthorizationServer: string } => {
	const url = parseIssuer(issuer);
	// RFC 8414 s3.1: any terminating "/" is removed before inserting the well-known segment.
	const path = url.pathname.replace(/\/$/, '');
	return {
		openidConfiguration: `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`,
		oauthAuthorizationServer: `${url.origin}/.well-known/oauth-authorization-server${path}`,
	};
};
