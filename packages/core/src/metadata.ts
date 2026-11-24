import { assertionAlgorithms } from './keys.ts';

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
	readonly scopesSupported?: readonly string[];
	readonly grantTypesSupported?: readonly string[];
	readonly tokenEndpointAuthMethodsSupported?: readonly string[];
	readonly tokenEndpointAuthSigningAlgValuesSupported?: readonly string[];
	/** Must include RS256 (OIDC Discovery s3) unless `allowWithoutRs256` is set. */
	readonly idTokenSigningAlgValuesSupported?: readonly string[];
	/** Permit an ID token alg list without RS256, as FAPI 2.0 OPs do. */
	readonly allowWithoutRs256?: boolean;
	readonly claimsSupported?: readonly string[];
	readonly subjectTypesSupported?: readonly string[];
	/** OIDC Core s5.5 `claims` request parameter; default false. */
	readonly claimsParameterSupported?: boolean;
}

/** RFC 8414 s2 and OIDC Discovery s3 document; absent optional fields are omitted. */
export interface AuthorizationServerMetadata {
	readonly issuer: string;
	readonly authorization_endpoint: string;
	readonly token_endpoint: string;
	readonly jwks_uri: string;
	readonly userinfo_endpoint?: string;
	readonly introspection_endpoint?: string;
	readonly revocation_endpoint?: string;
	readonly registration_endpoint?: string;
	readonly end_session_endpoint?: string;
	readonly scopes_supported?: readonly string[];
	readonly response_types_supported: readonly string[];
	readonly response_modes_supported: readonly string[];
	readonly grant_types_supported: readonly string[];
	readonly subject_types_supported: readonly string[];
	readonly id_token_signing_alg_values_supported: readonly string[];
	readonly token_endpoint_auth_methods_supported: readonly string[];
	readonly token_endpoint_auth_signing_alg_values_supported?: readonly string[];
	readonly claims_supported?: readonly string[];
	readonly code_challenge_methods_supported: readonly string[];
	readonly authorization_response_iss_parameter_supported: boolean;
	readonly claims_parameter_supported: boolean;
	readonly request_parameter_supported: boolean;
	readonly request_uri_parameter_supported: boolean;
}

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

const compact = <T extends object>(doc: T): T =>
	Object.fromEntries(Object.entries(doc).filter(([, value]) => value !== undefined)) as T;

/** RFC 8414 s2 and OIDC Discovery s3 document in snake_case. */
export const authorizationServer = (options: AuthorizationServerOptions): AuthorizationServerMetadata => {
	const { issuer, endpoints: e } = options;
	parseIssuer(issuer);
	const authMethods = options.tokenEndpointAuthMethodsSupported ?? ['client_secret_basic', 'client_secret_post', 'private_key_jwt'];
	const signingAlgs = options.tokenEndpointAuthSigningAlgValuesSupported ?? assertionAlgorithms;
	if (signingAlgs.some((alg) => !assertionAlgorithms.includes(alg))) {
		throw new TypeError('token_endpoint_auth_signing_alg_values_supported must be assertionAlgorithms');
	}
	const idAlgs = options.idTokenSigningAlgValuesSupported ?? ['RS256'];
	if (!idAlgs.includes('RS256') && options.allowWithoutRs256 !== true) {
		throw new TypeError('id_token_signing_alg_values_supported must include RS256 (OIDC Discovery s3)');
	}
	const doc = {
		issuer,
		authorization_endpoint: e.authorization,
		token_endpoint: e.token,
		jwks_uri: e.jwks,
		userinfo_endpoint: e.userinfo,
		introspection_endpoint: e.introspection,
		revocation_endpoint: e.revocation,
		registration_endpoint: e.registration,
		end_session_endpoint: e.endSession,
		scopes_supported: options.scopesSupported,
		response_types_supported: ['code'],
		response_modes_supported: ['query'],
		grant_types_supported: options.grantTypesSupported ?? ['authorization_code', 'refresh_token'],
		subject_types_supported: options.subjectTypesSupported ?? ['public'],
		// OIDC Discovery s3: RS256 MUST be listed, so it is the default.
		id_token_signing_alg_values_supported: idAlgs,
		token_endpoint_auth_methods_supported: authMethods,
		token_endpoint_auth_signing_alg_values_supported: authMethods.includes('private_key_jwt') ? signingAlgs : undefined,
		claims_supported: options.claimsSupported,
		code_challenge_methods_supported: ['S256'],
		authorization_response_iss_parameter_supported: true,
		claims_parameter_supported: options.claimsParameterSupported ?? false,
		// OIDC Discovery s3 defaults these to true when absent; request objects are not supported.
		request_parameter_supported: false,
		request_uri_parameter_supported: false,
	};
	return compact(doc);
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
