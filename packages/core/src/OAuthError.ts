import { challenge, json, noStoreHeaders, redirect } from './internal/http.ts';

/** Error codes from RFC 6749 s4.1.2.1 and s5.2, RFC 6750 s3.1, RFC 8707 s2 and OIDC Core s3.1.2.6. */
export type Code =
	| 'invalid_request'
	| 'invalid_client'
	| 'invalid_grant'
	| 'unauthorized_client'
	| 'unsupported_grant_type'
	| 'unsupported_response_type'
	| 'invalid_scope'
	| 'invalid_target'
	| 'access_denied'
	| 'login_required'
	| 'consent_required'
	| 'interaction_required'
	| 'account_selection_required'
	| 'request_not_supported'
	| 'request_uri_not_supported'
	| 'registration_not_supported'
	| 'invalid_token'
	| 'insufficient_scope'
	| 'server_error'
	| 'temporarily_unavailable';

export interface Options {
	readonly status?: number;
	readonly description?: string;
}

export interface RedirectOptions {
	readonly state?: string;
	readonly issuer: string;
}

/**
 * An OAuth error. `description` is sent to the client, so it must never contain
 * request input, tokens or secrets.
 */
export class OAuthError extends Error {
	readonly _tag: string = 'OAuthError';
	readonly code: string;
	readonly status: number;
	readonly description: string | undefined;

	constructor(code: string, options: Options = {}) {
		super(options.description ? `${code}: ${options.description}` : code);
		this.name = 'OAuthError';
		this.code = code;
		this.status = options.status ?? 400;
		this.description = options.description;
	}

	toJSON(): { error: string; error_description?: string } {
		return this.description === undefined
			? { error: this.code }
			: { error: this.code, error_description: this.description };
	}

	/** RFC 6749 s5.2 JSON error response. */
	toResponse(): Response {
		return json(this.toJSON(), this.status, noStoreHeaders());
	}

	/** Authorization error redirect (RFC 6749 s4.1.2.1) with `iss` (RFC 9207). */
	toRedirect(redirectUri: string, options: RedirectOptions): Response {
		return redirect(
			redirectUri,
			{ error: this.code, error_description: this.description, state: options.state },
			options.issuer,
		);
	}
}

const bearer = (error: OAuthError, extra: Record<string, string | undefined>): Response => {
	const headers = noStoreHeaders();
	headers.set(
		'WWW-Authenticate',
		challenge('Bearer', { error: error.code, error_description: error.description, ...extra }),
	);
	return json(error.toJSON(), error.status, headers);
};

export class InvalidRequest extends OAuthError {
	override readonly _tag = 'InvalidRequest' as const;
	constructor(description?: string) {
		super('invalid_request', { description });
	}
}

/** RFC 6749 s5.2: 401 with a `WWW-Authenticate` challenge for the scheme the client used. */
export class InvalidClient extends OAuthError {
	override readonly _tag = 'InvalidClient' as const;
	constructor(description?: string) {
		super('invalid_client', { status: 401, description });
	}

	override toResponse(): Response {
		const response = super.toResponse();
		response.headers.set('WWW-Authenticate', 'Basic realm="token"');
		return response;
	}
}

export class InvalidGrant extends OAuthError {
	override readonly _tag = 'InvalidGrant' as const;
	constructor(description?: string) {
		super('invalid_grant', { description });
	}
}

export class UnauthorizedClient extends OAuthError {
	override readonly _tag = 'UnauthorizedClient' as const;
	constructor(description?: string) {
		super('unauthorized_client', { description });
	}
}

export class UnsupportedGrantType extends OAuthError {
	override readonly _tag = 'UnsupportedGrantType' as const;
	constructor(description?: string) {
		super('unsupported_grant_type', { description });
	}
}

export class UnsupportedResponseType extends OAuthError {
	override readonly _tag = 'UnsupportedResponseType' as const;
	constructor(description?: string) {
		super('unsupported_response_type', { description });
	}
}

export class InvalidScope extends OAuthError {
	override readonly _tag = 'InvalidScope' as const;
	constructor(description?: string) {
		super('invalid_scope', { description });
	}
}

export class InvalidTarget extends OAuthError {
	override readonly _tag = 'InvalidTarget' as const;
	constructor(description?: string) {
		super('invalid_target', { description });
	}
}

export class AccessDenied extends OAuthError {
	override readonly _tag = 'AccessDenied' as const;
	constructor(description?: string) {
		super('access_denied', { status: 403, description });
	}
}

export class LoginRequired extends OAuthError {
	override readonly _tag = 'LoginRequired' as const;
	constructor(description?: string) {
		super('login_required', { description });
	}
}

export class ConsentRequired extends OAuthError {
	override readonly _tag = 'ConsentRequired' as const;
	constructor(description?: string) {
		super('consent_required', { description });
	}
}

export class InteractionRequired extends OAuthError {
	override readonly _tag = 'InteractionRequired' as const;
	constructor(description?: string) {
		super('interaction_required', { description });
	}
}

export class AccountSelectionRequired extends OAuthError {
	override readonly _tag = 'AccountSelectionRequired' as const;
	constructor(description?: string) {
		super('account_selection_required', { description });
	}
}

export class RequestNotSupported extends OAuthError {
	override readonly _tag = 'RequestNotSupported' as const;
	constructor(description?: string) {
		super('request_not_supported', { description });
	}
}

export class RequestUriNotSupported extends OAuthError {
	override readonly _tag = 'RequestUriNotSupported' as const;
	constructor(description?: string) {
		super('request_uri_not_supported', { description });
	}
}

export class RegistrationNotSupported extends OAuthError {
	override readonly _tag = 'RegistrationNotSupported' as const;
	constructor(description?: string) {
		super('registration_not_supported', { description });
	}
}

/** RFC 6750 s3.1: 401 with a Bearer challenge. */
export class InvalidToken extends OAuthError {
	override readonly _tag = 'InvalidToken' as const;
	constructor(description?: string) {
		super('invalid_token', { status: 401, description });
	}

	override toResponse(): Response {
		return bearer(this, {});
	}
}

/** RFC 6750 s3.1: 403 with a Bearer challenge naming the scopes required. */
export class InsufficientScope extends OAuthError {
	override readonly _tag = 'InsufficientScope' as const;
	readonly scope: string | undefined;
	constructor(scope?: string, description?: string) {
		super('insufficient_scope', { status: 403, description });
		this.scope = scope;
	}

	override toResponse(): Response {
		return bearer(this, { scope: this.scope });
	}
}

export class ServerError extends OAuthError {
	override readonly _tag = 'ServerError' as const;
	constructor(description?: string) {
		super('server_error', { status: 500, description });
	}
}

export class TemporarilyUnavailable extends OAuthError {
	override readonly _tag = 'TemporarilyUnavailable' as const;
	constructor(description?: string) {
		super('temporarily_unavailable', { status: 503, description });
	}
}

/** An error with any code, for extension specs (for example `use_dpop_nonce`). */
export const make = (code: Code | (string & {}), options?: Options): OAuthError =>
	new OAuthError(code, options);
