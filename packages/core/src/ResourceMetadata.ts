export interface Options {
	readonly resource: string;
	readonly authorizationServers: readonly string[];
	readonly scopesSupported?: readonly string[];
	readonly bearerMethodsSupported?: readonly string[];
	readonly resourceName?: string;
	readonly jwksUri?: string;
	readonly resourceSigningAlgValuesSupported?: readonly string[];
	readonly resourceDocumentation?: string;
}

const parseResource = (resource: string): URL => {
	let url: URL;
	try {
		url = new URL(resource);
	} catch {
		throw new TypeError('Resource must be an absolute URL');
	}
	if (url.protocol !== 'https:' || url.hash || resource.includes('#')) {
		throw new TypeError('Resource must be an https URL without a fragment (RFC 9728 s2)');
	}
	return url;
};

/** RFC 9728 s2 protected resource metadata in snake_case. */
export const make = (options: Options): Record<string, unknown> => {
	parseResource(options.resource);
	if (options.authorizationServers.length === 0) throw new TypeError('authorizationServers must not be empty');
	const doc: Record<string, unknown> = {
		resource: options.resource,
		authorization_servers: options.authorizationServers,
		scopes_supported: options.scopesSupported,
		bearer_methods_supported: options.bearerMethodsSupported ?? ['header'],
		resource_name: options.resourceName,
		jwks_uri: options.jwksUri,
		resource_signing_alg_values_supported: options.resourceSigningAlgValuesSupported,
		resource_documentation: options.resourceDocumentation,
	};
	for (const key of Object.keys(doc)) if (doc[key] === undefined) delete doc[key];
	return doc;
};

/** RFC 9728 s3.1: `/.well-known/oauth-protected-resource` inserted before the resource path. */
export const wellKnownUrl = (resource: string): string => {
	const url = parseResource(resource);
	const path = url.pathname === '/' ? '' : url.pathname;
	return `${url.origin}/.well-known/oauth-protected-resource${path}`;
};
