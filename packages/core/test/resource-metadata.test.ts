import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { ResourceMetadata } from '../src/index.ts';

describe('RFC 9728 s2 protected resource metadata', () => {
	it('builds the document with header bearer default', () => {
		assert.deepEqual(
			ResourceMetadata.make({
				resource: 'https://api.example/v1',
				authorizationServers: ['https://as.example'],
				scopesSupported: ['read'],
				resourceName: 'API',
			}),
			{
				resource: 'https://api.example/v1',
				authorization_servers: ['https://as.example'],
				scopes_supported: ['read'],
				bearer_methods_supported: ['header'],
				resource_name: 'API',
			},
		);
	});

	it('requires authorization servers and a valid resource', () => {
		assert.throws(() => ResourceMetadata.make({ resource: 'https://api.example', authorizationServers: [] }), TypeError);
		assert.throws(() => ResourceMetadata.make({ resource: 'http://api.example', authorizationServers: ['x'] }), TypeError);
		assert.throws(() => ResourceMetadata.make({ resource: 'https://api.example#f', authorizationServers: ['x'] }), TypeError);
	});

	it('inserts the well-known segment before the path', () => {
		assert.equal(ResourceMetadata.wellKnownUrl('https://api.example/v1/items'), 'https://api.example/.well-known/oauth-protected-resource/v1/items');
		assert.equal(ResourceMetadata.wellKnownUrl('https://api.example'), 'https://api.example/.well-known/oauth-protected-resource');
	});
});
