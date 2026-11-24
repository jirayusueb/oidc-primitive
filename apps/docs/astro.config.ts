import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import starlightLinksValidator from 'starlight-links-validator';

const site = 'https://oidc-primitive.vercel.app';

export default defineConfig({
	site,
	integrations: [
		starlight({
			title: 'oidc-primitive',
			description: 'Spec-cited OAuth 2.1 and OpenID Connect security primitives for TypeScript servers. Web APIs and jose only.',
			logo: { light: './src/assets/logo-light.svg', dark: './src/assets/logo-dark.svg' },
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/jirayusueb/oidc-primitive' }],
			customCss: [
				'@fontsource-variable/ibm-plex-sans',
				'@fontsource/ibm-plex-mono/400.css',
				'@fontsource/ibm-plex-mono/600.css',
				'./src/styles/theme.css',
			],
			components: { Hero: './src/components/Hero.astro' },
			expressiveCode: {
				themes: ['github-dark-default', 'github-light-default'],
				styleOverrides: {
					borderRadius: '0.5rem',
					borderColor: 'var(--sl-color-hairline)',
					codeBackground: 'var(--op-code-bg)',
					codeFontFamily: 'var(--sl-font-mono)',
					uiFontFamily: 'var(--sl-font-mono)',
					frames: {
						shadowColor: 'transparent',
						editorTabBarBackground: 'var(--op-code-bg)',
						editorActiveTabBackground: 'var(--op-code-bg)',
						editorActiveTabIndicatorBottomColor: 'var(--op-accent)',
						editorTabBarBorderBottomColor: 'var(--sl-color-hairline)',
						terminalBackground: 'var(--op-code-bg)',
						terminalTitlebarBackground: 'var(--op-code-bg)',
						terminalTitlebarBorderBottomColor: 'var(--sl-color-hairline)',
					},
				},
			},
			head: [
				{ tag: 'meta', attrs: { property: 'og:image', content: `${site}/og.png` } },
				{ tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
				{ tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
				{ tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
				{ tag: 'meta', attrs: { name: 'twitter:image', content: `${site}/og.png` } },
			],
			plugins: [starlightLinksValidator()],
			sidebar: [
				{
					label: 'Start',
					items: [
						{ label: 'Getting started', slug: 'guide/getting-started' },
						{ label: 'Library and host', slug: 'guide/library-and-host' },
						{ label: 'Example OpenID Provider', slug: 'guide/example-op' },
					],
				},
				{
					label: 'Flows',
					items: [
						{ label: 'Authorization code flow', slug: 'guide/authorization-code-flow' },
						{ label: 'Client credentials', slug: 'guide/client-credentials' },
						{ label: 'Refresh token rotation', slug: 'guide/refresh-token-rotation' },
					],
				},
				{
					label: 'Build a provider',
					items: [
						{ label: 'Authorization requests', slug: 'guide/authorization-requests' },
						{ label: 'Client authentication', slug: 'guide/client-authentication' },
						{ label: 'Tokens and keys', slug: 'guide/tokens-and-keys' },
						{ label: 'Discovery and responses', slug: 'guide/discovery-and-responses' },
						{ label: 'Host checklist', slug: 'guide/host-checklist' },
					],
				},
				{
					label: 'Protect an API',
					items: [{ label: 'Resource servers', slug: 'guide/resource-servers' }],
				},
				{
					label: 'Use cases',
					items: [
						{ label: 'Choose your use case', slug: 'guide/use-cases' },
						{ label: 'Multi-tenant', slug: 'guide/multi-tenant' },
						{ label: 'MCP authorization', slug: 'guide/mcp-authorization-server' },
					],
				},
				{
					label: 'Reference',
					items: [{ autogenerate: { directory: 'reference' } }],
				},
				{
					label: 'Project',
					items: [{ label: 'Roadmap', slug: 'roadmap' }],
				},
			],
		}),
	],
});
