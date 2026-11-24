import { defineConfig } from 'tsdown';

// https://tsdown.dev/guide/; packages/core is the only published package.
export default defineConfig([
	{
		name: 'core',
		entry: ['packages/core/src/index.ts'],
		outDir: 'packages/core/dist',
		format: 'esm',
		platform: 'neutral',
		external: ['jose'],
		dts: { isolatedDeclarations: true, tsconfig: 'packages/core/tsconfig.json' },
	},
]);
