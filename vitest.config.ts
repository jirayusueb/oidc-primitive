import { defineConfig } from 'vitest/config';

// The same files run under `bun test` (Bun) and `vitest run` (Node).
export default defineConfig({
	test: {
		include: ['packages/*/test/**/*.test.ts'],
	},
});
