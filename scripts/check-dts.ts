// Fails when an emitted declaration file exposes `any` (design G4).
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dist = join(import.meta.dirname, '../packages/core/dist');
const offenders: string[] = [];
for (const file of readdirSync(dist, { recursive: true, encoding: 'utf8' })) {
	if (!file.endsWith('.d.ts')) continue;
	// Drop comments and string literals first, so JSDoc prose that says "any" is not a finding.
	readFileSync(join(dist, file), 'utf8')
		.replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ''))
		.split('\n')
		.forEach((line, i) => {
			if (/\bany\b/.test(line.replace(/\/\/.*$|'[^']*'|"[^"]*"/g, ''))) {
				offenders.push(`${file}:${i + 1}: ${line.trim()}`);
			}
		});
}
if (offenders.length > 0) {
	console.error(`d.ts files expose any:\n${offenders.join('\n')}`);
	process.exit(1);
}
console.log('d.ts check: no any');
