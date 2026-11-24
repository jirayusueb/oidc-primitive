// Runs the OpenID Foundation conformance suite (release v5.3.4) against examples/bun-op.
// Usage: bun run conformance [<plan> <config>]...   KEEP=1 leaves the containers running.
import { $ } from 'bun';
import { mkdir, rm } from 'node:fs/promises';

const SUITE_COMMIT = '23353b36957d6466010de767c812d2c91ed37638'; // release-v5.3.4, same as compose.yaml
const RUNNER_SCRIPTS: Record<string, string> = {
	'run-test-plan.py': '6043f8fb9d64dcd30235540cae1f32eb4e94618d1fc5408f1e8ae626d6553ad2',
	'conformance.py': '660214cc6ca9b3c09297f61908a575db7b1552e8f44eecd5740d1c27fa2cfca8',
	'test_plan_parser.py': '2b00870b2dc46f1d44d047c715c0ef6978f24ece97a4a9d3b48ceeea8d01830f',
};
const PLANS = [
	'oidcc-config-certification-test-plan',
	'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]',
];
const REDIRECT_URI = 'https://localhost.emobix.co.uk:8443/test/a/oidc-primitive/callback';

const here = import.meta.dir;
$.cwd(here);
const compose = (...args: string[]) => $`docker compose --file compose.yaml --profile runner ${args}`;

const fetchRunner = async (): Promise<void> => {
	await mkdir(`${here}/.cache/runner/certs-keys`, { recursive: true });
	for (const [name, sum] of Object.entries(RUNNER_SCRIPTS)) {
		const path = `${here}/.cache/runner/${name}`;
		const file = Bun.file(path);
		if ((await file.exists()) && new Bun.CryptoHasher('sha256').update(await file.bytes()).digest('hex') === sum) continue;
		const res = await fetch(`https://gitlab.com/openid/conformance-suite/-/raw/${SUITE_COMMIT}/scripts/${name}`);
		const bytes = new Uint8Array(await res.arrayBuffer());
		if (!res.ok || new Bun.CryptoHasher('sha256').update(bytes).digest('hex') !== sum) {
			throw new Error(`${name} does not match its pinned SHA-256`);
		}
		await Bun.write(path, bytes);
	}
};

const secret = (): string => Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString('base64url');

const waitForOp = async (): Promise<void> => {
	for (let i = 0; i < 60; i++) {
		const ok = await compose('exec', '-T', 'op-tls', 'wget', '-q', '-O', '/dev/null', 'http://op:3000/healthz')
			.quiet()
			.nothrow();
		if (ok.exitCode === 0) return;
		await Bun.sleep(1000);
	}
	throw new Error('examples/bun-op did not become ready');
};

await fetchRunner();
await $`bun run build`.cwd(`${here}/..`);
await rm(`${here}/results`, { recursive: true, force: true });
await mkdir(`${here}/results`);

const secrets = [secret(), secret(), secret()];
const client = (n: number, method: string) => ({
	client_id: `conformance-${n}`,
	client_secret: secrets[n - 1],
	redirect_uris: [REDIRECT_URI],
	token_endpoint_auth_method: method,
	// The suite's Basic plan clients send no PKCE; RFC 9700 s2.1.1 allows nonce instead (design D13).
	pkce: 'oidc-nonce',
	grant_types: ['authorization_code', 'refresh_token'],
});
process.env.CLIENTS = JSON.stringify([
	client(1, 'client_secret_basic'),
	client(2, 'client_secret_basic'),
	client(3, 'client_secret_post'),
]);
const config = (await Bun.file(`${here}/config/oidcc.json`).text())
	.replace('${SECRET_1}', secrets[0] as string)
	.replace('${SECRET_2}', secrets[1] as string)
	.replace('${SECRET_3}', secrets[2] as string);
await Bun.write(`${here}/.cache/oidcc.json`, config);

let status = 1;
try {
	await compose('up', '--detach', '--quiet-pull', 'mongodb', 'server', 'nginx', 'op', 'op-tls');
	await waitForOp();
	const args = process.argv.slice(2);
	const planArgs = args.length > 0 ? args : PLANS.flatMap((plan) => [plan, '.cache/oidcc.json']);
	status = (await compose('run', '--rm', '--no-deps', 'runner', ...planArgs).nothrow()).exitCode;
} finally {
	const logs = (services: string[]) => compose('logs', '--no-color', ...services).quiet().nothrow();
	await Bun.write(`${here}/results/op.log`, (await logs(['op', 'op-tls'])).text());
	await Bun.write(`${here}/results/suite.log`, (await logs(['server', 'nginx'])).text());
	if (process.env.KEEP !== '1') await compose('down', '--volumes', '--remove-orphans').quiet().nothrow();
}
process.exit(status);
