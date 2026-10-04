import { testDatabaseURL } from './database';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { chromium, expect } from '@playwright/test';
import postgres from 'postgres';
import { createHmac, randomUUID } from 'node:crypto';
const database = testDatabaseURL();
const sql = postgres(database.href);
const token = randomUUID(),
	userId = randomUUID(),
	sessionId = randomUUID();
await sql`insert into "user" (id,name,email,email_verified) values (${userId},'Browser test',${userId + '@example.test'},true)`;
await sql`insert into session (id,user_id,token,expires_at,updated_at) values (${sessionId},${userId},${token},now()+interval '1 hour',now())`;
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();
await page.addInitScript(() => {
	const get = navigator.credentials.get.bind(navigator.credentials);
	navigator.credentials.get = async (options) => {
		try {
			return await get(options);
		} catch (e) {
			Object.assign(window, {
				credentialError: String(e),
				credentialOptions: JSON.stringify(options, (_, v) =>
					v instanceof ArrayBuffer ? 'buffer' : v
				)
			});
			throw e;
		}
	};
});
const errors: string[] = [];
page.on('pageerror', (e) => errors.push(e.message));
const requests: string[] = [];
page.on('request', (r) => {
	if (r.url().includes('/api/auth/passkey/verify')) requests.push(r.postData() || '');
});
await context.addCookies([
	{
		name: 'better-auth.session_token',
		value: encodeURIComponent(
			token +
				'.' +
				createHmac('sha256', 'voe-passwordless-local-test-secret-only')
					.update(token)
					.digest('base64')
		),
		url: 'http://localhost:5174',
		httpOnly: true,
		sameSite: 'Lax'
	}
]);
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
	options: {
		protocol: 'ctap2',
		ctap2Version: 'ctap2_1',
		transport: 'internal',
		hasResidentKey: true,
		hasUserVerification: true,
		isUserVerified: true,
		automaticPresenceSimulation: true,
		hasPrf: true
	}
});
try {
	await page.goto('http://localhost:5174/dashboard/env');
	await page.getByRole('button', { name: 'Create passkey', exact: true }).click();
	await expect(page.getByRole('heading', { name: 'Save your recovery key' })).toBeVisible({
		timeout: 15000
	});
	const recovery = await page.locator('section[aria-label="Unlock vault"] code').innerText();
	await page.getByLabel('Paste your saved key to verify your backup').fill(recovery);
	await page.getByRole('button', { name: 'Finish setup', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Lock vault', exact: true })).toBeVisible({
		timeout: 15000
	});
	await page.getByLabel('New workspace name').fill('Browser workspace');
	await page.getByRole('button', { name: 'Create workspace', exact: true }).click();
	await expect(page.getByRole('heading', { name: 'Add or update a secret' })).toBeVisible({
		timeout: 15000
	});
	await page.getByLabel('Folder name', { exact: true }).fill('production');
	await page.getByRole('button', { name: 'Create folder', exact: true }).click();
	await page.getByRole('button', { name: '▸ production Folder' }).click();
	await page.getByLabel('Secret name', { exact: true }).fill('API_KEY');
	await page.getByLabel('Secret value', { exact: true }).fill('browser-test-only');
	await page.getByRole('button', { name: 'Save secret', exact: true }).click();
	await expect(page.getByText('API_KEY', { exact: true })).toBeVisible();
	await page.getByRole('button', { name: 'Show values' }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible();
	await page.screenshot({ path: '/tmp/voe-workspace-desktop.png', fullPage: true });
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toHaveCount(0);
	await page.getByRole('button', { name: 'Unlock with passkey', exact: true }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible({
		timeout: 15000
	});
	await page.getByRole('button', { name: 'Settings', exact: true }).click();
	await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
	const backup = await cdp.send('WebAuthn.addVirtualAuthenticator', {
		options: {
			protocol: 'ctap2',
			ctap2Version: 'ctap2_1',
			transport: 'usb',
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true,
			hasPrf: true
		}
	});
	await page.getByRole('button', { name: 'Add backup passkey' }).click();
	await expect(page.getByText('Backup passkey enrolled for vault unlock.')).toBeVisible({
		timeout: 15000
	});
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await page.getByRole('button', { name: 'Unlock with passkey', exact: true }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible({
		timeout: 15000
	});
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await page.getByText('Recover with an offline key', { exact: true }).click();
	await page.getByLabel('Recovery key', { exact: true }).fill(recovery);
	await page.getByRole('button', { name: 'Recover vault', exact: true }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible({
		timeout: 15000
	});
	await page.setViewportSize({ width: 390, height: 844 });
	await page.screenshot({ path: '/tmp/voe-workspace-mobile.png', fullPage: true });
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

	const oldPassword = 'legacy-test-password';
	const material = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(oldPassword),
		'PBKDF2',
		false,
		['deriveKey']
	);
	const oldKey = await crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: new TextEncoder().encode('fixedsalt'),
			iterations: 100000,
			hash: 'SHA-256'
		},
		material,
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt']
	);
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const oldCipher = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: nonce },
		oldKey,
		new TextEncoder().encode('migrated-test-value')
	);
	await sql`insert into env_vault (id,"userId","fullKey","encryptedValue") values (${randomUUID()},${userId},'old:project:LEGACY_KEY',${Buffer.concat([nonce, Buffer.from(oldCipher)]).toString('base64')})`;
	await page.setViewportSize({ width: 1440, height: 1000 });
	await page.goto('http://localhost:5174/dashboard/migrate');
	await page.getByRole('button', { name: 'Unlock with passkey', exact: true }).click();
	await page.getByLabel('old:project — legacy password', { exact: true }).fill(oldPassword);
	await page.getByRole('checkbox').check();
	await page.getByRole('button', { name: 'Migrate and verify', exact: true }).click();
	await expect(page.getByText('Migration verified.', { exact: false })).toBeVisible({
		timeout: 15000
	});
	const [migration] = await sql`select * from legacy_migration where user_id=${userId}`;
	expect(migration.status).toBe('complete');
	const [{ count }] =
		await sql`select count(*)::int as count from member where organization_id=${migration.organization_id}`;
	expect(count).toBe(1);
	await page.reload();
	await page.getByRole('button', { name: 'Unlock with passkey', exact: true }).click();
	await page.getByLabel('old:project — legacy password', { exact: true }).fill(oldPassword);
	await page.getByRole('checkbox').check();
	await page.getByRole('button', { name: 'Verify completed migration', exact: true }).click();
	await expect(page.getByText('Every migrated value verified.')).toBeVisible();
	console.log(
		'PASS: browser migration, read-back verification, retained source, personal audience, and resumed verification'
	);
	if (process.env.VOE_TEST_CLI === '1') {
		const directory = await mkdtemp(join(tmpdir(), 'voe-cli-e2e-'));
		const executable = resolve('../cli/target/debug/ve');
		const environment = { ...process.env, VOE_BASE_URL: 'http://localhost:5174' };
		let output = '';
		const authProcess = Bun.spawn([executable, 'auth'], {
			cwd: directory,
			env: environment,
			stdout: 'pipe',
			stderr: 'pipe'
		});
		const reading = (async () => {
			for await (const chunk of authProcess.stdout) output += new TextDecoder().decode(chunk);
		})();
		const run = async (args: string[]) => {
			const child = Bun.spawn([executable, ...args], {
				cwd: directory,
				env: environment,
				stdout: 'pipe',
				stderr: 'pipe'
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text()
			]);
			expect(code, stderr).toBe(0);
			return stdout;
		};
		try {
			for (let i = 0; i < 300 && !output.includes('Device fingerprint:'); i++) await Bun.sleep(100);
			const url = output.match(/Open (http:\/\/[^\s]+)/)?.[1];
			const fingerprint = output.match(/Device fingerprint: ([a-f0-9]+)/)?.[1];
			if (!url || !fingerprint) {
				authProcess.kill();
				throw new Error(
					`CLI enrollment did not start: ${output} ${await new Response(authProcess.stderr).text()}`
				);
			}
			expect(fingerprint).toHaveLength(64);
			await page.goto(url!);
			await page.getByRole('button', { name: 'Unlock with passkey', exact: true }).click();
			await page.getByLabel('Device fingerprint from your terminal').fill(fingerprint!);
			await page.getByLabel('Browser workspace', { exact: true }).check();
			await page.getByRole('button', { name: 'Authorize device', exact: true }).click();
			await expect(page.getByRole('heading', { name: 'Device authorized' })).toBeVisible();
			const result = await Promise.race([authProcess.exited, Bun.sleep(20000).then(() => -1)]);
			if (result === -1) authProcess.kill();
			expect(result, await new Response(authProcess.stderr).text()).toBe(0);
			await reading;
			const [org] =
				await sql`select organization.id from organization inner join member on member.organization_id=organization.id where member.user_id=${userId} and organization.name='Browser workspace'`;
			await run(['init', '--org', org.id, '--path', 'production']);
			await writeFile(
				join(directory, '.env'),
				'CLI_KEY="cli-round-trip"\nVE_VAULT_KEYPASS="legacy+password"\n',
				{ mode: 0o600 }
			);
			await run(['push']);
			await run(['pull', '--force']);
			const pulled = await readFile(join(directory, '.env'), 'utf8');
			expect(pulled).toContain('CLI_KEY="cli-round-trip"');
			expect(pulled).toContain('API_KEY="browser-test-only"');
			expect(pulled).not.toContain('VE_VAULT_KEYPASS');
			const config = JSON.parse(await readFile(join(directory, '.voe.json'), 'utf8'));
			expect(Object.keys(config).sort()).toEqual(['folderId', 'organizationId', 'server']);
			console.log(
				'PASS: real Rust CLI browser enrollment, OS credential-store persistence, init, encrypted push/pull and password removal'
			);
		} finally {
			authProcess.kill();
			await run(['logout']).catch(() => {});
			await rm(directory, { recursive: true, force: true });
		}
	}
	expect(errors).toEqual([]);
	expect(requests.length).toBeGreaterThan(3);
	for (const request of requests) {
		expect(request).not.toContain('clientExtensionResults');
		expect(request).not.toContain('prf');
	}
	console.log(
		'PASS: Chromium PRF authenticator onboarding, verified recovery backup, workspace/folder/secret creation, lock/unlock, backup passkey, recovery, responsive layout, and no PRF network serialization'
	);
} catch (e) {
	await page.screenshot({ path: '/tmp/voe-browser-failure.png', fullPage: true });
	console.error(await page.locator('body').innerText());
	console.error(
		await page.evaluate(() => ({
			error: (window as any).credentialError,
			options: (window as any).credentialOptions
		}))
	);
	throw e;
} finally {
	await browser.close();
	await sql.end();
}
