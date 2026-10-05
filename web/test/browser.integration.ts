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
page.setDefaultTimeout(15000);
page.setDefaultNavigationTimeout(60000);
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
	await expect(page.getByRole('dialog')).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCSS('position', 'fixed');
	await expect(page.getByRole('button', { name: 'Create passkey', exact: true })).toBeVisible();
	await page.keyboard.press('Escape');
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Set up vault', exact: true }).click();
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
	await page.getByRole('button', { name: 'Create workspace', exact: true }).click();
	await page.getByLabel('New workspace name').fill('Browser workspace');
	await page
		.getByRole('dialog')
		.getByRole('button', { name: 'Create workspace', exact: true })
		.click();
	await expect(page.getByRole('button', { name: 'Add secret', exact: true })).toBeVisible({
		timeout: 15000
	});
	await page.getByRole('button', { name: 'New folder', exact: true }).click();
	await page.getByLabel('Folder name', { exact: true }).fill('production');
	await page.getByRole('button', { name: 'Create folder', exact: true }).click();
	await page.getByRole('button', { name: 'production', exact: true }).click();
	await page.getByRole('button', { name: 'Add secret', exact: true }).click();
	await page.getByLabel('Name', { exact: true }).fill('API_KEY');
	await page.getByLabel('Value', { exact: true }).fill('browser-test-only');
	await page.getByRole('button', { name: 'Save secret', exact: true }).click();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await expect(page.getByText('API_KEY', { exact: true })).toBeVisible();
	await page.getByRole('button', { name: 'Show values' }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible();
	const longName = 'DOCUMENT_INTELLIGENCE_ENDPOINT_WITH_A_VERY_LONG_ENVIRONMENT_VARIABLE_NAME';
	await page.getByRole('button', { name: 'Add secret', exact: true }).click();
	await page.getByLabel('Name', { exact: true }).fill(longName);
	await page
		.getByLabel('Value', { exact: true })
		.fill('demo_' + 'A'.repeat(4096) + '\n' + 'B'.repeat(4096));
	const checkDialogBounds = async () => {
		for (const width of [1440, 390]) {
			await page.setViewportSize({ width, height: 844 });
			await expect
				.poll(() =>
					page.getByRole('dialog').evaluate((dialog) => {
						const bounds = dialog.getBoundingClientRect();
						return (
							bounds.left >= 0 &&
							bounds.right <= innerWidth &&
							bounds.top >= 0 &&
							bounds.bottom <= innerHeight &&
							dialog.scrollWidth <= dialog.clientWidth &&
							[...dialog.querySelectorAll('input, textarea, button')].every((field) => {
								const rect = field.getBoundingClientRect();
								return rect.left >= bounds.left && rect.right <= bounds.right;
							})
						);
					})
				)
				.toBe(true);
		}
		await page.setViewportSize({ width: 1440, height: 1000 });
	};
	await checkDialogBounds();
	await page.getByRole('button', { name: 'Save secret', exact: true }).click();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	const longRow = page.getByRole('row').filter({ hasText: longName });
	await expect(longRow).toBeVisible();
	for (const width of [1440, 390]) {
		await page.setViewportSize({ width, height: 900 });
		expect(
			await longRow.evaluate((row) => {
				const cells = row.querySelectorAll('td');
				const name = cells[0].firstElementChild!.getBoundingClientRect();
				const value = cells[1].firstElementChild!.getBoundingClientRect();
				return name.right <= value.left && document.documentElement.scrollWidth <= innerWidth;
			})
		).toBe(true);
	}
	await page.setViewportSize({ width: 1440, height: 1000 });
	await page.screenshot({ path: '/tmp/voe-workspace-desktop.png', fullPage: true });
	await page.getByLabel('Search this folder').fill('DOCUMENT_INTELLIGENCE');
	await expect(page.getByText('API_KEY', { exact: true })).toHaveCount(0);
	await page.getByRole('button', { name: `Actions for ${longName}` }).click();
	await page.getByRole('menuitem', { name: 'Edit secret' }).click();
	await expect(page.getByLabel('Name', { exact: true })).toHaveAttribute('readonly');
	await checkDialogBounds();
	await page.getByLabel('Value', { exact: true }).fill('updated-value');
	await page.getByRole('button', { name: 'Save secret', exact: true }).click();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await expect(longRow).toContainText('updated-value');
	await page.getByRole('button', { name: `Actions for ${longName}` }).click();
	await page.getByRole('menuitem', { name: 'Delete secret' }).click();
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete', exact: true }).click();
	await expect(longRow).toHaveCount(0);
	await page.getByLabel('Search this folder').fill('');
	const vaultURL = page.url();
	await page.getByRole('button', { name: 'Install CLI', exact: true }).click();
	await expect(page.getByRole('dialog')).toBeVisible();
	await expect(page.getByLabel('Installation command')).toContainText('/install.sh');
	await page.getByRole('tab', { name: 'Windows' }).click();
	await expect(page.getByLabel('Installation command')).toContainText('/install.ps1');
	expect(page.url()).toBe(vaultURL);
	await page.keyboard.press('Escape');
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Switch workspace' }).click();
	await expect(page.getByRole('menuitem', { name: 'Browser workspace' })).toBeVisible();
	await page.keyboard.press('Escape');
	await page.getByRole('link', { name: 'Workspace settings', exact: true }).click();
	await expect(page.getByRole('heading', { name: 'Browser workspace' })).toBeVisible();
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	const settingsVerificationCount = requests.length;
	await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.reload();
	await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
	await expect(page.getByRole('heading', { name: 'Devices with workspace access' })).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	expect(requests.length).toBe(settingsVerificationCount);
	await page.getByRole('button', { name: 'Leave', exact: true }).click();
	await page
		.getByRole('alertdialog')
		.getByRole('button', { name: 'Leave workspace', exact: true })
		.click();
	await expect(page.getByRole('alertdialog')).toContainText(
		'Add another owner before removing the last owner'
	);
	expect(requests.length).toBe(settingsVerificationCount + 1);
	await page.getByRole('alertdialog').getByRole('button', { name: 'Cancel', exact: true }).click();
	await page.getByRole('button', { name: 'Invite member', exact: true }).click();
	await page.getByLabel('Role', { exact: true }).click();
	await page.getByRole('option', { name: 'Viewer', exact: true }).click();
	await expect(page.getByText('Can read secrets.', { exact: true })).toBeVisible();
	await page.getByRole('button', { name: 'Cancel', exact: true }).click();
	await page.setViewportSize({ width: 390, height: 844 });
	await page.getByRole('button', { name: 'Toggle navigation' }).click();
	await expect(page.getByRole('button', { name: 'Close navigation' })).toBeVisible();
	await expect(page.getByRole('link', { name: 'Documentation', exact: true })).toBeVisible();
	await page.screenshot({ path: '/tmp/voe-sidebar-mobile.png', fullPage: true });
	await page.getByRole('link', { name: 'Vault', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Close navigation' })).toHaveCount(0);
	await page.setViewportSize({ width: 1440, height: 1000 });
	await page.getByRole('button', { name: 'production', exact: true }).click();
	await page.getByRole('button', { name: 'Show values' }).click();

	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toHaveCount(0);
	await page.keyboard.press('Escape');
	await expect(page.getByRole('dialog')).toHaveCount(0);
	const verificationCount = requests.length;
	await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Lock vault', exact: true })).toBeVisible();
	expect(requests.length).toBe(verificationCount + 1);
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Show values' })).toBeVisible({ timeout: 15000 });
	await page.getByRole('button', { name: 'Show values' }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible();
	await page.getByRole('button', { name: 'Account menu' }).click();
	await page.getByRole('menuitem', { name: 'Account settings' }).click();
	const deviceId = randomUUID();
	const [identity] = await sql`select public_key from encryption_identity where user_id=${userId}`;
	await sql`insert into encryption_device (id,user_id,public_key,device_code_id,last_used_at) values (${deviceId},${userId},${identity.public_key},${randomUUID()},'2026-10-05T10:30:00Z')`;
	await page.getByRole('link', { name: 'Vault', exact: true }).click();
	await page.getByRole('button', { name: 'Account menu' }).click();
	await page.getByRole('menuitem', { name: 'Account settings' }).click();
	await expect(page.getByText(deviceId.slice(0, 8), { exact: true })).toBeVisible();
	await expect(page.locator('time[datetime="2026-10-05T10:30:00.000Z"]')).toBeVisible();
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await page.reload();
	await expect(page.getByText(deviceId.slice(0, 8), { exact: true })).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Revoke access', exact: true })).toBeDisabled();
	await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Lock vault', exact: true })).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Revoke access', exact: true }).click();
	await page
		.getByRole('alertdialog')
		.getByRole('button', { name: 'Revoke access', exact: true })
		.click();
	await expect(page.getByText('No approved devices.', { exact: true })).toBeVisible();
	const [revoked] = await sql`select revoked from encryption_device where id=${deviceId}`;
	expect(revoked.revoked).toBe(true);
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
	await page.getByRole('button', { name: 'Add passkey' }).click();
	await expect(page.getByText('Passkey added.')).toBeVisible({
		timeout: 15000
	});
	await page.getByRole('link', { name: 'Vault', exact: true }).click();
	await page.getByRole('button', { name: 'production', exact: true }).click();
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await page.getByRole('button', { name: 'Unlock with passkey', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Show values' })).toBeVisible({ timeout: 15000 });
	await page.getByRole('button', { name: 'Show values' }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible();
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await page.getByText('Recover with an offline key', { exact: true }).click();
	await page.getByLabel('Recovery key', { exact: true }).fill(recovery);
	await page.getByRole('button', { name: 'Recover vault', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Show values' })).toBeVisible({ timeout: 15000 });
	await page.getByRole('button', { name: 'Show values' }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible();
	await page.setViewportSize({ width: 390, height: 844 });
	await page.screenshot({ path: '/tmp/voe-workspace-mobile.png', fullPage: true });
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

	await page.setViewportSize({ width: 1440, height: 1000 });

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
			const originalConfig = await readFile(join(directory, '.voe.json'), 'utf8');
			await run(['init', '--org', 'browser WORKSPACE', '--path', 'production']);
			expect(await readFile(join(directory, '.voe.json'), 'utf8')).toBe(originalConfig);
			await writeFile(join(directory, '.env'), 'CLI_KEY="cli-round-trip"\n', { mode: 0o600 });
			await run(['push']);
			await run(['pull', '--force']);
			const pulled = await readFile(join(directory, '.env'), 'utf8');
			expect(pulled).toContain('CLI_KEY="cli-round-trip"');
			expect(pulled).toContain('API_KEY="browser-test-only"');
			const config = JSON.parse(await readFile(join(directory, '.voe.json'), 'utf8'));
			expect(Object.keys(config).sort()).toEqual(['folderId', 'organizationId', 'server']);
			console.log(
				'PASS: real Rust CLI browser enrollment, OS credential-store persistence, init, encrypted push/pull'
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
		'PASS: Chromium PRF onboarding, recovery, secret CRUD, long-name layout, install modal, workspace role selector, mobile navigation, device revocation, backup passkey, and no PRF network serialization'
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
