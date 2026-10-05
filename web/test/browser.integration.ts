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
const command = await page.evaluate(() =>
	/Mac|iPhone|iPad/.test(navigator.platform) ? 'Meta' : 'Control'
);
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
	const inviteEmail = `${randomUUID()}@example.test`;
	const orgResponse = await context.request.post(
		'http://localhost:5174/api/auth/organization/create',
		{
			headers: { origin: 'http://localhost:5174' },
			data: { name: 'Invited workspace', slug: randomUUID() }
		}
	);
	expect(orgResponse.status()).toBe(200);
	const invitedOrg = await orgResponse.json();
	const inviteResponse = await context.request.post(
		'http://localhost:5174/api/auth/organization/invite-member',
		{
			headers: { origin: 'http://localhost:5174' },
			data: { organizationId: invitedOrg.id, email: inviteEmail, role: 'viewer' }
		}
	);
	expect(inviteResponse.status()).toBe(200);
	const inviteMessages = (await readFile('/tmp/voe-test-mailbox.jsonl', 'utf8'))
		.trim()
		.split('\n')
		.map((s) => JSON.parse(s))
		.filter((m) => m.to.includes(inviteEmail));
	expect(inviteMessages).toHaveLength(1);
	const inviteURL = inviteMessages[0].text.match(/http:\/\/localhost:5174\/invite\/\S+/)[0];
	await page.goto(inviteURL);
	await expect(page.getByRole('button', { name: 'Sign out to continue' })).toBeVisible();
	const invitedContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
	try {
		const invitedPage = await invitedContext.newPage();
		const extraEmails: string[] = [];
		invitedPage.on('request', (request) => {
			if (request.url().includes('/sign-in/magic-link')) extraEmails.push(request.url());
		});
		await invitedPage.goto(inviteURL);
		await expect(
			invitedPage.getByRole('heading', { name: 'Join Invited workspace' })
		).toBeVisible();
		await invitedPage.reload();
		await invitedPage.getByLabel('Your name', { exact: true }).fill('Invited teammate');
		await invitedPage.getByRole('button', { name: 'Join workspace' }).click();
		await expect(
			invitedPage.getByRole('button', { name: 'Set up vault', exact: true })
		).toBeVisible({ timeout: 15000 });
		await expect(invitedPage.getByRole('dialog')).toHaveCount(0);
		expect(new URL(invitedPage.url()).searchParams.get('workspace')).toBe(invitedOrg.id);
		const [joined] = await sql`select name,email_verified from "user" where email=${inviteEmail}`;
		expect(joined).toMatchObject({ name: 'Invited teammate', email_verified: true });
		expect(extraEmails).toHaveLength(0);
	} finally {
		await invitedContext.close();
		await sql`delete from organization where id=${invitedOrg.id}`;
		await sql`delete from "user" where email=${inviteEmail}`;
	}
	await page.goto('http://localhost:5174/dashboard/env');
	await expect(page.getByRole('button', { name: 'Set up vault', exact: true })).toBeEnabled();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Set up vault', exact: true }).click();
	await expect(page.getByRole('dialog')).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCSS('position', 'fixed');
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
	await page.locator('body').click({ position: { x: 1000, y: 50 } });
	await page.keyboard.press('Shift+N');
	await expect(page.getByRole('dialog')).toBeVisible();
	await page.keyboard.press(`${command}+Enter`);
	await expect(page.getByLabel('Folder name', { exact: true })).toBeFocused();
	await page.getByLabel('Folder name', { exact: true }).fill('production');
	await page.keyboard.press(`${command}+Enter`);
	const folderTree = page.getByRole('navigation', { name: 'Folders', exact: true });
	const folderPath = page.getByRole('navigation', { name: 'Folder path', exact: true });
	await expect(folderPath).toBeVisible();
	expect(await folderPath.evaluate((path) => !!path.closest('main > header'))).toBe(true);
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
	await expect(folderTree.getByRole('button', { name: 'production', exact: true })).toHaveAttribute(
		'aria-current',
		'location'
	);
	await page.getByRole('button', { name: 'New folder', exact: true }).click();
	await page.getByLabel('Folder name', { exact: true }).fill('nested');
	await page.getByRole('button', { name: 'Create folder', exact: true }).click();
	await expect(folderTree.getByRole('button', { name: 'nested', exact: true })).toBeVisible();
	await folderTree.getByRole('button', { name: 'Collapse production', exact: true }).click();
	await expect(folderTree.getByRole('button', { name: 'nested', exact: true })).toHaveCount(0);
	await folderTree.getByRole('button', { name: 'Expand production', exact: true }).click();
	await folderTree.getByRole('button', { name: 'nested', exact: true }).click();
	await expect(folderTree.getByRole('button', { name: 'nested', exact: true })).toHaveAttribute(
		'aria-current',
		'location'
	);
	await expect(
		folderTree.getByRole('button', { name: 'Collapse production', exact: true })
	).toHaveAttribute('aria-expanded', 'true');
	await expect(folderPath).toContainText('nested');
	await page.keyboard.press('Alt+ArrowUp');
	await expect(folderPath).not.toContainText('nested');
	await folderTree.getByRole('button', { name: 'nested', exact: true }).click();
	await page.getByRole('button', { name: 'Folder actions', exact: true }).click();
	await page.getByRole('menuitem', { name: 'Delete empty folder', exact: true }).click();
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete', exact: true }).click();
	await expect(folderTree.getByRole('button', { name: 'nested', exact: true })).toHaveCount(0);
	await expect(folderTree.getByRole('button', { name: 'production', exact: true })).toHaveAttribute(
		'aria-current',
		'location'
	);
	await expect(page.getByRole('status').filter({ hasText: 'No secrets' })).toBeVisible();
	await expect(page.getByRole('table')).toHaveCount(0);
	await expect(page.getByLabel('Search this folder')).toHaveCount(0);
	await folderTree.getByRole('button', { name: 'Vault', exact: true }).click();
	await expect(page.getByRole('status').filter({ hasText: 'No secrets' })).toBeVisible();
	await expect(page.getByLabel('Search this folder')).toHaveCount(0);
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
	await expect(folderTree.getByRole('button', { name: 'production', exact: true })).toHaveAttribute(
		'aria-current',
		'location'
	);
	for (const width of [390, 320]) {
		await page.setViewportSize({ width, height: 844 });
		await expect(folderTree).toBeHidden();
		await page.getByRole('button', { name: 'Folders', exact: true }).click();
		await expect(folderTree).toBeVisible();
		await folderTree.getByRole('button', { name: 'Vault', exact: true }).click();
		await expect(folderTree).toBeHidden();
		await expect(folderPath).not.toContainText('production');
		await page.getByRole('button', { name: 'Folders', exact: true }).click();
		await folderTree.getByRole('button', { name: 'production', exact: true }).click();
		await expect
			.poll(() =>
				folderPath.evaluate((path) => {
					const current = path.querySelector('button[disabled]')!.getBoundingClientRect();
					const bounds = path.getBoundingClientRect();
					return current.left >= bounds.left - 1 && current.right <= bounds.right + 1;
				})
			)
			.toBe(true);
		expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
			true
		);
	}
	await page.setViewportSize({ width: 1440, height: 1000 });
	await page.keyboard.press('n');
	await expect(page.getByRole('dialog')).toBeVisible();
	await page.getByRole('dialog').getByRole('heading', { name: 'Add secret', exact: true }).click();
	const shortcutURL = page.url();
	await page.keyboard.press('Shift+W');
	expect(page.url()).toBe(shortcutURL);
	await page.keyboard.press('n');
	await expect(page.getByRole('dialog')).toHaveCount(1);
	await page.getByLabel('Name', { exact: true }).fill('API_KEY');
	await page.getByLabel('Value', { exact: true }).fill('browser-test-only');
	await page.keyboard.press(`${command}+Enter`);
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await expect(page.getByText('API_KEY', { exact: true })).toBeVisible();
	await page.keyboard.press('/');
	await expect(page.getByLabel('Search this folder')).toBeFocused();
	await page.keyboard.type('n?N');
	await page.keyboard.press(`${command}+b`);
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Toggle navigation' })).toHaveAttribute(
		'aria-expanded',
		'true'
	);
	await page.getByLabel('Search this folder').fill('no-match');
	await expect(page.getByRole('status').filter({ hasText: 'No matches' })).toBeVisible();
	await page.getByRole('button', { name: 'Clear filter', exact: true }).click();
	await expect(page.getByText('API_KEY', { exact: true })).toBeVisible();
	await page.getByLabel('Search this folder').fill('no-match');
	await folderTree.getByRole('button', { name: 'Vault', exact: true }).click();
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
	await expect(page.getByLabel('Search this folder')).toHaveValue('');
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
	for (const width of [1440, 768, 390, 320]) {
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
	await expect(page.getByRole('alertdialog')).toHaveCount(0);
	await page.getByLabel('Search this folder').fill('');
	const vaultURL = page.url();
	await page.getByRole('button', { name: 'Hide values' }).focus();
	await page.keyboard.press('Shift+E');
	await expect(page.getByRole('button', { name: 'Show values' })).toBeVisible();
	await page.keyboard.press('Shift+E');
	await page.keyboard.press(`${command}+b`);
	await expect(page.getByRole('button', { name: 'Toggle navigation' })).toHaveAttribute(
		'aria-expanded',
		'false'
	);
	await page.keyboard.press(`${command}+b`);
	await expect(page.getByRole('button', { name: 'Toggle navigation' })).toHaveAttribute(
		'aria-expanded',
		'true'
	);
	await page.evaluate(() => {
		window.dispatchEvent(new KeyboardEvent('keydown', { key: 'n', repeat: true, bubbles: true }));
		window.dispatchEvent(
			new KeyboardEvent('keydown', { key: 'n', isComposing: true, bubbles: true })
		);
	});
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.keyboard.press('Shift+?');
	await expect(page.getByRole('dialog')).toHaveAccessibleName('Keyboard shortcuts');
	await expect(page.getByRole('dialog')).toContainText('Add secret');
	for (const width of [1440, 390, 320]) {
		await page.setViewportSize({ width, height: 844 });
		expect(
			await page
				.getByRole('dialog')
				.evaluate(
					(dialog) =>
						dialog.scrollWidth <= dialog.clientWidth &&
						dialog.getBoundingClientRect().left >= 0 &&
						dialog.getBoundingClientRect().right <= innerWidth
				)
		).toBe(true);
	}
	await page.screenshot({ path: '/tmp/voe-shortcuts-mobile.png' });
	await page.keyboard.press('Escape');
	await page.setViewportSize({ width: 1440, height: 1000 });
	await page.keyboard.down('Alt');
	await expect(page.getByRole('dialog')).toHaveAccessibleName('Keyboard shortcuts');
	await page.keyboard.up('Alt');
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Account menu' }).click();
	await page.getByRole('menuitem', { name: 'Keyboard shortcuts' }).click();
	await expect(page.getByRole('dialog')).toHaveAccessibleName('Keyboard shortcuts');
	await expect
		.poll(() =>
			page.getByRole('dialog').evaluate((dialog) => dialog.contains(document.activeElement))
		)
		.toBe(true);
	await page.keyboard.press('Escape');
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.keyboard.press('Shift+I');
	await expect(page.getByRole('dialog')).toBeVisible();
	await expect(page.getByLabel('Installation command')).toContainText('/install.sh');
	await page.evaluate(() => {
		const original = navigator.clipboard.writeText;
		let release: () => void;
		Object.assign(window, {
			finishClipboard: () => {
				release();
				navigator.clipboard.writeText = original;
			}
		});
		navigator.clipboard.writeText = () =>
			new Promise<void>((resolve) => {
				release = resolve;
			});
	});
	await page.keyboard.press('Shift+C');
	await expect(
		page.getByRole('button', { name: 'Copy install command', exact: true })
	).toBeDisabled();
	await expect(
		page.getByRole('button', { name: 'Copy install command', exact: true })
	).toHaveAttribute('data-loading', 'true');
	await page.keyboard.press('Shift+C');
	await page.evaluate(() =>
		(window as typeof window & { finishClipboard: () => void }).finishClipboard()
	);
	await expect(page.getByRole('button', { name: 'Command copied', exact: true })).toBeEnabled();
	await expect(page.getByRole('button', { name: 'Command copied', exact: true })).toHaveAttribute(
		'data-loading',
		'false'
	);
	await page.getByRole('tab', { name: 'Windows' }).click();
	await expect(page.getByLabel('Installation command')).toContainText('/install.ps1');
	expect(page.url()).toBe(vaultURL);
	await page.keyboard.press('Escape');
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Switch workspace' }).click();
	await expect(page.getByRole('menuitem', { name: 'Browser workspace' })).toBeVisible();
	await page.keyboard.press('Escape');
	await page.keyboard.press('Shift+W');
	await expect(page.getByRole('heading', { name: 'Browser workspace' })).toBeVisible();
	await expect(folderPath).toHaveCount(0);
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	const settingsVerificationCount = requests.length;
	await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.reload();
	await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
	await expect(page.getByRole('heading', { name: 'Devices with workspace access' })).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	expect(requests.length).toBe(settingsVerificationCount);
	await page.getByRole('link', { name: 'Vault', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Unlock vault', exact: true })).toBeEnabled();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('link', { name: 'Workspace settings', exact: true }).click();
	await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
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
	await page.keyboard.press('n');
	await expect(page.getByRole('dialog')).toHaveAccessibleName('Invite member');
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
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.setViewportSize({ width: 1440, height: 1000 });
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
	await page.getByRole('button', { name: 'Show values' }).click();

	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toHaveCount(0);
	await expect(page.getByRole('heading', { name: 'Vault locked', exact: true })).toBeVisible();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.reload();
	await expect(page.getByRole('button', { name: 'Unlock vault', exact: true })).toBeEnabled();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	const verificationCount = requests.length;
	await page.getByRole('button', { name: 'Unlock vault', exact: true }).focus();
	await page.keyboard.press('n');
	await expect(page.getByRole('dialog')).toHaveCount(0);
	expect(requests.length).toBe(verificationCount);
	await page.keyboard.press('Shift+U');
	await expect(page.getByRole('button', { name: 'Lock vault', exact: true })).toBeVisible();
	expect(requests.length).toBe(verificationCount + 1);
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
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
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Show values' })).toBeVisible({ timeout: 15000 });
	await page.getByRole('button', { name: 'Show values' }).click();
	await expect(page.getByText('browser-test-only', { exact: true })).toBeVisible();
	await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
	await expect(page.getByRole('dialog')).toHaveCount(0);
	await page.getByRole('button', { name: 'Recovery options', exact: true }).click();
	await page.getByText('Recover with an offline key', { exact: true }).click();
	await page.getByLabel('Recovery key', { exact: true }).fill(recovery);
	await page.getByRole('button', { name: 'Recover vault', exact: true }).click();
	await folderTree.getByRole('button', { name: 'production', exact: true }).click();
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
			await expect(page.getByRole('button', { name: 'Unlock vault', exact: true })).toBeEnabled();
			await expect(page.getByRole('dialog')).toHaveCount(0);
			await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
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
		'PASS: Chromium PRF onboarding, recovery, secret CRUD, folder tree navigation, guarded keyboard shortcuts, responsive shortcut help, async button loading, long-name layout, install modal, workspace role selector, mobile navigation, device revocation, backup passkey, and no PRF network serialization'
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
