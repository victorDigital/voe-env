import { testDatabaseURL } from './database';
import postgres from 'postgres';
import { createHmac, randomUUID, createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { identityKeyPair, randomKey, seal, wrapTo, bytes, encode } from '../src/lib/vault-crypto';
import { context, orgContext, folderContext, secretContext } from '../src/lib/vault-format';
const sql = postgres(testDatabaseURL().href);
const userId = randomUUID(),
	token = randomUUID(),
	sessionId = randomUUID();
const pair = await identityKeyPair(),
	accountKey = randomKey(),
	recovery = randomKey();
const hash = (value: Uint8Array | string) => createHash('sha256').update(value).digest('hex');
const recoveryProof = hash(
	new Uint8Array([...bytes('voe.recovery.authentication.v1'), ...recovery])
);
try {
	await sql`insert into "user" (id,name,email,email_verified) values (${userId},'Alex Morgan',${`alex-${userId.slice(0, 8)}@example.test`},true)`;
	await sql`insert into session (id,user_id,token,expires_at,updated_at) values (${sessionId},${userId},${token},now()+interval '8 hours',now())`;
	await sql`insert into encryption_identity (user_id,public_key,encrypted_private_key,recovery_envelope,recovery_auth_hash) values (${userId},${pair.publicKey},${await seal(accountKey, pair.privateKey, context('identity', userId))},${await seal(recovery, accountKey, context('recovery', userId))},${hash(recoveryProof)})`;
	const orgIds: string[] = [];
	for (const name of ['Wemuda', 'Sandbox']) {
		const orgId = randomUUID(),
			orgKey = randomKey(),
			root = randomUUID(),
			folderKey = randomKey();
		orgIds.push(orgId);
		await sql`insert into organization (id,name,slug,created_at) values (${orgId},${name},${orgId},now())`;
		await sql`insert into member (id,organization_id,user_id,role,created_at) values (${randomUUID()},${orgId},${userId},'owner',now())`;
		await sql`insert into workspace (organization_id,epoch,revision) values (${orgId},1,1)`;
		await sql`insert into vault_folder (id,organization_id,parent_id,name,wrapped_key) values (${root},${orgId},null,'',${await seal(orgKey, folderKey, folderContext(orgId, root, 1))})`;
		const recipient = `user:${userId}`;
		await sql`insert into organization_key_envelope (organization_id,recipient,epoch,wrapped_key,identity_binding,provisioned_by) values (${orgId},${recipient},1,${await wrapTo(pair.publicKey, orgKey, orgContext(orgId, recipient, 1))},${await seal(orgKey, bytes(pair.publicKey), context('recipient', orgId, recipient, 1))},${userId})`;
		for (const folderName of ['infood', 'website']) {
			const id = randomUUID();
			await sql`insert into vault_folder (id,organization_id,parent_id,name,wrapped_key) values (${id},${orgId},${root},${folderName},${await seal(orgKey, randomKey(), folderContext(orgId, id, 1))})`;
		}
		for (const name of [
			'AI_GATEWAY_API_KEY',
			'DATABASE_URL',
			'DOCUMENT_INTELLIGENCE_API_KEY',
			'DOCUMENT_INTELLIGENCE_ENDPOINT',
			'OPENAI_TRANSLATION_MODEL',
			'PARSER_STAGING_PASSWORD',
			'A_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_THAT_MUST_NEVER_OVERLAP_THE_VALUE_COLUMN'
		]) {
			const id = randomUUID();
			await sql`insert into vault_secret (id,organization_id,folder_id,name,encrypted_value) values (${id},${orgId},${root},${name},${await seal(folderKey, bytes('demo-value-only'), secretContext(orgId, root, id, name, 1))})`;
		}
		if (name === 'Wemuda') {
			for (const [name, email, role] of [
				['Jamie Chen', 'jamie@example.test', 'admin'],
				['Taylor Reed', 'taylor@example.test', 'member']
			]) {
				const id = randomUUID();
				await sql`insert into "user" (id,name,email,email_verified) values (${id},${name},${`${id.slice(0, 8)}-${email}`},true)`;
				await sql`insert into member (id,organization_id,user_id,role,created_at) values (${randomUUID()},${orgId},${id},${role},now())`;
			}
			await sql`insert into invitation (id,organization_id,email,role,status,expires_at,inviter_id) values (${randomUUID()},${orgId},'riley@example.test','viewer','pending',now()+interval '7 days',${userId})`;
		}
	}
	const device = randomUUID();
	await sql`insert into encryption_device (id,user_id,public_key,device_code_id) values (${device},${userId},${pair.publicKey},${randomUUID()})`;
	await writeFile(
		'/tmp/voe-ui-fixture.json',
		JSON.stringify({
			userId,
			orgIds,
			device,
			recovery: encode(recovery),
			cookie: encodeURIComponent(
				token +
					'.' +
					createHmac('sha256', 'voe-passwordless-local-test-secret-only')
						.update(token)
						.digest('base64')
			)
		}),
		{ mode: 0o600 }
	);
	console.log('Synthetic preview account saved to /tmp/voe-ui-fixture.json');
} finally {
	await sql.end();
}
