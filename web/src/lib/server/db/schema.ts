import { sql } from 'drizzle-orm';
import {
	pgTable,
	text,
	timestamp,
	boolean,
	index,
	integer,
	unique,
	foreignKey,
	check,
	primaryKey
} from 'drizzle-orm/pg-core';

export const user = pgTable('user', {
	id: text('id').primaryKey(),
	name: text('name').notNull(),
	email: text('email').notNull().unique(),
	emailVerified: boolean('email_verified').default(false).notNull(),
	image: text('image'),
	createdAt: timestamp('created_at').defaultNow().notNull(),
	updatedAt: timestamp('updated_at')
		.defaultNow()
		.$onUpdate(() => /* @__PURE__ */ new Date())
		.notNull()
});

export const session = pgTable(
	'session',
	{
		id: text('id').primaryKey(),
		expiresAt: timestamp('expires_at').notNull(),
		token: text('token').notNull().unique(),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.$onUpdate(() => /* @__PURE__ */ new Date())
			.notNull(),
		activeOrganizationId: text('active_organization_id'),
		ipAddress: text('ip_address'),
		userAgent: text('user_agent'),
		userId: text('user_id')
			.notNull()
			.references(() => user.id, { onDelete: 'cascade' })
	},
	(table) => [index('session_userId_idx').on(table.userId)]
);

export const account = pgTable(
	'account',
	{
		id: text('id').primaryKey(),
		accountId: text('account_id').notNull(),
		providerId: text('provider_id').notNull(),
		userId: text('user_id')
			.notNull()
			.references(() => user.id, { onDelete: 'cascade' }),
		accessToken: text('access_token'),
		refreshToken: text('refresh_token'),
		idToken: text('id_token'),
		accessTokenExpiresAt: timestamp('access_token_expires_at'),
		refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
		scope: text('scope'),
		password: text('password'),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.$onUpdate(() => /* @__PURE__ */ new Date())
			.notNull()
	},
	(table) => [index('account_userId_idx').on(table.userId)]
);

export const verification = pgTable(
	'verification',
	{
		id: text('id').primaryKey(),
		identifier: text('identifier').notNull(),
		value: text('value').notNull(),
		expiresAt: timestamp('expires_at').notNull(),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.defaultNow()
			.$onUpdate(() => /* @__PURE__ */ new Date())
			.notNull()
	},
	(table) => [index('verification_identifier_idx').on(table.identifier)]
);

export const deviceCode = pgTable('deviceCode', {
	id: text('id').primaryKey(),
	deviceCode: text('deviceCode').notNull(),
	userCode: text('userCode').notNull(),
	userId: text('userId').references(() => user.id),
	clientId: text('clientId'),
	scope: text('scope'),
	status: text('status').notNull(),
	expiresAt: timestamp('expiresAt').notNull(),
	lastPolledAt: timestamp('lastPolledAt'),
	pollingInterval: integer('pollingInterval'),
	createdAt: timestamp('createdAt').defaultNow().notNull(),
	updatedAt: timestamp('updatedAt')
		.defaultNow()
		.$onUpdate(() => /* @__PURE__ */ new Date())
		.notNull()
});

export const organization = pgTable('organization', {
	id: text('id').primaryKey(),
	name: text('name').notNull(),
	slug: text('slug').notNull().unique(),
	logo: text('logo'),
	metadata: text('metadata'),
	createdAt: timestamp('created_at').notNull()
});
export const member = pgTable(
	'member',
	{
		id: text('id').primaryKey(),
		organizationId: text('organization_id')
			.notNull()
			.references(() => organization.id, { onDelete: 'cascade' }),
		userId: text('user_id')
			.notNull()
			.references(() => user.id, { onDelete: 'cascade' }),
		role: text('role').notNull(),
		createdAt: timestamp('created_at').notNull()
	},
	(t) => [
		unique('member_org_user').on(t.organizationId, t.userId),
		check('member_role', sql`${t.role} in ('owner','admin','member','viewer')`)
	]
);
export const invitation = pgTable('invitation', {
	id: text('id').primaryKey(),
	organizationId: text('organization_id')
		.notNull()
		.references(() => organization.id, { onDelete: 'cascade' }),
	email: text('email').notNull(),
	role: text('role').notNull(),
	status: text('status').notNull(),
	expiresAt: timestamp('expires_at').notNull(),
	inviterId: text('inviter_id')
		.notNull()
		.references(() => user.id, { onDelete: 'cascade' }),
	createdAt: timestamp('created_at').defaultNow().notNull()
});
export const passkey = pgTable('passkey', {
	id: text('id').primaryKey(),
	name: text('name'),
	publicKey: text('public_key').notNull(),
	userId: text('user_id')
		.notNull()
		.references(() => user.id, { onDelete: 'cascade' }),
	credentialID: text('credential_id').notNull().unique(),
	counter: integer('counter').notNull(),
	deviceType: text('device_type').notNull(),
	backedUp: boolean('backed_up').notNull(),
	transports: text('transports'),
	createdAt: timestamp('created_at'),
	aaguid: text('aaguid')
});
export const encryptionIdentity = pgTable('encryption_identity', {
	userId: text('user_id')
		.primaryKey()
		.references(() => user.id, { onDelete: 'cascade' }),
	publicKey: text('public_key').notNull(),
	encryptedPrivateKey: text('encrypted_private_key').notNull(),
	recoveryEnvelope: text('recovery_envelope').notNull(),
	recoveryAuthHash: text('recovery_auth_hash').notNull(),
	createdAt: timestamp('created_at').defaultNow().notNull()
});
export const accountEnvelope = pgTable('account_key_envelope', {
	credentialId: text('credential_id')
		.primaryKey()
		.references(() => passkey.credentialID, { onDelete: 'cascade' }),
	userId: text('user_id')
		.notNull()
		.references(() => encryptionIdentity.userId, { onDelete: 'cascade' }),
	wrappedKey: text('wrapped_key').notNull()
});
export const workspace = pgTable('workspace', {
	organizationId: text('organization_id')
		.primaryKey()
		.references(() => organization.id, { onDelete: 'cascade' }),
	epoch: integer('epoch').default(1).notNull(),
	revision: integer('revision').default(0).notNull(),
	rotationRequired: boolean('rotation_required').default(false).notNull()
});
export const vaultFolder = pgTable(
	'vault_folder',
	{
		id: text('id').primaryKey(),
		organizationId: text('organization_id')
			.notNull()
			.references(() => workspace.organizationId, { onDelete: 'cascade' }),
		parentId: text('parent_id'),
		name: text('name').notNull(),
		wrappedKey: text('wrapped_key').notNull()
	},
	(t) => [
		unique('folder_org_id').on(t.organizationId, t.id),
		unique('folder_sibling').on(t.organizationId, t.parentId, t.name).nullsNotDistinct(),
		foreignKey({
			columns: [t.organizationId, t.parentId],
			foreignColumns: [t.organizationId, t.id]
		}),
		check(
			'folder_name',
			sql`(${t.parentId} is null and ${t.name} = '') or (${t.parentId} is not null and ${t.name} <> '' and position(':' in ${t.name}) = 0)`
		)
	]
);
export const vaultSecret = pgTable(
	'vault_secret',
	{
		id: text('id').primaryKey(),
		organizationId: text('organization_id')
			.notNull()
			.references(() => workspace.organizationId, { onDelete: 'cascade' }),
		folderId: text('folder_id').notNull(),
		name: text('name').notNull(),
		encryptedValue: text('encrypted_value').notNull()
	},
	(t) => [
		unique('secret_folder_name').on(t.folderId, t.name),
		foreignKey({
			columns: [t.organizationId, t.folderId],
			foreignColumns: [vaultFolder.organizationId, vaultFolder.id]
		}).onDelete('cascade')
	]
);
export const encryptionDevice = pgTable('encryption_device', {
	id: text('id').primaryKey(),
	userId: text('user_id').references(() => user.id, { onDelete: 'cascade' }),
	publicKey: text('public_key').notNull(),
	deviceCodeId: text('device_code_id').notNull().unique(),
	sessionId: text('session_id')
		.unique()
		.references(() => session.id, { onDelete: 'set null' }),
	revoked: boolean('revoked').default(false).notNull(),
	lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
	createdAt: timestamp('created_at').defaultNow().notNull()
});
export const organizationEnvelope = pgTable(
	'organization_key_envelope',
	{
		organizationId: text('organization_id')
			.notNull()
			.references(() => workspace.organizationId, { onDelete: 'cascade' }),
		recipient: text('recipient').notNull(),
		identityBinding: text('identity_binding').notNull(),
		epoch: integer('epoch').notNull(),
		wrappedKey: text('wrapped_key').notNull(),
		provisionedBy: text('provisioned_by')
			.notNull()
			.references(() => user.id)
	},
	(t) => [primaryKey({ columns: [t.organizationId, t.recipient] })]
);
export const auditEvent = pgTable('audit_event', {
	id: text('id').primaryKey(),
	organizationId: text('organization_id').references(() => organization.id, {
		onDelete: 'cascade'
	}),
	actorId: text('actor_id').notNull(),
	action: text('action').notNull(),
	createdAt: timestamp('created_at').defaultNow().notNull()
});
export const passkeyVerification = pgTable('passkey_verification', {
	sessionId: text('session_id')
		.primaryKey()
		.references(() => session.id, { onDelete: 'cascade' }),
	credentialId: text('credential_id'),
	recovery: boolean('recovery').default(false).notNull(),
	verifiedAt: timestamp('verified_at').defaultNow().notNull()
});
