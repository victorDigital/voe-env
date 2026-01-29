import { pgTable, text, integer, boolean, timestamp, unique } from 'drizzle-orm/pg-core';

export const user = pgTable('user', {
	id: text('id').primaryKey(),
	name: text('name').notNull(),
	email: text('email').notNull(),
	emailVerified: boolean('emailVerified').notNull(),
	image: text('image'),
	createdAt: timestamp('createdAt', { mode: 'string' }).notNull(),
	updatedAt: timestamp('updatedAt', { mode: 'string' }).notNull()
});

export const session = pgTable('session', {
	id: text('id').primaryKey(),
	userId: text('userId')
		.notNull()
		.references(() => user.id),
	token: text('token').notNull(),
	expiresAt: timestamp('expiresAt', { mode: 'string' }).notNull(),
	ipAddress: text('ipAddress'),
	userAgent: text('userAgent'),
	createdAt: timestamp('createdAt', { mode: 'string' }).notNull(),
	updatedAt: timestamp('updatedAt', { mode: 'string' }).notNull()
});

export const account = pgTable('account', {
	id: text('id').primaryKey(),
	userId: text('userId')
		.notNull()
		.references(() => user.id),
	accountId: text('accountId').notNull(),
	providerId: text('providerId').notNull(),
	accessToken: text('accessToken'),
	refreshToken: text('refreshToken'),
	accessTokenExpiresAt: timestamp('accessTokenExpiresAt', { mode: 'string' }),
	refreshTokenExpiresAt: timestamp('refreshTokenExpiresAt', { mode: 'string' }),
	scope: text('scope'),
	idToken: text('idToken'),
	password: text('password'),
	createdAt: timestamp('createdAt', { mode: 'string' }).notNull(),
	updatedAt: timestamp('updatedAt', { mode: 'string' }).notNull()
});

export const verification = pgTable('verification', {
	id: text('id').primaryKey(),
	identifier: text('identifier').notNull(),
	value: text('value').notNull(),
	expiresAt: timestamp('expiresAt', { mode: 'string' }).notNull(),
	createdAt: timestamp('createdAt', { mode: 'string' }).notNull(),
	updatedAt: timestamp('updatedAt', { mode: 'string' }).notNull()
});

export const envVault = pgTable(
	'env_vault',
	{
		id: text('id').primaryKey(),
		userId: text('userId')
			.notNull()
			.references(() => user.id),
		fullKey: text('fullKey').notNull(),
		encryptedValue: text('encryptedValue').notNull(),
		createdAt: timestamp('createdAt', { mode: 'string' }).notNull(),
		updatedAt: timestamp('updatedAt', { mode: 'string' }).notNull()
	},
	(table) => ({
		userKeyUnique: unique('env_vault_userId_fullKey_unique').on(table.userId, table.fullKey)
	})
);

export const deviceCode = pgTable('deviceCode', {
	id: text('id').primaryKey(),
	deviceCode: text('deviceCode').notNull(),
	userCode: text('userCode').notNull(),
	userId: text('userId').references(() => user.id),
	clientId: text('clientId'),
	scope: text('scope'),
	status: text('status').notNull(),
	expiresAt: timestamp('expiresAt', { mode: 'string' }).notNull(),
	lastPolledAt: timestamp('lastPolledAt', { mode: 'string' }),
	pollingInterval: integer('pollingInterval'),
	createdAt: timestamp('createdAt', { mode: 'string' }).notNull(),
	updatedAt: timestamp('updatedAt', { mode: 'string' }).notNull()
});

export const deviceLog = pgTable('deviceLog', {
	id: text('id').primaryKey(),
	userId: text('userId')
		.notNull()
		.references(() => user.id),
	clientId: text('clientId').notNull(),
	userCode: text('userCode').notNull(),
	scope: text('scope'),
	approvedAt: timestamp('approvedAt', { mode: 'string' }).notNull()
});
