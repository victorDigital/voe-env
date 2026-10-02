import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';
import { DATABASE_URL } from '$app/env/private';
import { building } from '$app/env';

if (!DATABASE_URL && !building) {
	throw new Error('DATABASE_URL environment variable is required');
}

console.log('[DB] Connecting to PostgreSQL...');

const client = DATABASE_URL ? postgres(DATABASE_URL) : postgres();
export const db = drizzle(client, { schema });

console.log('[DB] PostgreSQL connection established');
