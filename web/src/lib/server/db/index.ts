import { drizzle } from 'drizzle-orm/postgres-js';

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
	throw new Error('DATABASE_URL environment variable is required');
}

console.log('[DB] Connecting to PostgreSQL...');

// Create postgres connection
export const db = drizzle({ connection: DATABASE_URL });

console.log('[DB] PostgreSQL connection established');
