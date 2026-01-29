import { drizzle } from 'drizzle-orm/bun-sqlite';
import * as schema from './schema';
import { Database } from 'bun:sqlite';
import { DATABASE_URL } from '$env/static/private';
import { dev } from '$app/environment';

// Parse the DATABASE_URL to get the actual file path
function getDatabasePath(url: string): string {
	if (url.startsWith('file:')) {
		return url.substring(5); // Remove 'file:' prefix
	}
	return url;
}

const dbPath = getDatabasePath(DATABASE_URL);

console.log('[DB] Connecting to database at:', dbPath);

// Create database connection with create flag
export const client = new Database(dbPath, { create: true });
export const db = drizzle(client, { schema });

console.log('[DB] Database connection established');
