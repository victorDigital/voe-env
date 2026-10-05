import { toSvelteKitHandler } from 'better-auth/svelte-kit';
import { auth } from '#lib/server/auth.ts';
const handler = toSvelteKitHandler(auth);
export { handler as GET, handler as POST };
