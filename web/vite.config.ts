import adapter from '@sveltejs/adapter-node';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
	const { BETTER_AUTH_URL } = loadEnv(mode, process.cwd(), '');

	return {
		plugins: [
			tailwindcss(),
			sveltekit({
				adapter: adapter(),
				paths: { origin: BETTER_AUTH_URL ? new URL(BETTER_AUTH_URL).origin : undefined }
			})
		]
	};
});
