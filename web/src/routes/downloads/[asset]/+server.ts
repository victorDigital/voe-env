import { env } from '$env/dynamic/private';
import { error, redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

const assets = new Set([
	've-linux-amd64',
	've-linux-arm64',
	've-darwin-amd64',
	've-darwin-arm64',
	've-windows-amd64.exe',
	've-windows-arm64.exe',
	'SHA256SUMS'
]);

export const GET: RequestHandler = ({ params, setHeaders }) => {
	if (!assets.has(params.asset)) {
		throw error(404, 'CLI download not found');
	}

	const releaseURL =
		env.VOE_CLI_RELEASE_URL || 'https://github.com/victorDigital/voe-env/releases/latest/download';

	setHeaders({ 'cache-control': 'no-store' });
	throw redirect(302, `${releaseURL.replace(/\/$/, '')}/${params.asset}`);
};
