import { error } from '@sveltejs/kit';
const retired = () =>
	error(
		410,
		'Individual shares and password vault APIs have been retired. Upgrade the CLI and use workspaces. Existing data is available in the legacy archive.'
	);
export const GET = retired;
export const POST = retired;
export const DELETE = retired;
