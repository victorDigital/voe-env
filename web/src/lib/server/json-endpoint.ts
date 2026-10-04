import { error, json, type RequestEvent } from '@sveltejs/kit';
import { ZodError } from 'zod';
export function jsonEndpoint<E extends RequestEvent>(
	handler: (event: E) => Response | Promise<Response>
) {
	return async (event: E) => {
		try {
			return await handler(event);
		} catch (cause) {
			if (cause instanceof ZodError || cause instanceof SyntaxError)
				return json({ message: 'Invalid request data' }, { status: 400 });
			throw cause;
		}
	};
}
export async function readJson(request: Request) {
	const reader = request.body?.getReader();
	if (!reader) error(400, 'JSON body required');
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > 16_000_000) error(413, 'Request too large');
			chunks.push(value);
		}
	} finally {
		await reader.cancel();
	}
	return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
