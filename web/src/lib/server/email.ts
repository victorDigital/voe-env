import { EMAIL_API_KEY, EMAIL_FROM } from '$app/env/private';
export async function sendEmail(to: string, subject: string, text: string) {
	if (!EMAIL_API_KEY || !EMAIL_FROM)
		throw new Error('Email delivery is not configured. Set EMAIL_API_KEY and EMAIL_FROM.');
	const response = await fetch('https://api.resend.com/emails', {
		method: 'POST',
		headers: { Authorization: `Bearer ${EMAIL_API_KEY}`, 'Content-Type': 'application/json' },
		body: JSON.stringify({ from: EMAIL_FROM, to: [to], subject, text })
	});
	if (!response.ok) throw new Error('Email delivery failed');
}
