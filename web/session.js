'use strict';
// Never store credentials/session IDs in script-accessible storage. Only real local
// input renews the idle deadline; video, audio, pings and status polling do not.
let lastActivity = 0;
let returning = false;
function showLogin() {
	if (returning) return;
	returning = true;
	document.body.replaceChildren();
	location.replace('/');
}
async function request(path, method = 'GET') {
	try {
		const response = await fetch(path, {
			method,
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'X-Voxl-Login': '1' },
		});
		if (response.status === 401) showLogin();
		return response;
	} catch {
		return null;
	}
}
for (const name of [
	'pointerdown',
	'pointermove',
	'keydown',
	'wheel',
	'touchstart',
]) {
	addEventListener(
		name,
		(event) => {
			if (
				!event.isTrusted ||
				document.hidden ||
				Date.now() - lastActivity < 10000
			)
				return;
			lastActivity = Date.now();
			void request('/auth/activity', 'POST');
		},
		{ passive: true, capture: true }
	);
}
setInterval(() => {
	void request('/auth/status');
}, 2000);
addEventListener('pageshow', () => {
	void request('/auth/status');
});
addEventListener('DOMContentLoaded', () => {
	const button = document.getElementById('lock-session-btn');
	if (!button) return;
	button.hidden = false;
	const label = 'Lock Voxl session — require your password again';
	button.title = label;
	button.addEventListener('pointerdown', (event) => event.stopPropagation());
	button.addEventListener('click', async () => {
		button.disabled = true;
		const response = await request('/auth/logout', 'POST');
		if (response?.ok) showLogin();
		else {
			button.disabled = false;
			button.title = 'Lock failed — click to retry';
			button.setAttribute('aria-label', button.title);
		}
	});
});
