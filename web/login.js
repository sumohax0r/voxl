'use strict';
const form = document.getElementById('login');
const error = document.getElementById('error');
form.addEventListener('submit', async (event) => {
	event.preventDefault();
	if (!window.isSecureContext) {
		error.textContent = 'Use HTTPS to protect your operating-system password.';
		return;
	}
	const button = form.querySelector('button');
	button.disabled = true;
	button.textContent = 'Signing in…';
	error.textContent = '';
	// Keep credentials only in this submit's memory, long enough to complete a
	// Windows session handoff. Never put them in a URL, cookie or browser storage.
	const credentials = {
		username: form.elements.username.value.trim(),
		password: form.elements.password.value,
		duration: Number(form.elements.duration.value),
		idle: Number(form.elements.idle.value),
	};
	form.elements.password.value = '';
	try {
		let response = null;
		for (let attempt = 0; attempt < 5; attempt++) {
			try {
				// Retries must wait for the previous Windows handoff attempt.
				// oxlint-disable-next-line no-await-in-loop
				response = await fetch('/auth/login', {
					method: 'POST',
					credentials: 'same-origin',
					cache: 'no-store',
					headers: { 'Content-Type': 'application/json', 'X-Voxl-Login': '1' },
					body: JSON.stringify(credentials),
				});
			} catch {
				response = null;
			}
			if (response?.ok) {
				location.replace('/');
				return;
			}
			// A wrong password, an active RDP session and rate limiting are final.
			// Only retry transport/unavailable responses during a desktop handoff.
			if (response && response.status !== 503) break;
			if (attempt < 4) {
				button.textContent = 'Opening Windows…';
				// oxlint-disable-next-line no-await-in-loop
				await new Promise((resolve) => setTimeout(resolve, 5000));
			}
		}
		error.textContent =
			response?.status === 429
				? 'Too many attempts. Wait a minute and try again.'
				: response?.status === 409
					? await response.text()
					: !response || response.status === 503
						? 'Windows desktop sign-in is unavailable or did not finish. Please try again.'
						: 'Sign-in failed. Check your username and password, or ask the host administrator.';
	} finally {
		credentials.password = '';
		button.disabled = false;
		button.textContent = 'Sign in';
	}
});
