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
	error.textContent = '';
	try {
		const response = await fetch('/auth/login', {
			method: 'POST',
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/json', 'X-Voxl-Login': '1' },
			body: JSON.stringify({
				username: form.elements.username.value.trim(),
				password: form.elements.password.value,
				duration: Number(form.elements.duration.value),
				idle: Number(form.elements.idle.value),
			}),
		});
		form.elements.password.value = '';
		if (response.ok) {
			location.replace('/');
			return;
		}
		error.textContent =
			response.status === 429
				? 'Too many attempts. Wait a minute and try again.'
				: response.status === 409
					? await response.text()
					: response.status === 503
						? 'Windows desktop sign-in is unavailable or did not finish. Please try again.'
						: 'Sign-in failed. Check your username and password, or ask the host administrator.';
	} catch {
		form.elements.password.value = '';
		error.textContent = 'Unable to reach the host. Please try again.';
	} finally {
		button.disabled = false;
	}
});
