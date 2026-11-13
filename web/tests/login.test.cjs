const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const vm = require('node:vm');
const source = readFileSync(resolve(__dirname, '../login.js'), 'utf8');
async function submit(results) {
	let handler;
	const button = { disabled: false, textContent: 'Sign in' };
	const error = { textContent: '' };
	const form = {
		elements: Object.fromEntries(
			Object.entries({
				username: 'ai',
				password: 'test-only-password',
				duration: '3600',
				idle: '300',
			}).map(([k, value]) => [k, { value }])
		),
		addEventListener: (_, callback) => {
			handler = callback;
		},
		querySelector: () => button,
	};
	const requests = [],
		navigations = [],
		delays = [];
	vm.runInNewContext(source, {
		document: { getElementById: (id) => (id === 'login' ? form : error) },
		window: { isSecureContext: true },
		location: { replace: (url) => navigations.push(url) },
		setTimeout: (callback, delay) => {
			delays.push(delay);
			callback();
		},
		fetch: async (url, options) => {
			requests.push({
				url,
				...options,
				credentialsBody: JSON.parse(options.body),
			});
			const result = results[Math.min(requests.length - 1, results.length - 1)];
			if (result === 'offline')
				throw new Error('connection closed during session change');
			return {
				ok: result === 200,
				status: result,
				text: async () => 'An RDP connection is active.',
			};
		},
	});
	await handler({ preventDefault() {} });
	return { button, error, form, requests, navigations, delays };
}
test('automatically completes login after Windows handoff interrupts transport', async () => {
	const state = await submit(['offline', 503, 200]);
	assert.equal(state.requests.length, 3);
	assert.deepEqual(state.navigations, ['/']);
	assert.deepEqual(state.delays, [5000, 5000]);
	assert.equal(state.form.elements.password.value, '');
	for (const request of state.requests) {
		assert.equal(request.url, '/auth/login');
		assert.equal(request.method, 'POST');
		assert.equal(request.credentialsBody.password, 'test-only-password');
	}
});
test('never retries wrong credentials, RDP conflicts, or rate limits', async () => {
	for (const status of [401, 409, 429]) {
		// oxlint-disable-next-line no-await-in-loop
		const state = await submit([status, 200]);
		assert.equal(state.requests.length, 1);
		assert.deepEqual(state.navigations, []);
		assert.deepEqual(state.delays, []);
		assert.equal(state.button.disabled, false);
		assert.equal(state.form.elements.password.value, '');
	}
});
test('bounds unavailable-host retries and restores the login form', async () => {
	const state = await submit([503]);
	assert.equal(state.requests.length, 5);
	assert.equal(state.delays.length, 4);
	assert.equal(state.button.disabled, false);
	assert.match(state.error.textContent, /did not finish/);
});
