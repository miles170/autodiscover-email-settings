"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const xmlParser = require("xml-parser");
const { accessLog, autodiscover } = require("../index.js");
const ldap = require("../ldap.js");
const settings = require("../settings.js");

function request(email) {
	const body = xmlParser(`<Autodiscover><Request><EMailAddress>${email}</EMailAddress></Request></Autodiscover>`);
	let rendered;
	const ctx = {
		request: { body },
		state: {},
		set() {},
		async render(view, options) {
			rendered = { view, options };
		}
	};

	return {
		ctx,
		get rendered() {
			return rendered;
		}
	};
}

test("autodiscover resolves DisplayName", async (t) => {
	const originalLookup = ldap.lookupUserName;
	const originalCompanyName = settings.info.name;
	const originalDomain = settings.domain;

	t.after(() => {
		ldap.lookupUserName = originalLookup;
		settings.info.name = originalCompanyName;
		settings.domain = originalDomain;
	});

	await t.test("uses the LDAP display name", async () => {
		const testRequest = request("miles@example.com");
		ldap.lookupUserName = async (email) => {
			assert.strictEqual(email, "miles@example.com");
			return "Miles";
		};
		settings.info.name = "Fallback Company";

		await autodiscover(testRequest.ctx);

		assert.strictEqual(testRequest.rendered.view, "autodiscover");
		assert.strictEqual(testRequest.rendered.options.displayName, "Miles");
		assert.strictEqual(testRequest.ctx.state.displayName, "Miles");
	});

	await t.test("falls back to the company name", async () => {
		const testRequest = request("unknown@example.com");
		ldap.lookupUserName = async () => null;
		settings.info.name = "My Company Inc";

		await autodiscover(testRequest.ctx);

		assert.strictEqual(testRequest.rendered.options.displayName, "My Company Inc");
	});

	await t.test("falls back when LDAP fails", async () => {
		const testRequest = request("timeout@example.com");
		ldap.lookupUserName = async () => {
			throw new Error("LDAP connection timeout");
		};
		settings.info.name = "My Company Inc";

		await autodiscover(testRequest.ctx);

		assert.strictEqual(testRequest.rendered.options.displayName, "My Company Inc");
		assert.strictEqual(
			testRequest.ctx.state.accessWarning,
			"LDAP display name lookup failed: LDAP connection timeout"
		);
	});

	await t.test("uses the email when no other display name is available", async () => {
		const testRequest = request("solo.user@example.com");
		ldap.lookupUserName = async () => null;
		settings.info.name = "";

		await autodiscover(testRequest.ctx);

		assert.strictEqual(testRequest.rendered.options.displayName, "solo.user@example.com");
	});

	await t.test("expands a local part before lookup", async () => {
		const testRequest = request("john.doe");
		settings.domain = "example.com";
		ldap.lookupUserName = async (email) => {
			assert.strictEqual(email, "john.doe@example.com");
			return "John Doe";
		};

		await autodiscover(testRequest.ctx);

		assert.strictEqual(testRequest.rendered.options.displayName, "John Doe");
	});

	await t.test("marks a request without an email as unprocessable", async () => {
		const testRequest = request("");
		ldap.lookupUserName = async () => null;

		await autodiscover(testRequest.ctx);

		assert.strictEqual(testRequest.ctx.state.accessWarning, "missing EMailAddress");
	});
});

test("accessLog", async (t) => {
	function context(overrides = {}) {
		return {
			ip: "192.0.2.1",
			method: "POST",
			path: "/autodiscover/autodiscover.xml",
			status: 200,
			state: {},
			...overrides
		};
	}

	async function capture(method, callback) {
		let message;
		const original = console[method];
		console[method] = (value) => {
			message = value;
		};
		try {
			await callback();
		} finally {
			console[method] = original;
		}
		return message;
	}

	await t.test("logs completed requests", async () => {
		const message = await capture("info", () => accessLog(context(), async () => {}));
		assert.match(message, /^\[access\] 192\.0\.2\.1 POST \/autodiscover\/autodiscover\.xml 200 \d+\.\dms$/);
	});

	await t.test("warns when a request cannot be handled", async () => {
		const ctx = context({
			state: {
				accessWarning: "invalid XML body",
				displayName: "Fallback Company",
				rawRequestBody: "<Request>\n  <Password>secret</Password>\n</Request>"
			}
		});
		const message = await capture("warn", () => accessLog(ctx, async () => {}));
		assert.ok(message.endsWith(
			'- invalid XML body displayName="Fallback Company" body="<Request>\\n  <Password>[REDACTED]</Password>\\n</Request>"'
		));
	});

	await t.test("identifies unmatched routes", async () => {
		const message = await capture("warn", () => accessLog(context({ status: 404 }), async () => {}));
		assert.match(message, / 404 \d+\.\dms - unhandled request$/);
	});

	await t.test("logs unhandled errors with status 500", async () => {
		const message = await capture("error", async () => {
			await assert.rejects(
				accessLog(context(), async () => {
					throw new Error("unexpected failure");
				}),
				{ message: "unexpected failure" }
			);
		});
		assert.match(message, / 500 \d+\.\dms - unexpected failure$/);
	});
});
