"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const xmlParser = require("xml-parser");
const { accessLog, autodiscover, app, getClientIp } = require("../index.js");
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

	await t.test("resolves client IP when REAL_IP_HEADER is configured", async () => {
		const originalRealIp = settings.realIp;
		settings.realIp = { header: "X-Real-Ip", trustedAddresses: [] };
		try {
			const req = {
				method: "POST",
				url: "/autodiscover/autodiscover.xml",
				headers: { "x-real-ip": "203.0.113.195" },
				socket: { remoteAddress: "127.0.0.1" }
			};
			const res = { setHeader() {}, statusCode: 200 };
			const ctx = app.createContext(req, res);
			ctx.status = 200;

			const message = await capture("info", () => accessLog(ctx, async () => {}));
			assert.match(message, /^\[access\] 203\.0\.113\.195 POST \/autodiscover\/autodiscover\.xml 200 \d+\.\dms$/);
			assert.strictEqual(ctx.ip, "203.0.113.195");
		} finally {
			settings.realIp = originalRealIp;
		}
	});

	await t.test("resolves client IP from trusted reverse proxy address", async () => {
		const originalRealIp = settings.realIp;
		settings.realIp = { header: "X-Real-Ip", trustedAddresses: ["127.0.0.1", "172.16.0.0/12"] };
		try {
			const req = {
				method: "POST",
				url: "/autodiscover/autodiscover.xml",
				headers: { "x-real-ip": "203.0.113.195" },
				socket: { remoteAddress: "::ffff:172.18.0.2" }
			};
			const res = { setHeader() {}, statusCode: 200 };
			const ctx = app.createContext(req, res);
			ctx.status = 200;

			const message = await capture("info", () => accessLog(ctx, async () => {}));
			assert.match(message, /^\[access\] 203\.0\.113\.195 POST \/autodiscover\/autodiscover\.xml 200 \d+\.\dms$/);
		} finally {
			settings.realIp = originalRealIp;
		}
	});

	await t.test("rejects proxy headers from untrusted addresses", async () => {
		const originalRealIp = settings.realIp;
		settings.realIp = { header: "X-Real-Ip", trustedAddresses: ["172.16.0.0/12"] };
		try {
			const req = {
				method: "POST",
				url: "/autodiscover/autodiscover.xml",
				headers: { "x-real-ip": "203.0.113.195" },
				socket: { remoteAddress: "198.51.100.22" }
			};
			const res = { setHeader() {}, statusCode: 200 };
			const ctx = app.createContext(req, res);
			ctx.status = 200;

			const message = await capture("info", () => accessLog(ctx, async () => {}));
			assert.match(message, /^\[access\] 198\.51\.100\.22 POST \/autodiscover\/autodiscover\.xml 200 \d+\.\dms$/);
		} finally {
			settings.realIp = originalRealIp;
		}
	});
});

test("getClientIp", async (t) => {
	await t.test("works with single REAL_IP_HEADER (e.g. X-Real-Ip)", () => {
		const ctx = {
			socket: { remoteAddress: "127.0.0.1" },
			get(name) {
				return name.toLowerCase() === "x-real-ip" ? "203.0.113.195" : "";
			}
		};
		assert.strictEqual(getClientIp(ctx, { header: "X-Real-Ip", trustedAddresses: [] }), "203.0.113.195");
	});

	await t.test("defaults to X-Forwarded-For when trustedAddresses is provided without header", () => {
		const ctx = {
			socket: { remoteAddress: "10.0.0.5" },
			get(name) {
				return name.toLowerCase() === "x-forwarded-for" ? "198.51.100.1, 10.0.0.5" : "";
			}
		};
		assert.strictEqual(getClientIp(ctx, { trustedAddresses: ["10.0.0.0/8"] }), "198.51.100.1");
	});

	await t.test("supports IPv6 and IPv4 CIDRs in trusted addresses", () => {
		const ctxIpv4 = {
			socket: { remoteAddress: "192.168.1.100" },
			get: () => "203.0.113.5"
		};
		assert.strictEqual(getClientIp(ctxIpv4, { header: "X-Real-Ip", trustedAddresses: ["192.168.0.0/16"] }), "203.0.113.5");

		const ctxIpv6 = {
			socket: { remoteAddress: "::1" },
			get: () => "203.0.113.6"
		};
		assert.strictEqual(getClientIp(ctxIpv6, { header: "X-Real-Ip", trustedAddresses: ["::1"] }), "203.0.113.6");
	});

	await t.test("falls back to remoteAddress when no proxy settings are configured", () => {
		const ctx = {
			socket: { remoteAddress: "192.0.2.1" },
			get: () => "203.0.113.1"
		};
		assert.strictEqual(getClientIp(ctx, { header: undefined, trustedAddresses: [] }), "192.0.2.1");
	});

	await t.test("prevents spoofing in X-Forwarded-For by selecting furthest untrusted address", () => {
		const ctx = {
			socket: { remoteAddress: "10.0.0.5" },
			get(name) {
				return name.toLowerCase() === "x-forwarded-for" ? "1.1.1.1, 203.0.113.195, 10.0.0.5" : "";
			}
		};
		assert.strictEqual(getClientIp(ctx, { trustedAddresses: ["10.0.0.0/8"] }), "203.0.113.195");
	});

	await t.test("matches uncompressed IPv6 address against trusted addresses", () => {
		const ctx = {
			socket: { remoteAddress: "0:0:0:0:0:0:0:1" },
			get: () => "203.0.113.8"
		};
		assert.strictEqual(getClientIp(ctx, { header: "X-Real-Ip", trustedAddresses: ["::1"] }), "203.0.113.8");
	});
});

test("real_ip settings", async (t) => {
	const originalEnv = { ...process.env };

	t.afterEach(() => {
		process.env = { ...originalEnv };
		delete require.cache[require.resolve("../settings.js")];
	});

	await t.test("reads REAL_IP_HEADER and REAL_IP_TRUSTED_ADDRESSES", () => {
		process.env.REAL_IP_HEADER = "X-Real-Ip";
		process.env.REAL_IP_TRUSTED_ADDRESSES = "127.0.0.1, 10.0.0.0/8, 172.16.0.0/12";
		delete require.cache[require.resolve("../settings.js")];
		const current = require("../settings.js");
		assert.strictEqual(current.realIp.header, "X-Real-Ip");
		assert.deepStrictEqual(current.realIp.trustedAddresses, ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12"]);
	});
});
