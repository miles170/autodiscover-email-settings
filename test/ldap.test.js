"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { buildFilter, getLdapUrl, lookupUserName } = require("../ldap.js");

test("buildFilter", async (t) => {
	await t.test("defaults to (mail=<escaped_email>)", () => {
		const filter = buildFilter("miles@example.com");
		assert.strictEqual(filter, "(mail=miles@example.com)");
	});

	await t.test("treats a blank custom filter as unset", () => {
		const filter = buildFilter("miles@example.com", { filter: "   " });
		assert.strictEqual(filter, "(mail=miles@example.com)");
	});

	await t.test("supports custom filter with %{email} placeholder", () => {
		const filter = buildFilter("miles@example.com", {
			filter: "(&(objectClass=PostfixBookMailAccount)(mailEnabled=TRUE)(mailHomeDirectory=*)(mailQuota=*)(uniqueIdentifier=%{email}))"
		});
		assert.strictEqual(
			filter,
			"(&(objectClass=PostfixBookMailAccount)(mailEnabled=TRUE)(mailHomeDirectory=*)(mailQuota=*)(uniqueIdentifier=miles@example.com))"
		);
	});

	await t.test("does not reuse the mobile profile search filter", () => {
		const filter = buildFilter("miles@example.com", {
			searchfilter: "(|(objectClass=PostfixBookMailAccount))"
		});
		assert.strictEqual(filter, "(mail=miles@example.com)");
	});

	await t.test("combines a custom base filter with the email lookup", () => {
		const filter = buildFilter("miles@example.com", {
			filter: "(|(objectClass=PostfixBookMailAccount))"
		});
		assert.strictEqual(filter, "(&(|(objectClass=PostfixBookMailAccount))(mail=miles@example.com))");
	});

	await t.test("escapes RFC 4515 special characters to prevent filter injection", () => {
		const malicious = "admin*)(|(objectClass=*";
		const filter = buildFilter(malicious, {
			filter: "(&(objectClass=PostfixBookMailAccount)(uniqueIdentifier=%{email}))"
		});
		assert.strictEqual(
			filter,
			"(&(objectClass=PostfixBookMailAccount)(uniqueIdentifier=admin\\2a\\29\\28|\\28objectClass=\\2a))"
		);
	});
});

test("getLdapUrl", async (t) => {
	await t.test("constructs standard ldap url", () => {
		assert.strictEqual(getLdapUrl({ host: "ldap.example.com" }), "ldap://ldap.example.com:389");
	});

	await t.test("constructs ldaps url with SSL socket", () => {
		assert.strictEqual(
			getLdapUrl({ host: "ldap.example.com", port: "636", socket: "SSL" }),
			"ldaps://ldap.example.com:636"
		);
	});

	await t.test("infers ldaps when port is 636", () => {
		assert.strictEqual(
			getLdapUrl({ host: "ldap.example.com", port: 636 }),
			"ldaps://ldap.example.com:636"
		);
	});

	await t.test("constructs ldap url with STARTTLS", () => {
		assert.strictEqual(
			getLdapUrl({ host: "ldap.example.com", socket: "STARTTLS" }),
			"ldap://ldap.example.com:389"
		);
	});

	await t.test("prefers explicit STARTTLS over port-based SSL inference", () => {
		assert.strictEqual(
			getLdapUrl({ host: "ldap.example.com", port: "636", socket: "STARTTLS" }),
			"ldap://ldap.example.com:636"
		);
	});

});

test("lookupUserName", async (t) => {
	await t.test("returns null if email is empty or invalid", async () => {
		assert.strictEqual(await lookupUserName(""), null);
		assert.strictEqual(await lookupUserName("   "), null);
		assert.strictEqual(await lookupUserName(null), null);
	});

	await t.test("returns null if LDAP is not configured", async () => {
		const settings = { ldap: {} };
		assert.strictEqual(await lookupUserName("miles@example.com", settings), null);
	});

	await t.test("returns null if search base is missing", async () => {
		const settings = { ldap: { host: "ldap.example.com" } };
		assert.strictEqual(await lookupUserName("miles@example.com", settings), null);
	});

	await t.test("returns cn when user is found", async () => {
		class MockClient {
			constructor(opts) {
				this.opts = opts;
				this.unbound = false;
			}
			async bind() {}
			async search(base, opts) {
				assert.strictEqual(base, "ou=People,dc=example,dc=com");
				assert.deepStrictEqual(opts.attributes, ["cn"]);
				return {
					searchEntries: [{ dn: "uid=miles,ou=People,dc=example,dc=com", cn: "Miles" }]
				};
			}
			async unbind() {
				this.unbound = true;
			}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				usersbase: "ou=People,dc=example,dc=com",
				binddn: "cn=admin,dc=example,dc=com",
				bindpassword: "secret"
			}
		};

		const name = await lookupUserName("miles@example.com", settings, MockClient);
		assert.strictEqual(name, "Miles");
	});

	await t.test("falls back from usersbase to base", async () => {
		let searchedBase = null;
		class MockClient {
			async bind() {}
			async search(base) {
				searchedBase = base;
				return { searchEntries: [{ cn: "Miles" }] };
			}
			async unbind() {}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com"
			}
		};

		const name = await lookupUserName("miles@example.com", settings, MockClient);
		assert.strictEqual(name, "Miles");
		assert.strictEqual(searchedBase, "dc=example,dc=com");
	});

	await t.test("handles multi-valued cn attribute", async () => {
		class MockClient {
			async bind() {}
			async search() {
				return { searchEntries: [{ cn: ["Miles", "Lawrence Wu"] }] };
			}
			async unbind() {}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com"
			}
		};

		const name = await lookupUserName("miles@example.com", settings, MockClient);
		assert.strictEqual(name, "Miles");
	});

	await t.test("handles Buffer cn attribute", async () => {
		class MockClient {
			async bind() {}
			async search() {
				return { searchEntries: [{ cn: Buffer.from("Miles", "utf8") }] };
			}
			async unbind() {}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com"
			}
		};

		const name = await lookupUserName("miles@example.com", settings, MockClient);
		assert.strictEqual(name, "Miles");
	});

	await t.test("case-insensitively finds cn attribute", async () => {
		class MockClient {
			async bind() {}
			async search() {
				return { searchEntries: [{ CN: "Miles" }] };
			}
			async unbind() {}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com"
			}
		};

		const name = await lookupUserName("miles@example.com", settings, MockClient);
		assert.strictEqual(name, "Miles");
	});

	await t.test("returns null when user is not found", async () => {
		class MockClient {
			async bind() {}
			async search() {
				return { searchEntries: [] };
			}
			async unbind() {}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com"
			}
		};

		const name = await lookupUserName("notfound@example.com", settings, MockClient);
		assert.strictEqual(name, null);
	});

	await t.test("returns null when cn is missing or empty", async () => {
		class MockClient {
			async bind() {}
			async search() {
				return { searchEntries: [{ mail: "user@example.com", cn: "   " }] };
			}
			async unbind() {}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com"
			}
		};

		const name = await lookupUserName("user@example.com", settings, MockClient);
		assert.strictEqual(name, null);
	});

	await t.test("always calls unbind even on search error", async () => {
		let unbindCalled = false;
		class MockClient {
			async bind() {}
			async search() {
				throw new Error("LDAP timeout");
			}
			async unbind() {
				unbindCalled = true;
			}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com"
			}
		};

		await assert.rejects(
			async () => {
				await lookupUserName("user@example.com", settings, MockClient);
			},
			{ message: "LDAP timeout" }
		);
		assert.strictEqual(unbindCalled, true);
	});

	await t.test("calls startTLS if socket is STARTTLS", async () => {
		let tlsCalled = false;
		class MockClient {
			async startTLS() {
				tlsCalled = true;
			}
			async bind() {}
			async search() {
				return { searchEntries: [{ cn: "TLS User" }] };
			}
			async unbind() {}
		}

		const settings = {
			ldap: {
				host: "ldap.example.com",
				base: "dc=example,dc=com",
				socket: "STARTTLS"
			}
		};

		const name = await lookupUserName("user@example.com", settings, MockClient);
		assert.strictEqual(name, "TLS User");
		assert.strictEqual(tlsCalled, true);
	});

});
