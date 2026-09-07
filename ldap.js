"use strict";

const { Client, Filter } = require("ldapts");
const defaultSettings = require("./settings.js");

function buildFilter(email, ldapSettings = {}) {
	const escapedEmail = Filter.escape(email);
	const customFilter = ldapSettings.filter;

	if (!customFilter) {
		return `(mail=${escapedEmail})`;
	}

	const trimmed = customFilter.trim();
	if (!trimmed) {
		return `(mail=${escapedEmail})`;
	}
	if (trimmed.includes("%{email}")) {
		return trimmed.replaceAll("%{email}", escapedEmail);
	}

	const base = trimmed.startsWith("(") && trimmed.endsWith(")") ? trimmed : `(${trimmed})`;
	return `(&${base}(mail=${escapedEmail}))`;
}

function getLdapUrl(ldapSettings = {}) {
	const host = ldapSettings.host || "";
	const socket = (ldapSettings.socket || "").toUpperCase();
	const isSSL = socket === "SSL" || (!socket && String(ldapSettings.port) === "636");
	const protocol = isSSL ? "ldaps" : "ldap";
	const port = ldapSettings.port || (isSSL ? 636 : 389);
	return `${protocol}://${host}:${port}`;
}

async function lookupUserName(email, settings = defaultSettings, ClientClass = Client) {
	if (!email || typeof email !== "string") {
		return null;
	}
	email = email.trim();
	if (!email) {
		return null;
	}

	const ldapSettings = settings && settings.ldap ? settings.ldap : {};
	if (!ldapSettings.host) {
		return null;
	}

	const baseDN = ldapSettings.usersbase || ldapSettings.base;
	if (!baseDN) {
		return null;
	}

	const url = getLdapUrl(ldapSettings);
	const socket = (ldapSettings.socket || "").toUpperCase();
	const isStartTLS = socket === "STARTTLS";
	const nameField = ldapSettings.namefield || "cn";
	const filter = buildFilter(email, ldapSettings);

	const client = new ClientClass({
		url,
		timeout: 5000,
		connectTimeout: 5000
	});

	try {
		if (isStartTLS && typeof client.startTLS === "function") {
			await client.startTLS();
		}

		if (ldapSettings.binddn) {
			await client.bind(ldapSettings.binddn, ldapSettings.bindpassword || "");
		}

		const result = await client.search(baseDN, {
			scope: "sub",
			filter,
			attributes: [nameField],
			sizeLimit: 1,
			timeLimit: 5
		});

		if (!result || !result.searchEntries || !result.searchEntries.length) {
			return null;
		}

		const entry = result.searchEntries[0];
		let value = entry[nameField];
		if (value === undefined) {
			const key = Object.keys(entry).find(k => k.toLowerCase() === nameField.toLowerCase());
			if (key) {
				value = entry[key];
			}
		}

		if (Array.isArray(value)) {
			value = value[0];
		}

		if (Buffer.isBuffer(value)) {
			value = value.toString("utf8");
		}

		if (typeof value === "string") {
			value = value.trim();
		}

		return value || null;
	} finally {
		try {
			await client.unbind();
		} catch {
			// ignore unbind error
		}
	}
}

module.exports = {
	lookupUserName,
	buildFilter,
	getLdapUrl
};
