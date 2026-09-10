"use strict";

const net		= require("node:net");
const path		= require("path");
const util		= require("util");
const Koa		= require("koa");
const Router	= require("koa-router");
const swig		= require("swig-templates");
const xmlParser	= require("xml-parser");
const settings	= require("./settings.js");
const ldap		= require("./ldap.js");

const app		= new Koa();
const router	= new Router();

swig.setDefaults({
	autoescape: true,
	cache: "memory",
	locals: settings
});

const renderFile = util.promisify(swig.renderFile);

app.context.render = async function(view, options = {}) {
	const file = path.extname(view) ? view : `${view}.xml`;
	const filePath = path.join(__dirname, "views", file);
	this.body = await renderFile(filePath, { ...settings, ...this.state, ...options });
};

function formatRequestBody(rawBody) {
	const redacted = rawBody.replace(
		/<((?:[\w.-]+:)?(?:password|secret|token))(?:\s[^>]*)?>[\s\S]*?<\/\1\s*>/gi,
		"<$1>[REDACTED]</$1>"
	);
	const limit = 2000;
	const body = redacted.length > limit ? `${redacted.slice(0, limit)}…` : redacted;
	return JSON.stringify(body);
}

function normalizeIp(ip) {
	if (!ip) return "";
	if (ip.startsWith("::ffff:")) return ip.slice(7);
	return ip;
}

const matcherCache = new WeakMap();

function buildIpMatcher(trustedList) {
	if (!trustedList || trustedList.length === 0) return () => true;
	const blockList = new net.BlockList();
	for (const raw of trustedList) {
		const item = normalizeIp(raw.trim());
		if (item === "*" || item === "all") return () => true;
		if (item === "loopback") {
			blockList.addSubnet("127.0.0.0", 8, "ipv4");
			blockList.addAddress("::1", "ipv6");
			continue;
		}
		const [addr, prefixStr] = item.split("/");
		const type = net.isIP(addr);
		if (!type) continue;
		const family = type === 6 ? "ipv6" : "ipv4";
		if (prefixStr !== undefined) {
			const prefix = parseInt(prefixStr, 10);
			const maxPrefix = type === 6 ? 128 : 32;
			if (Number.isInteger(prefix) && prefix >= 0 && prefix <= maxPrefix) {
				blockList.addSubnet(addr, prefix, family);
			}
		} else {
			blockList.addAddress(addr, family);
		}
	}
	return (ip) => {
		const normalized = normalizeIp(ip);
		const type = net.isIP(normalized);
		return Boolean(type && blockList.check(normalized, type === 6 ? "ipv6" : "ipv4"));
	};
}

function getIpMatcher(trustedList) {
	if (!trustedList || trustedList.length === 0) return () => true;
	let matcher = matcherCache.get(trustedList);
	if (!matcher) {
		matcher = buildIpMatcher(trustedList);
		matcherCache.set(trustedList, matcher);
	}
	return matcher;
}

function getClientIp(ctx, config = settings.realIp) {
	const rawRemote = ctx.socket?.remoteAddress || ctx.req?.socket?.remoteAddress || ctx.ip || "";
	const remoteIp = normalizeIp(rawRemote);
	const header = config?.header;
	const trusted = config?.trustedAddresses;

	if (!header && (!trusted || trusted.length === 0)) {
		return remoteIp || ctx.ip || "-";
	}
	const isTrusted = getIpMatcher(trusted);
	if (trusted && trusted.length > 0 && !isTrusted(remoteIp)) {
		return remoteIp || ctx.ip || "-";
	}
	const headerName = header || "X-Forwarded-For";
	const headerValue = (ctx.get ? ctx.get(headerName) : ctx.headers?.[headerName.toLowerCase()]) || "";
	if (!headerValue) {
		return remoteIp || ctx.ip || "-";
	}
	if (headerName.toLowerCase() === "x-forwarded-for") {
		const ips = headerValue.split(",").map((s) => s.trim()).filter(Boolean);
		if (trusted && trusted.length > 0) {
			for (let i = ips.length - 1; i >= 0; i--) {
				if (!isTrusted(ips[i])) {
					return ips[i];
				}
			}
		}
		return ips[0] || remoteIp || ctx.ip || "-";
	}
	return headerValue.split(",")[0].trim() || remoteIp || ctx.ip || "-";
}

async function accessLog(ctx, next) {
	const startedAt = process.hrtime.bigint();
	const clientIp = getClientIp(ctx);
	if (ctx.request) {
		ctx.request.ip = clientIp;
	}
	let requestError;

	try {
		await next();
	} catch (err) {
		requestError = err;
		throw err;
	} finally {
		const duration = Number(process.hrtime.bigint() - startedAt) / 1e6;
		const status = requestError ? requestError.status || 500 : ctx.status;
		const issue = ctx.state.accessWarning || (status === 404 ? "unhandled request" : undefined);
		const detail = requestError ?
			(requestError instanceof Error ? requestError.message : String(requestError)) :
			issue;
		const metadata = [];
		if (ctx.state.displayName !== undefined) {
			metadata.push(`displayName=${JSON.stringify(ctx.state.displayName)}`);
		}
		if ((requestError || issue) && ctx.state.rawRequestBody !== undefined) {
			metadata.push(`body=${formatRequestBody(ctx.state.rawRequestBody)}`);
		}
		const message = [
			"[access]",
			clientIp || ctx.ip || "-",
			ctx.method,
			ctx.path,
			status,
			`${duration.toFixed(1)}ms`,
			detail ? `- ${detail}` : "",
			...metadata
		].filter(Boolean).join(" ");

		if (requestError) {
			console.error(message);
		} else if (issue || status >= 400) {
			console.warn(message);
		} else {
			console.info(message);
		}
	}
}

function findChild(name, children, def = null) {
	if (!children) {
		return def;
	}
	for (let child of children) {
		if (child.name === name) {
			return child;
		}
	}
	return def;
}

// Microsoft Outlook / Apple Mail
async function autodiscover(ctx) {
	ctx.set("Content-Type", "application/xml");

	const request	= ctx.request.body && ctx.request.body.root ?
		findChild("Request", ctx.request.body.root.children) :
		null;
	const schema	= request !== null ?
		findChild("AcceptableResponseSchema", request.children) :
		null;
	const xmlns		= schema !== null ?
		schema.content :
		"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006";

	let email		= request !== null ?
		findChild("EMailAddress", request.children) :
		null;

	let username;
	let domain;
	if (email === null || typeof email.content !== "string" || !email.content.trim()) {
		ctx.state.accessWarning ||= "missing EMailAddress";
		email		= "";
		username	= "";
		domain		= settings.domain;
	} else if (~email.content.indexOf("@")) {
		email		= email.content;
		username	= email.split("@")[0];
		domain		= email.split("@")[1];
	} else {
		username	= email.content;
		domain		= settings.domain;
		email		= username + "@" + domain;
	}

	const imapenc	= settings.imap.socket === "STARTTLS" ? "TLS" : settings.imap.socket;
	const popenc	= settings.pop.socket === "STARTTLS" ? "TLS" : settings.pop.socket;
	const smtpenc	= settings.smtp.socket === "STARTTLS" ? "TLS" : settings.smtp.socket;

	const imapssl	= settings.imap.socket === "SSL" ? "on" : "off";
	const popssl	= settings.pop.socket === "SSL" ? "on" : "off";
	const smtpssl	= settings.smtp.socket === "SSL" ? "on" : "off";

	let displayName;
	try {
		displayName = await ldap.lookupUserName(email);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		ctx.state.accessWarning ||= `LDAP display name lookup failed: ${message}`;
	}

	displayName = displayName || settings.info.name || email;
	ctx.state.displayName = displayName;

	await ctx.render("autodiscover", {
		schema: xmlns,
		displayName,
		email,
		username,
		domain,
		imapenc,
		popenc,
		smtpenc,
		imapssl,
		popssl,
		smtpssl
	});
}

router.get("/autodiscover/autodiscover.xml", autodiscover);
router.post("/autodiscover/autodiscover.xml", autodiscover);
router.get("/Autodiscover/Autodiscover.xml", autodiscover);
router.post("/Autodiscover/Autodiscover.xml", autodiscover);


// Thunderbird
router.get("/mail/config-v1.1.xml", async (ctx) => {
	ctx.set("Content-Type", "application/xml");
	await ctx.render("autoconfig");
});


// iOS / Apple Mail (/email.mobileconfig?email=username@domain.com or /email.mobileconfig?email=username)
router.get("/email.mobileconfig", async (ctx) => {
	let email = ctx.query.email;

	if (!email) {
		ctx.status = 400;
		return;
	}

	let username;
	let domain;
	if (~email.indexOf("@")) {
		username	= email.split("@")[0];
		domain		= email.split("@")[1];
	} else {
		username	= email;
		domain		= settings.domain;
		email		= username + "@" + domain;
	}

	const filename	= `${domain}.mobileconfig`;

	const imapssl	= settings.imap.socket === "SSL" || settings.imap.socket === "STARTTLS" ? "true" : "false";
	const popssl	= settings.pop.socket === "SSL" || settings.pop.socket === "STARTTLS" ? "true" : "false";
	const smtpssl	= settings.smtp.socket === "SSL" || settings.smtp.socket === "STARTTLS" ? "true" : "false";
	const ldapssl	= settings.ldap.socket === "SSL" || settings.ldap.port === "636" ? "true" : "false";

	ctx.set("Content-Type", "application/x-apple-aspen-config; charset=utf-8");
	ctx.set("Content-Disposition", `attachment; filename="${filename}"`);

	await ctx.render("mobileconfig", {
		email,
		username,
		domain,
		imapssl,
		popssl,
		smtpssl,
		ldapssl
	});
});

// XML body parser middleware
app.use(accessLog);
app.use(async (ctx, next) => {
	if (ctx.method === "POST") {
		const raw = await new Promise((resolve, reject) => {
			let data = "";
			ctx.req.setEncoding("utf8");
			ctx.req.on("data", (chunk) => {
				data += chunk;
			});
			ctx.req.on("end", () => {
				resolve(data);
			});
			ctx.req.on("error", reject);
		});
		ctx.state.rawRequestBody = raw;
		if (ctx.is("xml") || ctx.is("text/xml") || ctx.is("application/xml")) {
			try {
				ctx.request.body = xmlParser(raw);
			} catch {
				ctx.request.body = null;
				ctx.state.accessWarning = "invalid XML body";
			}
		}
	}
	await next();
});

app.use(router.routes());
app.use(router.allowedMethods());

if (require.main === module) {
	app.listen(process.env.PORT || 8000);
}

module.exports = { app, autodiscover, accessLog, getClientIp };
