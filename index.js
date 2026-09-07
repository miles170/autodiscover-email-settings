"use strict";

const fs		= require("fs");
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

async function accessLog(ctx, next) {
	const startedAt = process.hrtime.bigint();
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
		const message = [
			"[access]",
			ctx.ip || "-",
			ctx.method,
			ctx.path,
			status,
			`${duration.toFixed(1)}ms`,
			detail ? `- ${detail}` : ""
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


// Generic support page
router.get("/", async (ctx) => {
	await ctx.render("index.html");
});

router.get("/favicon.ico", async (ctx) => {
	ctx.type = "image/x-icon";
	ctx.body = fs.createReadStream(path.join(__dirname, "views", "favicon.ico"));
});

// XML body parser middleware
app.use(accessLog);
app.use(async (ctx, next) => {
	if (ctx.method === "POST" && (ctx.is("xml") || ctx.is("text/xml") || ctx.is("application/xml"))) {
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
		try {
			ctx.request.body = xmlParser(raw);
		} catch {
			ctx.request.body = null;
			ctx.state.accessWarning = "invalid XML body";
		}
	}
	await next();
});

app.use(router.routes());
app.use(router.allowedMethods());

if (require.main === module) {
	app.listen(process.env.PORT || 8000);
}

module.exports = { app, autodiscover, accessLog };
