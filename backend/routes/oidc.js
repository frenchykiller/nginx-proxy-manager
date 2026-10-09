import express from "express";
import { Issuer, generators } from "openid-client";
import { debug, express as logger } from "../logger.js";
import userModel from "../models/user.js";
import userPermissionModel from "../models/user_permission.js";
import internalToken from "../internal/token.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

let client = null;
let isConfigured = false;

export async function setupOIDC() {
	const issuerUrl = process.env.OIDC_ISSUER_URL;
	const clientId = process.env.OIDC_CLIENT_ID;
	const clientSecret = process.env.OIDC_CLIENT_SECRET;

	if (issuerUrl && clientId && clientSecret) {
		try {
			const issuer = await Issuer.discover(issuerUrl);
			client = new issuer.Client({
				client_id: clientId,
				client_secret: clientSecret,
				response_types: ['code'],
			});
			isConfigured = true;
			debug(logger, "OIDC Client configured successfully.");
		} catch (err) {
			debug(logger, `OIDC configuration failed: ${err.message}`);
            isConfigured = false;
		}
	} else {
        isConfigured = false;
    }
}

// Initialize on startup
setupOIDC();

router.get("/config", (req, res) => {
	res.status(200).send({
		enabled: isConfigured
	});
});

router.get("/login", async (req, res, next) => {
	if (!isConfigured) {
		return res.status(400).send({ error: "OIDC is not configured" });
	}

	try {
		const redirectUri = process.env.OIDC_REDIRECT_URI || `${req.protocol}://${req.get("host")}/api/oidc/callback`;
		const state = generators.state();
		const codeVerifier = generators.codeVerifier();
		const codeChallenge = generators.codeChallenge(codeVerifier);

		const authorizationUrl = client.authorizationUrl({
			scope: process.env.OIDC_SCOPES || "openid profile email",
			state: state,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
			redirect_uri: redirectUri
		});

		res.cookie('oidc_state', state, { httpOnly: true, maxAge: 300000 });
		res.cookie('oidc_code_verifier', codeVerifier, { httpOnly: true, maxAge: 300000 });
		res.cookie('oidc_redirect_uri', redirectUri, { httpOnly: true, maxAge: 300000 });

		res.redirect(authorizationUrl);
	} catch (err) {
		next(err);
	}
});

router.get("/callback", async (req, res, next) => {
	if (!isConfigured) {
		return res.status(400).send({ error: "OIDC is not configured" });
	}

	try {
		let cookies = {};
		if (req.headers.cookie) {
			req.headers.cookie.split(';').forEach(cookie => {
				const parts = cookie.split('=');
				cookies[parts.shift().trim()] = decodeURI(parts.join('='));
			});
		}

		const state = cookies['oidc_state'];
		const codeVerifier = cookies['oidc_code_verifier'];
		const redirectUri = process.env.OIDC_REDIRECT_URI || cookies['oidc_redirect_uri'] || `${req.protocol}://${req.get("host")}/api/oidc/callback`;

		if (!state || !codeVerifier) {
			return res.status(400).send({ error: "Missing OIDC state/verifier. Please try logging in again." });
		}

		const params = client.callbackParams(req);
		const tokenSet = await client.callback(redirectUri, params, { code_verifier: codeVerifier, state });

		let claims = tokenSet.claims();
		if (!claims.email) {
			try {
				const userInfo = await client.userinfo(tokenSet.access_token);
				claims = { ...claims, ...userInfo };
			} catch (err) {
				debug(logger, `Failed to fetch userinfo: ${err.message}`);
			}
		}
		
		const email = claims.email;

		if (!email) {
			return res.status(400).send({ error: "OIDC provider did not return an email claim." });
		}

		let user = await userModel.query().findOne({ email: email, is_deleted: 0 });

		let isAdmin = false;

		if (!user) {
			const name = claims.name || claims.preferred_username || email.split('@')[0];
			const roles = [];
			
			const adminGroup = process.env.OIDC_ADMIN_GROUP;
			if (adminGroup) {
				const groups = claims.groups || claims.roles || [];
				if (groups.includes(adminGroup)) {
					roles.push("admin");
				}
			}

			user = await userModel.query().insertAndFetch({
				created_on: new Date().toISOString(),
				modified_on: new Date().toISOString(),
				is_deleted: 0,
				is_disabled: 0,
				email: email,
				name: name,
				nickname: name.substring(0, 50),
				avatar: "",
				roles: roles
			});

			isAdmin = roles.includes("admin");
		} else {
			const adminGroup = process.env.OIDC_ADMIN_GROUP;
			if (adminGroup) {
				const groups = claims.groups || claims.roles || [];
				isAdmin = groups.includes(adminGroup);
				const currentRoles = user.roles || [];
				
				if (isAdmin && !currentRoles.includes("admin")) {
					user = await userModel.query().patchAndFetchById(user.id, { roles: [...currentRoles, "admin"] });
				} else if (!isAdmin && currentRoles.includes("admin")) {
					user = await userModel.query().patchAndFetchById(user.id, { roles: currentRoles.filter(r => r !== "admin") });
				}
			} else {
				isAdmin = (user.roles || []).includes("admin");
			}
		}

		// Ensure permissions row exists and has correct visibility
		const existingPerm = await userPermissionModel.query().where("user_id", user.id).first();
		if (existingPerm) {
			if (existingPerm.visibility !== (isAdmin ? "all" : "user")) {
				await userPermissionModel.query().where("user_id", user.id).patch({ visibility: isAdmin ? "all" : "user" });
			}
		} else {
			await userPermissionModel.query().insert({
				user_id: user.id,
				visibility: isAdmin ? "all" : "user",
				proxy_hosts: "manage",
				redirection_hosts: "manage",
				dead_hosts: "manage",
				streams: "manage",
				access_lists: "manage",
				certificates: "manage",
			});
		}

		const jwt = await internalToken.getTokenFromUser(user);

		res.clearCookie('oidc_state');
		res.clearCookie('oidc_code_verifier');
		res.clearCookie('oidc_redirect_uri');

		res.send(`
			<html>
			<body>
				<script>
					localStorage.setItem('authentications', JSON.stringify([{
						token: '${jwt.token}',
						expires: '${jwt.expires}'
					}]));
					window.location.href = '/';
				</script>
			</body>
			</html>
		`);

	} catch (err) {
		next(err);
	}
});

export default router;
