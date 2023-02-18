import { timingSafeEqual, randomBytes, pbkdf2 } from 'crypto';
import { existsSync, readFileSync } from 'fs';
import oauthPlugin from 'fastify-oauth2';
import { fileURLToPath } from 'url';
import { join } from 'path';
import { promisify } from 'util';

const randomBytesAsync = promisify(randomBytes);
const pbkdf2Async = promisify(pbkdf2);
const __dirname = fileURLToPath(new URL('.', import.meta.url));

// use config file location
const configFilePath = join(__dirname, '..', '.authConfig.json');

// use config file (if present) or ENV variables
const CONFIG = existsSync(configFilePath)
	? JSON.parse(readFileSync(configFilePath))
	: {
			provider: process.env.PROVIDER,
			loginPath: process.env.LOGIN_PATH,
			callback: process.env.CALLBACK,
			schema: process.env.SCHEMA,
			table: process.env.TABLE,
			salt_rounds: process.env.SALT_ROUNDS,
			logout: process.env.LOGOUT,
			client: {
				id: process.env.CLIENT_ID,
				secret: process.env.CLIENT_SECRET,
			},
	  };


const makeHash = async (token) => (await pbkdf2Async(token, CONFIG.salt, 100000, 64, 'sha512')).toString('hex');

const extractToken = (authorizationHeader) => {
	const [type, fullToken] = authorizationHeader.split(' ');
	if (type !== 'harperdb') {
		throw new Error('Invalid Authorization Type');
	}

	const [user, token] = fullToken.split('.');
	return { user, token };
};

/**
 * Create the schema and table for the authentication tokens
 * @param {*} request
 * @param {*} response
 * @param {*} hdbCore
 * @param {*} logger
 * @returns
 */
async function setupSchema(request, response, hdbCore, logger) {
	logger.notify('Creating HDB Auth Schema');
	try {
		await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'create_schema',
				schema: CONFIG.schema,
			},
		});
		logger.notify('HDB Auth Schema has been created');
	} catch (error) {
		logger.notify('HDB Auth Schema already exists');
	}

	logger.notify('Create HDB Auth Table');
	try {
		await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'create_table',
				schema: CONFIG.schema,
				table: CONFIG.table,
				hash_attribute: 'user',
			},
		});
		logger.notify('HDB Auth Table has been created');
	} catch (error) {
		logger.notify('HDB Auth Table already exists');
	}

	return response.code(200).send('HDB Auth has been setup');
}

const loadRoutes = async ({ server, hdbCore }) => {
	server.register(oauthPlugin, {
		name: 'githubOAuth2',
		credentials: {
			client: CONFIG.client,
			auth: oauthPlugin[CONFIG.provider],
		},
		// register a server url to start the redirect flow
		startRedirectPath: CONFIG.loginPath,
		// facebook redirect here after the user login
		callbackUri: CONFIG.callback,
	});

	const callback = CONFIG.callback.split('/').pop();
	server.get(`/${callback}`, async function (request) {
		const { access_token } = await this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

		const hdbToken = await makeHash(access_token);
		const hdbTokenUser = (await randomBytesAsync(12)).toString('hex');
		const hashedToken = await makeHash(hdbToken);

		await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'insert',
				schema: CONFIG.schema,
				table: CONFIG.table,
				records: [{ user: hdbTokenUser, token: hashedToken }],
			},
		});

		return `${hdbTokenUser}.${hdbToken}`;
	});

	server.get(`${CONFIG.logout}`, async function (request, reply) {
		try {
			const { user, token } = extractToken(request.headers.authorization);

			const results = await hdbCore.requestWithoutAuthentication({
				body: {
					operation: 'search_by_hash',
					schema: CONFIG.schema,
					table: CONFIG.table,
					hash_values: [user],
					get_attributes: ['token'],
				},
			});

			for (const result of results) {
				const hashedToken = result.token;
				const hashedReceivedToken = await makeHash(token);
				if (timingSafeEqual(Buffer.from(hashedReceivedToken), Buffer.from(hashedToken))) {
					await hdbCore.requestWithoutAuthentication({
						body: {
							operation: 'delete',
							schema: CONFIG.schema,
							table: CONFIG.table,
							hash_values: [user],
						},
					});
				}
			}

			return reply.code(200).send('Logout Successful');
		} catch (err) {
			return reply.code(500).send(err.message || 'Logout Error');
		}
	});
};

const validate = async (request, response, next, hdbCore) => {
	try {
		const { user, token } = extractToken(request.headers.authorization);
		const results = await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'search_by_hash',
				schema: CONFIG.schema,
				table: CONFIG.table,
				hash_values: [user],
				get_attributes: ['token'],
			},
		});
		if (!results.length) {
			return response.code(401).send('HDB Token Error');
		}

		const { token: hashedToken } = results[0];

		const hashedReceivedToken = await makeHash(token);

		if (!timingSafeEqual(Buffer.from(hashedReceivedToken), Buffer.from(hashedToken))) {
			return response.code(401).send('HDB Token Error');
		}

		if (!request.body) {
			request.body = {};
		}
		request.body.hdb_user = { role: { permission: { super_user: true } } };
		return next();
	} catch (error) {
		console.error('error', error);
		return response.code(500).send(error.message || 'HDB Token Error');
	}
};

export default { setupSchema, loadRoutes, validate };
