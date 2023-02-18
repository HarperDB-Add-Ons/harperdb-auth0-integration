import authHelper from '../helpers/authHelper.js';

export default async (server, { hdbCore, logger }) => {
	await authHelper.loadRoutes({ server, hdbCore, logger });

	server.route({
		url: '/setup',
		method: 'GET',
		handler: (request, response) => authHelper.setupSchema(request, response, hdbCore, logger),
	});

	// CREATE SCHEMA
	server.route({
		url: '/create/schema/:schema',
		preValidation: (request, response, next) => authHelper.validate(request, response, next, hdbCore, logger),
		method: 'GET',
		handler: (request) => {
			const { schema } = request.params;
			return hdbCore.requestWithoutAuthentication({
				body: {
					operation: 'create_schema',
					schema,
				},
			});
		},
	});

	// CREATE TABLE
	server.route({
		url: '/create/table/:schema/:table',
		preValidation: (request, response, next) => authHelper.validate(request, response, next, hdbCore, logger),
		method: 'GET',
		handler: (request) => {
			const { schema, table } = request.params;
			return hdbCore.requestWithoutAuthentication({
				body: {
					operation: 'create_table',
					schema,
					table,
					hash_attribute: 'id',
				},
			});
		},
	});

	// POST A DATA RECORD
	server.route({
		url: '/:schema/:table',
		preValidation: (request, response, next) => authHelper.validate(request, response, next, hdbCore, logger),
		method: 'POST',
		handler: (request) => {
			const records = [].concat(request.body);
			console.log('records', records);
			const { schema, table } = request.params;
			return hdbCore.requestWithoutAuthentication({
				body: {
					operation: 'insert',
					schema,
					table,
					records,
				},
			});
		},
	});

	// GET A DATA RECORD
	server.route({
		url: '/:schema/:table/:id',
		preValidation: (request, response, next) => authHelper.validate(request, response, next, hdbCore, logger),
		method: 'GET',
		handler: async (request) => {
			const { schema, table, id } = request.params;
			const results = await hdbCore.requestWithoutAuthentication({
				body: {
					operation: 'search_by_hash',
					schema: schema,
					table: table,
					hash_values: [id],
					get_attributes: ['*'],
				},
			});
			results.forEach((result) => delete result.hdb_user);
			return results;
		},
	});
};
