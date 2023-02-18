# HarperDB OAuth2.0 Custom Function

This is a [HarperDB](https://harperdb.io/) Custom Function to integrate OAuth 2.0 authorization via major providers via [the Fastify-OAuth2 library](https://github.com/fastify/fastify-oauth2).

## Setup

This [Custom Function](https://harperdb.io/docs/custom-functions/) can be deployed via the [HarperDB Studio](https://studio.harperdb.io/) or locally by cloning this repository into a directory inside the `/custom_functions/` directory (i.e `/custom_funtions/oauth`).

Configure the provider, OAuth keys and endpoints in the file .authConfig.json or with the following environment variables.

```
CLIENT_ID: '12134',
CLIENT_SECRET: '12234',
PROVIDER: GITHUB_CONFIGURATION,
LOGINPATH: /login/github,
CALLBACK: http://localhost:9926/oauth/callback,
SCHEMA: hdb_auth,
TABLE: sessions,
SALT_ROUNDS: 5,
LOGOUT: /logout
```

## How to Use
**note: in the below examples, "oauth" is the given name of the Custom Function, and it's using the GitHub provider OAuth provider.

1. Ensure the above config file or environment variables have been set.
2. Create a GET request to [$HOST/oauth/setup]($HOST/oauth/setup) to create the auth schema and table.
3. Visit [http://$HOST/oauth/login/github](http://$HOST/oauth/login/github) to be redirected to the GitHub authorization page to create a token.
4. Save the return HDB Token for use in the Authorization header for the following requests. You should use the token in the Authorization header in the format `harperdb $token`
5. With the HDB Token in the Authorization header, make a GET call to [http://$HOST/oauth/create/schema/:schema](http://$HOST/oauth/create/schema/:schema) to create a schema
6. With the HDB Token in the Authorization header, make a GET call to [http://$HOST/oauth/create/table/:schema/:table](http://$HOST/oauth/create/table/:schema/:table) to create a table
7. With the HDB Token in the Authorization header, make a POST call to [http://$HOST/oauth/:schema/:table](http://$HOST/oauth/:schema/:table) to insert records into the server (the request body can be an object or an array of objects).
8. With the HDB Token in the Authorization header, make a GET call to [http://$HOST/oauth/create/table/:schema/:table/:id](http://$HOST/oauth/create/table/:schema/:table/:id) to retrieve a record from the table

## Postman Collection
There's a Postman collection available in this repo - HarperDB OAuth.postman_collection

## Structure and Updates
The majority of the functionality is contained in the helpers/authHelper.js file. Here the configuration is loaded and used to set up [the Fastify-OAuth2](https://github.com/fastify/fastify-oauth2) library](https://github.com/fastify/fastify-oauth2), which is a wrapper around the [Simple OAuth2.0 library](https://github.com/lelylan/simple-oauth2).

Refer to the fastify-oauth2 doc for a list of providers and the simple-oauth2 documentation for additional configuration options.

## Running Locally
There's a Makefile located in this repo that will start a containerized instance of HarperDB with the Custom Function mounted to the src directory.

### To Start
Run `make` to start the container.

### To Restart the Custom Function
Run `make cfr` to restart the Custom Functions server

### To Stop
Run `make down` to stop the container
