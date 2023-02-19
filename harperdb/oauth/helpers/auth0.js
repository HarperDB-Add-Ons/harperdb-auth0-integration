import axios from 'axios';

export const getAccessToken = async (auth0Url, auth0ClientId, auth0ClientSecret, callbackUrl, code) => {
	const tokenExchangeUrl = `${auth0Url}/oauth/token`;
	const response = await axios.request({
		method: 'POST',
		url: tokenExchangeUrl,
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
		},
		data: new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: auth0ClientId,
			client_secret: auth0ClientSecret,
			code,
			redirect_uri: callbackUrl,
		}),
	});
	return response.data;
};
