import type { CompanionOAuthResource } from '@companion-module/base'
import { nanoid } from 'nanoid'
import { UserConfigProps } from '~/UserConfig/Components/Common'
import {
	validateAuthorizeEndpoint,
	validateClientId,
	validateRedirectionEndpoint,
	validateScopes,
	validateTokenEndpoint,
} from './OAuthValidate'

/**
 * Get the OAuth callback URL used by Companion OAuth support for a userconfig.
 * XXX should figure out how to get this from the service, which would require
 *     something akin to `UserConfigProps` for the service itself...
 */
export function getOAuthCallbackURL({
	config: { oauth_callback_listen_host: host, oauth_callback_listen_port: port },
}: UserConfigProps): string {
	return `http://${host}:${port}`
}

/** Generate the `state` parameter for an OAuth authorization flow. */
function stateAsNonceAndOrigin(): string {
	// `state` must not be guessable to prevent CSRF by pairing each valid
	// redirect URI callback load with exactly one prior valid authorization
	// request.
	//
	// The callback page needs to know the Web UI origin for *this client*, to
	// `postMessage` sensitive tokens to this origin only.
	//
	// We make `state` the minimally-structured concatenation of a nonce and the
	// current origin to meet both requirements.
	return `${nanoid()}:${window.location.origin}`
}

async function sha256(s: string): Promise<ArrayBuffer> {
	const data = new TextEncoder().encode(s)
	// XXX `crypto.subtle.digest` is only exposed in secure contexts -- HTTPS or
	//     localhost addresses.  So this won't work if running Companion not on
	//     the loopback interface, for accesses through some other IP address or
	//     through a hostname or mDNS etc.
	return window.crypto.subtle.digest('SHA-256', data)
}

function base64URLEncode(buf: ArrayBuffer) {
	// Convert the ArrayBuffer to string using Uint8 array.  btoa takes chars from
	// 0-255 and base64 encodes.  Then convert the base64 encoded to base64url
	// encoded.  (replace + with -, replace / with _, trim trailing =)
	return btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(buf))))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')
}

/**
 * Compute an RFC 7636 `code_verifier`, and add corresponding `code_challenge`
 * and `code_challenge_method` parameters to `params`.  Then return
 * `code_verifier`.
 *
 * @param params Parameters to modify
 * @returns The code verifier whose hashed form was added to `params`
 */
async function addPKCEChallengeParameters(params: URLSearchParams): Promise<string> {
	// https://www.rfc-editor.org/rfc/rfc7636#section-4.2
	//
	// If the client is capable of using "S256", it MUST use "S256", as "S256" is
	// Mandatory To Implement (MTI) on the server.
	params.set('code_challenge_method', 'S256')

	// https://www.rfc-editor.org/rfc/rfc7636#section-4.1
	//
	// ABNF for "code_verifier" is as follows.
	//
	// code-verifier = 43*128unreserved
	// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	// ALPHA = %x41-5A / %x61-7A
	// DIGIT = %x30-39
	//
	// `nanoid` generates only the 64 characters in /[a-ZA-Z0-9_\-]/, omitting the
	// two characters in /[\.~]/.  Use length 48 rather than 43 to compensate
	// (64**48 > 66**43).
	const VerifierLen = 48
	const codeVerifier = nanoid(VerifierLen)

	// https://www.rfc-editor.org/rfc/rfc7636#section-4.2
	//
	// S256
	// 	code-challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	const codeChallenge = base64URLEncode(await sha256(codeVerifier))
	params.set('code_challenge', codeChallenge)

	return codeVerifier
}

/**
 * Compute the full authorization URL to load to start the authorization code
 * grant process for the given client.
 *
 * @param authorizeEndpoint
 *   The authorize endpoint URL before the necessary OAuth parameters are added
 *   to it, conforming to the requirements in RFC 6749.
 * @param clientId
 *   The user-defined client identifier to use to access the OAuth-protected
 *   resource.
 * @param scopes
 *	 The scope(s) of access requested.
 * @param redirectURI
 *   The redirection endpoint URL to include in the ultimate authorization URL,
 *   in order that the authorization URL's server can redirect to it once
 *   authorization is complete.
 * @returns
 *   The constructed authorization URL with authorization parameters added to
 *   it, the `state` parameter included in it, and the `code_verifier` that was
 *   used to create the `code_challenge` parameter included in it.
 */
async function getAuthorizationURL(
	{ authorizeEndpoint, scopes }: CompanionOAuthResource,
	redirectURI: string,
	clientId: string
): Promise<{
	authorizationURL: URL
	state: string
	codeVerifier: string
}> {
	const authRequestURL = validateAuthorizeEndpoint(authorizeEndpoint)
	if (typeof authRequestURL === 'string') {
		throw new Error(authRequestURL)
	}

	const clientIdent = validateClientId(clientId)
	if (typeof clientIdent === 'string') {
		throw new Error(clientIdent)
	}

	// Ensure validation can't return a `URL` that might mistakenly be used
	// instead of `redirectURI`, because redirect URIs are most safely validated
	// by authorization servers by exact comparison to a preregistered list.
	const redirectResult: string | null = validateRedirectionEndpoint(redirectURI)
	if (typeof redirectResult === 'string') {
		throw new Error(`BUG: Constructed an invalid Companion OAuth callback redirect URI (${redirectResult})`)
	}

	const scopeResult = validateScopes(scopes)
	if (typeof scopeResult === 'string') {
		throw new Error(scopeResult)
	}

	const state = stateAsNonceAndOrigin()

	const params = authRequestURL.searchParams

	params.set('response_type', 'code')
	params.set('client_id', clientId)
	params.set('redirect_uri', redirectURI)
	params.set('scope', scopes.join(' '))
	params.set('state', state)

	const codeVerifier = await addPKCEChallengeParameters(params)

	return { authorizationURL: authRequestURL, state, codeVerifier }
}

type AuthorizationCode = {
	code: string
	codeVerifier: string
}

/**
 * Validate that the data `postMessage`'d to us by the OAuth callback server is
 * well-formed.
 *
 * The callback page is essentially static so it *should* be impossible for
 * anything to affect sent data or cause anything but these values to be sent.
 * But in security, paranoia is mandatory.
 */
function toValidCallbackData(unverifiedData: unknown): { code: string; state: string } {
	// XXX use an off-the-shelf library for this?
	if (unverifiedData === null || typeof unverifiedData !== 'object') {
		throw new Error("Callback didn't return an object")
	}

	const dataObject = unverifiedData as Record<string, unknown>

	const code = dataObject['code']
	if (typeof code !== 'string') {
		throw new Error('Callback returned a non-string code')
	}

	const state = dataObject['state']
	if (typeof state !== 'string') {
		throw new Error('Callback returned a non-string state')
	}

	return { code, state }
}

/**
 * For the given client/redirect URI, trigger the authorization process with the
 * supplied OAuth resource and eventually return the authentication results from
 * it.
 */
async function getAuthorizationCode({
	oauthResource,
	redirectURI,
	clientId,
}: {
	oauthResource: CompanionOAuthResource
	redirectURI: string
	clientId: string
}): Promise<AuthorizationCode> {
	const { authorizationURL, state, codeVerifier } = await getAuthorizationURL(oauthResource, redirectURI, clientId)
	console.log(`Authorization URL: ${authorizationURL}`)
	console.log(`code-verifier:     ${codeVerifier}`)

	// The scheme we follow below is to open the authorization URL in a popup
	// window.  The authorization server will process the authentication attempt.
	// It will either fail the attempt completely and not load the redirect URI if
	// it doesn't recognize it (because it wasn't registered with the
	// authorization server).  Or it will open the redirect URI, typically but not
	// necessarily by redirecting to it by HTTP 302, passing the
	// authorization/error response to the attempt in the query string.  The
	// redirect URI will be the HTML page mostly-statically encoded into the OAuth
	// callback server we've implemented.  That HTML page will process the
	// parameters in the query string and `postMessage` the authorization results
	// to its opener window, i.e. to us.
	//
	// This strategy requires that we know the redirect URI, in order to process
	// authorization results sent *only* from the OAuth callback server origin.
	// (An origin is a scheme://host:port.)  We trivially know it because we just
	// interpolated it into the authorization URL.
	//
	// It also requires that the OAuth callback server know what origin *we* are,
	// in order to send sensitive authorization results back only to us.  The
	// origin *we* are is not statically knowable.  It could include 127.0.0.1
	// when accessing on the machine running Companion on a solely loopback
	// interface.  It could be a public IP address when running Companion on a
	// non-loopback interface.  It could be HTTP if using Companion as it normally
	// runs -- or it could be HTTPS if HTTPS support was enabled in Companion.
	// Ultimately we must determine our origin at runtime -- and we pass it within
	// the `state` parameter in the authorization URL, which then also passes it
	// in the same fashion to the redirect URI, and then the OAuth callback server
	// can target its authentication results only to us.
	//
	// Two final notes.  First, this depends on the popup window opening, which
	// depends upon the user permitting popups to open, which seems like a
	// reasonable expectation of the user.  Second, it depends on `window.opener`
	// not being cut off by a Cross-Origin-Opener-Policy.  Our OAuth callback
	// server doesn't send this header, so would not restrict `window.opener`.
	// (If the authorization server sends the header, it's believed -- but not
	// verified -- that this would cut off `window.opener` for *it*, but that the
	// cutoff wouldn't extend to the redirect URI it subsequently navigates to.)

	return new Promise<AuthorizationCode>((resolve, reject) => {
		// `getAuthorizationURL` validated `redirectURI`, but because redirect
		// URIs are compared for exact equality no `URL` object for it was
		// returned.  Create a new one to extract the origin from it.
		const redirectOrigin = new URL(redirectURI).origin

		let authWindow: Window | null = null

		const waitForAuthorizationCode = (event: MessageEvent) => {
			// *Any* window that gets a reference to `window` can send us messages.
			// We must actively ignore messages sent to us not by the authorization
			// popup.
			if (event.source !== authWindow) {
				return
			}

			// OAuth authentication is not specified to send messages to an opener
			// window.  If the authorization server directly sends us messages for
			// some reason -- there's no actual prohibition on it happening -- we
			// should ignore them.  We should only receive messages sent by the
			// redirect URI we prescribed, i.e. the OAuth callback server.
			if (event.origin !== redirectOrigin) {
				return
			}

			try {
				const { code: callbackCode, state: callbackState } = toValidCallbackData(event.data)

				// Enforce that *exactly this function call* initiated eventual load of
				// the OAuth callback, by requiring that the unguessable `state` nonce
				// above was returned to us, to protect against CSRF.
				if (callbackState !== state) {
					reject(new Error('State parameter mismatch detected, CSRF blocked'))
					return
				}

				// We're getting data from our own callback, specifically from the
				// authorization attempt initiated above because only we know what
				// `state` is.  `callbackCode` is valid, and authorization may continue.
				resolve({ code: callbackCode, codeVerifier })
			} finally {
				stopWaitingForAuthorizationCode()
			}
		}
		const stopWaitingForAuthorizationCode = () => window.removeEventListener('message', waitForAuthorizationCode, false)

		try {
			// Try to open the popup.
			authWindow = window.open(authorizationURL)

			// *After* `authWindow` is set, add the event listener that wants
			// `authWindow` to be set.
			window.addEventListener('message', waitForAuthorizationCode, false)

			// *Then* throw if the window didn't open.
			if (!authWindow) {
				throw new Error('Could not open authentication window')
			}
		} catch (e) {
			stopWaitingForAuthorizationCode()
			throw e
		}
	})
}

/** Return the valid token endpoint URL specified by the OAuth resource. */
function getTokenURL(oauthResource: CompanionOAuthResource): URL {
	const tokenRequestURL = validateTokenEndpoint(oauthResource.tokenEndpoint)
	if (typeof tokenRequestURL === 'string') {
		throw new Error(tokenRequestURL)
	}
	return tokenRequestURL
}

/**
 * Compute an HTTP Basic Authorization header specifying the given client ID and
 * secret.
 */
function authorizationHeaderFor(clientId: string, clientSecret: string): string {
	// RFC 6749 §3.2.1 https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1
	// invokes §2.3.1 https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
	// to say that token servers MUST support specifying client credentials using
	// HTTP Basic authentication in an Authorization header.
	//
	// *Some* OAuth token servers MAY support including client credentials in the
	// request-body.  But it is NOT RECOMMENDED (§2.3.1) for clients to do this.
	//
	// Also, at least per RFC, client credentials MUST NOT (§2.3.1) be included in
	// the request URI (although it seems that at least Google's token endpoint
	// allows it anyway).
	//
	// Thus we use the HTTP Basic authentication scheme rather than these two
	// alternatives.
	const basicAuthRaw = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
	const basicAuth = Buffer.from(basicAuthRaw).toString('base64')
	return `Basic ${basicAuth}`
}

/** Fetch a token from the OAuth token endpoint using the given parameters. */
async function fetchToken({
	oauthResource,
	authorizationCode,
	redirectURI,
	clientId,
	clientSecret,
	codeVerifier,
}: {
	oauthResource: CompanionOAuthResource
	authorizationCode: string
	redirectURI: string
	clientId: string
	clientSecret: string
	codeVerifier: string
}): Promise<Response> {
	const tokenRequestURL = getTokenURL(oauthResource)
	console.log(`Hitting token endpoint: ${tokenRequestURL}`)

	const authorizationHeader = authorizationHeaderFor(clientId, clientSecret)
	console.log(`Authorization: ${authorizationHeader}`)

	return fetch(tokenRequestURL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			Authorization: authorizationHeader,
		},
		body: new URLSearchParams({
			client_id: clientId,
			code_verifier: codeVerifier,
			code: authorizationCode,
			grant_type: 'authorization_code',
			redirect_uri: redirectURI,
		}).toString(),
	})
}

/**
 * A type specifying the data returned in response to a request sent to the
 * token endpoint.
 */
type TokenResponse = {
	/** An OAuth access token to use in API operations. */
	accessToken: string

	/**
	 * The amount of time until the access token expires, in seconds, if specified
	 * in the token response.  (XXX allow config field definition to define a
	 * default as fallback?)
	 */
	expiresInSeconds?: number

	/**
	 * If specified, a refresh token that can be exchanged at at a future time for
	 * a new access token (and potentially a new refresh token that should replace
	 * this one).
	 */
	refreshToken?: string

	/**
	 * Either the scopes that were actually granted (which may not equal those
	 * requested), or omitted if the scopes requested were granted.
	 */
	scope?: string
}

function invalidInEndpointResponse(param: string): string {
	return `Invalid ${param} in token endpoint response`
}

/**
 * Convert the supplied value to a well-formed token response from the
 * authorization server, performing the type-checking needed to construct such
 * response.
 */
function toTokenResponse(jsonUnknown: unknown): TokenResponse {
	// XXX use an off-the-shelf library for this?
	if (jsonUnknown === null || typeof jsonUnknown !== 'object') {
		throw new TypeError('Token endpoint response was not a JSON object')
	}

	const json = jsonUnknown as Record<string, unknown>

	const accessToken: unknown = json['access_token']
	if (typeof accessToken !== 'string') {
		throw new TypeError(invalidInEndpointResponse('access_token'))
	}

	const expiresInSeconds: unknown = json['expires_in']
	if (expiresInSeconds !== undefined && typeof expiresInSeconds !== 'number') {
		throw new Error(invalidInEndpointResponse('expires_in'))
	}

	const refreshToken: unknown = json['refresh_token']
	if (refreshToken !== undefined && typeof refreshToken !== 'string') {
		throw new TypeError(invalidInEndpointResponse('refresh_token'))
	}

	const scope: unknown = json['scope']
	if (scope !== undefined && typeof scope !== 'string') {
		throw new TypeError(invalidInEndpointResponse('scope'))
	}

	return { accessToken, expiresInSeconds, refreshToken, scope }
}

/**
 * Get token response information from the given OAuth resource.
 * @param param0
 * @returns
 */
async function getTokens({
	oauthResource,
	redirectURI,
	authorizationCode,
	clientId,
	clientSecret,
	codeVerifier,
}: {
	oauthResource: CompanionOAuthResource
	redirectURI: string
	authorizationCode: string
	clientId: string
	clientSecret: string
	codeVerifier: string
}): Promise<TokenResponse> {
	const response = await fetchToken({
		oauthResource,
		authorizationCode,
		redirectURI,
		clientId,
		clientSecret,
		codeVerifier,
	})
	const status = response.status
	if (status !== 200) {
		throw new Error(`Token endpoint response with status ${status} !== 200`)
	}

	const tokenResponse = toTokenResponse(await response.json())

	// Within `AccessTokenResponse`, the token fields and the access token
	// expiration duration  are arbitrary, and their validity can't be tested
	// except by actually using them.
	//
	// The scope field, indicating the actual scope of access granted, can be
	// checked.  If it was omitted, then the scope granted was the scope requested
	// -- but if it's present, then the granted scope of access might not include
	// all the access requested.  If the response contains a scope, then, we must
	// ensure it's a loose superset of the scopes requested by `oauthResource`.
	//
	// (The authorization server could support incremental grant of scopes, as
	// when using a web service requires access to increasingly more parts of,
	// say, the user's Google account.  That's a good fit for an interactive app
	// with someone constantly in the driver's seat to authorize new scopes of
	// access.  It's not a good fit for Companion which might want to perform
	// far-flung API operations at any instant without any visible UI.)
	const actualScopes = tokenResponse.scope
	if (actualScopes !== undefined) {
		const actualSet = new Set(actualScopes.split(' '))
		const requestedSet = new Set(oauthResource.scopes)
		if (!actualSet.isSupersetOf(requestedSet)) {
			throw new Error('Token endpoint authorized access to fewer scopes than requested')
		}
	}

	return tokenResponse
}

/**
 * The result of a token endpoint request, in more usefully typed format.
 * (Scope information is trimmed out because we require that all previously
 * requested scopes were in fact granted -- for Companion purposes where no user
 * may be around to reauthorize access, partial granting of scope is a hassle,
 * not a benefit.)
 */
type TokenInfo = {
	accessToken: string
	refreshToken?: string
	accessTokenExpiresInSeconds?: number
}

/**
 * Acquire an OAuth access token (and a refresh token, if returned one) for the
 * given OAuth resource and credentials.
 */
export async function getOAuthTokens({
	oauthResource,
	redirectURI,
	clientId,
	clientSecret,
}: {
	oauthResource: CompanionOAuthResource
	redirectURI: string
	clientId: string
	clientSecret: string
}): Promise<TokenInfo> {
	const { code, codeVerifier } = await getAuthorizationCode({ oauthResource, redirectURI, clientId })

	const res = await getTokens({
		oauthResource,
		redirectURI,
		authorizationCode: code,
		clientId,
		clientSecret,
		codeVerifier,
	})

	return {
		accessToken: res.accessToken,
		refreshToken: res.refreshToken,
		accessTokenExpiresInSeconds: res.expiresInSeconds,
	}
}
