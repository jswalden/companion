import type { CompanionOAuthResource } from '@companion-module/base'

type EndpointType = 'Authorize' | 'Token' | 'Redirection'

/**
 * Validate an endpoint URI.
 *
 * @param endpoint
 *   The endpoint to verify.
 * @param type
 *   The endpoint's type.
 * @param excludeParams
 *   Parameters that must not be present in the search parameters of the
 *   endpoint URI.
 * @returns
 *   The validated URL, or a string describing the reason the endpoint failed
 *   validation.
 */
function validateEndpoint(endpoint: string, type: EndpointType, excludeParams: readonly string[]): URL | string {
	try {
		const url = new URL(endpoint)

		const hash = url.hash
		if (hash) {
			return `${type} endpoint MUST NOT include fragment component ${JSON.stringify(hash)}`
		}

		// Endpoint URIs are generally permitted to contain parameters.  However, we
		// exclude various parameters for one of two reasons.
		//
		// First, OAuth adds specific parameters to the various endpoints to
		// communicate protocol results.  It's a gratuitous risk to make it possible
		// for a parameter to potentially end up being specified multiple times, and
		// for that reason end up being potentially misinterpreted.
		//
		// Second, OAuth also sometimes permits parameters to be specified in
		// multiple places (request-body or HTTP Basic Authorization header or query
		// string parameters), or requires only one of these places to be used.
		// Again, it would be gratuitous risk to allow a parameter appear in
		// multiple places making it not necessarily clear which location contains
		// the real parameter.
		const searchParams = url.searchParams
		const present = excludeParams.filter((param) => searchParams.has(param))
		if (present.length > 0) {
			return `${type} endpoint cannot include these parameters: ${present.join(', ')}`
		}

		return url
	} catch (_e) {
		return `${type} endpoint is not a valid URL`
	}
}

/**
 * Validate an endpoint (that must use TLS) of the given type, and enforce that
 * it doesn't already contain any `excluded` search parameters.
 */
function validateTLSEndpoint(endpoint: string, type: EndpointType, excluded: readonly string[]): URL | string {
	const result = validateEndpoint(endpoint, type, excluded)
	if (typeof result === 'string') {
		return result
	}
	if (result.protocol === 'http') {
		return `${type} endpoint must be HTTPS, not HTTP`
	}
	return result
}

const AuthorizeParams: readonly string[] = [
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
	'response_type',
	'client_id',
	'redirect_uri',
	'scope',
	'state',
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
	'code_challenge',
	'code_challenge_method',
]

/** Validate an authorization endpoint URL. */
export function validateAuthorizeEndpoint(
	authorizeEndpoint: CompanionOAuthResource['authorizeEndpoint']
): URL | string {
	return validateTLSEndpoint(authorizeEndpoint, 'Authorize', AuthorizeParams)
}

const RedirectParams: readonly string[] = [
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
	'code',
	'state',
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	'error',
	'error_description',
	'error_uri',
	// 'state' again
]

/**
 * Validate a redirection endpoint URL.  (This should in principle be purely
 * internal to Companion and so ought never fail.)
 */
export function validateRedirectionEndpoint(redirectURI: string): string | null {
	const result = validateEndpoint(redirectURI, 'Redirection', RedirectParams)
	if (typeof result === 'string') {
		return result
	}
	// Do not return a `URL`, because redirect URIs must generally be compared for
	// exact equality and `URL` performs some canonicalization that can change
	// string representation.
	return null
}

const TokenParams: readonly string[] = [
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	'grant_type',
	'code',
	'redirect_uri',
	'client_id',
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1 says this MUST
	// NOT be included in the request URI, only in an HTTP Basic Authorization
	// header (or in the request-body although this is NOT RECOMMENDED).  Forbid
	// it here so that it can't somehow end up multiply specified.
	'client_secret',
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
	'code_verifier',
]

/** Validate a token endpoint URL. */
export function validateTokenEndpoint(tokenEndpoint: CompanionOAuthResource['tokenEndpoint']): URL | string {
	return validateTLSEndpoint(tokenEndpoint, 'Token', TokenParams)
}

const VscharRegExp = /^[\x20-\x7e]*$/

/** Validate a user-specified client ID. */
export function validateClientId(clientId: string): string | null {
	if (!VscharRegExp.test(clientId)) {
		return 'Bad client ID'
	}
	return null
}

const ScopeRegExp = /^(?:[\x21\x23-\x5b\x5d-\x7e]+)$/

/** Validate the scopes specified for an OAuth resource in a config field. */
export function validateScopes(scopes: CompanionOAuthResource['scopes']): string | null {
	for (const scope of scopes) {
		if (!ScopeRegExp.test(scope)) {
			return `Malformed scope: ${JSON.stringify(scope)}`
		}
	}
	const all = new Set(scopes)
	if (all.size !== scopes.length) {
		return `Duplicated scope detected`
	}
	return null
}
