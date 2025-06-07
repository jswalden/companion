import cors from 'cors'
import express, { Express } from 'express'
import { Server as HttpServer } from 'http'
import { nanoid } from 'nanoid'
import { ServiceBase } from './Base.js'
import LogController from '../Log/Controller.js'
import { sendOverIpc } from '../Resources/Util.js'
import { DataUserConfig } from '../Data/UserConfig.js'

function oauthCallbackServerApp(): Express {
	const app = express()

	// Allow cross-origin access.
	app.use(cors())

	// Use a query string parser that guarantees web/standards compatibility and
	// forces `req.query` to be of type `Record<string, string | undefined>`.
	app.set('query parser', (raw: string) => {
		return Object.fromEntries(new URLSearchParams(raw).entries())
	})

	// Aggressively lock down the callback server.
	app.use((_req, res, next) => {
		res.header('X-App', 'Bitfocus Companion OAuth Callback')
		res.header('X-Frame-Options', 'deny')
		res.header('Cache-Control', 'no-cache, no-store')
		res.header('Pragma', 'no-cache')

		next()
	})

	// The universal redirect URI used by all OAuth clients.
	app.use('/', (_req, res) => {
		const nonce = nanoid()
		res.header(
			'Content-Security-Policy',
			[
				"default-src 'none'",
				"frame-ancestors 'none'",
				"base-uri 'none'",
				"require-trusted-types-for 'script'",
				// https://csp-evaluator.withgoogle.com/ suggests using 'unsafe-inline'
				// with 'nonce-*' for script-src for backwards compatibility with older
				// browsers that don't understand nonces.  (The nonce overrides the
				// 'unsafe-inline' directive in newer browsers.)
				`script-src 'unsafe-inline' 'nonce-${nonce}'`,
				// But it does not recommend it for style-src, so we don't add it there.
				`style-src 'nonce-${nonce}'`,
			].join('; ')
		)

		// OAuth callback info for authorization code grants is passed in the query
		// string.
		//
		// It'd be nice to process parameters right here, in TypeScript.  But we'd
		// have to handle interpolation into HTML, too, which is especially tricky
		// to do for <script> content.
		//
		// So we just send client-side JavaScript to do the work.

		res.header('Content-Type', 'text/html; charset=utf-8')
		res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
	<title>Companion OAuth Callback</title>
	<style type="text/css" nonce="${nonce}">
body {
	width: min(90vw, 40em);
	margin-left: 1em;
	margin-right: 1em;
}

#title::before {
	content: "⏳ ";
}

#title {
	font-weight: bold;
}

.success {
	color: green;
}
#title.success::before {
	content: "✅ ";
}

.failure {
	color: #b42525;
}
#title.failure::before {
	content: "❌ ";
}

#infos, .hidden {
	display: none;
}

blockquote {
	background-color: lightgray;
	color: black;
	margin-left: 2em;
	margin-right: 2em;
	padding: 0.2em;
	border-radius: 0.2em;
	white-space: pre-line;
}

code {
	background-color: lightgray;
	color: black;
	font-weight: bolder;
	padding-inline: 0.2em;
	border-radius: 0.2em;
}
	</style>
	<script type="text/javascript" nonce="${nonce}">
/** @param {boolean} success */
function setTitle(success) {
	var title = document.getElementById('title');
	title.textContent = success ? 'Authorization complete' : 'Authorization failed';
	title.className = success ? 'success' : 'failure';
}

/** @param {string} id */
function displayInfo(id) {
	var elt = document.getElementById(id);
	elt.remove();
	document.getElementById('display').append(elt);
}

/** @param {string} id */
function failure(id) {
	setTitle(false);
	displayInfo(id);
}

function success() {
	setTitle(true);
	displayInfo('can-close-now');
}

/** @param {URLSearchParams} params */
function getStateAndWebUIOrigin(params) {
	var state = params.get('state');
	if (!state) {
		failure('missing-state');
		return null;
	}

	var colon = state.indexOf(':'); // nonce:webUIOrigin
	if (colon < 0) {
		failure('malformed-state');
		return null;
	}

	return { state: state, webUIOrigin: state.slice(colon + 1) };
}

/**
 * @param {string} code
 * @param {URLSearchParams} params
 */
function authorized(code, params) {
	var stateWebUI = getStateAndWebUIOrigin(params);
	if (!stateWebUI) {
		return;
	}
	var state = stateWebUI.state;
	var webUIOrigin = stateWebUI.webUIOrigin;

	var webUI = window.opener;
	if (!webUI) {
		failure('no-webui');
		return;
	}

	webUI.postMessage({ code: code, state: state }, webUIOrigin);

	success('can-close-now');
}

/**
 * @param {string} error
 * @param {URLSearchParams} params
 */
function errored(error, params) {
	var stateWebUI = getStateAndWebUIOrigin(params);
	if (!stateWebUI) {
		return;
	}
	var state = stateWebUI.state;
	var webUIOrigin = stateWebUI.webUIOrigin;

	document.getElementById('error-code').textContent = error;

	var errorDescription = params.get('error_description') || '';
	var errorUri = params.get('error_uri') || "";
	try {
		var errorUrl = new URL(errorUri);
		errorUri = /^https?:$/.test(errorUrl.protocol) ? errorUrl.toString() : '';
	} catch (_e) {
		errorUri = '';
	}

	if (errorDescription) {
		document.getElementById('error-description-text').textContent = errorDescription;
		document.getElementById('have-error-description').className = '';
	}

	if (errorUri) {
		document.getElementById('error-uri-link').href = errorUri;
	  document.getElementById('have-error-uri').className = '';
	}

	failure('responded-with-error');
}

function processSearchParameters() {
	var params = new URL(window.location.href).searchParams;

	var code = params.get('code');
	var error = params.get('error');

	// It's really too bad we can't do a Rust-style match on a tuple.
	if (!code) {
		if (!error) {
			failure('no-code-or-error');
			return;
		}

		errored(error, params);
		return;
	}

	if (!error) {
		authorized(code, params)
		return;
	}

	failure('code-and-error');
}

window.onload = function() {
	debugger;
	try {
			processSearchParameters();
	} catch (e) {
		document.getElementById('exception-thrown-info').textContent = e.toString();
		failure('exception-thrown');
	}
};
	</script>
</head>
<body>
<h1 id="title">Processing authorization response...</h1>
<div id="display"></div>
<div id="infos">
	<p id="missing-state">
		Missing <code>state</code> parameter in callback
	</p>
	<p id="malformed-state">
		Callback <code>state</code> parameter is malformed
	</p>
	<p id="no-webui">
		Couldn't send authorization results to Companion
	</p>
	<p id="code-and-error">
		Received both <code>code</code> and <code>error</code> parameters when only
		one should have been received
	</p>
	<p id="no-code-or-error">
		No <code>code</code> or <code>error</code> parameter was received
	</p>

	<div id="responded-with-error">
		<p>
			Authorization failed with the error <code id="error-code"></code>.
		</p>
		<div class="hidden" id="have-error-description">
			<p>
				The authorization server provided this description of the error:
			</p>
			<blockquote id="error-description-text"></blockquote>
		</div>
		<p class="hidden" id="have-error-uri">
			The authorization server also gave <a id="error-uri-link">this explanation</a>
			of the error.
		</p>
	</div>

	<div id="exception-thrown">
		<p>
			Processing of callback parameters threw an exception:
		</p>
		<blockquote id="exception-thrown-info"></blockquote>
	</div>

	<p id="can-close-now">
		You can close this window now
	</p>
</div>
</body>
</html>`)
	})

	return app
}

class OAuthCallbackServer extends HttpServer {
	readonly #logger = LogController.createLogger('OAuthCallbackEndpoint/Server')

	constructor() {
		super(oauthCallbackServerApp())
	}

	/**
	 *
	 */
	rebindHttp(bindIp: string, bindPort: number) {
		if (this !== undefined && this.close !== undefined) {
			this.close()
		}
		try {
			this.on('error', (e: any) => {
				if (e.code == 'EADDRNOTAVAIL') {
					this.#logger.error(`Failed to bind to: ${bindIp}`)
					sendOverIpc({
						messageType: 'oauth-bind-status',
						appStatus: 'Error',
						appURL: `${bindIp} unavailable. Select another IP`,
						appLaunch: null,
					})
				} else {
					this.#logger.error(e)
				}
			})
			this.listen(bindPort, bindIp, () => {
				const address0 = this.address()
				const address = typeof address0 === 'object' ? address0 : undefined

				this.#logger.info(`new url: http://${address?.address}:${address?.port}/`)

				let ip = bindIp == '0.0.0.0' ? '127.0.0.1' : bindIp
				let url = `http://${ip}:${address?.port}/`
				let info = bindIp == '0.0.0.0' ? `All Interfaces: e.g. ${url}` : url
				sendOverIpc({
					messageType: 'oauth-bind-status',
					appStatus: 'Running',
					appURL: info,
					appLaunch: url,
				})
			})
		} catch (e) {
			this.#logger.error(`http bind error: ${e}`)
		}
	}
}

/** Class providing OAuth callback server functionality. */
export class ServiceOAuthCallback extends ServiceBase {
	#server: OAuthCallbackServer | null = null

	/** Start the OAuth callback service. */
	constructor(userconfig: DataUserConfig) {
		super(userconfig, 'Service/OAuthCallbackServer', null, 'oauth_callback_listen_port')

		this.init()
	}

	#hostPort(): [string, number] {
		let host = this.userconfig.getKey('oauth_callback_listen_host')
		if (typeof host !== 'string') {
			host = '127.0.0.1'
		}

		const port = this.portConfig ? Number(this.userconfig.getKey(this.portConfig)) : 8889

		return [host, port]
	}

	#callbackEndpoint([host, port]: [string, number]): URL {
		return new URL(`http://${host}:${port}/oauth-callback`)
	}

	#startServer(host: string, port: number): void {
		try {
			this.#server = new OAuthCallbackServer()
			this.#server.rebindHttp(host, port)

			const callbackEndpoint = this.#callbackEndpoint([host, port])
			this.logger.info(`OAuth callback endpoint available at ${callbackEndpoint}`)
		} catch (e: any) {
			this.logger.error(`Couldn't start OAuth callback server: ${e.message}`)
		}
	}

	override listen() {
		const [host, port] = this.#hostPort()
		this.port = port

		if (this.#server !== null) {
			this.#server.close(() => {
				this.#startServer(host, port)
			})
		} else {
			this.#startServer(host, port)
		}
	}

	callbackEndpoint(): URL {
		return this.#callbackEndpoint(this.#hostPort())
	}

	override close() {
		if (this.#server) {
			this.#server.close()
			this.#server = null
		}
	}

	/**
	 * Process an update userconfig value and enable/disable the module, if necessary.
	 */
	override updateUserConfig(key: string, value: boolean | number | string): void {
		super.updateUserConfig(key, value)

		this.logger.log('info', `Got updateUserConfig(${JSON.stringify(key)}, ${JSON.stringify(value)})`)

		if (key.startsWith('oauth_callback_listen_')) {
			this.restartModule()
		}
	}
}
