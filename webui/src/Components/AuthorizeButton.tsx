import { CompanionOAuthResource } from '@companion-module/base'
import { CButton } from '@coreui/react'
import { faSync } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import React, { useCallback, useMemo, useState } from 'react'
import { getOAuthCallbackURL, getOAuthTokens } from './OAuthAuthorize'
import { useUserConfigProps } from '~/UserConfig/Context'
import { StaticTextFieldText } from '~/Controls/StaticTextField'

interface AuthorizeButtonProps {
	oauthResource: CompanionOAuthResource
	clientId: string
	clientSecret: string
	disabled: boolean
	onAuthorizeResult: (tokens: { accessToken: string; refreshToken: string }) => void
}

export function AuthorizeButton({
	oauthResource,
	clientId,
	clientSecret,
	disabled,
	onAuthorizeResult,
}: AuthorizeButtonProps): React.JSX.Element | null {
	const [authorizing, setAuthorizing] = useState<boolean>(false)

	const userConfigProps = useUserConfigProps()

	const redirectURI = useMemo(() => {
		return userConfigProps ? getOAuthCallbackURL(userConfigProps) : ''
	}, [userConfigProps])

	const doAuthorize = useCallback(() => {
		void (async () => {
			try {
				setAuthorizing(true)

				// XXX add a timeout?  does this need an AbortController/AbortSignal in
				//     case the user exits the config UI?
				const tokenInfo = await getOAuthTokens({
					oauthResource,
					redirectURI,
					clientId,
					clientSecret,
				})

				onAuthorizeResult({
					accessToken: tokenInfo.accessToken,
					refreshToken: tokenInfo.refreshToken ?? '',
				})

				// XXX If they're filled in, use the accessTokenExpiresInSeconds and
				//     refreshToken fields to refresh the access (and potentially refresh)
				//     tokens on a suitable interval -- using the definition's
				//     defaultAccessTokenExpiresInSeconds field as fallback if the token
				//     endpoint didn't return a time til expiration.  Probably shove
				//     this automated refreshing into `ServiceOAuthCallback`?
				void tokenInfo.accessTokenExpiresInSeconds
			} catch (e) {
				console.log(`ERROR getting auth tokens: ${e}`)
				throw e
			} finally {
				setAuthorizing(false)
			}
		})()
	}, [oauthResource, redirectURI, clientId, clientSecret, setAuthorizing, onAuthorizeResult])

	if (!userConfigProps) {
		return null
	}

	return (
		<>
			<StaticTextFieldText
				label="Redirect URI"
				value={`Redirect URI: <code>${redirectURI}</code>`}
				tooltip="Add this exact value to the authorized redirect URIs for the OAuth-protected service"
			/>
			<CButton
				disabled={disabled || authorizing}
				color="info"
				size="sm"
				onClick={doAuthorize}
				title="Attempt to acquire access/refresh tokens from the OAuth service"
			>
				Authorize {authorizing && <FontAwesomeIcon icon={faSync} spin />}
			</CButton>
		</>
	)
}
