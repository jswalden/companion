import type { CompanionOAuthResource, CompanionOAuthConfig } from '@companion-module/base'
import { CFormInput, CFormLabel } from '@coreui/react'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AuthorizeButton } from './AuthorizeButton'
import { StaticTextFieldText } from '~/Controls/StaticTextField'

function defaultValue(): CompanionOAuthConfig {
	return { clientId: '', clientSecret: '', accessToken: '', refreshToken: '' }
}

interface OAuthInputFieldProps {
	oauthResource: CompanionOAuthResource
	label: React.ReactNode
	value: unknown
	setValue: (value: CompanionOAuthConfig) => void
	setValid: (valid: boolean) => void
}

export function OAuthClientInputField({
	oauthResource,
	label,
	value,
	setValue,
	setValid,
}: OAuthInputFieldProps): React.JSX.Element {
	const currentValue = useMemo(() => {
		if (value) {
			const obj = value as Record<string, unknown>
			if (
				typeof obj.clientId === 'string' &&
				typeof obj.clientSecret === 'string' &&
				typeof obj.accessToken === 'string' &&
				typeof obj.refreshToken === 'string'
			) {
				return obj as CompanionOAuthConfig
			}
		}

		return defaultValue()
	}, [value])

	const [tmpValue, setTmpValue] = useState<CompanionOAuthConfig | null>(null)

	const isValueValid = useCallback((config: CompanionOAuthConfig) => {
		// Access and refresh tokens are only filled upon explicit successful
		// authorization.
		return config.clientId !== '' && config.clientSecret !== ''
	}, [])

	// If the value is undefined, populate with the default. Also inform the
	// parent about the validity
	useEffect(() => {
		setValid?.(isValueValid(currentValue))
	}, [isValueValid, currentValue, setValid])

	const showValue = tmpValue ?? currentValue

	const storeValue = useCallback(
		<K extends keyof CompanionOAuthConfig>(key: K, value: CompanionOAuthConfig[K]) => {
			const newval: CompanionOAuthConfig = {
				...showValue,
				[key]: value,
			}
			setTmpValue(newval)
			setValue(newval)
			setValid?.(isValueValid(newval))
		},
		[showValue, setTmpValue, setValue, setValid, isValueValid]
	)

	const doOnClientIdChange = useCallback<React.ChangeEventHandler<HTMLInputElement>>(
		(e) => storeValue('clientId', e.target.value),
		[storeValue]
	)
	const doOnClientSecretChange = useCallback<React.ChangeEventHandler<HTMLInputElement>>(
		(e) => storeValue('clientSecret', e.target.value),
		[storeValue]
	)

	const handleAuthorizeResult = useCallback(
		({ accessToken, refreshToken }: { accessToken: string; refreshToken: string }) => {
			const newval: CompanionOAuthConfig = {
				...showValue,
				accessToken,
				refreshToken,
			}
			setTmpValue(newval)
			setValue(newval)
			setValid?.(isValueValid(newval))
		},
		[showValue, setTmpValue, setValue, setValid, isValueValid]
	)

	const currentValueRef = useRef<CompanionOAuthConfig>()
	currentValueRef.current = currentValue
	const focusStoreValue = useCallback(() => setTmpValue(currentValueRef.current ?? currentValue), [currentValue])
	const blurClearValue = useCallback(() => setTmpValue(null), [])

	return (
		<div>
			<hr />
			{label ? (
				<>
					<CFormLabel>{label}</CFormLabel>
					<div />
				</>
			) : (
				''
			)}
			<CFormInput
				label="Client ID"
				type="text"
				value={showValue.clientId}
				title="OAuth client ID"
				onChange={doOnClientIdChange}
				onFocus={focusStoreValue}
				onBlur={blurClearValue}
			/>
			<CFormInput
				label="Client secret"
				type="text"
				value={showValue.clientSecret}
				title="OAuth client secret"
				onChange={doOnClientSecretChange}
				onFocus={focusStoreValue}
				onBlur={blurClearValue}
			/>
			<StaticTextFieldText
				label="Access token"
				value={`Access token: <code>${showValue.accessToken}</code>`}
				tooltip="The last access token value acquired during successful authorization; may no longer be valid"
			/>
			<StaticTextFieldText
				label="Refresh token"
				value={`Refresh token: <code>${showValue.refreshToken}</code>`}
				tooltip="The last refresh token value acquired during successful authorization; may no longer be valid"
			/>
			<AuthorizeButton
				disabled={!isValueValid(showValue)}
				oauthResource={oauthResource}
				clientId={showValue.clientId}
				clientSecret={showValue.clientSecret}
				onAuthorizeResult={handleAuthorizeResult}
			/>
			<hr />
		</div>
	)
}
