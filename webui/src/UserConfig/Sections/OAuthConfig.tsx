import React from 'react'
import { observer } from 'mobx-react-lite'
import { UserConfigHeadingRow } from '../Components/UserConfigHeadingRow.js'
import { UserConfigProps } from '../Components/Common.js'
import { UserConfigPortNumberRow } from '../Components/UserConfigPortNumberRow.js'
import { UserConfigTextInputRow } from '../Components/UserConfigTextInputRow.js'
import { UserConfigStaticTextRow } from '../Components/UserConfigStaticTextRow.js'
import { InlineHelp } from '~/Components/InlineHelp.js'

export const OAuthConfig = observer(function OAuthConfig(props: UserConfigProps) {
	return (
		<>
			<UserConfigHeadingRow label="OAuth Callback Server" />

			<tr>
				<td colSpan={3}>
					<p>
						If you configure Companion on the computer Companion runs on, you can specify <code>127.0.0.1</code> as
						host.
					</p>
					<p>
						If you configure Companion on a different computer, specify the host through which you access the Companion
						web UI.
					</p>
					{false && (
						<p>
							With the currently defined settings, you must add{' '}
							<code>
								http://{props.config.oauth_callback_listen_host}:{props.config.oauth_callback_listen_port}
								/oauth-callback
							</code>{' '}
							as redirect URI to your OAuth resources to use them as module OAuth resources.
						</p>
					)}
				</td>
			</tr>

			<UserConfigTextInputRow
				userConfig={props}
				label="OAuth Callback Server Host"
				field="oauth_callback_listen_host"
			/>
			<UserConfigPortNumberRow
				userConfig={props}
				label="OAuth Callback Server Listen Port"
				field="oauth_callback_listen_port"
			/>

			<UserConfigStaticTextRow
				label={<InlineHelp help="You can't change this value.">Companion OAuth Redirect URI</InlineHelp>}
				text={
					<code>
						http://{props.config.oauth_callback_listen_host}:{props.config.oauth_callback_listen_port}/oauth-callback
					</code>
				}
			/>
		</>
	)
})
