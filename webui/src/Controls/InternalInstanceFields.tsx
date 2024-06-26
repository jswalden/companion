import React, { useContext, useMemo } from 'react'
import { DropdownInputField } from '../Components/index.js'
import { ConnectionsContext, useComputed } from '../util.js'
import TimePicker from 'react-time-picker'
import { InternalInputField } from '@companion-app/shared/Model/Options.js'
import { DropdownChoice } from '@companion-module/base'
import { RootAppStoreContext } from '../Stores/RootAppStore.js'
import { observer } from 'mobx-react-lite'

export function InternalInstanceField(
	option: InternalInputField,
	isOnControl: boolean,
	readonly: boolean,
	value: any,
	setValue: (value: any) => void
): JSX.Element | null {
	switch (option.type) {
		case 'internal:instance_id':
			return (
				<InternalInstanceIdDropdown
					disabled={readonly}
					value={value}
					includeAll={option.includeAll}
					multiple={option.multiple}
					setValue={setValue}
					filterActionsRecorder={option.filterActionsRecorder}
				/>
			)
		case 'internal:page':
			return (
				<InternalPageDropdown
					disabled={readonly}
					isOnControl={isOnControl}
					includeDirection={option.includeDirection}
					includeStartup={option.includeStartup}
					value={value}
					setValue={setValue}
				/>
			)
		case 'internal:custom_variable':
			return (
				<InternalCustomVariableDropdown
					disabled={readonly}
					value={value}
					setValue={setValue}
					includeNone={option.includeNone}
				/>
			)
		case 'internal:variable':
			return <InternalVariableDropdown disabled={readonly} value={value} setValue={setValue} />
		case 'internal:surface_serial':
			return (
				<InternalSurfaceBySerialDropdown
					disabled={readonly}
					isOnControl={isOnControl}
					value={value}
					setValue={setValue}
					includeSelf={option.includeSelf}
					useRawSurfaces={option.useRawSurfaces}
				/>
			)
		case 'internal:trigger':
			return (
				<InternalTriggerDropdown
					disabled={readonly}
					isOnControl={isOnControl}
					value={value}
					setValue={setValue}
					includeSelf={option.includeSelf}
				/>
			)
		case 'internal:time':
			return <InternalTimePicker disabled={readonly} value={value} setValue={setValue} />
		default:
			// Use fallback
			return null
	}
}

interface InternalInstanceIdDropdownProps {
	includeAll: boolean | undefined
	value: any
	setValue: (value: any) => void
	disabled: boolean
	multiple: boolean
	filterActionsRecorder: boolean | undefined
}

function InternalInstanceIdDropdown({
	includeAll,
	value,
	setValue,
	disabled,
	multiple,
	filterActionsRecorder,
}: Readonly<InternalInstanceIdDropdownProps>) {
	const context = useContext(ConnectionsContext)

	const choices = useMemo(() => {
		const instance_choices = []
		if (includeAll) {
			instance_choices.push({ id: 'all', label: 'All Instances' })
		}

		for (const [id, config] of Object.entries(context)) {
			if (filterActionsRecorder && !config.hasRecordActionsHandler) continue

			instance_choices.push({ id, label: config.label ?? id })
		}
		return instance_choices
	}, [context, includeAll, filterActionsRecorder])

	return (
		<DropdownInputField disabled={disabled} value={value} choices={choices} multiple={!!multiple} setValue={setValue} />
	)
}

interface InternalPageDropdownProps {
	isOnControl: boolean
	includeStartup: boolean | undefined
	includeDirection: boolean | undefined
	value: any
	setValue: (value: any) => void
	disabled: boolean
}

const InternalPageDropdown = observer(function InternalPageDropdown({
	isOnControl,
	includeStartup,
	includeDirection,
	value,
	setValue,
	disabled,
}: InternalPageDropdownProps) {
	const { pages } = useContext(RootAppStoreContext)

	const choices = useComputed(() => {
		const choices: DropdownChoice[] = []
		if (isOnControl) {
			choices.push({ id: 0, label: 'This page' })
		}
		if (includeStartup) {
			choices.push({ id: 'startup', label: 'Startup page' })
		}
		if (includeDirection) {
			choices.push({ id: 'back', label: 'Back' }, { id: 'forward', label: 'Forward' })
		}

		const pagesSorted = pages.sortedEntries
		for (const [i, pageInfo] of pagesSorted) {
			choices.push({ id: i, label: `${i} (${pageInfo.name || ''})` })
		}
		return choices
	}, [pages, isOnControl, includeStartup, includeDirection])

	return <DropdownInputField disabled={disabled} value={value} choices={choices} multiple={false} setValue={setValue} />
})

interface InternalCustomVariableDropdownProps {
	value: any
	setValue: (value: any) => void
	includeNone: boolean | undefined
	disabled: boolean
}

export const InternalCustomVariableDropdown = observer(function InternalCustomVariableDropdown({
	value,
	setValue,
	includeNone,
	disabled,
}: Readonly<InternalCustomVariableDropdownProps>) {
	const { variablesStore: customVariables } = useContext(RootAppStoreContext)

	const choices = useComputed(() => {
		const choices = []

		if (includeNone) {
			choices.push({
				id: '',
				label: 'None',
			})
		}

		for (const [id, info] of customVariables.customVariables) {
			choices.push({
				id,
				label: `${info.description} (internal:custom_${id})`,
			})
		}

		return choices
	}, [customVariables, includeNone])

	return (
		<DropdownInputField
			disabled={disabled}
			value={value ?? ''}
			choices={choices}
			multiple={false}
			setValue={setValue}
		/>
	)
})

interface InternalVariableDropdownProps {
	value: any
	setValue: (value: any) => void
	disabled: boolean
}

const InternalVariableDropdown = observer(function InternalVariableDropdown({
	value,
	setValue,
	disabled,
}: Readonly<InternalVariableDropdownProps>) {
	const { variablesStore } = useContext(RootAppStoreContext)

	const baseVariableDefinitions = variablesStore.allVariableDefinitions.get()
	const choices = useMemo(() => {
		const choices = []

		for (const variable of baseVariableDefinitions) {
			const id = `${variable.connectionLabel}:${variable.name}`
			choices.push({
				id,
				label: `${variable.label} (${id})`,
			})
		}

		choices.sort((a, b) => a.id.localeCompare(b.id))

		return choices
	}, [baseVariableDefinitions])

	return (
		<DropdownInputField
			disabled={disabled}
			value={value}
			choices={choices}
			multiple={false}
			setValue={setValue}
			allowCustom /* Allow specifying a variable which doesnt currently exist, perhaps as something is offline */
		/>
	)
})

interface InternalSurfaceBySerialDropdownProps {
	isOnControl: boolean
	value: any
	setValue: (value: any) => void
	disabled: boolean
	includeSelf: boolean | undefined
	useRawSurfaces: boolean | undefined
}

const InternalSurfaceBySerialDropdown = observer(function InternalSurfaceBySerialDropdown({
	isOnControl,
	value,
	setValue,
	disabled,
	includeSelf,
	useRawSurfaces,
}: InternalSurfaceBySerialDropdownProps) {
	const { surfaces } = useContext(RootAppStoreContext)

	const choices = useComputed(() => {
		const choices: DropdownChoice[] = []
		if (isOnControl && includeSelf) {
			choices.push({ id: 'self', label: 'Current surface' })
		}

		if (!useRawSurfaces) {
			for (const group of surfaces.store.values()) {
				if (!group) continue

				choices.push({
					label: group.displayName,
					id: group.id,
				})
			}
		} else {
			for (const group of surfaces.store.values()) {
				if (!group) continue

				for (const surface of group.surfaces) {
					choices.push({
						label: surface.displayName,
						id: surface.id,
					})
				}
			}
		}

		return choices
	}, [surfaces, isOnControl, includeSelf, useRawSurfaces])

	return <DropdownInputField disabled={disabled} value={value} choices={choices} multiple={false} setValue={setValue} />
})

interface InternalTriggerDropdownProps {
	isOnControl: boolean
	value: any
	setValue: (value: any) => void
	disabled: boolean
	includeSelf: boolean | undefined
}

const InternalTriggerDropdown = observer(function InternalTriggerDropdown({
	isOnControl,
	value,
	setValue,
	disabled,
	includeSelf,
}: InternalTriggerDropdownProps) {
	const { triggersList } = useContext(RootAppStoreContext)

	const choices = useComputed(() => {
		const choices: DropdownChoice[] = []
		if (!isOnControl && includeSelf) {
			choices.push({ id: 'self', label: 'Current trigger' })
		}

		for (const [id, trigger] of triggersList.triggers.entries()) {
			choices.push({
				id: id,
				label: trigger.name || `Trigger #${id}`,
			})
		}
		return choices
	}, [triggersList, isOnControl, includeSelf])

	return <DropdownInputField disabled={disabled} value={value} choices={choices} multiple={false} setValue={setValue} />
})

interface InternalTimePickerProps {
	value: any
	setValue: (value: any) => void
	disabled: boolean
}

function InternalTimePicker({ value, setValue, disabled }: InternalTimePickerProps) {
	return (
		<TimePicker
			disabled={disabled}
			format="HH:mm:ss"
			maxDetail="second"
			required
			value={value}
			onChange={setValue}
			className={''}
			openClockOnFocus={false}
		/>
	)
}
