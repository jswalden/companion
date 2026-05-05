import type {
	FeedbackValue,
	StoreResultToCustomVariable,
	StoreResultToLocalVariable,
} from '@companion-app/shared/Model/EntityModel.js'
import type { ExpressionValueType } from '@companion-app/shared/Model/Options.js'
import type { InstanceDefinitions } from '../../Instance/Definitions.js'
import type { InstanceProcessManager } from '../../Instance/ProcessManager.js'
import type { InternalController } from '../../Internal/Controller.js'

export type InstanceDefinitionsForEntity = Pick<InstanceDefinitions, 'getEntityDefinition'>

export type ProcessManagerForEntity = Pick<
	InstanceProcessManager,
	'connectionEntityUpdate' | 'connectionEntityDelete' | 'connectionEntityLearnOptions'
>

export type InternalControllerForEntity = Pick<
	InternalController,
	'entityUpdate' | 'entityDelete' | 'entityUpgrade' | 'executeLogicFeedback'
>

export interface NewFeedbackValue {
	entityId: string
	controlId: string

	value: FeedbackValue
}

export type StoreActionResultToLocalVariable = {
	target: StoreResultToLocalVariable['target']
	location: ExpressionValueType<StoreResultToLocalVariable['location']>
	variableName: ExpressionValueType<StoreResultToLocalVariable['variableName']>
}

export type StoreActionResultToCustomVariable = {
	target: StoreResultToCustomVariable['target']
	variableName: ExpressionValueType<StoreResultToCustomVariable['variableName']>
	createIfNotExists: StoreResultToCustomVariable['createIfNotExists']
}

export type StoreActionResultTargetValue =
	| StoreActionResultToLocalVariable
	| StoreActionResultToCustomVariable
	| undefined
