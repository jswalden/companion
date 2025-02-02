import { cloneDeep } from 'lodash-es'
import { nanoid } from 'nanoid'
import LogController, { Logger } from '../../Log/Controller.js'
import { FragmentActionList } from './FragmentActionList.js'
import type { InstanceDefinitions } from '../../Instance/Definitions.js'
import type { InternalController } from '../../Internal/Controller.js'
import type { ModuleHost } from '../../Instance/Host.js'
import type { InternalVisitor } from '../../Internal/Types.js'
import type { ActionDefinition } from '@companion-app/shared/Model/ActionDefinitionModel.js'
import type { ActionInstance } from '@companion-app/shared/Model/ActionModel.js'
import { visitActionInstance } from '../../Resources/Visitors/ActionInstanceVisitor.js'

export class FragmentActionInstance {
	/**
	 * The logger
	 */
	readonly #logger: Logger

	readonly #instanceDefinitions: InstanceDefinitions
	readonly #internalModule: InternalController
	readonly #moduleHost: ModuleHost

	/**
	 * Id of the control this belongs to
	 */
	readonly #controlId: string

	readonly #data: Omit<ActionInstance, 'children'>

	#children = new Map<string, FragmentActionList>()

	/**
	 * Get the id of this action instance
	 */
	get id(): string {
		return this.#data.id
	}

	get disabled(): boolean {
		return !!this.#data.disabled
	}

	/**
	 * Get the id of the connection this action belongs to
	 */
	get connectionId(): string {
		return this.#data.instance
	}

	/**
	 * Get a reference to the options for this action
	 * Note: This must not be a copy, but the raw object
	 */
	get rawOptions() {
		return this.#data.options
	}

	/**
	 * @param instanceDefinitions
	 * @param internalModule
	 * @param moduleHost
	 * @param controlId - id of the control
	 * @param data
	 * @param isCloned Whether this is a cloned instance and should generate new ids
	 */
	constructor(
		instanceDefinitions: InstanceDefinitions,
		internalModule: InternalController,
		moduleHost: ModuleHost,
		controlId: string,
		data: ActionInstance,
		isCloned: boolean
	) {
		this.#logger = LogController.createLogger(`Controls/Fragments/Actions/${controlId}`)

		this.#instanceDefinitions = instanceDefinitions
		this.#internalModule = internalModule
		this.#moduleHost = moduleHost
		this.#controlId = controlId

		this.#data = cloneDeep(data) // TODO - cleanup unwanted properties
		if (!this.#data.options) this.#data.options = {}

		if (isCloned) {
			this.#data.id = nanoid()
		}

		if (data.instance === 'internal' && data.children) {
			for (const [groupId, actions] of Object.entries(data.children)) {
				if (!actions) continue

				try {
					const childGroup = this.#getOrCreateActionGroup(groupId)
					childGroup.loadStorage(actions, true, isCloned)
				} catch (e: any) {
					this.#logger.error(`Error loading child action group: ${e.message}`)
				}
			}
		}
	}

	#getOrCreateActionGroup(groupId: string): FragmentActionList {
		const existing = this.#children.get(groupId)
		if (existing) return existing

		// Check what names are allowed
		const definition = this.connectionId === 'internal' && this.getDefinition()
		if (!definition) throw new Error('Action cannot accept children.')

		if (!definition.supportsChildActionGroups.includes(groupId)) {
			throw new Error('Action cannot accept children in this group.')
		}

		const childGroup = new FragmentActionList(
			this.#instanceDefinitions,
			this.#internalModule,
			this.#moduleHost,
			this.#controlId,
			{ parentActionId: this.id, childGroup: groupId }
		)
		this.#children.set(groupId, childGroup)

		return childGroup
	}

	/**
	 * Get this action as a `ActionInstance`
	 */
	asActionInstance(): ActionInstance {
		const actionInstance: ActionInstance = { ...this.#data }

		if (this.connectionId === 'internal') {
			actionInstance.children = {}

			for (const [groupId, actionGroup] of this.#children) {
				actionInstance.children[groupId] = actionGroup.asActionInstances()
			}
		}

		return actionInstance
	}

	/**
	 * Get the definition for this action
	 */
	getDefinition(): ActionDefinition | undefined {
		return this.#instanceDefinitions.getActionDefinition(this.#data.instance, this.#data.action)
	}

	/**
	 * Inform the instance of a removed/disabled action
	 */
	cleanup() {
		// Inform relevant module
		const connection = this.#moduleHost.getChild(this.#data.instance, true)
		if (connection) {
			connection.actionDelete(this.asActionInstance()).catch((e) => {
				this.#logger.silly(`action_delete to connection failed: ${e.message}`)
			})
		}

		for (const actionGroup of this.#children.values()) {
			actionGroup.cleanup()
		}
	}

	/**
	 * Inform the instance of an updated action
	 * @param recursive whether to call recursively
	 * @param onlyConnectionId If set, only subscribe actions for this connection
	 */
	subscribe(recursive: boolean, onlyConnectionId?: string): void {
		if (this.#data.disabled) return

		if (!onlyConnectionId || this.#data.instance === onlyConnectionId) {
			if (this.#data.instance === 'internal') {
				// this.#internalModule.actionUpdate(this.asActionInstance(), this.#controlId)
			} else {
				const connection = this.#moduleHost.getChild(this.#data.instance, true)
				if (connection) {
					connection.actionUpdate(this.asActionInstance(), this.#controlId).catch((e) => {
						this.#logger.silly(`action_update to connection failed: ${e.message} ${e.stack}`)
					})
				}
			}
		}

		if (recursive) {
			for (const actionGroup of this.#children.values()) {
				actionGroup.subscribe(recursive, onlyConnectionId)
			}
		}
	}

	/**
	 * Set whether this action is enabled
	 */
	setEnabled(enabled: boolean): void {
		this.#data.disabled = !enabled

		// Inform relevant module
		if (!this.#data.disabled) {
			this.subscribe(true)
		} else {
			this.cleanup()
		}
	}

	/**
	 * Set the headline for this action
	 */
	setHeadline(headline: string): void {
		this.#data.headline = headline

		// Don't need to resubscribe
	}

	/**
	 * Set the connection instance of this action
	 */
	setInstance(instanceId: string | number): void {
		const instance = `${instanceId}`

		// first unsubscribe action from old instance
		this.cleanup()
		// next change instance
		this.#data.instance = instance
		// last subscribe to new instance
		this.subscribe(true, instance)
	}

	/**
	 * Set the options for this action
	 */
	setOptions(options: Record<string, any>): void {
		this.#data.options = options

		// Inform relevant module
		this.subscribe(false)
	}

	/**
	 * Learn the options for a action, by asking the instance for the current values
	 */
	async learnOptions(): Promise<boolean> {
		const instance = this.#moduleHost.getChild(this.connectionId)
		if (!instance) return false

		const newOptions = await instance.actionLearnValues(this.asActionInstance(), this.#controlId)
		if (newOptions) {
			this.setOptions(newOptions)

			return true
		}

		return false
	}

	/**
	 * Set an option for this action
	 */
	setOption(key: string, value: any): void {
		this.#data.options[key] = value

		// Inform relevant module
		this.subscribe(false)
	}

	/**
	 * Find a child action by id
	 */
	findChildById(id: string): FragmentActionInstance | undefined {
		for (const actionGroup of this.#children.values()) {
			const result = actionGroup.findById(id)
			if (result) return result
		}
		return undefined
	}

	/**
	 * Find the index of a child action, and the parent list
	 */
	findParentAndIndex(
		id: string
	): { parent: FragmentActionList; index: number; item: FragmentActionInstance } | undefined {
		for (const actionGroup of this.#children.values()) {
			const result = actionGroup.findParentAndIndex(id)
			if (result) return result
		}
		return undefined
	}

	/**
	 * Add a child action to this action
	 */
	addChild(groupId: string, action: ActionInstance): FragmentActionInstance {
		if (this.connectionId !== 'internal') {
			throw new Error('Only internal actions can have children')
		}

		const actionGroup = this.#getOrCreateActionGroup(groupId)
		return actionGroup.addAction(action)
	}

	/**
	 * Remove a child action
	 */
	removeChild(id: string): boolean {
		for (const actionGroup of this.#children.values()) {
			if (actionGroup.removeAction(id)) return true
		}
		return false
	}

	/**
	 * Duplicate a child action
	 */
	duplicateChild(id: string): FragmentActionInstance | undefined {
		for (const actionGroup of this.#children.values()) {
			const newAction = actionGroup.duplicateAction(id)
			if (newAction) return newAction
		}
		return undefined
	}

	// /**
	//  * Reorder a action in the list
	//  */
	// moveChild(groupId: string, oldIndex: number, newIndex: number): void {
	// 	const actionGroup = this.#children.get(groupId)
	// 	if (!actionGroup) return

	// 	return actionGroup.moveAction(oldIndex, newIndex)
	// }

	// /**
	//  * Pop a child action from the list
	//  * Note: this is used when moving a action to a different parent. Lifecycle is not managed
	//  */
	// popChild(index: number): FragmentActionInstance | undefined {
	// 	return this.#children.popAction(index)
	// }

	/**
	 * Push a child action to the list
	 * Note: this is used when moving a action from a different parent. Lifecycle is not managed
	 */
	pushChild(action: FragmentActionInstance, groupId: string, index: number): void {
		const actionGroup = this.#getOrCreateActionGroup(groupId)
		return actionGroup.pushAction(action, index)
	}

	/**
	 * Check if this list can accept a specified child
	 */
	canAcceptChild(groupId: string, action: FragmentActionInstance): boolean {
		const actionGroup = this.#getOrCreateActionGroup(groupId)
		return actionGroup.canAcceptAction(action)
	}

	/**
	 * Recursively get all the actions
	 */
	getAllChildren(): FragmentActionInstance[] {
		const actions: FragmentActionInstance[] = []

		for (const actionGroup of this.#children.values()) {
			actions.push(...actionGroup.getAllActions())
		}

		return actions
	}

	/**
	 * Cleanup and forget any children belonging to the given connection
	 */
	forgetChildrenForConnection(connectionId: string): boolean {
		let changed = false
		for (const actionGroup of this.#children.values()) {
			if (actionGroup.forgetForConnection(connectionId)) {
				changed = true
			}
		}
		return changed
	}

	/**
	 * Prune all actions/feedbacks referencing unknown conncetions
	 * Doesn't do any cleanup, as it is assumed that the connection has not been running
	 */
	verifyChildConnectionIds(knownConnectionIds: Set<string>): boolean {
		let changed = false
		for (const actionGroup of this.#children.values()) {
			if (actionGroup.verifyConnectionIds(knownConnectionIds)) {
				changed = true
			}
		}
		return changed
	}

	/**
	 * If this control was imported to a running system, do some data cleanup/validation
	 */
	postProcessImport(): Promise<void>[] {
		const ps: Promise<void>[] = []

		if (this.#data.instance === 'internal') {
			const newProps = this.#internalModule.actionUpgrade(this.asActionInstance(), this.#controlId)
			if (newProps) {
				this.replaceProps(newProps, false)
			}

			// setImmediate(() => {
			// 	this.#internalModule.actionUpdate(this.asActionInstance(), this.#controlId)
			// })
		} else {
			const instance = this.#moduleHost.getChild(this.connectionId, true)
			if (instance) {
				ps.push(instance.actionUpdate(this.asActionInstance(), this.#controlId))
			}
		}

		for (const childGroup of this.#children.values()) {
			ps.push(...childGroup.postProcessImport())
		}

		return ps
	}

	/**
	 * Replace portions of the action with an updated version
	 */
	replaceProps(newProps: Pick<ActionInstance, 'action' | 'options'>, skipNotifyModule = false): void {
		this.#data.action = newProps.action // || newProps.actionId
		this.#data.options = newProps.options

		delete this.#data.upgradeIndex

		if (!skipNotifyModule) {
			this.subscribe(false)
		}
	}

	/**
	 * Visit any references in the current action
	 */
	visitReferences(visitor: InternalVisitor): void {
		visitActionInstance(visitor, this.#data)
	}
}
