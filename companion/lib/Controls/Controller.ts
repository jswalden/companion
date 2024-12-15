import { CoreBase } from '../Core/Base.js'
import { ControlButtonNormal } from './ControlTypes/Button/Normal.js'
import { ControlButtonPageDown } from './ControlTypes/PageDown.js'
import { ControlButtonPageNumber } from './ControlTypes/PageNumber.js'
import { ControlButtonPageUp } from './ControlTypes/PageUp.js'
import {
	CreateBankControlId,
	CreateTriggerControlId,
	ParseControlId,
	formatLocation,
} from '@companion-app/shared/ControlId.js'
import { ControlConfigRoom } from './ControlBase.js'
import { ActionRunner } from './ActionRunner.js'
import { ActionRecorder } from './ActionRecorder.js'
import { ControlTrigger } from './ControlTypes/Triggers/Trigger.js'
import { nanoid } from 'nanoid'
import { TriggerEvents } from './TriggerEvents.js'
import debounceFn from 'debounce-fn'
import type { SomeButtonModel } from '@companion-app/shared/Model/ButtonModel.js'
import type { ClientTriggerData, TriggerModel } from '@companion-app/shared/Model/TriggerModel.js'
import type { SomeControl } from './IControlFragments.js'
import type { Registry } from '../Registry.js'
import type { ClientSocket } from '../UI/Handler.js'
import type { ControlLocation } from '@companion-app/shared/Model/Common.js'
import { EventEmitter } from 'events'
import type { ControlCommonEvents, ControlDependencies } from './ControlDependencies.js'

export const TriggersListRoom = 'triggers:list'
const ActiveLearnRoom = 'learn:active'

type SomeControlModel = SomeButtonModel | TriggerModel

/**
 * The class that manages the controls
 *
 * @author Håkon Nessjøen <haakon@bitfocus.io>
 * @author Keith Rocheck <keith.rocheck@gmail.com>
 * @author William Viker <william@bitfocus.io>
 * @author Julian Waller <me@julusian.co.uk>
 * @since 1.0.4
 * @copyright 2022 Bitfocus AS
 * @license
 * This program is free software.
 * You should have received a copy of the MIT licence as well as the Bitfocus
 * Individual Contributor License Agreement for Companion along with
 * this program.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the Companion software without
 * disclosing the source code of your own applications.
 */
export class ControlsController extends CoreBase {
	readonly #registry: Registry
	readonly #controlEvents: EventEmitter<ControlCommonEvents>

	/**
	 * Actions runner
	 */
	readonly actionRunner: ActionRunner

	/**
	 * Actions recorder
	 */
	readonly actionRecorder: ActionRecorder

	/**
	 * The currently configured controls
	 */
	#controls = new Map<string, SomeControl<any>>()

	/**
	 * Triggers events
	 */
	readonly triggers: TriggerEvents

	/**
	 * Active learn requests. Ids of actions & feedbacks
	 */
	readonly #activeLearnRequests = new Set<string>()

	constructor(registry: Registry, controlEvents: EventEmitter<ControlCommonEvents>) {
		super(registry, 'Controls/Controller')

		this.#registry = registry
		this.#controlEvents = controlEvents

		this.actionRunner = new ActionRunner(registry)
		this.actionRecorder = new ActionRecorder(registry)
		this.triggers = new TriggerEvents()
	}

	/**
	 * Abort all delayed actions across all controls
	 */
	abortAllDelayedActions(): void {
		for (const control of this.#controls.values()) {
			if (control.supportsActions) {
				control.abortDelayedActions(false)
			}
		}
	}

	#createControlDependencies(): ControlDependencies {
		// This has to be done lazily for now, as the registry is not fully populated at the time of construction
		return {
			db: this.#registry.db,
			io: this.#registry.ui.io,
			graphics: this.#registry.graphics,
			surfaces: this.#registry.surfaces,
			page: this.#registry.page,
			internalModule: this.#registry.internalModule,
			instance: this.#registry.instance,
			variables: this.#registry.variables,
			userconfig: this.#registry.userconfig,
			actionRunner: this.actionRunner,
			events: this.#controlEvents,
		}
	}

	/**
	 * Check the connection-status of every control
	 */
	checkAllStatus = debounceFn(
		(): void => {
			for (const control of this.#controls.values()) {
				if (typeof control.checkButtonStatus === 'function') {
					control.checkButtonStatus()
				}
			}
		},
		{
			before: false,
			after: true,
			wait: 100,
			maxWait: 500,
		}
	)

	/**
	 * Remove any tracked state for a connection
	 */
	clearConnectionState(connectionId: string): void {
		for (const control of this.#controls.values()) {
			if (control.supportsActions || control.supportsFeedbacks) {
				control.clearConnectionState(connectionId)
			}
		}
	}

	/**
	 * Setup a new socket client's events
	 */
	clientConnect(client: ClientSocket): void {
		this.actionRecorder.clientConnect(client)

		this.triggers.emit('client_connect')

		client.onPromise('controls:subscribe', (controlId) => {
			client.join(ControlConfigRoom(controlId))

			setImmediate(() => {
				// Send the preview image shortly after
				const location = this.page.getLocationOfControlId(controlId)
				if (location) {
					const img = this.graphics.getCachedRenderOrGeneratePlaceholder(location)
					// TODO - rework this to use the shared render cache concept
					client.emit(`controls:preview-${controlId}`, img?.asDataUrl)
				}
			})

			const control = this.getControl(controlId)
			return {
				config: control?.toJSON(false),
				runtime: control?.toRuntimeJSON(),
			}
		})

		client.onPromise('controls:unsubscribe', (controlId) => {
			client.leave(ControlConfigRoom(controlId))
		})

		client.onPromise('controls:reset', (location, type) => {
			const controlId = this.page.getControlIdAt(location)

			if (controlId) {
				this.deleteControl(controlId)
			}

			if (type) {
				this.createButtonControl(location, type)
			}
		})
		client.onPromise('controls:copy', (fromLocation, toLocation) => {
			// Don't try copying over itself
			if (
				fromLocation.pageNumber === toLocation.pageNumber &&
				fromLocation.column === toLocation.column &&
				fromLocation.row === toLocation.row
			)
				return false

			// Make sure target page number is valid
			if (!this.page.isPageValid(toLocation.pageNumber)) return false

			// Make sure there is something to copy
			const fromControlId = this.page.getControlIdAt(fromLocation)
			if (!fromControlId) return false

			const fromControl = this.getControl(fromControlId)
			if (!fromControl) return false
			const controlJson = fromControl.toJSON(true)

			// Delete the control at the destination
			const toControlId = this.page.getControlIdAt(toLocation)
			if (toControlId) {
				this.deleteControl(toControlId)
			}

			const newControlId = CreateBankControlId(nanoid())
			const newControl = this.#createClassForControl(newControlId, 'button', controlJson, true)
			if (newControl) {
				this.#controls.set(newControlId, newControl)

				this.page.setControlIdAt(toLocation, newControlId)

				newControl.triggerRedraw()

				return true
			}

			return false
		})
		client.onPromise('controls:move', (fromLocation, toLocation) => {
			// Don't try moving over itself
			if (
				fromLocation.pageNumber === toLocation.pageNumber &&
				fromLocation.column === toLocation.column &&
				fromLocation.row === toLocation.row
			)
				return false

			// Make sure target page number is valid
			if (!this.page.isPageValid(toLocation.pageNumber)) return false

			// Make sure there is something to move
			const fromControlId = this.page.getControlIdAt(fromLocation)
			if (!fromControlId) return false

			// Delete the control at the destination
			const toControlId = this.page.getControlIdAt(toLocation)
			if (toControlId) {
				this.deleteControl(toControlId)
			}

			// Perform the move
			this.page.setControlIdAt(fromLocation, null)
			this.page.setControlIdAt(toLocation, fromControlId)

			// Inform the control it was moved
			const control = this.getControl(fromControlId)
			if (control) control.triggerLocationHasChanged()

			// Force a redraw
			this.graphics.invalidateButton(fromLocation)
			this.graphics.invalidateButton(toLocation)

			return false
		})
		client.onPromise('controls:swap', (fromLocation, toLocation) => {
			// Don't try moving over itself
			if (
				fromLocation.pageNumber === toLocation.pageNumber &&
				fromLocation.column === toLocation.column &&
				fromLocation.row === toLocation.row
			)
				return false

			// Make sure both page numbers are valid
			if (!this.page.isPageValid(toLocation.pageNumber) || !this.page.isPageValid(fromLocation.pageNumber)) return false

			// Find the ids to move
			const fromControlId = this.page.getControlIdAt(fromLocation)
			const toControlId = this.page.getControlIdAt(toLocation)

			// Perform the swap
			this.page.setControlIdAt(toLocation, null)
			this.page.setControlIdAt(fromLocation, toControlId)
			this.page.setControlIdAt(toLocation, fromControlId)

			// Inform the controls they were moved
			const controlA = fromControlId && this.getControl(fromControlId)
			if (controlA) controlA.triggerLocationHasChanged()
			const controlB = toControlId && this.getControl(toControlId)
			if (controlB) controlB.triggerLocationHasChanged()

			// Force a redraw
			this.graphics.invalidateButton(fromLocation)
			this.graphics.invalidateButton(toLocation)

			return true
		})

		client.onPromise('controls:set-style-fields', (controlId, diff) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsStyle) {
				return control.styleSetFields(diff)
			} else {
				throw new Error(`Control "${controlId}" does not support config`)
			}
		})

		client.onPromise('controls:set-options-field', (controlId, key, value) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsOptions) {
				return control.optionsSetField(key, value)
			} else {
				throw new Error(`Control "${controlId}" does not support options`)
			}
		})

		client.onPromise('controls:feedback:add', (controlId, parentId, connectionId, feedbackId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				const feedbackItem = this.instance.definitions.createFeedbackItem(
					connectionId,
					feedbackId,
					control.feedbacks.isBooleanOnly
				)
				if (feedbackItem) {
					return control.feedbacks.feedbackAdd(feedbackItem, parentId)
				} else {
					return false
				}
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:learn', async (controlId, id) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				if (this.#activeLearnRequests.has(id)) throw new Error('Learn is already running')
				try {
					this.#setIsLearning(id, true)

					control.feedbacks
						.feedbackLearn(id)
						.catch((e) => {
							this.logger.error(`Learn failed: ${e}`)
						})
						.then(() => {
							this.#setIsLearning(id, false)
						})

					return true
				} catch (e) {
					this.#setIsLearning(id, false)
					throw e
				}
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:enabled', (controlId, id, enabled) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackEnabled(id, enabled)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:set-headline', (controlId, id, headline) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackHeadline(id, headline)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:remove', (controlId, id) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackRemove(id)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:duplicate', (controlId, id) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackDuplicate(id)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:set-option', (controlId, id, key, value) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackSetOptions(id, key, value)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:set-connection', (controlId, feedbackId, connectionId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackSetConnection(feedbackId, connectionId)
			} else {
				throw new Error(
					`Trying to set connection of feedback ${feedbackId} to ${connectionId} but control ${controlId} does not support feedbacks`
				)
			}
		})

		client.onPromise('controls:feedback:set-inverted', (controlId, id, isInverted) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackSetInverted(id, isInverted)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:feedback:move', (controlId, moveFeedbackId, newParentId, newIndex) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (moveFeedbackId === newParentId) throw new Error('Cannot move feedback to itself')

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackMoveTo(moveFeedbackId, newParentId, newIndex)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})
		client.onPromise('controls:feedback:set-style-selection', (controlId, id, selected) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackSetStyleSelection(id, selected)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})
		client.onPromise('controls:feedback:set-style-value', (controlId, id, key, value) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsFeedbacks) {
				return control.feedbacks.feedbackSetStyleValue(id, key, value)
			} else {
				throw new Error(`Control "${controlId}" does not support feedbacks`)
			}
		})

		client.onPromise('controls:hot-press', (location, direction, surfaceId) => {
			this.logger.silly(`being told from gui to hot press ${formatLocation(location)} ${direction} ${surfaceId}`)
			if (!surfaceId) throw new Error('Missing surfaceId')

			const controlId = this.page.getControlIdAt(location)
			if (!controlId) return

			this.pressControl(controlId, direction, `hot:${surfaceId}`)
		})

		client.onPromise('controls:hot-rotate', (location, direction, surfaceId) => {
			this.logger.silly(`being told from gui to hot rotate ${formatLocation(location)} ${direction} ${surfaceId}`)

			const controlId = this.page.getControlIdAt(location)
			if (!controlId) return

			this.rotateControl(controlId, direction, surfaceId ? `hot:${surfaceId}` : undefined)
		})

		client.onPromise('controls:action:add', (controlId, stepId, setId, parentId, connectionId, actionId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActions) {
				const actionItem = this.instance.definitions.createActionItem(connectionId, actionId)
				if (actionItem) {
					return control.actionAdd(stepId, setId, actionItem, parentId)
				} else {
					return false
				}
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})

		client.onPromise('controls:action:learn', async (controlId, stepId, setId, id) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActions) {
				if (this.#activeLearnRequests.has(id)) throw new Error('Learn is already running')
				try {
					this.#setIsLearning(id, true)

					control
						.actionLearn(stepId, setId, id)
						.catch((e) => {
							this.logger.error(`Learn failed: ${e}`)
						})
						.then(() => {
							this.#setIsLearning(id, false)
						})

					return true
				} catch (e) {
					this.#setIsLearning(id, false)
					throw e
				}
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})

		client.onPromise('controls:action:enabled', (controlId, stepId, setId, id, enabled) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActions) {
				return control.actionEnabled(stepId, setId, id, enabled)
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})

		client.onPromise('controls:action:set-headline', (controlId, stepId, setId, id, headline) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActions) {
				return control.actionHeadline(stepId, setId, id, headline)
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})

		client.onPromise('controls:action:remove', (controlId, stepId, setId, id) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActions) {
				return control.actionRemove(stepId, setId, id)
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})

		client.onPromise('controls:action:duplicate', (controlId, stepId, setId, id) => {
			const control = this.getControl(controlId)
			if (!control) return null

			if (control.supportsActions) {
				return control.actionDuplicate(stepId, setId, id)
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})

		client.onPromise('controls:action:set-connection', (controlId, stepId, setId, id, connectionId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActions) {
				return control.actionSetConnection(stepId, setId, id, connectionId)
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})

		client.onPromise('controls:action:set-option', (controlId, stepId, setId, id, key, value) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActions) {
				return control.actionSetOption(stepId, setId, id, key, value)
			} else {
				throw new Error(`Control "${controlId}" does not support actions`)
			}
		})
		client.onPromise(
			'controls:action:move',
			(controlId, dragStepId, dragSetId, dragActionId, hoverStepId, hoverSetId, hoverParentId, hoverIndex) => {
				const control = this.getControl(controlId)
				if (!control) return false

				if (control.supportsActions) {
					return control.actionMoveTo(
						dragStepId,
						dragSetId,
						dragActionId,
						hoverStepId,
						hoverSetId,
						hoverParentId,
						hoverIndex
					)
				} else {
					throw new Error(`Control "${controlId}" does not support actions`)
				}
			}
		)
		client.onPromise('controls:action-set:add', (controlId, stepId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActionSets) {
				return control.actionSetAdd(stepId)
			} else {
				throw new Error(`Control "${controlId}" does not support this operation`)
			}
		})
		client.onPromise('controls:action-set:remove', (controlId, stepId, setId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActionSets) {
				return control.actionSetRemove(stepId, setId)
			} else {
				throw new Error(`Control "${controlId}" does not support this operation`)
			}
		})

		client.onPromise('controls:action-set:rename', (controlId, stepId, oldSetId, newSetId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActionSets) {
				return control.actionSetRename(stepId, oldSetId, newSetId)
			} else {
				throw new Error(`Control "${controlId}" does not support this operation`)
			}
		})

		client.onPromise('controls:action-set:set-run-while-held', (controlId, stepId, setId, runWhileHeld) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsActionSets) {
				return control.actionSetRunWhileHeld(stepId, setId, runWhileHeld)
			} else {
				throw new Error(`Control "${controlId}" does not support this operation`)
			}
		})

		client.onPromise('controls:step:add', (controlId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsSteps) {
				return control.stepAdd()
			} else {
				throw new Error(`Control "${controlId}" does not support steps`)
			}
		})
		client.onPromise('controls:step:duplicate', (controlId, stepId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsSteps) {
				return control.stepDuplicate(stepId)
			} else {
				throw new Error(`Control "${controlId}" does not support steps`)
			}
		})
		client.onPromise('controls:step:remove', (controlId, stepId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsSteps) {
				return control.stepRemove(stepId)
			} else {
				throw new Error(`Control "${controlId}" does not support steps`)
			}
		})

		client.onPromise('controls:step:swap', (controlId, stepId1, stepId2) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsSteps) {
				return control.stepSwap(stepId1, stepId2)
			} else {
				throw new Error(`Control "${controlId}" does not support steps`)
			}
		})

		client.onPromise('controls:step:set-current', (controlId, stepId) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsSteps) {
				return control.stepSelectCurrent(stepId)
			} else {
				throw new Error(`Control "${controlId}" does not support steps`)
			}
		})

		client.onPromise('controls:step:rename', (controlId, stepId, newName) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsSteps) {
				return control.stepRename(stepId, newName)
			} else {
				throw new Error(`Control "${controlId}" does not support steps`)
			}
		})

		client.onPromise('triggers:subscribe', () => {
			client.join(TriggersListRoom)

			const triggers: Record<string, ClientTriggerData> = {}

			for (const [controlId, control] of this.#controls.entries()) {
				if (control instanceof ControlTrigger) {
					triggers[controlId] = control.toTriggerJSON()
				}
			}

			return triggers
		})
		client.onPromise('triggers:unsubscribe', () => {
			client.leave(TriggersListRoom)
		})
		client.onPromise('triggers:create', () => {
			const controlId = CreateTriggerControlId(nanoid())

			const newControl = new ControlTrigger(this.#createControlDependencies(), this.triggers, controlId, null, false)
			this.#controls.set(controlId, newControl)

			// Add trigger to the end of the list
			const allTriggers: ControlTrigger[] = []
			for (const control of this.#controls.values()) {
				if (control instanceof ControlTrigger) {
					allTriggers.push(control)
				}
			}
			const maxRank = Math.max(0, ...allTriggers.map((control) => control.options.sortOrder))
			newControl.optionsSetField('sortOrder', maxRank, true)

			// Ensure it is stored to the db
			newControl.commitChange()

			return controlId
		})
		client.onPromise('triggers:delete', (controlId) => {
			if (!this.#validateTriggerControlId(controlId)) {
				// Control id is not valid!
				return false
			}

			const control = this.getControl(controlId)
			if (control) {
				control.destroy()

				this.#controls.delete(controlId)

				this.db.deleteTableKey('controls', controlId)

				return true
			}

			return false
		})
		client.onPromise('triggers:clone', (controlId) => {
			if (!this.#validateTriggerControlId(controlId)) {
				// Control id is not valid!
				return false
			}

			const newControlId = CreateTriggerControlId(nanoid())

			const fromControl = this.getControl(controlId)
			if (fromControl) {
				const controlJson = fromControl.toJSON(true)

				const newControl = this.#createClassForControl(newControlId, 'trigger', controlJson, true)
				if (newControl) {
					this.#controls.set(newControlId, newControl)

					return newControlId
				}
			}

			return false
		})
		client.onPromise('triggers:test', (controlId) => {
			if (!this.#validateTriggerControlId(controlId)) {
				// Control id is not valid!
				return false
			}

			const control = this.getControl(controlId)
			if (control && control instanceof ControlTrigger) {
				control.executeActions(Date.now(), true)
			}

			return false
		})
		client.onPromise('triggers:set-order', (triggerIds) => {
			if (!Array.isArray(triggerIds)) throw new Error('Expected array of ids')

			triggerIds = triggerIds.filter((id) => this.#validateTriggerControlId(id))

			// This is a bit naive, but should be sufficient if the client behaves

			// Update the order based on the ids provided
			triggerIds.forEach((id, index) => {
				const control = this.getControl(id)
				if (control && control.supportsOptions) control.optionsSetField('sortOrder', index, true)
			})

			// Fill in for any which weren't specified
			const updatedTriggerIds = new Set(triggerIds)
			const triggerControls = this.getAllTriggers()
			triggerControls.sort((a, b) => a.options.sortOrder - b.options.sortOrder)

			let nextIndex = triggerIds.length
			for (const control of triggerControls) {
				if (!updatedTriggerIds.has(control.controlId) && control.supportsOptions) {
					control.optionsSetField('sortOrder', nextIndex++, true)
				}
			}

			return true
		})

		client.onPromise('controls:event:add', (controlId, eventType) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsEvents) {
				const eventItem = this.instance.definitions.createEventItem(eventType)
				if (eventItem) {
					return control.eventAdd(eventItem)
				} else {
					return false
				}
			} else {
				throw new Error(`Control "${controlId}" does not support events`)
			}
		})

		client.onPromise('controls:event:enabled', (controlId, id, enabled) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsEvents) {
				return control.eventEnabled(id, enabled)
			} else {
				throw new Error(`Control "${controlId}" does not support events`)
			}
		})

		client.onPromise('controls:event:set-headline', (controlId, id, headline) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsEvents) {
				return control.eventHeadline(id, headline)
			} else {
				throw new Error(`Control "${controlId}" does not support events`)
			}
		})

		client.onPromise('controls:event:remove', (controlId, id) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsEvents) {
				return control.eventRemove(id)
			} else {
				throw new Error(`Control "${controlId}" does not support events`)
			}
		})

		client.onPromise('controls:event:duplicate', (controlId, id) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsEvents) {
				return control.eventDuplicate(id)
			} else {
				throw new Error(`Control "${controlId}" does not support events`)
			}
		})

		client.onPromise('controls:event:set-option', (controlId, id, key, value) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsEvents) {
				return control.eventSetOptions(id, key, value)
			} else {
				throw new Error(`Control "${controlId}" does not support events`)
			}
		})

		client.onPromise('controls:event:reorder', (controlId, oldIndex, newIndex) => {
			const control = this.getControl(controlId)
			if (!control) return false

			if (control.supportsEvents) {
				return control.eventReorder(oldIndex, newIndex)
			} else {
				throw new Error(`Control "${controlId}" does not support events`)
			}
		})

		client.onPromise('controls:subscribe:learn', async () => {
			client.join(ActiveLearnRoom)

			return Array.from(this.#activeLearnRequests)
		})
		client.onPromise('controls:unsubscribe:learn', async () => {
			client.leave(ActiveLearnRoom)
		})
	}

	/**
	 * Create a new control class instance
	 * @param controlId Id of the control
	 * @param category 'button' | 'trigger' | 'all'
	 * @param controlObj The existing configuration of the control, or string type if it is a new control. Note: the control must be given a clone of an object
	 * @param isImport Whether this is an import, and needs additional processing
	 */
	#createClassForControl(
		controlId: string,
		category: 'button' | 'trigger' | 'all',
		controlObj: SomeControlModel | string,
		isImport: boolean
	): SomeControl<any> | null {
		const controlType = typeof controlObj === 'object' ? controlObj.type : controlObj
		const controlObj2 = typeof controlObj === 'object' ? controlObj : null
		if (category === 'all' || category === 'button') {
			if (controlObj2?.type === 'button' || (controlType === 'button' && !controlObj2)) {
				return new ControlButtonNormal(this.#createControlDependencies(), controlId, controlObj2, isImport)
			} else if (controlObj2?.type === 'pagenum' || (controlType === 'pagenum' && !controlObj2)) {
				return new ControlButtonPageNumber(this.#createControlDependencies(), controlId, controlObj2, isImport)
			} else if (controlObj2?.type === 'pageup' || (controlType === 'pageup' && !controlObj2)) {
				return new ControlButtonPageUp(this.#createControlDependencies(), controlId, controlObj2, isImport)
			} else if (controlObj2?.type === 'pagedown' || (controlType === 'pagedown' && !controlObj2)) {
				return new ControlButtonPageDown(this.#createControlDependencies(), controlId, controlObj2, isImport)
			}
		}

		if (category === 'all' || category === 'trigger') {
			if (controlObj2?.type === 'trigger' || (controlType === 'trigger' && !controlObj2)) {
				return new ControlTrigger(this.#createControlDependencies(), this.triggers, controlId, controlObj2, isImport)
			}
		}

		// Unknown type
		this.logger.warn(`Cannot create control "${controlId}" of unknown type "${controlType}"`)
		return null
	}

	/**
	 * Update all controls to forget a connection
	 */
	forgetConnection(connectionId: string): void {
		for (const control of this.#controls.values()) {
			if (control.supportsActions || control.supportsFeedbacks) {
				control.forgetConnection(connectionId)
			}
		}
	}

	/**
	 * Get all of the populated controls
	 */
	getAllControls(): ReadonlyMap<string, SomeControl<any>> {
		return this.#controls // TODO - readonly?
	}

	/**
	 * Get all of the trigger controls
	 */
	getAllTriggers(): ControlTrigger[] {
		const triggers: ControlTrigger[] = []
		for (const control of this.#controls.values()) {
			if (control instanceof ControlTrigger) {
				triggers.push(control)
			}
		}
		return triggers
	}

	/**
	 * Get a control if it has been populated
	 */
	getControl(controlId: string): SomeControl<any> | undefined {
		if (!controlId) return undefined
		return this.#controls.get(controlId)
	}

	/**
	 * Get a Trigger control if it exists
	 */
	getTrigger(triggerId: string): ControlTrigger | undefined {
		const controlId = CreateTriggerControlId(triggerId)
		const control = this.#controls.get(controlId)
		if (!control || !(control instanceof ControlTrigger)) return undefined
		return control
	}

	/**
	 * Import a control
	 */
	importControl(location: ControlLocation, definition: SomeButtonModel, forceControlId?: string): boolean {
		if (forceControlId && !this.#validateBankControlId(forceControlId)) {
			// Control id is not valid!
			return false
		}

		// Delete old control at the coordinate
		const oldControlId = this.page.getControlIdAt(location)
		if (oldControlId) {
			this.deleteControl(oldControlId)
		}

		const newControlId = forceControlId || CreateBankControlId(nanoid())
		const newControl = this.#createClassForControl(newControlId, 'button', definition, true)
		if (newControl) {
			this.#controls.set(newControlId, newControl)

			this.page.setControlIdAt(location, newControlId)

			newControl.triggerRedraw()

			// Ensure it is stored to the db
			newControl.commitChange()

			return true
		}

		return false
	}

	/**
	 * Import a trigger
	 */
	importTrigger(controlId: string, definition: TriggerModel): boolean {
		if (!this.#validateTriggerControlId(controlId)) {
			// Control id is not valid!
			return false
		}

		if (this.#controls.has(controlId)) throw new Error(`Trigger ${controlId} already exists`)

		const newControl = this.#createClassForControl(controlId, 'trigger', definition, true)
		if (newControl) {
			this.#controls.set(controlId, newControl)

			// Ensure it is stored to the db
			newControl.commitChange()

			return true
		}

		return false
	}

	/**
	 * Initialise the controls
	 */
	init(): void {
		// Init all the control classes
		const config: Record<string, SomeControlModel> = this.db.getTable('controls')
		for (const [controlId, controlObj] of Object.entries(config)) {
			if (controlObj && controlObj.type) {
				const inst = this.#createClassForControl(controlId, 'all', controlObj, false)
				if (inst) this.#controls.set(controlId, inst)
			}
		}
	}

	/**
	 * Propagate variable changes to the controls
	 */
	onVariablesChanged(allChangedVariablesSet: Set<string>): void {
		// Inform triggers of the change
		this.triggers.emit('variables_changed', allChangedVariablesSet)

		if (allChangedVariablesSet.size > 0) {
			for (const control of this.#controls.values()) {
				if (control.supportsStyle) {
					control.onVariablesChanged(allChangedVariablesSet)
				}
			}
		}
	}

	/**
	 * Execute a press of a control
	 * @param controlId Id of the control
	 * @param pressed Whether the control is pressed
	 * @param surfaceId The surface that initiated this press
	 * @param force Trigger actions even if already in the state
	 */
	pressControl(controlId: string, pressed: boolean, surfaceId: string | undefined, force?: boolean): boolean {
		const control = this.getControl(controlId)
		if (control) {
			this.triggers.emit('control_press', controlId, pressed, surfaceId)

			control.pressControl(pressed, surfaceId, force)

			return true
		}

		return false
	}

	/**
	 * Execute rotation of a control
	 * @param controlId Id of the control
	 * @param direction Whether the control is rotated to the right
	 * @param surfaceId The surface that initiated this rotate
	 */
	rotateControl(controlId: string, direction: boolean, surfaceId: string | undefined): boolean {
		const control = this.getControl(controlId)
		if (control && control.supportsActionSets) {
			control.rotateControl(direction, surfaceId)
			return true
		}

		return false
	}

	/**
	 * Rename a connection for variables used in the controls
	 * @param labelFrom - the old connection short name
	 * @param labelTo - the new connection short name
	 */
	renameVariables(labelFrom: string, labelTo: string): void {
		for (const control of this.#controls.values()) {
			control.renameVariables(labelFrom, labelTo)
		}
	}

	/**
	 * Delete a control
	 */
	deleteControl(controlId: string): void {
		const control = this.getControl(controlId)
		if (control) {
			control.destroy()
			this.#controls.delete(controlId)

			this.db.deleteTableKey('controls', controlId)
		}

		const location = this.page.getLocationOfControlId(controlId)
		if (location) {
			this.page.setControlIdAt(location, null)

			// Notify interested parties
			this.services.emberplus.updateButtonState(location, false, undefined)

			// Force a redraw
			this.graphics.invalidateButton(location)
		}
	}

	/**
	 * Create a control
	 * Danger: This will not delete an existing control from the specified location
	 * @param location Location to place in the grid
	 * @param newType The type of the new control to create (if any)
	 * @returns controlId
	 * @access public
	 */
	createButtonControl(location: ControlLocation, newType: string): string | null {
		if (!this.page.isPageValid(location.pageNumber)) return null

		const controlId = CreateBankControlId(nanoid())
		const newControl = this.#createClassForControl(controlId, 'button', newType, false)
		if (!newControl) return null

		this.#controls.set(controlId, newControl)
		this.page.setControlIdAt(location, controlId)

		// Notify interested parties
		this.services.emberplus.updateButtonState(location, false, undefined)

		// Force a redraw
		this.graphics.invalidateButton(location)

		return controlId
	}

	/**
	 * Set an item as learning, or not
	 */
	#setIsLearning(id: string, isActive: boolean): void {
		if (isActive) {
			this.#activeLearnRequests.add(id)
			this.io.emitToRoom(ActiveLearnRoom, 'learn:add', id)
		} else {
			this.#activeLearnRequests.delete(id)
			this.io.emitToRoom(ActiveLearnRoom, 'learn:remove', id)
		}
	}

	/**
	 * Update values for some feedbacks
	 * @param connectionId
	 * @param result - object containing new values for the feedbacks that have changed
	 */
	updateFeedbackValues(connectionId: string, result: NewFeedbackValue[]): void {
		if (result.length === 0) return

		const values: Record<string, Record<string, any>> = {}

		for (const item of result) {
			if (!values[item.controlId]) values[item.controlId] = {}

			values[item.controlId][item.id] = item.value
		}

		// Pass values to controls
		for (const [controlId, newValues] of Object.entries(values)) {
			const control = this.getControl(controlId)
			if (control && control.supportsFeedbacks) {
				control.feedbacks.updateFeedbackValues(connectionId, newValues)
			}
		}
	}

	/**
	 * Verify a controlId is valid for the current id scheme and grid size
	 */
	#validateBankControlId(controlId: string): boolean {
		const parsed = ParseControlId(controlId)
		if (parsed?.type !== 'bank') return false

		return true
	}

	/**
	 * Verify a controlId is valid for the current id scheme and grid size
	 */
	#validateTriggerControlId(controlId: string): boolean {
		const parsed = ParseControlId(controlId)
		if (parsed?.type !== 'trigger') return false

		return true
	}

	/**
	 * Prune any items on controls which belong to an unknown connectionId
	 * @access public
	 */
	verifyConnectionIds(): void {
		const knownConnectionIds = new Set(this.instance.getAllInstanceIds())
		knownConnectionIds.add('internal')

		for (const control of this.#controls.values()) {
			control.verifyConnectionIds(knownConnectionIds)
		}
	}
}

export interface NewFeedbackValue {
	id: string
	controlId: string
	value: any
}
