export class TsCryptoHasherError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'TsCryptoHasherError'
	}
}

export class TsCryptoAlreadyFinishedError extends TsCryptoHasherError {
	constructor() {
		super('Attempted to update an already finished hash.')
		this.name = 'TsCryptoAlreadyFinishedError'
	}
}
