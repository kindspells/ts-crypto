export interface Hasher {
	reset(): this
	update(data: BufferSource): this
	digest(): Promise<ArrayBuffer> | ArrayBuffer
}

export type HashFunction = (
	data: BufferSource,
) => Promise<ArrayBuffer> | ArrayBuffer
