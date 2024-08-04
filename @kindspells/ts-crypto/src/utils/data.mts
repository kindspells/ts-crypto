export function convertToBuffer(data: BufferSource): Uint8Array {
	return ArrayBuffer.isView(data)
		? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
		: new Uint8Array(data)
}
