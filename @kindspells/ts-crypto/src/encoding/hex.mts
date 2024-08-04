const numToHexL: { [key: number]: string } = {}
const numToHexU: { [key: number]: string } = {}
const hexToNum: { [key: string]: number } = {}

for (let i = 0; i < 256; i++) {
	const hex = i.toString(16).padStart(2, '0')
	numToHexL[i] = hex // Number.toString returns lowercase
	numToHexU[i] = hex.toUpperCase()
	hexToNum[hex] = i
}

export function fromHex(hex: string): Uint8Array {
	const _hex = hex.toLowerCase()
	const buffer = new Uint8Array(_hex.length >> 1)

	for (let i = 0; i < _hex.length; i += 2) {
		// biome-ignore lint/style/noNonNullAssertion: it is up to the caller to ensure that `hex` is a valid input
		buffer[i >> 1] = hexToNum[_hex.slice(i, i + 2)]!
	}
	return buffer
}

export function toHex(buffer: Uint8Array, lowerCase = true): string {
	const table = lowerCase ? numToHexL : numToHexU

	let hex = ''
	for (const byte of buffer) {
		hex += table[byte]
	}

	return hex
}
