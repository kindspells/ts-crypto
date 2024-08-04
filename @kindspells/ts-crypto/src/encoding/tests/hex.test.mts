import { describe, expect, it } from 'vitest'

import { fromHex, toHex } from '../hex.mts'

describe('fromHex', () => {
	it('returns a buffer of length 0 for an empty string', () => {
		const buffer = fromHex('')
		expect(buffer).toBeInstanceOf(Uint8Array)
		expect(buffer).toHaveLength(0)
	})

	it('returns a buffer of length 1 for a single byte hex string', () => {
		const buffer = fromHex('00')
		expect(buffer).toBeInstanceOf(Uint8Array)
		expect(buffer).toHaveLength(1)
		expect(buffer[0]).toBe(0)
	})

	it('returns a buffer of length 1 for a single byte hex string with lowercase letters', () => {
		const buffer = fromHex('ff')
		expect(buffer).toBeInstanceOf(Uint8Array)
		expect(buffer).toHaveLength(1)
		expect(buffer[0]).toBe(255)
	})

	it('returns a buffer of length 1 for a single byte hex string with uppercase letters', () => {
		const buffer = fromHex('FF')
		expect(buffer).toBeInstanceOf(Uint8Array)
		expect(buffer).toHaveLength(1)
		expect(buffer[0]).toBe(255)
	})

	it('returns a buffer of length 2 for a two byte hex string', () => {
		const buffer = fromHex('00ff')
		expect(buffer).toBeInstanceOf(Uint8Array)
		expect(buffer).toHaveLength(2)
		expect(buffer[0]).toBe(0)
		expect(buffer[1]).toBe(255)
	})

	it('works with mixed case hex strings', () => {
		const buffer = fromHex('fF')
		expect(buffer).toBeInstanceOf(Uint8Array)
		expect(buffer).toHaveLength(1)
		expect(buffer[0]).toBe(255)
	})

	it('works with long hex strings', () => {
		const buffer = fromHex('0123456789abcdef')
		expect(buffer).toBeInstanceOf(Uint8Array)
		expect(buffer).toHaveLength(8)
		expect(buffer).toEqual(new Uint8Array([1, 35, 69, 103, 137, 171, 205, 239]))
	})
})

describe('toHex', () => {
	it('returns an empty string for a buffer of length 0', () => {
		const hex = toHex(new Uint8Array([]))
		expect(hex).toBe('')
	})

	it('returns a single byte hex string for a buffer of length 1', () => {
		const hex = toHex(new Uint8Array([0]))
		expect(hex).toBe('00')
	})

	it('returns a single byte hex string with lowercase letters for a buffer of length 1', () => {
		const hex = toHex(new Uint8Array([255]))
		expect(hex).toBe('ff')
	})

	it('returns a single byte hex string with uppercase letters for a buffer of length 1', () => {
		const hex = toHex(new Uint8Array([255]), false)
		expect(hex).toBe('FF')
	})

	it('returns a two byte hex string for a buffer of length 2', () => {
		const hex = toHex(new Uint8Array([0, 255]))
		expect(hex).toBe('00ff')
	})

	it('works with long buffers', () => {
		const hex = toHex(new Uint8Array([1, 35, 69, 103, 137, 171, 205, 239]))
		expect(hex).toBe('0123456789abcdef')
	})
})
