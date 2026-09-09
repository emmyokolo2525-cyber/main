import { nativeToScVal } from '@stellar/stellar-sdk'
import type { Hex32, HexBytes } from './stellarTypes'

export function asHex32(value: string, label = 'value'): Hex32 {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a 32-byte hex string.`)
  }
  return value.toLowerCase() as Hex32
}

export function asHexBytes(value: string, label = 'value'): HexBytes {
  if (!/^[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label} must be an even-length hex byte string.`)
  }
  return value.toLowerCase() as HexBytes
}

export function scBytes32(value: Hex32) {
  return nativeToScVal(hexToBytes(value))
}

export function scBytes(value: HexBytes) {
  return nativeToScVal(hexToBytes(value))
}

export function scU32(value: number) {
  return nativeToScVal(value)
}

export function bytesToHex(value: Uint8Array | ArrayLike<number>) {
  return Array.from(value, (byte) => Number(byte).toString(16).padStart(2, '0')).join('')
}

function hexToBytes(value: string) {
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}
