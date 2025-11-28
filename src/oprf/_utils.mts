import { abytes, bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";

/**
 * Convert an unsigned bigint/number into a (big-endian) byte string of fixed length
 * @see https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 * @param value
 * @param size
 * @throws Error if encoded size exceeds expected value
 * @returns
 */
export function I2OSP(value: number, size: number): Uint8Array {
	if (value < 0 || value >= (1 << (size * 8))) throw new Error("Invalid I2OSP input value");
	return numberToBytesBE(value, size);
}

/**
 * Convert a (big-endian) byte string into a bigint
 * @see https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
 * @param value
 * @returns
 */
export function OS2IP(value: Uint8Array): bigint {
	return bytesToNumberBE(value);
}

/**
 *
 * @param arr
 * @param size
 */
export function splitBytesShared(input: Uint8Array, size: number): Uint8Array[] {
	abytes(input);
	if (size <= 0) throw new Error("Invalid size parameter");

	const res: Uint8Array[] = [];
	for (let offset = 0; offset < input.length; offset += size) {
		res.push(input.subarray(offset, offset + size));
	}
	return res;
}
