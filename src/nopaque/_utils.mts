import { abytes } from "@noble/curves/utils.js";

/**
 *
 * @param a
 * @param b
 * @returns
 */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
	abytes(a);
	abytes(b);

	if (a.length != b.length) throw new Error("Input arrays must be of equal length");

	const res = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) {
		res[i] = a[i] ^ b[i];
	}
	return res;
}

export function splitByteFields(input: Uint8Array, fieldSizes: number[]): Uint8Array[] {
	const result = [];
	let start = 0, end = 0;
	for (const size of fieldSizes) {
		if (start >= input.length) throw new Error("Input value too short");
		end += size;
		result.push(input.slice(start, end));
		start += size;
	}
	return result;
}
