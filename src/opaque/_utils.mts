import { abytes } from "@noble/curves/abstract/utils";

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
