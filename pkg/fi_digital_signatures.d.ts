/* tslint:disable */
/* eslint-disable */
/**
* Algorithm family of [`Algorithm`]
*/
export enum AlgorithmFamily {
/**
* [`crate::algorithms::Algorithm::HS256`]
* [`crate::algorithms::Algorithm::HS384`]
* [`crate::algorithms::Algorithm::HS512`]
*/
  HMAC = 0,
/**
* [`crate::algorithms::Algorithm::ES256`]
* [`crate::algorithms::Algorithm::ES384`]
* [`crate::algorithms::Algorithm::ES512`]
* [`crate::algorithms::Algorithm::ES256K`]
*/
  EC = 1,
/**
* [`crate::algorithms::Algorithm::RS256`]
* [`crate::algorithms::Algorithm::RS384`]
* [`crate::algorithms::Algorithm::RS512`]
* [`crate::algorithms::Algorithm::PS256`]
* [`crate::algorithms::Algorithm::PS384`]
* [`crate::algorithms::Algorithm::PS512`]
*/
  RSA = 2,
/**
* [`crate::algorithms::Algorithm::EdDSA`]
*/
  OKP = 3,
  None = 4,
}
/**
* Algorithms that used to sign and verify content
*/
export enum Algorithm {
/**
* Sha-256 hash function based HMAC hash algotithm
*/
  HS256 = 0,
/**
* Sha-384 hash function based HMAC hash algotithm
*/
  HS384 = 1,
/**
* Sha-256 hash function based HMAC hash algotithm
*/
  HS512 = 2,
/**
* Sha-256 based RSA algorithm
*/
  RS256 = 3,
/**
* Sha-384 based RSA algorithm
*/
  RS384 = 4,
/**
* Sha-512 based RSA algorithm
*/
  RS512 = 5,
/**
* RSASSA-PSS using SHA-256
*/
  PS256 = 6,
/**
* RSASSA-PSS using SHA-384
*/
  PS384 = 7,
/**
* RSASSA-PSS using SHA-512
*/
  PS512 = 8,
/**
* Elliptic curve with NistP256
*/
  ES256 = 9,
/**
* Elliptic curve with NistP384
*/
  ES384 = 10,
/**
* Elliptic curve with NistP512
*/
  ES512 = 11,
/**
* Elliptic curve with Secp256k1
*/
  ES256K = 12,
/**
* Elliptic curve with Ed25519
*/
  EdDSA = 13,
}
/**
* Signing key for ED25519 algorithm [`crate::algorithms::Algorithm::EdDSA`]
*/
export class EDDSASigningKey {
  free(): void;
}
/**
* Verifying key for ED25519 algorithm
*/
export class EDDSAVerifyingKey {
  free(): void;
}
/**
* Object for error handling
*/
export class Error {
  free(): void;
/**
* @returns {string}
*/
  toString(): string;
}
/**
* Signing key for HMAC algorithm
*/
export class HMACKey {
  free(): void;
/**
* Create new <b>HMACKey</b> instance
* @param {string} pass
*/
  constructor(pass: string);
/**
* @param {object} value
* @returns {HMACKey}
*/
  static from_js_object(value: object): HMACKey;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES256`]
*/
export class P256SigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES256`]
*/
export class P256VerifyingKey {
  free(): void;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES256K`]
*/
export class P256kSigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES256K`]
*/
export class P256kVerifyingKey {
  free(): void;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES384`]
*/
export class P384SigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES384`]
*/
export class P384VerifyingKey {
  free(): void;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES512`]
*/
export class P512SigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES512`]
*/
export class P512VerifyingKey {
  free(): void;
}
/**
* Signing key for RSA based algorithms (RSA private key)
*/
export class RsaSigningKey {
  free(): void;
}
/**
* Verifying key for RSA based algorithms (RSA private key)
*/
export class RsaVerifyingKey {
  free(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_eddsasigningkey_free: (a: number) => void;
  readonly __wbg_eddsaverifyingkey_free: (a: number) => void;
  readonly __wbg_error_free: (a: number) => void;
  readonly error_toString: (a: number, b: number) => void;
  readonly __wbg_p512signingkey_free: (a: number) => void;
  readonly __wbg_p512verifyingkey_free: (a: number) => void;
  readonly __wbg_hmackey_free: (a: number) => void;
  readonly hmackey_new: (a: number, b: number) => number;
  readonly hmackey_from_js_object: (a: number, b: number) => void;
  readonly __wbg_p384signingkey_free: (a: number) => void;
  readonly __wbg_p384verifyingkey_free: (a: number) => void;
  readonly __wbg_rsasigningkey_free: (a: number) => void;
  readonly __wbg_rsaverifyingkey_free: (a: number) => void;
  readonly __wbg_p256ksigningkey_free: (a: number) => void;
  readonly __wbg_p256kverifyingkey_free: (a: number) => void;
  readonly __wbg_p256signingkey_free: (a: number) => void;
  readonly __wbg_p256verifyingkey_free: (a: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
