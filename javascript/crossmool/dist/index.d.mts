type KeyInput = string | Uint8Array;
declare function sm2PublicKeyToRawHex(publicKey: KeyInput): string;
declare function sm2PrivateKeyToRawHex(privateKey: KeyInput): string;

interface CiphertextSignaturePair {
    ciphertext: string;
    signature: string;
}
interface KeyPair {
    publicKey: string;
    privateKey: string;
}
declare class SM2Util {
    /**
     * Generate SM2 key pair (hex format).
     * @returns KeyPair with publicKey (130 chars: 04+X+Y) and privateKey (64 chars).
     */
    static generateKeyPairHex(): KeyPair;
    /**
     * Generate SM2 key pair (Base64 format).
     * @returns KeyPair with publicKey and privateKey encoded as Base64.
     */
    static generateKeyPairBase64(): KeyPair;
    /**
     * Generate SM2 key pair as DER-encoded Hex.
     * Public key: Hex of X.509 SubjectPublicKeyInfo DER.
     * Private key: Hex of PKCS#8 PrivateKeyInfo DER.
     */
    static generateKeyPairRaw(): KeyPair;
    static encryptToBytes(content: Uint8Array, publicKey: KeyInput): Uint8Array;
    static encryptToHex(content: string | Uint8Array, publicKey: KeyInput): string;
    static encryptToBase64(content: string | Uint8Array, publicKey: KeyInput): string;
    static encrypt(content: string, publicKey: KeyInput, toBase64?: boolean): string;
    static decryptToBytes(cipherBytes: Uint8Array, privateKey: KeyInput): Uint8Array;
    static decryptToUtf8(cipherHexOrBase64: string, privateKey: KeyInput): string;
    static decryptToBytesFromString(cipherHexOrBase64: string, privateKey: KeyInput): Uint8Array;
    static decrypt(cipherHexOrBase64: string, privateKey: KeyInput): string;
    static signToBytes(content: Uint8Array, privateKey: KeyInput): Uint8Array;
    static signToHex(content: string | Uint8Array, privateKey: KeyInput): string;
    static signToBase64(content: string | Uint8Array, privateKey: KeyInput): string;
    static sign(content: string, privateKey: KeyInput, toBase64?: boolean): string;
    static verify(content: string | Uint8Array, publicKey: KeyInput, signatureHexOrBase64: string): boolean;
    static encryptSign(content: string, encPublicKey: KeyInput, signPrivateKey: KeyInput, toBase64?: boolean): CiphertextSignaturePair;
    static encryptSignWithSameFormatKeys(content: string, encPublicKey: string, signPrivateKey: string): CiphertextSignaturePair;
    static verifyDecrypt(ciphertext: string, signature: string, signPublicKey: KeyInput, decPrivateKey: KeyInput): string;
    static verifyDecryptPair(pair: CiphertextSignaturePair, signPublicKey: KeyInput, decPrivateKey: KeyInput): string;
    /**
     * Encode DER public key bytes to PEM format.
     * @param pubDerHex hex string of X.509 SubjectPublicKeyInfo DER
     */
    static exportPublicKeyPEM(pubDerHex: string): string;
    /**
     * Encode DER private key bytes to PEM format.
     * @param privDerHex hex string of PKCS#8 PrivateKeyInfo DER
     */
    static exportPrivateKeyPEM(privDerHex: string): string;
    /**
     * Decode a PEM-encoded public key, returning the raw DER as hex.
     */
    static importPublicKeyPEM(pem: string): string;
    /**
     * Decode a PEM-encoded private key, returning the raw DER as hex.
     */
    static importPrivateKeyPEM(pem: string): string;
}

declare class SM3Util {
    static digestToBytes(input: Uint8Array): Uint8Array;
    static digestToHex(input: Uint8Array | string): string;
    static digestToBase64(input: Uint8Array | string): string;
    static digestFromBase64ToHex(base64: string): string;
    static digest(input: Uint8Array | string, toBase64?: boolean): string;
    static hmacBytes(key: Uint8Array, data: Uint8Array): Uint8Array;
    static hmacToHex(key: Uint8Array | string, data: Uint8Array | string): string;
    static hmacToBase64(key: Uint8Array | string, data: Uint8Array | string): string;
    static hmac(key: Uint8Array | string, data: Uint8Array | string, toBase64?: boolean): string;
    static generateHmacKeyBytes(keyLength?: number): Uint8Array;
    static generateHmacKeyHex(keyLength?: number): string;
    static generateHmacKeyBase64(keyLength?: number): string;
    static generateHmacKeyToStr(keyLength?: number | boolean, toBase64?: boolean): string;
    static hmacVerify(key: Uint8Array | string, data: Uint8Array | string, receivedHmac: string): boolean;
}

declare class SM4Util {
    static generateKeyBytes(): Uint8Array;
    static generateKeyHex(): string;
    static generateKeyBase64(): string;
    static parseHexKey(hexKey: string): Uint8Array;
    static generateGcmIV(): Uint8Array;
    /**
     * SM4 GCM encryption.
     * Returns Hex(IV[12] + ciphertext + Tag[16]) by default, or Base64 if toBase64=true
     */
    static encryptGcm(plaintext: Uint8Array, key: Uint8Array | string, iv?: Uint8Array, toBase64?: boolean): string;
    /**
     * SM4 GCM encryption, always returns Hex.
     */
    static encryptGcmHex(plaintext: Uint8Array, key: Uint8Array | string, iv?: Uint8Array): string;
    /**
     * SM4 GCM encryption, always returns Base64.
     */
    static encryptGcmBase64(plaintext: Uint8Array, key: Uint8Array | string, iv?: Uint8Array): string;
    /**
     * SM4 GCM decryption.
     * Input: Hex or Base64 encoded (IV[12] + ciphertext + Tag[16]), auto-detected
     * Returns plaintext bytes.
     */
    static decryptGcm(ciphertextHexOrBase64: string, key: Uint8Array | string): Uint8Array;
    /**
     * SM4 GCM decryption from Hex input only.
     */
    static decryptGcmFromHex(ciphertextHex: string, key: Uint8Array | string): Uint8Array;
    /**
     * SM4 GCM decrypt a UTF-8 string, returns Hex by default or Base64 if toBase64=true
     */
    static encryptGcmString(plainText: string, key: Uint8Array | string, iv?: Uint8Array, toBase64?: boolean): string;
    /**
     * SM4 GCM decrypt to UTF-8 string
     * Input: Hex or Base64 encoded, auto-detected
     */
    static decryptGcmToString(ciphertextHexOrBase64: string, key: Uint8Array | string): string;
}

type Bytes = Uint8Array;
declare function isHexString(input: string): boolean;
declare function isBase64String(input: string): boolean;
declare function hexToBytes(hex: string): Bytes;
declare function bytesToHex(bytes: Bytes): string;
declare function base64ToBytes(base64: string): Bytes;
declare function bytesToBase64(bytes: Bytes): string;
declare function utf8ToBytes(text: string): Bytes;
declare function bytesToUtf8(bytes: Bytes): string;
declare function decodeHexOrBase64ToBytes(input: string): Bytes;

export { type CiphertextSignaturePair, type KeyPair, SM2Util, SM3Util, SM4Util, base64ToBytes, bytesToBase64, bytesToHex, bytesToUtf8, decodeHexOrBase64ToBytes, hexToBytes, isBase64String, isHexString, sm2PrivateKeyToRawHex, sm2PublicKeyToRawHex, utf8ToBytes };
