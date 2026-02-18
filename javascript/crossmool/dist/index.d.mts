type KeyInput = string | Uint8Array;
declare function sm2PublicKeyToRawHex(publicKey: KeyInput): string;
declare function sm2PrivateKeyToRawHex(privateKey: KeyInput): string;

interface CiphertextSignaturePair {
    ciphertext: string;
    signature: string;
}
declare class SM2Util {
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
}

declare class SM3Util {
    static digestToBytes(input: Uint8Array): Uint8Array;
    static digestToHex(input: Uint8Array | string): string;
    static digestToBase64(input: Uint8Array | string): string;
    static digestFromBase64ToHex(base64: string): string;
}

declare class SM4Util {
    static generateKeyBytes(): Uint8Array;
    static generateKeyHex(): string;
    static generateKeyBase64(): string;
    static encryptEcbToBytes(input: Uint8Array, key: Uint8Array | string): Uint8Array;
    static decryptEcbToBytes(cipher: Uint8Array, key: Uint8Array | string): Uint8Array;
    static encryptEcbToHex(plainText: string, key: Uint8Array | string): string;
    static encryptEcbToBase64(plainText: string, key: Uint8Array | string): string;
    static decryptEcbToUtf8(cipherHexOrBase64: string, key: Uint8Array | string): string;
    static decryptEcbHexToUtf8(cipherHex: string, key: Uint8Array | string): string;
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

export { type CiphertextSignaturePair, SM2Util, SM3Util, SM4Util, base64ToBytes, bytesToBase64, bytesToHex, bytesToUtf8, decodeHexOrBase64ToBytes, hexToBytes, isBase64String, isHexString, sm2PrivateKeyToRawHex, sm2PublicKeyToRawHex, utf8ToBytes };
