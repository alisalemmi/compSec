export interface AesEncrypt {
  iv: Buffer;
  authTag: Buffer;
  encryptedText: string;
}
