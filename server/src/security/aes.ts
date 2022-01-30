import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { AesEncrypt } from './aes.interface';

export class AES {
  private _key: Buffer;

  constructor() {
    this._key = randomBytes(32);
  }

  get key(): string {
    return this._key.toString('hex');
  }

  encrypt(plain: string): AesEncrypt {
    const iv = randomBytes(10);

    const cipher = createCipheriv('aes-256-gcm', this._key, iv, {
      authTagLength: 16
    });

    let encryptedText = cipher.update(plain, 'utf8', 'hex');
    encryptedText += cipher.final('hex');

    return {
      iv,
      authTag: cipher.getAuthTag(),
      encryptedText
    };
  }

  decrypt(cipher: string, iv: Buffer, authTag: Buffer): string {
    const decipher = createDecipheriv('aes-256-gcm', this._key, iv, {
      authTagLength: 16
    });

    decipher.setAuthTag(authTag);

    let decryptedData = decipher.update(cipher, 'hex', 'utf-8');
    decryptedData += decipher.final('utf8');

    return decryptedData;
  }
}
