import { resolve } from 'path';
import { readFileSync } from 'fs';
import {
  createPublicKey,
  createPrivateKey,
  KeyObject,
  publicEncrypt,
  privateDecrypt,
  privateEncrypt
} from 'crypto';

export class RSA {
  private privateKey: KeyObject;
  private publicKey: KeyObject;

  constructor() {
    const keyPath = resolve(__dirname, '../../key');

    this.privateKey = createPrivateKey(
      readFileSync(`${keyPath}/private.pem`, 'utf8')
    );

    this.publicKey = createPublicKey(
      readFileSync(`${keyPath}/public.pem`, 'utf8')
    );
  }

  encrypt(plain: string | Buffer, publicKey?: KeyObject): Buffer {
    const key = publicKey ? publicKey : this.publicKey;
    const buffer = typeof plain === 'string' ? Buffer.from(plain) : plain;

    return publicEncrypt(key, buffer);
  }

  decrypt(cipher: string | Buffer): Buffer {
    const buffer = typeof cipher === 'string' ? Buffer.from(cipher) : cipher;

    return privateDecrypt(this.privateKey, buffer);
  }

  sign(plain: string | Buffer): Buffer {
    const buffer = typeof plain === 'string' ? Buffer.from(plain) : plain;

    return privateEncrypt(this.privateKey, buffer);
  }
}
