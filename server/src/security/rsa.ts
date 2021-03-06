import { resolve } from 'path';
import { readFileSync } from 'fs';
import {
  createPublicKey,
  createPrivateKey,
  createSign,
  KeyObject,
  publicEncrypt,
  privateDecrypt
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

  encrypt(plain: string, publicKey?: KeyObject): string {
    const key = publicKey ? publicKey : this.publicKey;
    const buffer = Buffer.from(plain);

    return publicEncrypt(key, buffer).toString('base64');
  }

  decrypt(cipher: string): string {
    const buffer = Buffer.from(cipher, 'base64');

    return privateDecrypt(this.privateKey, buffer).toString();
  }

  sign(plain: string): string {
    const sign = createSign('SHA256');
    sign.update(plain).end();

    return sign.sign(this.privateKey).toString('base64');
  }
}
