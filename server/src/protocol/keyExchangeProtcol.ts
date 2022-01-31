import { createPublicKey, KeyObject, randomBytes } from 'crypto';
import { MD5 } from '../security/md5';
import { RSA } from '../security/rsa';
import { AppError } from '../util/appError';
import { KeyExchangeStep } from './keyExchangeStep.enum';

export class KeyExchangeProtcol {
  private rsa = new RSA();

  private step = KeyExchangeStep.StartHandshake;
  private _clientPublicKey: KeyObject;
  private nonceA: number;
  private nonceB: number;

  handle(data: string) {
    const args = data.trim().split('.');

    switch (this.step) {
      case KeyExchangeStep.StartHandshake: {
        this.startHandshake(args);
        const message = this.verifyServer();

        this.step = KeyExchangeStep.VerifyClient;

        return {
          message,
          completed: false
        };
      }

      default:
        throw new AppError('unknown key exchange step');
    }
  }

  private startHandshake(args: string[]): void {
    if (args.length !== 2) throw new AppError('bad arguments');

    this.nonceA = this.decryptNonce(args[0]);
    this.clientPublicKey = args[1];
  }

  private verifyServer(): string {
    this.nonceB = this.generateNonce();

    const na = this.rsa
      .encrypt((this.nonceA + 1).toString(), this._clientPublicKey)
      .toString('base64');

    const nb = this.rsa
      .encrypt(this.nonceB.toString(), this._clientPublicKey)
      .toString('base64');

    const hashNonceB = MD5.hash(this.nonceB.toString());
    const hashPublicKey = MD5.hash(this.clientPublicKey);

    const signedMessage = this.rsa
      .sign(`${hashNonceB}.${hashPublicKey}`)
      .toString('base64');

    return `${na}.${nb}.${signedMessage}`;
  }

  private decryptNonce(encryptedNonce: string): number {
    let nonce: string;

    try {
      nonce = this.rsa.decrypt(encryptedNonce).toString();
    } catch {
      nonce = '';
    }

    if (!/^\d+$/.test(nonce)) throw new AppError('nonce is not valid');

    return +nonce;
  }

  private generateNonce(): number {
    return randomBytes(64).readUInt32BE();
  }

  private set clientPublicKey(key: string) {
    try {
      this._clientPublicKey = createPublicKey(
        `-----BEGIN RSA PUBLIC KEY-----\n${key}\n-----END RSA PUBLIC KEY-----`
      );
    } catch {
      throw new AppError('client public key is not valid');
    }
  }

  private get clientPublicKey(): string {
    return this._clientPublicKey
      .export({ format: 'pem', type: 'pkcs1' })
      .toString()
      .split('\n')
      .slice(1, -2)
      .join('');
  }
}
