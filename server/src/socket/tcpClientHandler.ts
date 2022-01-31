import { Socket } from 'net';
import { KeyExchangeProtcol } from '../protocol/keyExchangeProtcol';
import { AES } from '../security/aes';
import { AppError } from '../util/appError';
import { ClientStep } from './clientStep.enum';

export class TcpClientHandler {
  private keyExchangeProtcol = new KeyExchangeProtcol();
  private step = ClientStep.Handshake;
  private sessionKey: AES;

  constructor(private client: Socket) {}

  handle(data: string): void {
    switch (this.step) {
      case ClientStep.Handshake: {
        const res = this.keyExchangeProtcol.handle(data);
        this.sendMessage(res.message);

        if (res.completed) {
          this.step = ClientStep.Authenticate;
          this.sessionKey = res.sessionKey;
          delete this.keyExchangeProtcol;
        }
        break;
      }

      case ClientStep.Authenticate: {
        break;
      }

      default:
        throw new AppError('unknown key exchange step');
    }
  }

  private sendMessage(message: string): void {
    this.client.write(`${message}\n`);
  }
}
