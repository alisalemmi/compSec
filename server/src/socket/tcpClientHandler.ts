import { Socket } from 'net';
import { KeyExchangeProtcol } from '../protocol/keyExchangeProtcol';
import { AppError } from '../util/appError';
import { ClientStep } from './clientStep.enum';

export class TcpClientHandler {
  private keyExchangeProtcol = new KeyExchangeProtcol();
  private step = ClientStep.Handshake;

  constructor(private client: Socket) {}

  handle(data: string): void {
    switch (this.step) {
      case ClientStep.Handshake: {
        const res = this.keyExchangeProtcol.handle(data);
        this.sendMessage(res.message);

        if (res.completed) {
          this.step = ClientStep.Authenticate;
          delete this.keyExchangeProtcol;
        }
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
