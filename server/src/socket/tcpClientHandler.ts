import { Socket } from 'net';
import { KeyExchangeProtcol } from '../protocol/keyExchangeProtcol';
import { ClientStep } from './clientStep.enum';

export class TcpClientHandler {
  private keyExchangeProtcol = new KeyExchangeProtcol();
  private step = ClientStep.Handshake;

  constructor(private client: Socket) {}

  handle(data: string): void {
    switch (this.step) {
      case ClientStep.Handshake: {
        const res = this.keyExchangeProtcol.handle(data);
        this.client.write(res.message);

        if (res.completed) this.step = ClientStep.Authenticate;
        break;
      }
    }
  }
}
