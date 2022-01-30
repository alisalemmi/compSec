import { Socket } from 'net';

export class TcpClientHandler {
  constructor(private client: Socket) {}

  handle(data: Buffer): void {
    console.log(data.toString(), '%%');
  }
}
