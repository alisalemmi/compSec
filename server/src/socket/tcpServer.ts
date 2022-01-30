import { AddressInfo, createServer, Server, Socket } from 'net';
import { AppError } from '../util/appError';
import { TcpClientHandler } from './tcpClientHandler';

export class TcpServer {
  private server: Server;

  constructor() {
    this.server = createServer();

    this.server.on('listening', () => this.onStart());
    this.server.on('connection', client => this.onClientConnect(client));
    this.server.on('close', () => this.onClose());
    this.server.on('error', err => this.onError(err));

    this.server.listen(3000);
  }

  private onStart(): void {
    const port = (this.server.address() as AddressInfo).port;
    console.log(`listening on port ${port}...`);
  }

  private onClose(): void {
    console.log('server socket is closed');
  }

  private onError(error: Error): void {
    console.log('an error has been occurred');
    console.log(JSON.stringify(error, undefined, 2));
  }

  private onClientConnect(client: Socket): void {
    const address = `${client.remoteAddress}:${client.remotePort}`;

    // configure socket
    client.setEncoding('utf-8');

    // log events
    console.log(`connect ${address}`);
    client.on('close', () => console.log(`close   ${address}`));
    client.on('timeout', () => console.log('Client time out'));
    client.on('error', err => this.onError(err));

    // handle request
    const clientHandler = new TcpClientHandler(client);

    client.on('data', (data: string) => {
      try {
        clientHandler.handle(data);
      } catch (error) {
        this.sendError(client, error);
      }
    });
  }

  private sendError(client: Socket, error: unknown): void {
    const message =
      error instanceof AppError ? error.message : 'an error has been occurred';

    client.end(`Error: ${message}\n`);
  }
}
