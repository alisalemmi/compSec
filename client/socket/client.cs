using System.Net;
using System.Net.Sockets;
using System.Text;

class TcpClient
{
  Socket sender;

  public TcpClient()
  {
    IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
    IPAddress ipAddr = ipHost.AddressList[0];
    IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 3000);

    this.sender = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
    sender.Connect(localEndPoint);

    Console.WriteLine("Socket connected");
  }

  public string send(string message)
  {
    byte[] messageSent = Encoding.UTF8.GetBytes(message);
    int byteSent = sender.Send(messageSent);

    byte[] messageReceived = new byte[4096];
    int byteRecv = sender.Receive(messageReceived);

    return Encoding.UTF8.GetString(messageReceived, 0, byteRecv);
  }
}
