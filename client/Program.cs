Console.OutputEncoding = System.Text.Encoding.UTF8;

var socket = new TcpClient();
KeyExchangeProtocol keyExchangeProtocol = new KeyExchangeProtocol();

string startHandshake = keyExchangeProtocol.startHandshake();
string verifyServer = socket.send(startHandshake);
keyExchangeProtocol.verifyServer(verifyServer);
string encryptedSessionKey = socket.send(keyExchangeProtocol.verifyClient());
string sessionKey = keyExchangeProtocol.getSessionKey(encryptedSessionKey);

Console.WriteLine(sessionKey);
