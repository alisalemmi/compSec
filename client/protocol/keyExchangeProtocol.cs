class KeyExchangeProtocol
{
  public RSA clientRsa = new RSA();
  private RSA serverRsa = new RSA("../../server/key/public.pem");
  private uint nonceA;
  private uint nonceB;

  public string startHandshake()
  {
    this.nonceA = this.generateNonce();
    string encriptedNonce = this.serverRsa.encrypt(this.nonceA.ToString());

    return $"{encriptedNonce}.{this.clientRsa.publicKey}";
  }

  public void verifyServer(string data)
  {
    string[] args = data.Trim().Split(".");

    var na = Convert.ToUInt32(this.clientRsa.decrypt(args[0]));
    var nb = Convert.ToUInt32(this.clientRsa.decrypt(args[1]));

    if (na != this.nonceA + 1)
      throw new Exception("invalid nonce A");

    this.nonceB = nb;

    if (!this.serverRsa.verify(args[2], $"{nonceB}.{this.clientRsa.publicKey}"))
      throw new Exception("invalid signature");
  }

  private uint generateNonce()
  {
    byte[] buffer = new byte[sizeof(uint)];

    Random rnd = new Random();
    rnd.NextBytes(buffer);

    return BitConverter.ToUInt32(buffer, 0);
  }
}
