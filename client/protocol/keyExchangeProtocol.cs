class KeyExchangeProtocol
{
  public RSA clientRsa = new RSA();
  private RSA serverRsa = new RSA("../../server/key/public.pem");
  private uint nonceA;

  public string startHandshake()
  {
    this.nonceA = this.generateNonce();
    string encriptedNonce = this.serverRsa.encrypt(this.nonceA.ToString());

    return $"{encriptedNonce}.{this.clientRsa.publicKey}";
  }

  private uint generateNonce()
  {
    byte[] buffer = new byte[sizeof(uint)];

    Random rnd = new Random();
    rnd.NextBytes(buffer);

    return BitConverter.ToUInt32(buffer, 0);
  }
}
