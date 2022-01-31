using System.Security.Cryptography;
using System.Text;

class RSA
{
  private RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
  private UnicodeEncoding ByteConverter = new UnicodeEncoding();

  public string publicKey => Convert.ToBase64String(this.rsa.ExportRSAPublicKey());

  public string encrypt(string plain)
  {
    byte[] bytes = this.ByteConverter.GetBytes(plain);
    byte[] cipher = rsa.Encrypt(bytes, true);

    return Convert.ToBase64String(cipher);
  }

  public string decrypt(string cipher)
  {
    byte[] bytes = Convert.FromBase64String(cipher);
    byte[] plain = rsa.Decrypt(bytes, true);

    return this.ByteConverter.GetString(plain);
  }
}
