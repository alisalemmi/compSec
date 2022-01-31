using System.Security.Cryptography;
using System.Text.RegularExpressions;

class RSA
{
  private RSACryptoServiceProvider rsa;

  public RSA()
  {
    this.rsa = new RSACryptoServiceProvider();
  }

  public RSA(string publicKeyPath)
  {
    Regex regex = new Regex("-----(BEGIN|END) RSA PUBLIC KEY-----");

    string publicKeyFile = File.ReadAllText("../server/key/public.pem").Trim();
    string publicKey = regex.Replace(publicKeyFile, "").Replace("\n", "").Trim();
    byte[] publicKeyByte = Convert.FromBase64String(publicKey);

    this.rsa = new RSACryptoServiceProvider();
    rsa.ImportRSAPublicKey(new ReadOnlySpan<byte>(publicKeyByte), out var bytesRead);
  }

  public string publicKey => Convert.ToBase64String(this.rsa.ExportRSAPublicKey());

  public string encrypt(string plain)
  {
    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(plain);
    byte[] cipher = rsa.Encrypt(bytes, true);

    return Convert.ToBase64String(cipher);
  }

  public string decrypt(string cipher)
  {
    byte[] bytes = Convert.FromBase64String(cipher);
    byte[] plain = rsa.Decrypt(bytes, true);

    return System.Text.Encoding.UTF8.GetString(plain);
  }

  public bool verify(string sign, string data)
  {
    byte[] signBytes = Convert.FromBase64String(sign);
    byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);

    var hash = CryptoConfig.MapNameToOID("SHA256");

    if (hash != null)
      return this.rsa.VerifyData(dataBytes, hash, signBytes);
    else
      throw new Exception("invalid hash alg");
  }
}
