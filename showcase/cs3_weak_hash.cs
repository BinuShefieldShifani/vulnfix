using System.Security.Cryptography;
using System.Text;

public class Hasher {
    public byte[] HashPassword(string pw) {
        // VULNERABLE (line 6): MD5 for passwords
        using var md5 = MD5.Create();
        return md5.ComputeHash(Encoding.UTF8.GetBytes(pw));
    }
}
