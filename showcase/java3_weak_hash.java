import java.security.MessageDigest;

public class Hasher {
    public byte[] hashPassword(String pw) throws Exception {
        // VULNERABLE (line 5): MD5 for passwords
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(pw.getBytes());
    }
}
