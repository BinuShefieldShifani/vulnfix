import java.io.*;

public class SessionStore {
    public byte[] serialize(Object o) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        new ObjectOutputStream(bos).writeObject(o);
        return bos.toByteArray();
    }

    public Object load(byte[] data) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data));
        // VULNERABLE (line 12): untrusted deserialization
        return in.readObject();
    }
}
