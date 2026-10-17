using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class Cache {
    public byte[] Serialize(object o) {
        var ms = new MemoryStream();
        new BinaryFormatter().Serialize(ms, o);
        return ms.ToArray();
    }

    public object Load(byte[] data) {
        var ms = new MemoryStream(data);
        // VULNERABLE (line 13): BinaryFormatter deserialization
        return new BinaryFormatter().Deserialize(ms);
    }
}
