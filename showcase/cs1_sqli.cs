using System.Data.SqlClient;

public class UserRepository {
    private SqlConnection conn;
    public UserRepository(SqlConnection c) { conn = c; }

    public string Normalize(string s) {
        return s?.Trim() ?? "";
    }

    public SqlDataReader FindByName(string name) {
        var cmd = conn.CreateCommand();
        // VULNERABLE (line 13): SQL injection
        cmd.CommandText = "SELECT * FROM Users WHERE Name = '" + name + "'";
        return cmd.ExecuteReader();
    }
}
