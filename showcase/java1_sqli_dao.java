import java.sql.*;

public class UserDao {
    private Connection conn;

    public UserDao(Connection c) { this.conn = c; }

    public String normalize(String s) {
        return s == null ? "" : s.trim();
    }

    public ResultSet findByName(String name) throws SQLException {
        Statement st = conn.createStatement();
        // VULNERABLE (line 14): SQL injection
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public int count() throws SQLException {
        ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM users");
        return rs.next() ? rs.getInt(1) : 0;
    }
}
