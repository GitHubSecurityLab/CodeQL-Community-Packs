import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class SqlInjectionAuditTest {
  void test1(Connection connection, String username) throws SQLException {
    Statement statement = connection.createStatement();
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    statement.executeQuery(query);
  }

  void test2(Connection connection) throws SQLException {
    String hardcoded = "SELECT * FROM users";
    Statement statement = connection.createStatement();
    statement.executeQuery(hardcoded);
  }
}
