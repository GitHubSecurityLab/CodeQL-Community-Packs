package com.example;

import io.r2dbc.spi.Batch;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.Result;
import io.r2dbc.spi.Statement;

/**
 * Test source for the low-level `io.r2dbc.spi` SPI that Spring's
 * `DatabaseClient` (and every other reactive relational driver) is built on
 * top of. Code that drops down to this API to build/execute SQL text bypasses
 * `DatabaseClient` entirely, so it needs its own sink models.
 */
public class RawR2dbcHandler {

  // Fake remote flow source, recognized by DatabaseClientSqlInjection.ql.
  public static String source() {
    return null;
  }

  private final Connection connection;

  public RawR2dbcHandler(Connection connection) {
    this.connection = connection;
  }

  public Result runStatement() {
    String category = source();
    Statement statement =
        connection.createStatement( // sink 3: Connection.createStatement(String)
            "SELECT * FROM items WHERE category = '" + category + "'");
    return statement.execute();
  }

  public Result runBatch() {
    String category = source();
    Batch batch = connection.createBatch();
    batch.add("SELECT * FROM items WHERE category = '" + category + "'"); // sink 4: Batch.add(String)
    return batch.execute();
  }

  public Result runStatementSafe() {
    // Parameter binding, not string concatenation - should NOT be flagged.
    String category = source();
    Statement statement =
        connection.createStatement("SELECT * FROM items WHERE category = $1");
    statement.bind(0, category);
    return statement.execute();
  }

  public void runCreateSavepoint() {
    // Real drivers (e.g. r2dbc-postgresql) build this as
    // `String.format("SAVEPOINT %s", name)` with no escaping/validation.
    String name = source();
    connection.createSavepoint(name); // sink 5: Connection.createSavepoint(String)
  }

  public void runReleaseSavepoint() {
    String name = source();
    connection.releaseSavepoint(name); // sink 6: Connection.releaseSavepoint(String)
  }

  public void runRollbackTransactionToSavepoint() {
    String name = source();
    connection.rollbackTransactionToSavepoint(name); // sink 7: Connection.rollbackTransactionToSavepoint(String)
  }

  public Result runReturnGeneratedValues() {
    // Real drivers (e.g. r2dbc-postgresql) build this as
    // `String.format("%s RETURNING %s", sql, String.join(", ", columns))`
    // with no escaping/validation of the column names.
    String column = source();
    Statement statement = connection.createStatement("INSERT INTO items (name) VALUES ($1)");
    return statement.returnGeneratedValues(column).execute(); // sink 8: Statement.returnGeneratedValues(String...)
  }
}
