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
}
