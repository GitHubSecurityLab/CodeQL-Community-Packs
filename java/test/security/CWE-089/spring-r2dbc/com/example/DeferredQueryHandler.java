package com.example;

import org.springframework.r2dbc.core.DatabaseClient;

/**
 * Test source for the `DatabaseClient.sql(Supplier<String>)` overload: SQL
 * text is deferred behind a lambda instead of being passed directly as a
 * String.
 */
public class DeferredQueryHandler {

  // Fake remote flow source, recognized by DatabaseClientSqlInjection.ql.
  public static String source() {
    return null;
  }

  private final DatabaseClient databaseClient;

  public DeferredQueryHandler(DatabaseClient databaseClient) {
    this.databaseClient = databaseClient;
  }

  public Object runDeferredQuery() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .fetch()
        .all(); // sink 2: sql(Supplier<String>)
  }
}
