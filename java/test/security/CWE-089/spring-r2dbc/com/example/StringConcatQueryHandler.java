package com.example;

import org.springframework.r2dbc.core.DatabaseClient;

/**
 * Test source for `DatabaseClient.sql(String)`: request-derived values are
 * concatenated into a SQL string via a `StringBuilder`, then executed
 * directly.
 */
public class StringConcatQueryHandler {

  // Fake remote flow source, recognized by DatabaseClientSqlInjection.ql.
  public static String source() {
    return null;
  }

  private final DatabaseClient databaseClient;

  public StringConcatQueryHandler(DatabaseClient databaseClient) {
    this.databaseClient = databaseClient;
  }

  private void appendFilters(StringBuilder sql, String category, String sortBy, String sortOrder) {
    if (category != null) {
      sql.append(" AND category = '").append(category).append("'");
    }
    if (sortBy != null && sortOrder != null) {
      sql.append(" ORDER BY ").append(sortBy).append(" ").append(sortOrder);
    }
  }

  private String buildQuery(String category, String sortBy, String sortOrder) {
    StringBuilder sql = new StringBuilder("SELECT * FROM items WHERE 1=1");
    appendFilters(sql, category, sortBy, sortOrder);
    return sql.toString();
  }

  public Object runQuery() {
    String category = source();
    String sortBy = source();
    String sortOrder = source();
    String query = buildQuery(category, sortBy, sortOrder);
    return databaseClient.sql(query).fetch().all(); // sink 1: sql(String)
  }

  public Object runQuerySafe() {
    // Parameter binding, not string concatenation - should NOT be flagged.
    String category = source();
    return databaseClient
        .sql("SELECT * FROM items WHERE category = :category")
        .bind("category", category)
        .fetch()
        .all();
  }
}
