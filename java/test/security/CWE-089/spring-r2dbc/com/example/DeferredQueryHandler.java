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

  // Alternative terminal/execution-triggering method to fetch(): then().
  public Object runDeferredQueryThen() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .then(); // sink: sql(Supplier<String>) via then()
  }

  // Alternative terminal method: map(...).all() instead of fetch().all(),
  // matching the exact chain from the original real-world report.
  public Object runDeferredQueryWithMap() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .map(row -> row)
        .all(); // sink: sql(Supplier<String>) via map()
  }

  // Intermediate fluent bind() call between the deferred sql() and the
  // terminal fetch() - taint must survive the fluent chain.
  public Object runDeferredQueryWithBind() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .bind(0, "unrelated-value")
        .fetch()
        .all(); // sink: sql(Supplier<String>) via bind().fetch()
  }

  // Same as above but exercising the String-named bind() overload, to
  // confirm the summary model's signature string matches the correct
  // overload (not just the int-indexed one).
  public Object runDeferredQueryWithBindByName() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .bind("param", "unrelated-value")
        .fetch()
        .all(); // sink: sql(Supplier<String>) via bind(String,Object).fetch()
  }

  // Alternative terminal method: flatMap(...), which returns Flux<R>
  // directly instead of an intermediate RowsFetchSpec.
  public Object runDeferredQueryWithFlatMap() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .flatMap(row -> row); // sink: sql(Supplier<String>) via flatMap()
  }

  // Alternative terminal method: map(BiFunction).
  public Object runDeferredQueryWithMapBiFunction() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .map((row, meta) -> row)
        .all(); // sink: sql(Supplier<String>) via map(BiFunction)
  }

  // Chains bindNull(int,Class), bindValues(List), bindProperties(Object),
  // and filter(Function) before the mapValue(Class) terminal sink -
  // validates the remaining summary/sink signature strings in one flow.
  public Object runDeferredQueryWithBindNullAndFilter() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .bindNull(1, String.class)
        .bindValues(java.util.List.of("unrelated"))
        .bindProperties(new Object())
        .filter(spec -> spec)
        .mapValue(String.class)
        .all(); // sink: sql(Supplier<String>) via mapValue() after bindNull/bindValues(List)/bindProperties/filter(Function)
  }

  // Isolated: bindNull(String,Class) alone.
  public Object runDeferredQueryWithBindNullByName() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .bindNull("param", String.class)
        .fetch()
        .all(); // sink: sql(Supplier<String>) via bindNull(String,Class).fetch()
  }

  // Isolated: bindValues(Map) alone.
  public Object runDeferredQueryWithBindValuesMap() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .bindValues(java.util.Map.of("param", "unrelated"))
        .fetch()
        .all(); // sink: sql(Supplier<String>) via bindValues(Map).fetch()
  }

  // Isolated: filter(StatementFilterFunction) alone.
  public Object runDeferredQueryWithFilterOverload() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .filter((org.springframework.r2dbc.core.StatementFilterFunction) null)
        .fetch()
        .all(); // sink: sql(Supplier<String>) via filter(StatementFilterFunction).fetch()
  }

  // Isolated: mapProperties(Class) alone.
  public Object runDeferredQueryWithMapProperties() {
    String category = source();
    return databaseClient
        .sql(() -> "SELECT * FROM items WHERE category = '" + category + "'")
        .mapProperties(String.class)
        .all(); // sink: sql(Supplier<String>) via mapProperties()
  }
}
