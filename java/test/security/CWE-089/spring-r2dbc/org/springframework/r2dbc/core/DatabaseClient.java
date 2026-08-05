/*
 * Minimal stub of the Spring Data R2DBC `DatabaseClient` API, used only to
 * compile the test source in this directory. Not the real implementation.
 */
package org.springframework.r2dbc.core;

import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

public interface DatabaseClient {

  GenericExecuteSpec sql(String sql);

  GenericExecuteSpec sql(Supplier<String> sqlSupplier);

  interface GenericExecuteSpec {
    GenericExecuteSpec bind(int index, Object value);

    GenericExecuteSpec bind(String name, Object value);

    GenericExecuteSpec bindNull(int index, Class<?> type);

    GenericExecuteSpec bindNull(String name, Class<?> type);

    GenericExecuteSpec bindValues(List<Object> values);

    GenericExecuteSpec bindValues(Map<String, Object> values);

    GenericExecuteSpec bindProperties(Object source);

    GenericExecuteSpec filter(Function<Object, Object> filterFunction);

    GenericExecuteSpec filter(StatementFilterFunction filterFunction);

    <R> RowsFetchSpec<R> map(Function<Object, R> mappingFunction);

    <R> RowsFetchSpec<R> map(BiFunction<Object, Object, R> mappingFunction);

    <R> RowsFetchSpec<R> mapValue(Class<R> mappedClass);

    <R> RowsFetchSpec<R> mapProperties(Class<R> mappedClass);

    FetchSpec fetch();

    // Real Spring's `then()`: an alternative terminal/execution-triggering
    // method to `fetch()`, returning `Mono<Void>`. Stubbed as `Object` since
    // this test doesn't need Reactor on the classpath.
    Object then();

    // Real Spring's `flatMap(...)`: another terminal/execution-triggering
    // method, returning `Flux<R>` directly (no further `.all()` needed).
    // Stubbed with `Object` result since this test doesn't need Reactor.
    Object flatMap(Function<Object, Object> mappingFunction);
  }

  interface RowsFetchSpec<R> {
    Object all();
  }

  interface FetchSpec {
    Object all();
  }
}
