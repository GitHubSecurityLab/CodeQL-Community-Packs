/*
 * Minimal stub of the Spring Data R2DBC `DatabaseClient` API, used only to
 * compile the test source in this directory. Not the real implementation.
 */
package org.springframework.r2dbc.core;

import java.util.function.Supplier;

public interface DatabaseClient {

  GenericExecuteSpec sql(String sql);

  GenericExecuteSpec sql(Supplier<String> sqlSupplier);

  interface GenericExecuteSpec {
    GenericExecuteSpec bind(int index, Object value);

    GenericExecuteSpec bind(String name, Object value);

    FetchSpec fetch();
  }

  interface FetchSpec {
    Object all();
  }
}
