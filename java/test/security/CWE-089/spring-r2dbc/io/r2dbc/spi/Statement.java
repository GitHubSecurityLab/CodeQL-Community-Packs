/*
 * Minimal stub of the `io.r2dbc.spi` SPI, used only to compile the test
 * source in this directory. Not the real implementation.
 */
package io.r2dbc.spi;

public interface Statement {

  Statement bind(int index, Object value);

  Statement bind(String name, Object value);

  Statement bindNull(int index, Class<?> type);

  Statement bindNull(String name, Class<?> type);

  Statement add();

  Statement returnGeneratedValues(String... columns);

  Result execute();
}
