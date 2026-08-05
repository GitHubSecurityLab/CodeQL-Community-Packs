/*
 * Minimal stub of the `io.r2dbc.spi` SPI, used only to compile the test
 * source in this directory. Not the real implementation.
 */
package io.r2dbc.spi;

public interface Connection {

  Statement createStatement(String sql);

  Batch createBatch();

  void createSavepoint(String name);

  void releaseSavepoint(String name);

  void rollbackTransactionToSavepoint(String name);
}
