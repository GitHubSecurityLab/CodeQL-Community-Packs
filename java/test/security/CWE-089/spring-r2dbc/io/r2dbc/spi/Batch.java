/*
 * Minimal stub of the `io.r2dbc.spi` SPI, used only to compile the test
 * source in this directory. Not the real implementation.
 */
package io.r2dbc.spi;

public interface Batch {

  Batch add(String sql);

  Result execute();
}
