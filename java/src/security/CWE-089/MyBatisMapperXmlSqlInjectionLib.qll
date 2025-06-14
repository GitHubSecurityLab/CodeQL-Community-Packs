/**
 * Provide classes for SQL injection detection in MyBatis Mapper XML.
 */

import java
import semmle.code.java.frameworks.MyBatis
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.frameworks.Properties

/** A sink for MyBatis Mapper method call an argument. */
class MyBatisMapperMethodCallAnArgument extends DataFlow::Node {
  MyBatisMapperMethodCallAnArgument() {
    exists(MyBatisMapperSqlOperation mbmxe, MethodCall ma |
      mbmxe.getMapperMethod() = ma.getMethod()
    |
      ma.getAnArgument() = this.asExpr()
    )
  }
}
