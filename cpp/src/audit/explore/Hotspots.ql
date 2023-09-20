/**
 * @name Hotspots
 * @description Interesting places to review manually
 * @kind problem
 * @precision low
 * @id seclab/cpp-hotspots
 * @tags audit
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import Critical.OverflowDestination as Pb864640c // cpp/overflow-destination
import Likely_Bugs.Conversion.CastArrayPointerArithmetic as P0f6faebc // cpp/upcast-array-pointer-arithmetic
import Security.CWE.CWE_022.TaintedPath as Pe668a5ba // cpp/path-injection
import Security.CWE.CWE_078.ExecTainted as P84280c45 // cpp/command-line-injection
import Security.CWE.CWE_129.ImproperArrayIndexValidation as Pfd2dfbd5 // cpp/unclear-array-index-validation
import Security.CWE.CWE_190.ArithmeticUncontrolled as P2c62b1f9 // cpp/uncontrolled-arithmetic
import Security.CWE.CWE_190.TaintedAllocationSize as Pbf19fcaf // cpp/uncontrolled-allocation-size
import Security.CWE.CWE_311.CleartextBufferWrite as P9e90c5a1 // cpp/cleartext-storage-buffer
import Security.CWE.CWE_311.CleartextFileWrite as Pcc67a29f // cpp/cleartext-storage-file
import Security.CWE.CWE_311.CleartextTransmission as P6be8d893 // cpp/cleartext-transmission
import Security.CWE.CWE_313.CleartextSqliteDatabase as P7a820024 // cpp/cleartext-storage-database
import Security.CWE.CWE_319.UseOfHttp as Pa582973e // cpp/non-https-url
import Security.CWE.CWE_326.InsufficientKeySize as Pcd949cd0 // cpp/insufficient-key-size
import Security.CWE.CWE_611.XXE as P7c0fe853 // cpp/external-entity-expansion
import experimental.Security.CWE.CWE_078.WordexpTainted as Pd969e4a8 // cpp/wordexp-injection
import experimental.Security.CWE.CWE_190.AllocMultiplicationOverflow as P5eab2d42 // cpp/multiplication-overflow-in-alloc
import experimental.Security.CWE.CWE_193.InvalidPointerDeref as P7597eda8 // cpp/invalid-pointer-deref
import experimental.semmle.code.cpp.security.PrivateCleartextWrite as Pe6180bae // cpp/private-cleartext-write

Expr getSinkExpr(DataFlow::Node n) { result = n.asExpr() }

string getPath(DataFlow::Node n) { result = n.getLocation().getFile().getRelativePath() }

int getStartLine(DataFlow::Node n) { result = n.getLocation().getStartLine() }

int getEndLine(DataFlow::Node n) { result = n.getLocation().getEndLine() }

int getStartColumn(DataFlow::Node n) { result = n.getLocation().getStartColumn() }

int getEndColumn(DataFlow::Node n) { result = n.getLocation().getEndColumn() }


from DataFlow::Node n, string type
where
  P0f6faebc::CastToPointerArithFlowConfig::isSink(n, _) and type = "cpp/upcast-array-pointer-arithmetic" or
  P2c62b1f9::UncontrolledArithConfig::isSink(n) and type = "cpp/uncontrolled-arithmetic" or
  P5eab2d42::MultToAllocConfig::isSink(n) and type = "cpp/multiplication-overflow-in-alloc" or
  P6be8d893::FromSensitiveConfig::isSink(n) and type = "cpp/cleartext-transmission" or
  P7597eda8::FinalConfig::isSink(n, _) and type = "cpp/invalid-pointer-deref" or
  P7a820024::FromSensitiveConfig::isSink(n) and type = "cpp/cleartext-storage-database" or
  P7c0fe853::XxeConfig::isSink(n, _) and type = "cpp/external-entity-expansion" or
  P84280c45::ExecTaintConfig::isSink(n, _) and type = "cpp/command-line-injection" or
  P9e90c5a1::ToBufferConfig::isSink(n) and type = "cpp/cleartext-storage-buffer" or
  Pa582973e::HttpStringToUrlOpenConfig::isSink(n) and type = "cpp/non-https-url" or
  Pb864640c::OverflowDestinationConfig::isSink(n) and type = "cpp/overflow-destination" or
  Pbf19fcaf::TaintedAllocationSizeConfig::isSink(n) and type = "cpp/uncontrolled-allocation-size" or
  Pcc67a29f::FromSensitiveConfig::isSink(n) and type = "cpp/cleartext-storage-file" or
  Pcd949cd0::KeyStrengthFlowConfig::isSink(n) and type = "cpp/insufficient-key-size" or
  Pd969e4a8::WordexpTaintConfig::isSink(n) and type = "cpp/wordexp-injection" or
  Pe6180bae::PrivateCleartextWrite::WriteConfig::isSink(n) and type = "cpp/private-cleartext-write" or
  Pe668a5ba::TaintedPathConfig::isSink(n) and type = "cpp/path-injection" or
  Pfd2dfbd5::ImproperArrayIndexValidationConfig::isSink(n) and type = "cpp/unclear-array-index-validation"
select getSinkExpr(n),
  type + " @ " + getPath(n).toString() + ":" + getStartLine(n).toString() + "," +
    getEndLine(n).toString() + "," + getStartColumn(n).toString() + "," + getEndColumn(n)
