/**
 * @name Hotspots
 * @description Interesting places to review manually
 * @kind problem
 * @precision low
 * @id seclab/java-hotspots
 * @tags audit
 */

import java
import semmle.code.java.dataflow.DataFlow
import experimental.Security.CWE.CWE_036.OpenStream as Pc265169d // java/openstream-called-on-tainted-url
import experimental.Security.CWE.CWE_089.MyBatisAnnotationSqlInjection as P3433ca3c // java/mybatis-annotation-sql-injection
import experimental.Security.CWE.CWE_089.MyBatisMapperXmlSqlInjection as P4a732599 // java/mybatis-xml-sql-injection
import experimental.Security.CWE.CWE_094.BeanShellInjection_lib as P9a2a5d68 // java/beanshell-injection
import experimental.Security.CWE.CWE_094.InsecureDexLoading as P396175bb // java/android-insecure-dex-loading
import experimental.Security.CWE.CWE_094.JShellInjection_lib as P10edcac8 // java/jshell-injection
import experimental.Security.CWE.CWE_094.JakartaExpressionInjectionLib as P6606b44a // java/javaee-expression-injection
import experimental.Security.CWE.CWE_094.JythonInjection as P16b2fcc3 // java/jython-injection
import experimental.Security.CWE.CWE_094.ScriptInjection as Ped4eadee // java/unsafe-eval
import experimental.Security.CWE.CWE_1004.SensitiveCookieNotHttpOnly as Pd802360b // java/sensitive-cookie-not-httponly
import experimental.Security.CWE.CWE_200.InsecureWebResourceResponse as Pc48a7852 // java/insecure-webview-resource-response
import experimental.Security.CWE.CWE_352.JsonpInjection as Pc119427a // java/jsonp-injection
import experimental.Security.CWE.CWE_400.LocalThreadResourceAbuse as Pe69d7f46 // java/local-thread-resource-abuse
import experimental.Security.CWE.CWE_470.UnsafeReflection as P4165df50 // java/unsafe-reflection
import experimental.Security.CWE.CWE_502.UnsafeDeserializationRmi as Pa8c653fc // java/unsafe-deserialization-rmi
import experimental.Security.CWE.CWE_601.SpringUrlRedirect as Pdab9ce0e // java/spring-unvalidated-url-redirection
import experimental.Security.CWE.CWE_652.XQueryInjection as P633090ab // java/xquery-injection
import experimental.Security.CWE.CWE_759.HashWithoutSalt as Pb4705842 // java/hash-without-salt
import semmle.code.java.security.ArbitraryApkInstallationQuery as P2eaba430 // java/android/arbitrary-apk-installation
import semmle.code.java.security.CommandLineQuery as P24009c96 // java/command-line-injection
import semmle.code.java.security.FragmentInjectionQuery as Pe2b3cc8f // java/android/fragment-injection
import semmle.code.java.security.GroovyInjectionQuery as P3c1fe6f6 // java/groovy-injection
import semmle.code.java.security.ImplicitPendingIntentsQuery as P30e32595 // java/android/implicit-pendingintents
import semmle.code.java.security.InsecureBasicAuthQuery as P294b016c // java/insecure-basic-auth
import semmle.code.java.security.InsecureBeanValidationQuery as P37854cbc // java/insecure-bean-validation
import semmle.code.java.security.InsecureLdapAuthQuery as P91409f87 // java/insecure-ldap-auth
import semmle.code.java.security.InsecureTrustManagerQuery as P412beb01 // java/insecure-trustmanager
import semmle.code.java.security.InsufficientKeySizeQuery as P27b0e203 // java/insufficient-key-size
import semmle.code.java.security.IntentUriPermissionManipulationQuery as Pe00968ab // java/android/intent-uri-permission-manipulation
import semmle.code.java.security.JexlInjectionQuery as P4e68f413 // java/jexl-expression-injection
import semmle.code.java.security.JndiInjectionQuery as Pa130cc29 // java/jndi-injection
import semmle.code.java.security.LdapInjectionQuery as Pb62b2fce // java/ldap-injection
import semmle.code.java.security.MvelInjectionQuery as Pa33ca649 // java/mvel-expression-injection
import semmle.code.java.security.OgnlInjectionQuery as P10f3541b // java/ognl-injection
import semmle.code.java.security.PartialPathTraversalQuery as P0527c6fe // java/partial-path-traversal-from-remote
import semmle.code.java.security.RequestForgeryConfig as P7e555301 // java/ssrf
import semmle.code.java.security.RsaWithoutOaepQuery as P233b1f8a // java/rsa-without-oaep
import semmle.code.java.security.SensitiveResultReceiverQuery as Pff56da46 // java/android/sensitive-result-receiver
import semmle.code.java.security.SpelInjectionQuery as Peeaf7ef2 // java/spel-expression-injection
import semmle.code.java.security.SqlInjectionQuery as P3fb65efb // java/sql-injection
import semmle.code.java.security.TaintedPathQuery as Pf8fddf9b // java/path-injection
import semmle.code.java.security.UnsafeContentUriResolutionQuery as P45a403bb // java/android/unsafe-content-uri-resolution
import semmle.code.java.security.UnsafeDeserializationQuery as P9499bacc // java/unsafe-deserialization
import semmle.code.java.security.WebviewDebuggingEnabledQuery as P602272ad // java/android/webview-debugging-enabled
import semmle.code.java.security.XPathInjectionQuery as Pcabbd646 // java/xml/xpath-injection
import semmle.code.java.security.XsltInjectionQuery as P3dace8e1 // java/xslt-injection
import semmle.code.java.security.XxeRemoteQuery as Pc448879a // java/xxe
import semmle.code.java.security.ZipSlipQuery as P3a3037d6 // java/zipslip
import semmle.code.java.security.regexp.PolynomialReDoSQuery as P6365617b // java/polynomial-redos
import semmle.code.java.security.regexp.RegexInjectionQuery as Pd1e135f3 // java/regex-injection


Expr getSinkExpr(DataFlow::Node n) {
  not n.getLocation().getFile().getRelativePath().matches("%/src/test/%") and
  not n.asExpr() instanceof StringLiteral and
  (
      exists(MethodAccess ma | ma.getAnArgument() = n.asExpr() and result = ma)
      or
      exists(MethodAccess ma | ma.getQualifier() = n.asExpr() and result = ma)
      or
      not exists(MethodAccess ma | ma.getAnArgument() = n.asExpr()) and
      result = n.asExpr()
  )
}


string getPath(DataFlow::Node n) { result = n.getLocation().getFile().getRelativePath() }

int getStartLine(DataFlow::Node n) { result = n.getLocation().getStartLine() }

int getEndLine(DataFlow::Node n) { result = n.getLocation().getEndLine() }

int getStartColumn(DataFlow::Node n) { result = n.getLocation().getStartColumn() }

int getEndColumn(DataFlow::Node n) { result = n.getLocation().getEndColumn() }


from DataFlow::Node n, string type
where
  P0527c6fe::PartialPathTraversalFromRemoteConfig::isSink(n) and type = "java/partial-path-traversal-from-remote" or
  P10edcac8::JShellInjectionConfig::isSink(n) and type = "java/jshell-injection" or
  P10f3541b::OgnlInjectionFlowConfig::isSink(n) and type = "java/ognl-injection" or
  P16b2fcc3::CodeInjectionConfig::isSink(n) and type = "java/jython-injection" or
  P233b1f8a::RsaWithoutOaepConfig::isSink(n) and type = "java/rsa-without-oaep" or
  P24009c96::RemoteUserInputToArgumentToExecFlowConfig::isSink(n) and type = "java/command-line-injection" or
  P27b0e203::KeySizeConfig::isSink(n, _) and type = "java/insufficient-key-size" or
  P294b016c::BasicAuthFlowConfig::isSink(n) and type = "java/insecure-basic-auth" or
  P2eaba430::ApkInstallationConfig::isSink(n) and type = "java/android/arbitrary-apk-installation" or
  P30e32595::ImplicitPendingIntentStartConfig::isSink(n, _) and type = "java/android/implicit-pendingintents" or
  P3433ca3c::MyBatisAnnotationSqlInjectionConfig::isSink(n) and type = "java/mybatis-annotation-sql-injection" or
  P37854cbc::BeanValidationConfig::isSink(n) and type = "java/insecure-bean-validation" or
  P396175bb::InsecureDexConfig::isSink(n) and type = "java/android-insecure-dex-loading" or
  P3a3037d6::ZipSlipConfig::isSink(n) and type = "java/zipslip" or
  P3c1fe6f6::GroovyInjectionConfig::isSink(n) and type = "java/groovy-injection" or
  P3dace8e1::XsltInjectionFlowConfig::isSink(n) and type = "java/xslt-injection" or
  P3fb65efb::QueryInjectionFlowConfig::isSink(n) and type = "java/sql-injection" or
  P412beb01::InsecureTrustManagerConfig::isSink(n) and type = "java/insecure-trustmanager" or
  P4165df50::UnsafeReflectionConfig::isSink(n) and type = "java/unsafe-reflection" or
  P45a403bb::UnsafeContentResolutionConfig::isSink(n) and type = "java/android/unsafe-content-uri-resolution" or
  P4a732599::MyBatisMapperXmlSqlInjectionConfig::isSink(n) and type = "java/mybatis-xml-sql-injection" or
  P4e68f413::JexlInjectionConfig::isSink(n) and type = "java/jexl-expression-injection" or
  P602272ad::WebviewDebugEnabledConfig::isSink(n) and type = "java/android/webview-debugging-enabled" or
  P633090ab::XQueryInjectionConfig::isSink(n) and type = "java/xquery-injection" or
  P6365617b::PolynomialRedosConfig::isSink(n) and type = "java/polynomial-redos" or
  P6606b44a::JakartaExpressionInjectionConfig::isSink(n) and type = "java/javaee-expression-injection" or
  P7e555301::RequestForgeryConfig::isSink(n) and type = "java/ssrf" or
  P91409f87::InsecureLdapUrlConfig::isSink(n) and type = "java/insecure-ldap-auth" or
  P9499bacc::UnsafeDeserializationConfig::isSink(n) and type = "java/unsafe-deserialization" or
  P9a2a5d68::BeanShellInjectionConfig::isSink(n) and type = "java/beanshell-injection" or
  Pa130cc29::JndiInjectionFlowConfig::isSink(n) and type = "java/jndi-injection" or
  Pa33ca649::MvelInjectionFlowConfig::isSink(n) and type = "java/mvel-expression-injection" or
  Pa8c653fc::BindingUnsafeRemoteObjectConfig::isSink(n) and type = "java/unsafe-deserialization-rmi" or
  Pb4705842::HashWithoutSaltConfig::isSink(n) and type = "java/hash-without-salt" or
  Pb62b2fce::LdapInjectionFlowConfig::isSink(n) and type = "java/ldap-injection" or
  Pc119427a::RequestResponseFlowConfig::isSink(n) and type = "java/jsonp-injection" or
  Pc265169d::RemoteUrlToOpenStreamFlowConfig::isSink(n) and type = "java/openstream-called-on-tainted-url" or
  Pc448879a::XxeConfig::isSink(n) and type = "java/xxe" or
  Pc48a7852::InsecureWebResourceResponseConfig::isSink(n) and type = "java/insecure-webview-resource-response" or
  Pcabbd646::XPathInjectionConfig::isSink(n) and type = "java/xml/xpath-injection" or
  Pd1e135f3::RegexInjectionConfig::isSink(n) and type = "java/regex-injection" or
  Pd802360b::MissingHttpOnlyConfig::isSink(n) and type = "java/sensitive-cookie-not-httponly" or
  Pdab9ce0e::SpringUrlRedirectFlowConfig::isSink(n) and type = "java/spring-unvalidated-url-redirection" or
  Pe00968ab::IntentUriPermissionManipulationConfig::isSink(n) and type = "java/android/intent-uri-permission-manipulation" or
  Pe2b3cc8f::FragmentInjectionTaintConfig::isSink(n) and type = "java/android/fragment-injection" or
  Pe69d7f46::ThreadResourceAbuseConfig::isSink(n) and type = "java/local-thread-resource-abuse" or
  Ped4eadee::ScriptInjectionConfig::isSink(n) and type = "java/unsafe-eval" or
  Peeaf7ef2::SpelInjectionConfig::isSink(n) and type = "java/spel-expression-injection" or
  Pf8fddf9b::TaintedPathConfig::isSink(n) and type = "java/path-injection" or
  Pff56da46::SensitiveResultReceiverConfig::isSink(n) and type = "java/android/sensitive-result-receiver"
select getSinkExpr(n),
  type + " @ " + getPath(n).toString() + ":" + getStartLine(n).toString() + "," +
    getEndLine(n).toString() + "," + getStartColumn(n).toString() + "," + getEndColumn(n)
