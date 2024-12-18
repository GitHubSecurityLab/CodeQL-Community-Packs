import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.ApiGraphs
private import semmle.python.frameworks.Flask

abstract class CredentialSink extends DataFlow::Node { }

Expr getDictValueByKey(Dict dict, string key) {
  exists(KeyValuePair item |
    // d = {KEY: VALUE}
    item = dict.getAnItem() and
    key = item.getKey().(StringLiteral).getS() and
    result = item.getValue()
  )
}

Expr getAssignStmtByKey(AssignStmt assign, string key) {
  exists(Subscript sub |
    // dict['KEY'] = VALUE
    sub = assign.getASubExpression() and
    // Make sure the keys match
    // TODO: What happens if this value itself is not static?
    key = sub.getASubExpression().(StringLiteral).getS() and
    // TODO: Only supports static strings, resolve the value??
    // result = assign.getASubExpression().(StrConst)
    result = sub.getValue()
  )
}

Expr getAnyAssignStmtByKey(string key) { result = getAssignStmtByKey(any(AssignStmt a), key) }

// =========================
// Web Frameworks
// =========================
class FlaskCredentialSink extends CredentialSink {
  FlaskCredentialSink() {
    exists(API::Node node |
      exists(AssignStmt stmt |
        // app = flask.Flask(__name__)
        // app.secret_key = VALUE
        node = Flask::FlaskApp::instance().getMember("secret_key") and
        stmt = node.getAValueReachingSink().asExpr().getParentNode() and
        this = DataFlow::exprNode(stmt.getValue())
      )
      or
      exists(Expr assign, AssignStmt stmt |
        // app.config['SECRET_KEY'] = VALUE
        assign = getAnyAssignStmtByKey("SECRET_KEY").getParentNode() and
        stmt = assign.getParentNode() and
        this = DataFlow::exprNode(stmt.getValue())
      )
      or
      // app.config.update(SECRET_KEY=VALUE)
      node = Flask::FlaskApp::instance().getMember("config").getMember("update") and
      this = DataFlow::exprNode(node.getACall().getArgByName("SECRET_KEY").asExpr())
    )
  }
}

class DjangoCredentialSink extends CredentialSink {
  DjangoCredentialSink() {
    // Check Django import is present
    exists(API::moduleImport("django")) and
    exists(AssignStmt stmt |
      // Check is the SECRET_KEY is in the a settings.py file
      // Removed "settings/develop.py"
      stmt.getLocation().getFile().getBaseName() = ["settings.py", "settings/production.py"] and
      (
        stmt.getATarget().toString() = "SECRET_KEY" and
        this.asExpr() = stmt.getValue()
      )
    )
  }
}

// =========================
// Databases
// =========================
class MySqlSink extends CredentialSink {
  MySqlSink() {
    this =
      API::moduleImport("mysql")
          .getMember("connector")
          .getMember("connect")
          .getACall()
          .getArgByName("password")
  }
}

class AsyncpgSink extends CredentialSink {
  AsyncpgSink() {
    this = API::moduleImport("asyncpg").getMember("connect").getACall().getArgByName("password") or
    this =
      API::moduleImport("asyncpg")
          .getMember("connection")
          .getMember("Connection")
          .getACall()
          .getArgByName("password")
  }
}

class PsycopgSink extends CredentialSink {
  PsycopgSink() {
    this = API::moduleImport("psycopg2").getMember("connect").getACall().getArgByName("password")
  }
}

class AioredisSink extends CredentialSink {
  AioredisSink() {
    this =
      API::moduleImport("aioredis")
          .getMember("create_connection")
          .getACall()
          .getArgByName("password")
    or
    this =
      API::moduleImport("aioredis").getMember("create_pool").getACall().getArgByName("password")
    or
    this =
      API::moduleImport("aioredis").getMember("create_redis").getACall().getArgByName("password")
    or
    // redis = await aioredis.create_redis_pool(
    //   'redis://localhost', password='sEcRet')
    this =
      API::moduleImport("aioredis")
          .getMember("create_redis_pool")
          .getACall()
          .getArgByName("password")
    or
    this =
      API::moduleImport("aioredis")
          .getMember("sentinel")
          .getMember("create_sentinel")
          .getACall()
          .getArgByName("password")
    or
    this =
      API::moduleImport("aioredis")
          .getMember("sentinel")
          .getMember("create_sentinel_pool")
          .getACall()
          .getArgByName("password")
  }
}

// =========================
// Utils
// =========================
class RequestsSink extends CredentialSink {
  RequestsSink() {
    // from requests.auth import HTTPBasicAuth
    // auth = HTTPBasicAuth('user', 'mysecretpassword')
    this =
      API::moduleImport("requests")
          .getMember("auth")
          .getMember("HTTPBasicAuth")
          .getACall()
          .getArg(1)
  }
}

class PyJwtSink extends CredentialSink {
  PyJwtSink() {
    // import jwt
    // encoded = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    this = API::moduleImport("jwt").getMember("encode").getACall().getArg(1)
    or
    // decode = jwt.decode(encoded, "secret", algorithm="HS256")
    this = API::moduleImport("jwt").getMember("decode").getACall().getArg(1)
  }
}

class PyOtpSink extends CredentialSink {
  PyOtpSink() {
    // import pyotp
    // totp = pyotp.TOTP('base32secret3232')
    this = API::moduleImport("pyotp").getMember("TOTP").getACall().getArg(0)
  }
}

class Boto3Sink extends CredentialSink {
  Boto3Sink() {
    // https://docs.min.io/docs/how-to-use-aws-sdk-for-python-with-minio-server.html
    exists(DataFlow::CallCfgNode calls |
      // s3 = boto3.resource('s3',
      //     aws_access_key_id='YOUR-ACCESSKEYID',
      //     aws_secret_access_key='YOUR-SECRETACCESSKEY'
      //     aws_session_token="YOUR-SESSION-TOKEN"
      // )
      calls = API::moduleImport("boto3").getMember(["client", "resource"]).getACall() and
      (
        this = calls.getArgByName("aws_access_key_id") or
        this = calls.getArgByName("aws_secret_access_key") or
        this = calls.getArgByName("aws_session_token")
      )
    )
  }
}
