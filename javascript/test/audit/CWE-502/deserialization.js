// https://github.com/advanced-security/codeql-queries/blob/js/audit/codeql/javascript/ql/test/query-tests/Security/CWE-502/tst.js
const jsyaml = require("js-yaml");

data = jsyaml.load(req.params.data); // NOT OK
data = jsyaml.loadAll(req.params.data); // NOT OK
data = jsyaml.safeLoad(req.params.data); // OK
data = jsyaml.safeLoadAll(req.params.data); // OK

let unsafeConfig = { schema: jsyaml.DEFAULT_FULL_SCHEMA };
data = jsyaml.safeLoad(req.params.data, unsafeConfig); // NOT OK
data = jsyaml.safeLoadAll(req.params.data, unsafeConfig); // NOT OK
