// https://github.com/advanced-security/codeql-queries/blob/js/audit/codeql/javascript/ql/test/query-tests/Security/CWE-611/libxml.sax.js

const libxmljs = require('libxmljs');

// noent
libxmljs.parseXml(req.param("some-xml"), { noent: true });      // NOT OK
libxmljs.parseXmlString(req.param("some-xml"), {noent:true})    // NOT OK

// SAX
var parser = new libxmljs.SaxParser();
parser.parseString(req.param("some-xml")); // NOT OK

// SAX Push
var parser = new libxmljs.SaxPushParser();
parser.push(req.param("some-xml"));