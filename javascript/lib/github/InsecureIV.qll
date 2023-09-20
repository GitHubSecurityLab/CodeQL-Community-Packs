import semmle.javascript.dataflow.TaintTracking

import github.CommandLine

class RandomTaintsSourceConfiguration extends TaintTracking::Configuration {
    RandomTaintsSourceConfiguration() { this = "RandomTaintsSourceConfiguration" }

    override predicate isSource(DataFlow::Node source) {
        isSecureRandom(source)
    }

    override predicate isSink(DataFlow::Node sink) {
        not isSecureRandom(sink)
    }
}

class InsecureIVConfiguration extends TaintTracking::Configuration {
    InsecureIVConfiguration() { this = "InsecureIVConfiguration" }

    override predicate isSource(DataFlow::Node source) {
        exists(Literal literal|literal.flow() = source)
        or
        source instanceof DataFlow::ArrayLiteralNode
        or
        source instanceof RemoteFlowSource
        or
        source instanceof FileSystemReadAccess
        or
        source instanceof DatabaseAccess
        or
        source instanceof CommandLineArgument
        or
        // an external function that is not a known source of randomness
        (
            source instanceof ExternalCallWithOutput
            and not source instanceof CreateIVArgument
            and not source instanceof SecureRandomSource
        )
    }

    override predicate isSink(DataFlow::Node sink) {
        sink instanceof CreateIVArgument
    }
}

class ExternalCallWithOutput extends DataFlow::Node {
    CallExpr call;

    ExternalCallWithOutput() {
        not exists(MethodCallExpr method_call, ThisExpr this_expr| method_call = call and method_call.getReceiver() = this_expr )
        and
        this = call.flow()
    }
}

class SecureRandomSource extends DataFlow::Node {
    SecureRandomSource() {
        isSecureRandom(this)
    }
}

predicate isSecureRandom(DataFlow::Node node) {
    exists(string name|
        name in ["randomBytes", "getRandomValues"] and
        DataFlow::moduleMember("crypto", name).getACall() = node
    )
    or
    exists(string name|
        name in ["randomFill", "randomFillSync"] and
        DataFlow::moduleMember("crypto", name).getACall().getArgument(0) = node
    )
    or
    exists(string name|
        name in ["randomKey", "randomString"] and
        DataFlow::moduleMember("crypto-extra", name).getACall() = node
    )
    or
    exists(string name|
        name in ["cryptoRandomString", "cryptoRandomStringAsync"] and
        DataFlow::moduleMember("crypto-random-string", name).getACall() = node
    )
    or
    exists(string name|
        name in ["secureRandom", "randomArray", "randomUint8Array", "randomBuffer"] and
        DataFlow::moduleMember("secure-random", name).getACall() = node
    )
}

class CreateIVArgument extends DataFlow::Node {
    CreateIVArgument() {
        isCreateIV(this)
    }
}

predicate isCreateIV(DataFlow::Node node) {
    exists(string name|
        name = "createCipheriv" and
        DataFlow::moduleMember("crypto", name).getACall().getArgument(2) = node
    )
}

predicate knownCryptTest(DataFlow::Node sink) {
    sink.getFile().getRelativePath().matches(
        [
            "%/des.js/test/%",
            "test/common/tls.js",
            "test/%/test-crypto-%.js",
            "%/browserify-aes/populateFixtures.js",
            "%/evp_bytestokey%/test.js",
            "%/sshpk/lib/formats/ssh-private.js"
        ]
    )
}
