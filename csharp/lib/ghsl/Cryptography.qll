import csharp

module Cryptography {
  class HashingAlgorithm extends DataFlow::ExprNode {
    abstract DataFlow::ExprNode getHashValue();

    abstract DataFlow::ExprNode getSalt();

    abstract int defaultIterations();

    abstract DataFlow::ExprNode getIterations();
  }

  class HMacSigningAlgorithm extends DataFlow::ExprNode {
    abstract string algorithm();

    abstract DataFlow::ExprNode key();
  }

  class AsymmetricAlgorithm extends DataFlow::ExprNode {
    abstract int maxKeySize();

    abstract int minKeySize();

    abstract int getKeySize();
  }

  // Abstraction classes
  abstract class HashingAlgorithms extends HashingAlgorithm { }

  abstract class HMacSigningAlgorithms extends HMacSigningAlgorithm { }

  abstract class AsymmetricAlgorithms extends AsymmetricAlgorithm { }

  // Content
  class CryptoRfc2898DeriveBytes extends HashingAlgorithms {
    CryptoRfc2898DeriveBytes() {
      exists(ObjectCreation object |
        object.getType().hasFullyQualifiedName("System.Security.Cryptography", "Rfc2898DeriveBytes") and
        this.asExpr() = object
      )
    }

    override DataFlow::ExprNode getHashValue() {
      result.asExpr() = this.asExpr().(ObjectCreation).getArgument(0)
    }

    override DataFlow::ExprNode getSalt() {
      result.asExpr() = this.asExpr().(ObjectCreation).getArgument(1)
    }

    override int defaultIterations() { result = 1000 }

    override DataFlow::ExprNode getIterations() {
      result.asExpr() = this.asExpr().(ObjectCreation).getArgument(2)
      or
      // TODO: It this the best way? We need a better way of determinding
      // iterations isn't set.
      this.getExpr().(ObjectCreation).getNumberOfArguments() <= 2 and
      this.defaultIterations() < 100000 and
      result.asExpr() = this.getExpr()
    }
  }

  class DSACryptoServiceProvider extends AsymmetricAlgorithms {
    DSACryptoServiceProvider() {
      exists(ObjectCreation object |
        object
            .getType()
            .hasFullyQualifiedName("System.Security.Cryptography", "DSACryptoServiceProvider") and
        this.asExpr() = object
      )
    }

    override int maxKeySize() { result = 1024 }

    override int minKeySize() { result = 1024 }

    override int getKeySize() {
      this.asExpr().(ObjectCreation).hasNoArguments() and
      result = 1024
      or
      // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider.-ctor?view=net-6.0#system-security-cryptography-dsacryptoserviceprovider-ctor(system-int32)
      result = this.asExpr().(ObjectCreation).getArgument(0).getValue().toInt()
    }
  }

  class RC2CryptoServiceProvider extends AsymmetricAlgorithms {
    RC2CryptoServiceProvider() {
      exists(ObjectCreation object |
        object
            .getType()
            .hasFullyQualifiedName("System.Security.Cryptography", "RC2CryptoServiceProvider") and
        this.asExpr() = object
      )
    }

    override int maxKeySize() { result = 128 }

    override int minKeySize() { result = 128 }

    override int getKeySize() {
      this.asExpr().(ObjectCreation).hasNoArguments() and
      result = 128 // default
      or
      // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider.-ctor?view=net-6.0#system-security-cryptography-dsacryptoserviceprovider-ctor(system-int32)
      result = this.asExpr().(ObjectCreation).getArgument(0).getValue().toInt()
    }
  }

  class RSA extends AsymmetricAlgorithms {
    RSA() {
      exists(ObjectCreation object |
        object
            .getType()
            .hasFullyQualifiedName("System.Security.Cryptography",
              ["RSACryptoServiceProvider", "RSACng"]) and
        this.asExpr() = object
      )
      or
      exists(MethodCall call |
        call.getType().hasFullyQualifiedName("System.Security.Cryptography", ["RSA"]) and
        call.getTarget().hasName("Create") and
        this.asExpr() = call
      )
    }

    override int maxKeySize() { result = 2048 }

    override int minKeySize() { result = 2048 }

    override int getKeySize() {
      (
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider.-ctor?view=net-6.0#system-security-cryptography-dsacryptoserviceprovider-ctor(system-int32)
        this.asExpr().(ObjectCreation).hasNoArguments() and
        result = 1024
        or
        result = this.asExpr().(ObjectCreation).getArgument(0).getValue().toInt()
      )
      or
      (
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.create?view=net-6.0#system-security-cryptography-rsa-create(system-int32)
        this.asExpr().(MethodCall).hasNoArguments() and
        result = 1024
        or
        result = this.asExpr().(MethodCall).getArgument(0).getValue().toInt()
      )
    }
  }

  class HMac extends HMacSigningAlgorithms {
    HMac() {
      exists(ObjectCreation object |
        object
            .getType()
            .hasFullyQualifiedName("System.Security.Cryptography",
              ["HMACMD5", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACRIPEMD160"]) and
        this.asExpr() = object
      )
    }

    override string algorithm() {
      result = this.getType().getName().toUpperCase().replaceAll("HMAC", "")
    }

    override DataFlow::ExprNode key() {
      result.asExpr() = this.asExpr().(ObjectCreation).getArgument(0)
    }
  }
}
