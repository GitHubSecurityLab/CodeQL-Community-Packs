import csharp

abstract class HardcodedValues extends DataFlow::ExprNode { }

class NonEmptyStringLiteral extends HardcodedValues {
  NonEmptyStringLiteral() { this.getExpr().(StringLiteral).getValue().length() > 1 }
}

class ByteArrayLiteral extends HardcodedValues {
  ByteArrayLiteral() {
    this.getExpr() =
      any(ArrayCreation ac |
        ac.getArrayType().getElementType() instanceof ByteType and
        ac.hasInitializer()
      )
  }
}

class CharArrayLiteral extends HardcodedValues {
  CharArrayLiteral() {
    this.getExpr() =
      any(ArrayCreation ac |
        ac.getArrayType().getElementType() instanceof CharType and
        ac.hasInitializer()
      )
  }
}
