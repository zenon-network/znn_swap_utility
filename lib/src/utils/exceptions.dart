abstract class SwapException implements Exception {
  final String cause;

  SwapException(this.cause);

  @override
  String toString() {
    return cause;
  }
}

class InvalidChecksumException extends SwapException {
  InvalidChecksumException(String cause) : super(cause);
}

class IllegalCharacterException extends SwapException {
  IllegalCharacterException(String cause) : super(cause);
}

class InvalidParameterException extends SwapException {
  InvalidParameterException(String cause) : super(cause);
}

class InvalidPathException extends SwapException {
  InvalidPathException(String cause) : super(cause);
}

class InvalidPointException extends SwapException {
  InvalidPointException(String cause) : super(cause);
}

class InvalidKeyException extends SwapException {
  InvalidKeyException(String cause) : super(cause);
}

class SignatureException extends SwapException {
  SignatureException(String cause) : super(cause);
}
