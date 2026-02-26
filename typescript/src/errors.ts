export class HttpSigError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = "HttpSigError";
  }
}

export class UnknownAlgorithmError extends HttpSigError {
  constructor(alg: string) {
    super(`unknown algorithm: ${alg}`, "UNKNOWN_ALGORITHM");
    this.name = "UnknownAlgorithmError";
  }
}

export class InvalidKeyError extends HttpSigError {
  constructor(message: string) {
    super(message, "INVALID_KEY");
    this.name = "InvalidKeyError";
  }
}

export class InvalidSignatureError extends HttpSigError {
  constructor(message = "invalid signature") {
    super(message, "INVALID_SIGNATURE");
    this.name = "InvalidSignatureError";
  }
}

export class MissingComponentError extends HttpSigError {
  constructor(component: string) {
    super(`missing component: ${component}`, "MISSING_COMPONENT");
    this.name = "MissingComponentError";
  }
}

export class MissingSignatureError extends HttpSigError {
  constructor() {
    super("missing signature", "MISSING_SIGNATURE");
    this.name = "MissingSignatureError";
  }
}

export class SignatureExpiredError extends HttpSigError {
  constructor() {
    super("signature expired", "SIGNATURE_EXPIRED");
    this.name = "SignatureExpiredError";
  }
}

export class KeyNotFoundError extends HttpSigError {
  constructor(keyId: string) {
    super(`key not found: ${keyId}`, "KEY_NOT_FOUND");
    this.name = "KeyNotFoundError";
  }
}

export class MalformedInputError extends HttpSigError {
  constructor(message: string) {
    super(message, "MALFORMED_INPUT");
    this.name = "MalformedInputError";
  }
}

export class DuplicateComponentError extends HttpSigError {
  constructor(component: string) {
    super(`duplicate component: ${component}`, "DUPLICATE_COMPONENT");
    this.name = "DuplicateComponentError";
  }
}
