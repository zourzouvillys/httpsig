package httpsig

import "errors"

var (
	// ErrUnknownAlgorithm is returned when an algorithm identifier is not recognized.
	ErrUnknownAlgorithm = errors.New("httpsig: unknown algorithm")

	// ErrInvalidKey is returned when a key is invalid for the requested operation.
	ErrInvalidKey = errors.New("httpsig: invalid key")

	// ErrInvalidSignature is returned when a signature fails verification.
	ErrInvalidSignature = errors.New("httpsig: invalid signature")

	// ErrMissingComponent is returned when a required component is not present in the message.
	ErrMissingComponent = errors.New("httpsig: missing component")

	// ErrMissingSignature is returned when no signature with the requested label exists.
	ErrMissingSignature = errors.New("httpsig: missing signature")

	// ErrSignatureExpired is returned when a signature's created/expires times are out of bounds.
	ErrSignatureExpired = errors.New("httpsig: signature expired")

	// ErrKeyNotFound is returned when a key provider cannot find a key for the given keyId.
	ErrKeyNotFound = errors.New("httpsig: key not found")

	// ErrMalformedSignatureInput is returned when the Signature-Input header cannot be parsed.
	ErrMalformedSignatureInput = errors.New("httpsig: malformed signature-input")

	// ErrMalformedSignature is returned when the Signature header value cannot be parsed.
	ErrMalformedSignature = errors.New("httpsig: malformed signature")

	// ErrDuplicateComponent is returned when a component appears more than once in the covered components.
	ErrDuplicateComponent = errors.New("httpsig: duplicate component")
)
