package ports

// SignatureVerifier verifies XML signatures on SAML metadata.
// This is a port interface - implementations are adapters.
//
// The interface returns validated bytes (not just error) following goxmldsig
// best practices to prevent signature wrapping attacks. The returned bytes
// should be used for further processing.
type SignatureVerifier interface {
	// Verify validates the XML signature on metadata and returns the
	// validated XML bytes. Returns error if signature is invalid or missing.
	Verify(data []byte) ([]byte, error)
}

// MetadataSigner signs XML documents for SAML metadata.
// This is a port interface - implementations are adapters.
type MetadataSigner interface {
	// Sign adds an enveloped XML signature to the metadata and returns
	// the signed XML bytes.
	Sign(data []byte) ([]byte, error)
}






