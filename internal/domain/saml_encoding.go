package domain

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
)

// DecodeSAMLRequest decodes a SAML request from HTTP-Redirect binding format.
// The pipeline is: URL decode -> Base64 decode -> Deflate inflate.
//
// This is a pure function that contains no I/O or external dependencies.
func DecodeSAMLRequest(encoded string) ([]byte, error) {
	// Step 1: URL decode
	urlDecoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, fmt.Errorf("URL decode SAMLRequest: %w", err)
	}

	// Step 2: Base64 decode
	base64Decoded, err := base64.StdEncoding.DecodeString(urlDecoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode SAMLRequest: %w", err)
	}

	// Step 3: Inflate (deflate decompress)
	inflatedReader := flate.NewReader(bytes.NewReader(base64Decoded))
	defer inflatedReader.Close()

	inflatedBytes, err := io.ReadAll(inflatedReader)
	if err != nil {
		return nil, fmt.Errorf("inflate SAMLRequest: %w", err)
	}

	return inflatedBytes, nil
}

// EncodeSAMLRequest encodes a SAML request for HTTP-Redirect binding format.
// The pipeline is: Deflate compress -> Base64 encode -> URL encode.
//
// This is a pure function that contains no I/O or external dependencies.
func EncodeSAMLRequest(xml []byte) (string, error) {
	// Step 1: Deflate compress
	var buf bytes.Buffer
	flateWriter, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("create deflate writer: %w", err)
	}

	if _, err := flateWriter.Write(xml); err != nil {
		flateWriter.Close()
		return "", fmt.Errorf("deflate SAMLRequest: %w", err)
	}
	flateWriter.Close()

	// Step 2: Base64 encode
	base64Encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	// Step 3: URL encode
	urlEncoded := url.QueryEscape(base64Encoded)

	return urlEncoded, nil
}
