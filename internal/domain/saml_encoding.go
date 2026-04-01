package domain

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
)

// maxSAMLRequestSize is the upper bound on the decompressed size of a SAML
// redirect-binding request. Legitimate AuthnRequests are well under 100 KB;
// 10 MB guards against decompression bombs without affecting real traffic.
const maxSAMLRequestSize = 10 * 1024 * 1024 // 10 MB

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

	// Step 3: Inflate (deflate decompress) with size limit to guard against
	// decompression bombs. We read one byte beyond the limit so we can detect
	// when the stream is truncated vs. exactly at the boundary.
	inflatedReader := flate.NewReader(bytes.NewReader(base64Decoded))
	defer inflatedReader.Close()

	limitedReader := io.LimitReader(inflatedReader, maxSAMLRequestSize+1)
	inflatedBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("inflate SAMLRequest: %w", err)
	}
	if int64(len(inflatedBytes)) > maxSAMLRequestSize {
		return nil, fmt.Errorf("inflate SAMLRequest: decompressed size exceeds %d bytes", maxSAMLRequestSize)
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
