/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// checkCABundleExpiry parses every CERTIFICATE block in pemData and returns
// an error if any certificate has already expired relative to now.
func checkCABundleExpiry(pemData []byte, now time.Time) error {
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA certificate: %w", err)
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("CA certificate %q expired on %s",
				cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339))
		}
	}
}
