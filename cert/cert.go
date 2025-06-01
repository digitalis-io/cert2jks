package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

type CertificateData struct {
	Certificate   *x509.Certificate
	PrivateKey    []byte
	CACertificate *x509.Certificate
}

func ReadPEMFile(content string) ([]byte, error) {
	if strings.Contains(content, "-----BEGIN") {
		return []byte(content), nil
	}
	return os.ReadFile(content)
}

func ParseCertificateData(certPEM, keyPEM, caPEM []byte) (*CertificateData, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode private key")
	}

	var caCert *x509.Certificate
	if len(caPEM) > 0 {
		caBlock, _ := pem.Decode(caPEM)
		if caBlock != nil && caBlock.Type == "CERTIFICATE" {
			caCert, _ = x509.ParseCertificate(caBlock.Bytes)
		}
	}

	return &CertificateData{
		Certificate:   cert,
		PrivateKey:    keyBlock.Bytes,
		CACertificate: caCert,
	}, nil
}
