package metadata

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/teamhanko/webauthn/metadata/certificate"
	"hash"
)

type MetadataParserVerifier interface {
	ParseAndVerifyMetadataBlob (tokenString string, roots []*x509.Certificate) (*jwt.Token, error)
}

type DefaultMetadataParserVerifier struct {
	CertificateChainVerifier *certificate.ChainVerifier
}

func (p *DefaultMetadataParserVerifier) ParseAndVerifyMetadataBlob (tokenString string, roots []*x509.Certificate) (*jwt.Token, error) {
	parsedToken, err := jwt.ParseWithClaims(tokenString, &MetadataBLOBPayload{}, p.getValidationKeyExtractor(roots))
	if err != nil {
		return nil, err
	}
	return parsedToken, nil
}

func (p *DefaultMetadataParserVerifier) getValidationKeyExtractor(rootCerts []*x509.Certificate) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Verify signing method (alg)
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		if !ok {
			_, ok = token.Method.(*jwt.SigningMethodRSA)
		}
		if !ok {
			return nil, fmt.Errorf("signing method (alg) %s not supported", token.Method)
		}

		// Get certificate chain from token
		certificateChain, err := p.extractCertificateChain(token)
		if err != nil {
			return nil, err
		}

		// Verify certificate chain
		err = p.CertificateChainVerifier.Verify(certificateChain, rootCerts)
		if err != nil {
			return nil, err
		}

		// Get public key
		return certificateChain[0].PublicKey, nil
	}
}

func (p *DefaultMetadataParserVerifier) extractCertificateChain(token *jwt.Token) ([]*x509.Certificate, error) {
	chain, ok := token.Header["x5c"].([]interface{})
	if !ok {
		return nil, errors.New("could not extract certificates from token")
	}

	s := make([]string, len(chain))
	for i, v := range chain {
		s[i] = fmt.Sprint(v)
	}

	var certificates []*x509.Certificate
	// Each string in the array is a base64-encoded (Section 4 of [RFC4648] --
	// not base64url-encoded) DER [ITU.X690.1994] PKIX certificate value.
	for _, v := range s {
		derBytes, err := base64.StdEncoding.DecodeString(v)
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}
	return certificates, nil
}

func (p *DefaultMetadataParserVerifier) getHashForAlg(alg string) (hash.Hash, error) {
	if alg == "ES256" || alg == "RS256" {
		return sha256.New(), nil
	} else if alg == "ES384" || alg == "RS384" {
		return sha512.New384(), nil
	} else if alg == "ES512" || alg == "RS512" {
		return sha512.New(), nil
	} else {
		return nil, errors.New("invalid algorithm")
	}
}