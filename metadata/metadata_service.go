package metadata

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"github.com/teamhanko/webauthn-go/metadata/certificate"
)

// MetadataService interface to get the MetadataStatement for Attestation verification
type MetadataService interface {
	// Get the MetadataStatement of an webauthn Authenticator
	GetWebAuthnAuthenticator(aaguid string) *MetadataStatement
	// Get the MetadataStatemtent of an U2F Authenticator
	GetU2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement
}

//go:embed certificate/globalsign-root-ca.crt
var FidoMdsRootCA []byte

// InMemoryMetadataService keeps the Metadata in memory
type InMemoryMetadataService struct {
	Metadata *MetadataBLOBPayload
}

// Parses and validates a JWT given in bytes and constructs a new in-memory MDS
func NewInMemoryMetadataService(jwtBytes []byte) (*InMemoryMetadataService, error) {
	// Parse FIDO MDS Certificate
	certParser := certificate.PemCertificateParser{}
	rootCa, err := certParser.Parse(FidoMdsRootCA)
	if err != nil {
		return nil, err
	}
	parser := &DefaultMetadataParserVerifier{}
	jwt, err := parser.ParseAndVerifyMetadataBlob(string(jwtBytes), []*x509.Certificate{rootCa})
	if err != nil {
		return nil, err
	}
	metadata, ok := jwt.Claims.(*MetadataBLOBPayload)
	if !ok {
		return nil, errors.New("Could not TypeAssert metadata")
	}
	err = metadata.Valid()
	if err != nil {
		return nil, err
	}

	mds := &InMemoryMetadataService{
		Metadata: metadata,
	}

	return mds, nil
}

func (d *InMemoryMetadataService) GetWebAuthnAuthenticator(aaguid string) *MetadataStatement {
	for _, v := range d.Metadata.Entries {
		if v.AaGUID == aaguid {
			return &v.MetadataStatement
		}
	}
	return nil
}

func (d *InMemoryMetadataService) GetU2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement {
	for _, v := range d.Metadata.Entries {
		for _, w := range v.AttestationCertificateKeyIdentifiers {
			if w == attestationCertificateKeyIdentifier {
				return &v.MetadataStatement
			}
		}
	}
	return nil
}

func (d *InMemoryMetadataService) GetNextUpdateDate() string {
	return d.Metadata.NextUpdate
}

func (d *InMemoryMetadataService) GetMetadataNumber() int {
	return d.Metadata.Number
}
