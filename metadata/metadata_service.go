package metadata

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"github.com/teamhanko/webauthn/metadata/certificate"
)

type MetadataService interface {
	WebAuthnAuthenticator(aaguid string) *MetadataStatement
	U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement
}

//go:embed certificate/globalsign-root-ca.crt
var FidoMdsRootCA []byte

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

func (d *InMemoryMetadataService) WebAuthnAuthenticator(aaguid string) *MetadataStatement {
	for _, v := range d.Metadata.Entries {
		if v.AaGUID == aaguid {
			return &v.MetadataStatement
		}
	}
	return nil
}

func (d *InMemoryMetadataService) U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement {
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
