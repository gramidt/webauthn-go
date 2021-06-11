package metadata

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"errors"
	"github.com/teamhanko/webauthn/metadata/certificate"
	"log"
	"net/http"
)
type MetadataService interface {
	WebAuthnAuthenticator(aaguid string) *MetadataStatement
	U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement
}


//go:embed globalsign-root-ca.crt
var fidoMdsRootCA []byte

const fidoMDSURL = "https://mds.fidoalliance.org/"

type DefaultMetadataService struct {
	mdsUrl string
	rootCert x509.Certificate
	metadata MetadataBLOBPayload
}

func NewDefaultMetadataService() *DefaultMetadataService {
	return NewDefaultMetadataServiceWithUrl(fidoMDSURL)
}

func NewDefaultMetadataServiceWithUrl(mdsURL string) *DefaultMetadataService {
	certParser := certificate.PemCertificateParser{}
	cert, err := certParser.Parse(fidoMdsRootCA)
	if err != nil {
		log.Println(err)
		return nil
	}
	return &DefaultMetadataService{
		rootCert: *cert,
		mdsUrl: mdsURL,
	}
}

func (d *DefaultMetadataService) Fetch() error {
	client := http.Client{}
	resp, err := client.Get(d.mdsUrl)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return err
	}

	parser := &DefaultMetadataParserVerifier{}
	jwt, err := parser.ParseAndVerifyMetadataBlob(buf.String(), []*x509.Certificate{&d.rootCert})
	if err != nil {
		return err
	}
	metadata, ok := jwt.Claims.(*MetadataBLOBPayload)
	if !ok {
		return errors.New("Could not TypeAssert metadata")
	}
	d.metadata = *metadata
	log.Printf("Fetched Metadata Nr. %v", d.metadata.Number)
	return d.metadata.Valid()
}

func (d *DefaultMetadataService) WebAuthnAuthenticator(aaguid string) *MetadataStatement {
	for _, v := range d.metadata.Entries {
		if v.AaGUID == aaguid {
			return &v.MetadataStatement
		}
	}
	return nil
}

func (d *DefaultMetadataService) U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement {
	for _, v := range d.metadata.Entries {
		for _, w := range v.AttestationCertificateKeyIdentifiers {
			if  w == attestationCertificateKeyIdentifier {
				return &v.MetadataStatement
			}
		}
	}
	return nil
}
