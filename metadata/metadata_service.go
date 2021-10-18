package metadata

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"errors"
	"github.com/go-co-op/gocron"
	"github.com/teamhanko/webauthn/metadata/certificate"
	"log"
	"net/http"
	"sync"
	"time"
)

type MetadataService interface {
	WebAuthnAuthenticator(aaguid string) *MetadataStatement
	U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement
}


//go:embed certificate/globalsign-root-ca.crt
var fidoMdsRootCA []byte

const fidoMDSURL = "https://mds.fidoalliance.org/"

type InMemoryMetadataService struct {
	mdsUrl string
	rootCert x509.Certificate
	Metadata *MetadataBLOBPayload
	mu sync.RWMutex
	scheduler *gocron.Scheduler
}

func NewInMemoryMetadataService() *InMemoryMetadataService {
	return NewInMemoryMetadataServiceWithUrl(fidoMDSURL)
}

func NewInMemoryMetadataServiceWithUrl(mdsURL string) *InMemoryMetadataService {
	certParser := certificate.PemCertificateParser{}
	cert, err := certParser.Parse(fidoMdsRootCA)
	if err != nil {
		log.Println(err)
		return nil
	}
	scheduler := gocron.NewScheduler(time.UTC)

	d := &InMemoryMetadataService{
		rootCert: *cert,
		mdsUrl: mdsURL,
		scheduler: scheduler,
		Metadata: &MetadataBLOBPayload{},
		mu: sync.RWMutex{},
	}
	_, err = scheduler.Every(1).Day().At("00:00").Do(d.Update)
	if err != nil {log.Println(err)}
	scheduler.StartAsync()
	err = d.Update()
	if err != nil {
		log.Println(err)
		return nil
	}
	return d
}

func (d *InMemoryMetadataService) Update() error {
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
	log.Printf("Fetched Metadata Nr. %v", metadata.Number)
	err = metadata.Valid()
	if err != nil {
		return err
	}
	log.Printf("Metadata valid.")
	log.Printf("Found: %v entries.", len(metadata.Entries))

	d.mu.Lock()
	d.Metadata = metadata
	d.mu.Unlock()

	return nil
}

func (d *InMemoryMetadataService) WebAuthnAuthenticator(aaguid string) *MetadataStatement {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, v := range d.Metadata.Entries {
		if v.AaGUID == aaguid {
			return &v.MetadataStatement
		}
	}
	return nil
}

func (d *InMemoryMetadataService) U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, v := range d.Metadata.Entries {
		for _, w := range v.AttestationCertificateKeyIdentifiers {
			if  w == attestationCertificateKeyIdentifier {
				return &v.MetadataStatement
			}
		}
	}
	return nil
}
