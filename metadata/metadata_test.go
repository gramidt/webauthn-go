package metadata

import (
	"crypto/x509"
	"github.com/teamhanko/webauthn-go/metadata/certificate"
	"io/ioutil"
	"testing"
)

func TestMetadataLoad(t *testing.T) {
	bytes, err := ioutil.ReadFile("./blob-6.jwt")
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	roots, err := ioutil.ReadFile("certificate/globalsign-root-ca.crt")
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	certParser := certificate.PemCertificateParser{}
	cert, err := certParser.Parse(roots)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	rootCerts := []*x509.Certificate{cert}
	parser := &DefaultMetadataParserVerifier{}
	jwt, err := parser.ParseAndVerifyMetadataBlob(string(bytes), rootCerts)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	metadata, ok := jwt.Claims.(*MetadataBLOBPayload)
	if !ok {
		t.Log("Type Assertion Failed...")
		t.Fail()
	}
	err = metadata.Valid()
	if err != nil {
		t.Fail()
	}
}

func TestNewInMemoryMetadataServiceBlob6(t *testing.T) {
	bytes, err := ioutil.ReadFile("./blob-6.jwt")
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	_, err = NewInMemoryMetadataService(bytes)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestNewInMemoryMetadataServiceBlob12(t *testing.T) {
	bytes, err := ioutil.ReadFile("./blob-12.jwt")
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	_, err = NewInMemoryMetadataService(bytes)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestSelfUpdatingMetadataService(t *testing.T) {
	def, err := NewSelfUpdatingMetaDataService()
	if err != nil {
		t.Fail()
	}
	statement := def.WebAuthnAuthenticator("3b1adb99-0dfe-46fd-90b8-7f7614a4de2a")
	if statement == nil {
		t.Fail()
	}
	statement = def.U2FAuthenticator("fd36573d24be3f7f32ad5040271ab61035a1fcad")
	if statement == nil {
		t.Fail()
	}
}
