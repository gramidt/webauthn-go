package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"github.com/stretchr/testify/suite"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

const rootCertBytes = "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoXDTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4imsrfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYwHwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAwZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciWDcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XUYjdBz56jSA=="
const leafCertBytes = "MIICnDCCAkKgAwIBAgINAewcjX0ynuzHzwJwazAKBggqhkjOPQQDAjBTMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNRklETyBBbGxpYW5jZTEdMBsGA1UECxMUTWV0YWRhdGEgVE9DIFNpZ25pbmcxDTALBgNVBAMTBENBLTEwHhcNMTgwNDE4MDAwMDAwWhcNMjEwNDE4MDAwMDAwWjBkMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNRklETyBBbGxpYW5jZTEdMBsGA1UECxMUTWV0YWRhdGEgVE9DIFNpZ25pbmcxHjAcBgNVBAMTFU1ldGFkYXRhIFRPQyBTaWduZXIgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIpf6ndbaPUZXiVDCfsdc2PiWH17bABron20EhCFtBOSoy81kacfE6fvJNnc2lg7lkZWCv9cLrqqWLsFYDyOBN+jgekwgeYwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFFyQ0X7PPEy4u+b6pGMt4lB/QPDLMB8GA1UdIwQYMBaAFGkRXi1pZIWdlrjW/1zNvzx1z0wYMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9tZHMuZmlkb2FsbGlhbmNlLm9yZy9DQS0xLmNybDBPBgNVHSAESDBGMEQGCysGAQQBguUcAQMBMDUwMwYIKwYBBQUHAgEWJ2h0dHBzOi8vbWRzLmZpZG9hbGxpYW5jZS5vcmcvcmVwb3NpdG9yeTAKBggqhkjOPQQDAgNIADBFAiEAlG26qOOLu3pkyCThAExxJpL6l/V/UYQy+GDcQ2Mtcq0CIGRYGaFVm8Enga8a9Le3CiLp+tc2N3OcGmPBOUy7pI6t"
const intCertBytes = "MIICsjCCAjigAwIBAgIORqmxk8NQuJfCENVYa1QwCgYIKoZIzj0EAwMwUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoXDTQwMDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRDQS0xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9sDgC8PzBYl/wKqpXfa98jOIo78l9pz4xOzGDGIz0zEXMXsBY6kAhyU4GRmT0wo4tyUvx5BY8OKlsLMzlbKMRaOB7zCB7DAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaRFeLWlkhZ2WuNb/XM2/PHXPTBgwHwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL21kcy5maWRvYWxsaWFuY2Uub3JnL1Jvb3QuY3JsME8GA1UdIARIMEYwRAYLKwYBBAGC5RwBAwEwNTAzBggrBgEFBQcCARYnaHR0cHM6Ly9tZHMuZmlkb2FsbGlhbmNlLm9yZy9yZXBvc2l0b3J5MAoGCCqGSM49BAMDA2gAMGUCMBLVq0JdWv2yY4Rp1IiyIVWEKG1PTz1pPAFqEnakPtw4RMRTGwHdb2ifcDbPoEkfYQIxAOLkfEPj22fBnej1wtgyylsu73rKLUv4xhDy9TAeVUml0iDBM8StE4DiVs/4ejFhqQ=="
const wrongCertBytes = "MIIDATCCAemgAwIBAgIEdbo6tzANBgkqhkiG9w0BAQsFADA4MQswCQYDVQQGEwJLUjENMAsGA1UECgwERVRSSTEaMBgGA1UEAwwRRVRSSSBGSURPIFJvb3QgQ0EwHhcNMTUwOTI1MDU0MzEyWhcNNDUwOTI1MDU0MzEyWjA4MQswCQYDVQQGEwJLUjENMAsGA1UECgwERVRSSTEaMBgGA1UEAwwRRVRSSSBGSURPIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCo17IoUZFypJAvOjw6dZia2PqIn2Jk7JYE6zgT8sJd/g+ZJy94qHppwH3E949uZMsxslO0KIywOVvJM1nbCjGe0bu78BV2LlpqDNPNyCgR17c2/ejvHEqaKGj+GFUKyidiO31EN1d2wAi0xHsgPeistib5scXP2DYCx7yWH3NO4FdNi5SPc67RwGUprdDQ8JBWDY/VhweE7km3vw2fthY7w7tkDY56GeaX8ZmlKMp2fe7smZ+9P+Mpkymla2DbxpohRyLtH3J69ziu0osCCIaDq+BKs1PCZOn/sBoTq6Y19gmClNmKmkyjzdNn3rMkqiqIUmtObct+9GM0SQcNdl5VAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABiCtfHGY0BZu8q4iHDO2iOAoAALNlo09BSSGuCFD9MUZH09WDigIVcf8jXMCOLNH5VUSIfcW7XOaaZqkbJCe+ytXhNXOnHgG/g7DS1oROBYKyxeckHnArJfUXzVrpDXmMF/W9RD+H9Ymw19ZV74ul3vfgzNAcU8wyez4aOtyiwHvGqBygcsKWt2OjAO+BhJ/MeHkD7QPRB0LokhLQ6dpqzxBSuLu3ECmhmpwjPXXdvmSRXvpd1kWAhKd25CeuDvTFo/622LDp3w41OflISxduB4jU7ZO1AjucUJ/yAjTHjfmzQPfZofajKxGb0EetgAEDEQspje8rLx3Aa9DvhZqX0="

const caCrl = `-----BEGIN X509 CRL-----
MIIBDDCBswIBATAKBggqhkjOPQQDAjBTMQswCQYDVQQGEwJVUzEWMBQGA1UEChMN
RklETyBBbGxpYW5jZTEdMBsGA1UECxMUTWV0YWRhdGEgVE9DIFNpZ25pbmcxDTAL
BgNVBAMTBENBLTEXDTIwMDgwNzAwMDAwMFoXDTIwMDkxNTAwMDAwMFqgLzAtMAoG
A1UdFAQDAgE+MB8GA1UdIwQYMBaAFGkRXi1pZIWdlrjW/1zNvzx1z0wYMAoGCCqG
SM49BAMCA0gAMEUCIQCaRXcc0d/a9+wTh4y3NxHHFTmw63tylXTSKU0L84iuQAIg
cTzoZAZRc1377HByMup/eAhx5Kddot2v3Zt/HPbxErs=
-----END X509 CRL-----`

type ChainVerifierSuite struct {
	suite.Suite
	RootCert *x509.Certificate
	IntermediateCert *x509.Certificate
	LeafCert *x509.Certificate
	WrongCert *x509.Certificate
	ChainVerifier *ChainVerifier
}

func (suite *ChainVerifierSuite) SetupSuite() {
	intermediateBytes, _ := base64.StdEncoding.DecodeString(intCertBytes)
	intermediate, _ := x509.ParseCertificate(intermediateBytes)

	leafBytes, _ := base64.StdEncoding.DecodeString(leafCertBytes)
	leaf, _ := x509.ParseCertificate(leafBytes)

	rootBytes, _ := base64.StdEncoding.DecodeString(rootCertBytes)
	root, _ := x509.ParseCertificate(rootBytes)

	wrongBytes, _ := base64.StdEncoding.DecodeString(wrongCertBytes)
	wrong, _ := x509.ParseCertificate(wrongBytes)

	suite.RootCert = root
	suite.IntermediateCert = intermediate
	suite.LeafCert = leaf
	suite.WrongCert = wrong
	suite.ChainVerifier = &ChainVerifier{}
}

func (suite *ChainVerifierSuite) TestVerify() {
	got := suite.ChainVerifier.Verify([]*x509.Certificate{suite.LeafCert, suite.IntermediateCert}, []*x509.Certificate{suite.RootCert})

	suite.Nil(got)
}

func (suite *ChainVerifierSuite) TestVerifyFails() {
	got := suite.ChainVerifier.Verify([]*x509.Certificate{suite.WrongCert}, []*x509.Certificate{suite.RootCert})

	suite.NotNil(got)
}

func TestChainVerifierSuite(t *testing.T) {
	suite.Run(t, new(ChainVerifierSuite))
}

type RevocationVerifierSuite struct {
	suite.Suite
	RevocationVerifier *RevocationVerifier
}

func (suite *RevocationVerifierSuite) SetupSuite() {
	suite.RevocationVerifier = &RevocationVerifier{}
}

func (suite *RevocationVerifierSuite) TestVerify() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(caCrl))
		suite.Nil(err)
	}))
	defer server.Close()

	derBytes, _ := base64.StdEncoding.DecodeString(leafCertBytes)
	certificate, _ := x509.ParseCertificate(derBytes)
	certificate.CRLDistributionPoints = []string{server.URL}

	got := suite.RevocationVerifier.Verify(certificate)

	suite.True(got)
}

func (suite *RevocationVerifierSuite) TestVerifyNoCrlDistributionPoints() {
	// given
	derBytes, _ := base64.StdEncoding.DecodeString(leafCertBytes)
	certificate, _ := x509.ParseCertificate(derBytes)
	certificate.CRLDistributionPoints = []string{}

	got := suite.RevocationVerifier.Verify(certificate)

	suite.True(got)
}

func (suite *RevocationVerifierSuite) TestVerifyCertificateFailsOnInvalidCrl() {
	// given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("ThisIsNotAValidCrl"))
		suite.Nil(err)
	}))

	defer server.Close()
	derBytes, _ := base64.StdEncoding.DecodeString(leafCertBytes)
	certificate, _ := x509.ParseCertificate(derBytes)
	certificate.CRLDistributionPoints = []string{server.URL}

	got := suite.RevocationVerifier.Verify(certificate)

	suite.False(got)
}

func (suite *RevocationVerifierSuite) TestVerifyCertificateFailsOnInvalidCrlUrl() {
	// given
	derBytes, _ := base64.StdEncoding.DecodeString(leafCertBytes)
	certificate, _ := x509.ParseCertificate(derBytes)
	certificate.CRLDistributionPoints = []string{"DonaldTrumpIsAnOrange"}

	got := suite.RevocationVerifier.Verify(certificate)

	suite.False(got)
}

func (suite *RevocationVerifierSuite) TestIsRevokedTrue() {
	// given
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123456),
	}

	revokedCert := pkix.RevokedCertificate{
		SerialNumber: big.NewInt(123456),
	}

	tbsCertList := pkix.TBSCertificateList{
		RevokedCertificates: []pkix.RevokedCertificate{revokedCert},
	}

	revocationList := &pkix.CertificateList{
		TBSCertList: tbsCertList,
	}

	got := suite.RevocationVerifier.IsRevoked(cert, revocationList)

	suite.True(got)
}

func (suite *RevocationVerifierSuite) TestIsRevokedFalse() {
	// given
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123456),
	}

	revokedCert := pkix.RevokedCertificate{
		SerialNumber: big.NewInt(78910),
	}

	tbsCertList := pkix.TBSCertificateList{
		RevokedCertificates: []pkix.RevokedCertificate{revokedCert},
	}

	revocationList := &pkix.CertificateList{
		TBSCertList: tbsCertList,
	}

	got := suite.RevocationVerifier.IsRevoked(cert, revocationList)

	suite.False(got)
}

func TestRevocationVerifierSuite(t *testing.T) {
	suite.Run(t, new(RevocationVerifierSuite))
}