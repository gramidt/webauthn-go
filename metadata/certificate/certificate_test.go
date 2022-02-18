package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"github.com/stretchr/testify/suite"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

//go:embed globalsign-root-ca.crt
var rootCertBytes []byte

const leafCertBytes = "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"
const intCertBytes = "MIIEYTCCA0mgAwIBAgIOSKQC3SeSDaIINJ3RmXswDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTYwOTIxMDAwMDAwWhcNMjYwOTIxMDAwMDAwWjBiMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTE4MDYGA1UEAxMvR2xvYmFsU2lnbiBFeHRlbmRlZCBWYWxpZGF0aW9uIENBIC0gU0hBMjU2IC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrawNnVNXcEfvFohPBjBkn3BB04mGDPfqO24+lD+SpvkY/Ar5EpAkcJjOfR0iBFYhWN80HzpXYy2tIA7mbXpKu2JpmYdU1xcoQpQK0ujE/we+vEDyjyjmtf76LLqbOfuq3xZbSqUqAY+MOvA67nnpdawvkHgJBFVPnxui45XH4BwTwbtDucx+Mo7EK4mS0Ti+P1NzARxFNCUFM8Wxc32wxXKff6WU4TbqUx/UJm485ttkFqu0Ox4wTUUbn0uuzK7yV3Y986EtGzhKBraMH36MekSYlE473GqHetRi9qbNG5pM++Sa+WjR9E1e0Yws16CGqsmVKwAqg4uc43eBTFUhVAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU3bPnbagu6MVObs905nU8lBXO6B0wHwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLdG7wwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHIzMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yMy5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQBVaJzl0J/i0zUV38iMXIQ+Q/yht+JZZ5DW1otGL5OYV0LZ6ZE6xh+WuvWJJ4hrDbhfo6khUEaFtRUnurqzutvVyWgW8msnoP0gtMZO11cwPUMUuUV8iGyIOuIB0flo6G+XbV74SZuR5v5RAgqgGXucYUPZWvv9AfzMMQhRQkr/MO/WR2XSdiBrXHoDL2xk4DmjA4K6iPI+1+qMhyrkUM/2ZEdA8ldqwl8nQDkKS7vq6sUZ5LPVdfpxJZZu5JBj4y7FNFTVW1OMlCUvwt5H8aFgBMLFik9xqK6JFHpYxYmf4t2sLLxN0LlCthJEabvp10ZlOtfu8hL5gCXcxnwGxzSb"
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
	RootCert         *x509.Certificate
	IntermediateCert *x509.Certificate
	LeafCert         *x509.Certificate
	WrongCert        *x509.Certificate
	ChainVerifier    *ChainVerifier
}

func (suite *ChainVerifierSuite) SetupSuite() {
	intermediateBytes, _ := base64.StdEncoding.DecodeString(intCertBytes)
	intermediate, _ := x509.ParseCertificate(intermediateBytes)

	leafBytes, _ := base64.StdEncoding.DecodeString(leafCertBytes)
	leaf, _ := x509.ParseCertificate(leafBytes)

	certParser := PemCertificateParser{}
	root, err := certParser.Parse(rootCertBytes)
	if err != nil {
		log.Println(err)
	}

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
