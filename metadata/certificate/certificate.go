package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
)

type ChainVerifier struct{}

func (v *ChainVerifier) Verify(chain []*x509.Certificate, rootCertificates []*x509.Certificate) error {
	roots := x509.NewCertPool()
	for _, v := range rootCertificates {
		roots.AddCert(v)
	}

	leafCert := chain[0]
	intermediateCerts := chain[1:]

	intermediates := x509.NewCertPool()
	for _, cert := range intermediateCerts {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err := leafCert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}

type RevocationVerifier struct{}

func (v *RevocationVerifier) Verify(certificate *x509.Certificate) bool {

	crls, err := v.getCrls(certificate)
	if err != nil {
		log.Println(err)
		return false
	}

	for _, crl := range crls {
		if v.IsRevoked(certificate, crl) {
			log.Println("Certificate got revoked.")
			return false
		}
	}

	return true
}

func (v *RevocationVerifier) getCrls(certificate *x509.Certificate) ([]*pkix.CertificateList, error) {
	distributionPoints := certificate.CRLDistributionPoints

	client := &http.Client{}

	var crls []*pkix.CertificateList
	for _, point := range distributionPoints {
		resp, err := client.Get(point)

		if err != nil {
			errors.Wrap(err, fmt.Sprintf("could not fetch CRL for distribution point %s", point))
			return nil, err
		}

		crlBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		crl, err := x509.ParseCRL(crlBytes)
		if err != nil {
			errors.Wrap(err, fmt.Sprintf("could not parse CRL: %s", err))
			return nil, err
		} else {
			crls = append(crls, crl)
		}
	}

	return crls, nil
}

func (v *RevocationVerifier) IsRevoked(certificate *x509.Certificate, crl *pkix.CertificateList) bool {
	for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
		if revokedCertificate.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true
		}
	}

	return false
}

type PemCertificateParser struct{}

func (p *PemCertificateParser) Parse(certBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %s", err.Error())
	}

	return cert, nil
}
