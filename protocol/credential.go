package protocol

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/scan/crypto/sha1"
	uuid "github.com/satori/go.uuid"
	"github.com/teamhanko/webauthn/credential"
	"github.com/teamhanko/webauthn/metadata"
	"io"
	"net/http"
)

// The basic credential type that is inherited by WebAuthn's
// PublicKeyCredential type
// https://w3c.github.io/webappsec-credential-management/#credential
type Credential struct {
	// ID is The credential’s identifier. The requirements for the
	// identifier are distinct for each type of credential. It might
	// represent a username for username/password tuples, for example.
	ID string `json:"id"`
	// Type is the value of the object’s interface object's [[type]] slot,
	// which specifies the credential type represented by this object.
	// This should be type "public-key" for Webauthn credentials.
	Type string `json:"type"`
}

// The PublicKeyCredential interface inherits from Credential, and contains
//  the attributes that are returned to the caller when a new credential
// is created, or a new assertion is requested.
type ParsedCredential struct {
	ID   string `cbor:"id"`
	Type string `cbor:"type"`
}

type PublicKeyCredential struct {
	Credential
	RawID      URLEncodedBase64                      `json:"rawId"`
	Extensions AuthenticationExtensionsClientOutputs `json:"extensions,omitempty"`
}

type ParsedPublicKeyCredential struct {
	ParsedCredential
	RawID      []byte                                `json:"rawId"`
	Extensions AuthenticationExtensionsClientOutputs `json:"extensions,omitempty"`
}

type CredentialCreationResponse struct {
	PublicKeyCredential
	AttestationResponse AuthenticatorAttestationResponse `json:"response"`
}

type ParsedCredentialCreationData struct {
	ParsedPublicKeyCredential
	Response ParsedAttestationResponse
	Raw      CredentialCreationResponse
}

func ParseCredentialCreationResponse(response *http.Request) (*ParsedCredentialCreationData, error) {
	if response == nil || response.Body == nil {
		return nil, ErrBadRequest.WithDetails("No response given")
	}
	return ParseCredentialCreationResponseBody(response.Body)
}

func ParseCredentialCreationResponseBody(body io.Reader) (*ParsedCredentialCreationData, error) {
	var ccr CredentialCreationResponse
	err := json.NewDecoder(body).Decode(&ccr)
	if err != nil {
		return nil, ErrBadRequest.WithDetails("Parse error for Registration").WithInfo(err.Error())
	}

	if ccr.ID == "" {
		return nil, ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("Missing ID")
	}

	testB64, err := base64.RawURLEncoding.DecodeString(ccr.ID)
	if err != nil || !(len(testB64) > 0) {
		return nil, ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("ID not base64.RawURLEncoded")
	}

	if ccr.PublicKeyCredential.Credential.Type == "" {
		return nil, ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("Missing type")
	}

	if ccr.PublicKeyCredential.Credential.Type != "public-key" {
		return nil, ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("Type not public-key")
	}

	var pcc ParsedCredentialCreationData
	pcc.ID, pcc.RawID, pcc.Type = ccr.ID, ccr.RawID, ccr.Type
	pcc.Raw = ccr

	parsedAttestationResponse, err := ccr.AttestationResponse.Parse()
	if err != nil {
		return nil, ErrParsingData.WithDetails("Error parsing attestation response")
	}

	pcc.Response = *parsedAttestationResponse

	return &pcc, nil
}

// Verifies the Client and Attestation data as laid out by §7.1. Registering a new credential
// https://www.w3.org/TR/webauthn-1/#registering-a-new-credential
func (pcc *ParsedCredentialCreationData) Verify(storedChallenge string, verifyUser bool, relyingPartyID string, relyingPartyOrigins []string, metadataService metadata.MetadataService, credentialStore credential.CredentialService, rpPolicy RelyingPartyPolicy) error {

	// Handles steps 3 through 6 - Verifying the Client Data against the Relying Party's stored data
	verifyError := pcc.Response.CollectedClientData.Verify(storedChallenge, CreateCeremony, relyingPartyOrigins)
	if verifyError != nil {
		return verifyError
	}

	// Step 7. Compute the hash of response.clientDataJSON using SHA-256.
	clientDataHash := sha256.Sum256(pcc.Raw.AttestationResponse.ClientDataJSON)

	// Step 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
	// structure to obtain the attestation statement format fmt, the authenticator data authData, and the
	// attestation statement attStmt. is handled while

	// TODO: Maybe check RP Policy first (if aaguid is in allowed authenticators list)

	// We do the above step while parsing and decoding the CredentialCreationResponse
	// Handle steps 9 through 14 - This verifies the attestaion object and
	verifyError = pcc.Response.AttestationObject.Verify(relyingPartyID, clientDataHash[:], verifyUser)
	if verifyError != nil {
		return verifyError
	}

	// Step 15. If validation is successful, obtain a list of acceptable trust anchors (attestation root
	// certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement
	// format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service provides
	// one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
	// [https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-service-v2.0-id-20180227.html]

	// TODO: if RelyingPartyPolicy allows any authenticator, then skip step 15 & 16
	var attestationTrustworthinessError error
	var metadataStatement *metadata.MetadataStatement
	if metadataService != nil {
		metadataStatement = GetMetadataStatement(pcc, metadataService)
		// TODO: When Apple send the right AAGUID, and authenticator is in metadata service, then remove check if format is `apple`
		if metadataStatement == nil && pcc.Response.AttestationObject.Format != "none" && pcc.Response.AttestationObject.Format != "apple" {
			attestationTrustworthinessError = ErrMetadataNotFound
		} else {

			// Step 16. Assess the attestation trustworthiness using outputs of the verification procedure in step 14, as follows:
			// - If self attestation was used, check if self attestation is acceptable under Relying Party policy.
			// - If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in
			//   the set of acceptable trust anchors obtained in step 15.
			// - Otherwise, use the X.509 certificates returned by the verification procedure to verify that the
			//   attestation public key correctly chains up to an acceptable root certificate.

			switch pcc.Response.AttestationObject.Format {
			case "packed":
				// Basic, Self, AttCA, ECDAA
				if pcc.isBasicOrAttCaAttestation() {
					attestationTrustworthinessError = verifyBasicOrAttCaAttestation(metadataStatement, pcc)
				} else if pcc.isEcdaaAttestation() {
					attestationTrustworthinessError = verifyEcdaaKeyId(metadataStatement, pcc)
				} else if pcc.isSelfAttestation() {
					attestationTrustworthinessError = nil
				}
			case "apple":
				// AttCA
				// TODO: When Apple send the right AAGUID, and authenticator is in metadata service, then check against metadataService (add verifyBasicOrAttCaAttestation() call)
				attestationTrustworthinessError = nil
			case "tpm":
				// Basic, AttCA
				attestationTrustworthinessError = verifyBasicOrAttCaAttestation(metadataStatement, pcc)
			case "android-key":
				// Basic (has x5c)
				attestationTrustworthinessError = verifyBasicOrAttCaAttestation(metadataStatement, pcc)
			case "android-safetynet":
				// Basic
				attestationTrustworthinessError = nil // should be verified before in attestation_safetynet.go
			case "fido-u2f":
				// Basic, AttCA (has x5c)
				attestationTrustworthinessError = verifyBasicOrAttCaAttestation(metadataStatement, pcc)
			case "none":
				attestationTrustworthinessError = nil // does not need verification
			}

			if attestationTrustworthinessError != nil {
				return attestationTrustworthinessError
			}
		}
	}

	// Step 17. Check that the credentialId is not yet registered to any other user. If registration is
	// requested for a credential that is already registered to a different user, the Relying Party SHOULD
	// fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting
	// the older registration.
	if credentialStore != nil {
		cred, err := credentialStore.ExistsCredential(pcc.Response.AttestationObject.AuthData.AttData.CredentialID)
		if err != nil {
			return err
		}
		if cred {
			return ErrCredentialAlreadyExists
		}
	}

	// Step 18 If the attestation statement attStmt verified successfully and is found to be trustworthy, then
	// register the new credential with the account that was denoted in the options.user passed to create(), by
	// associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as
	// appropriate for the Relying Party's system.

	// Can't be done here, because the library has no database access

	// Step 19. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above,
	// the Relying Party SHOULD fail the registration ceremony.

	if rpPolicy != nil {
		policyError := rpPolicy.Verify(pcc, attestationTrustworthinessError, metadataStatement)
		if policyError != nil {
			return policyError
		}
	} else {
		if attestationTrustworthinessError != nil {
			return attestationTrustworthinessError
		}
	}

	return nil
}

func (pcc *ParsedCredentialCreationData) isBasicOrAttCaAttestation() bool {
	_, x5cPresent := pcc.Response.AttestationObject.AttStatement["x5c"].([]interface{})
	return x5cPresent
}

func (pcc *ParsedCredentialCreationData) isEcdaaAttestation() bool {
	_, ecdaaKeyIdPresent := pcc.Response.AttestationObject.AttStatement["ecdaaKeyId"].([]byte)
	return ecdaaKeyIdPresent
}

func (pcc *ParsedCredentialCreationData) isSelfAttestation() bool {
	if pcc.isBasicOrAttCaAttestation() || pcc.isEcdaaAttestation() {
		return false
	} else {
		return true
	}
}

func verifyBasicOrAttCaAttestation(metadataStatement *metadata.MetadataStatement, pcc *ParsedCredentialCreationData) error {
	if metadataHasAttestation(metadataStatement, metadata.BasicFull) || metadataHasAttestation(metadataStatement, metadata.AttCA) {
		return verifyCertificateChain(metadataStatement, pcc)
	} else {
		return ErrAttestation.WithDetails("Authenticator doesn't support BasicFull or AttCa Attestation")
	}
}

func verifyCertificateChain(metadataStatement *metadata.MetadataStatement, pcc *ParsedCredentialCreationData) error {
	x5c, x5cPresent := pcc.Response.AttestationObject.AttStatement["x5c"].([]interface{})
	if x5cPresent {
		return VerifyX509CertificateChainAgainstMetadata(metadataStatement, x5c)
	} else {
		return ErrAttestation.WithDetails("X5C Certificate Chain not present")
	}
}

func verifyEcdaaKeyId(statement *metadata.MetadataStatement, pcc *ParsedCredentialCreationData) error {
	return ErrNotSpecImplemented.WithDetails("Ecdaa not implemented")
}

func metadataHasAttestation(metadataStatement *metadata.MetadataStatement, attestationType metadata.AuthenticatorAttestationType) bool {
	for _, at := range metadataStatement.AttestationTypes {
		if metadata.AuthenticatorAttestationType(at) == attestationType {
			return true
		}
	}
	return false
}

func GetMetadataStatement(pcc *ParsedCredentialCreationData, metadataService metadata.MetadataService) *metadata.MetadataStatement {
	aaguid, err := uuid.FromBytes(pcc.Response.AttestationObject.AuthData.AttData.AAGUID)
	if err != nil {
		return nil
	}
	if aaguid.String() == "00000000-0000-0000-0000-000000000000" {
		attestationCertificateKeyIdentifier, err := GenerateAttestationCertificateKeyIdentifier(pcc)
		if err != nil {
			return nil
		}
		metadataStatement := metadataService.U2FAuthenticator(attestationCertificateKeyIdentifier)
		return metadataStatement
	} else {
		metadataStatement := metadataService.WebAuthnAuthenticator(aaguid.String())
		return metadataStatement
	}
}

func GenerateAttestationCertificateKeyIdentifier(pcc *ParsedCredentialCreationData) (string, error) {
	x5c, x5cPresent := pcc.Response.AttestationObject.AttStatement["x5c"].([]interface{})
	if !x5cPresent {
		return "", fmt.Errorf("no Attestation Certificate found")
	}
	var attCert *x509.Certificate
	for i, attCertInterfaceBytes := range x5c {
		attCertBytes := attCertInterfaceBytes.([]byte)
		cert, err := x509.ParseCertificate(attCertBytes)
		if err != nil {
			return "", err
		}
		if i == 0 {
			attCert = cert
		}
	}

	if attCert == nil {
		return "", fmt.Errorf("no Attestation Certificate found")
	}

	spkiASN1, err := x509.MarshalPKIXPublicKey(attCert.PublicKey)
	if err != nil {
		return "", err
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return "", err
	}

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hex.EncodeToString(skid[:]), nil
}

func VerifyX509CertificateChainAgainstMetadata(metadataStatement *metadata.MetadataStatement, x5c []interface{}) error {
	if metadataStatement == nil {
		return ErrAttestation.WithDetails("Metadata for Authenticator not found")
	}

	trustAnchorPool := x509.NewCertPool()

	for _, certString := range metadataStatement.AttestationRootCertificates {
		// create a buffer large enough to hold the certificate bytes
		o := make([]byte, base64.StdEncoding.DecodedLen(len(certString)))
		// base64 decode the certificate into the buffer
		n, _ := base64.StdEncoding.Decode(o, []byte(certString))
		cert, err := x509.ParseCertificate(o[:n])
		if err == nil && cert != nil {
			trustAnchorPool.AddCert(cert)
		}
	}

	var attCert *x509.Certificate
	intermediateCerts := x509.NewCertPool()
	for i, attCertInterfaceBytes := range x5c {
		attCertBytes := attCertInterfaceBytes.([]byte)
		cert, err := x509.ParseCertificate(attCertBytes)
		if err != nil {
			return ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing certificate from ASN.1 data: %+v", err))
		}
		if i == 0 {
			attCert = cert
		} else {
			intermediateCerts.AddCert(cert)
		}
	}

	if attCert == nil {
		return ErrAttestation.WithDetails("Error no attestation certificate found in x5c certificate chain")
	}

	// TODO: maybe we shouldn't delete the unhandledCriticalExtensions right away, we should perform validation with requirements from https://www.w3.org/TR/webauthn-1/#tpm-cert-requirements
	if len(attCert.UnhandledCriticalExtensions) > 0 {
		for i, unhandledCriticalExtensions := range attCert.UnhandledCriticalExtensions {
			if unhandledCriticalExtensions.String() == "2.5.29.17" {
				attCert.UnhandledCriticalExtensions = remove(attCert.UnhandledCriticalExtensions, i)
			}
		}
	}

	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediateCerts,
		Roots:         trustAnchorPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := attCert.Verify(verifyOpts); err != nil {
		return ErrAttestation.WithDetails(fmt.Sprintf("Error validating certificate chain: %+v", err))
	}
	return nil
}
func remove(slice []asn1.ObjectIdentifier, i int) []asn1.ObjectIdentifier {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}
