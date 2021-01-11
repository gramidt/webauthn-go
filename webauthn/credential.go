package webauthn

import (
	"gitlab.com/hanko/webauthn/protocol"
)

// Credential contains all needed information about a WebAuthn credential for storage
type Credential struct {
	// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
	ID []byte
	// The public key portion of a Relying Party-specific credential key pair, generated by an authenticator and returned to
	// a Relying Party at registration time (see also public key credential). The private key portion of the credential key
	// pair is known as the credential private key. Note that in the case of self attestation, the credential key pair is also
	// used as the attestation key pair, see self attestation for details.
	PublicKey []byte
	// The attestation format used (if any) by the authenticator when creating the credential.
	AttestationType string
	// The Authenticator information for a given certificate
	Authenticator Authenticator
}

// MakeNewCredential will return a credential pointer on successful validation of a registration response
func MakeNewCredential(c *protocol.ParsedCredentialCreationData) (*Credential, error) {

	newCredential := &Credential{
		ID:              c.Response.AttestationObject.AuthData.AttData.CredentialID,
		PublicKey:       c.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
		AttestationType: c.Response.AttestationObject.Format,
		Authenticator: Authenticator{
			AAGUID:    c.Response.AttestationObject.AuthData.AttData.AAGUID,
			SignCount: c.Response.AttestationObject.AuthData.Counter,
		},
	}

	return newCredential, nil
}
