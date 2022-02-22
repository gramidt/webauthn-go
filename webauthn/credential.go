package webauthn

import (
	"github.com/teamhanko/webauthn-go/credential"
	"github.com/teamhanko/webauthn-go/protocol"
)

// MakeNewCredential will return a credential pointer on successful validation of a registration response
func MakeNewCredential(c *protocol.ParsedCredentialCreationData) (*credential.Credential, error) {

	newCredential := &credential.Credential{
		ID:               c.Response.AttestationObject.AuthData.AttData.CredentialID,
		PublicKey:        c.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
		AttestationType:  c.Response.AttestationObject.Format,
		UserVerification: c.Response.AttestationObject.AuthData.Flags.UserVerified(),
		Authenticator: credential.Authenticator{
			AAGUID:    c.Response.AttestationObject.AuthData.AttData.AAGUID,
			SignCount: c.Response.AttestationObject.AuthData.Counter,
		},
	}

	return newCredential, nil
}
