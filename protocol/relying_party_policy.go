package protocol

import (
	uuid "github.com/gofrs/uuid"
	"github.com/teamhanko/webauthn-go/metadata"
)

type RelyingPartyPolicy interface {
	Verify(pcc *ParsedCredentialCreationData, attestationTrustworthinessError error, metadataStatement *metadata.MetadataStatement) error
}

// This allows to use every FIDO2 authenticator with no restriction
type AllowAllPolicy struct{}

// AllowAllPolicy - always returns no error
func (aap AllowAllPolicy) Verify(pcc *ParsedCredentialCreationData, attestationTrustworthinessError error, metadataStatement *metadata.MetadataStatement) error {
	return nil
}

// This policy allows to use only an authenticator which MetadataStatements are available from the MetadataService
// This policy only works if a MetadataService is provided and the authenticator sends an attestation
type AllowOnlyAuthenticatorFromMetadataServicePolicy struct{}

// AllowOnlyAuthenticatorFromMetadataServicePolicy - returns an error if no MetadataStatement was found or if the attestation could not be verified as trustworthy with the information provided by the MetadataStatement
func (msp AllowOnlyAuthenticatorFromMetadataServicePolicy) Verify(pcc *ParsedCredentialCreationData, attestationTrustworthinessError error, metadataStatement *metadata.MetadataStatement) error {
	if metadataStatement == nil {
		return ErrAuthenticatorNotAllowed.WithDetails("No MetadataStatement for Authenticator found.")
	}
	return attestationTrustworthinessError
}

// This policy allows authenticators with specific AAGUIDs only
// This policy only works if a MetadataService is provided and the authenticator sends an attestation
type AllowlistPolicy struct {
	Allowlist []string `json:"allowlist"`
}

// AllowlistPolicy - returns an error if no MetadataStatement was found or if the attestation could not be verified as trustworthy with the information provided by the MetadataStatement or if the authenticator aaguid is not in the provided allowlist
func (ap AllowlistPolicy) Verify(pcc *ParsedCredentialCreationData, attestationTrustworthinessError error, metadataStatement *metadata.MetadataStatement) error {
	if attestationTrustworthinessError != nil {
		return attestationTrustworthinessError
	}

	if metadataStatement == nil {
		return ErrAuthenticatorNotAllowed.WithDetails("No MetadataStatement for Authenticator found.")
	}

	aaguid, err := uuid.FromBytes(pcc.Response.AttestationObject.AuthData.AttData.AAGUID)
	if err != nil {
		return ErrInvalidAttestation.WithDetails("AAGUID in AttestedCredentialData is not a valid uuid")
	}

	if ap.Allowlist == nil {
		return ErrAuthenticatorNotAllowed.WithDetails("The Authenticator " + aaguid.String() + " is not allowed by policy.")
	}

	isAaguidAllowed := false
	for _, allowedAaguid := range ap.Allowlist {
		if allowedAaguid == aaguid.String() {
			isAaguidAllowed = true
		}
	}

	if !isAaguidAllowed {
		return ErrAuthenticatorNotAllowed.WithDetails("The Authenticator " + aaguid.String() + " is not allowed by policy.")
	}
	return nil
}
