package webauthn

import "github.com/teamhanko/webauthn-go/protocol"

// SessionData is the data that should be stored by the Relying Party for
// the duration of the web authentication ceremony
type SessionData struct {
	Challenge               string                               `json:"challenge"`
	UserID                  []byte                               `json:"user_id"`
	AllowedCredentialIDs    [][]byte                             `json:"allowed_credentials,omitempty"`
	UserVerification        protocol.UserVerificationRequirement `json:"userVerification"`
	ConveyancePreference    protocol.ConveyancePreference        `json:"conveyance_preference"`
	AuthenticatorAttachment protocol.AuthenticatorAttachment     `json:"authenticator_attachment"`
	Timeout                 int                                  `json:"timeout"`
}
