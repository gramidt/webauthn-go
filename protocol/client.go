package protocol

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party
// and the client. It is a key-value mapping whose keys are strings. Values can be any type
// that has a valid encoding in JSON. Its structure is defined by the following Web IDL.
// https://www.w3.org/TR/webauthn-1/#sec-client-data
type CollectedClientData struct {
	// Type the string "webauthn.create" when creating new credentials,
	// and "webauthn.get" when getting an assertion from an existing credential. The
	// purpose of this member is to prevent certain types of signature confusion attacks
	//(where an attacker substitutes one legitimate signature for another).
	Type         CeremonyType  `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
	// Chromium (Chrome) returns a hint sometimes about how to handle clientDataJSON in a safe manner
	Hint string `json:"new_keys_may_be_added_here,omitempty"`
}

type CeremonyType string

const (
	CreateCeremony CeremonyType = "webauthn.create"
	AssertCeremony CeremonyType = "webauthn.get"
)

type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id,omitempty"`
}

type TokenBindingStatus string

const (
	// Indicates token binding was used when communicating with the
	// Relying Party. In this case, the id member MUST be present.
	Present TokenBindingStatus = "present"
	// Indicates token binding was used when communicating with the
	// negotiated when communicating with the Relying Party.
	Supported TokenBindingStatus = "supported"
	// Indicates token binding not supported
	// when communicating with the Relying Party.
	NotSupported TokenBindingStatus = "not-supported"
)

// Returns the origin : (scheme)://(host)
func FullyQualifiedOrigin(u *url.URL) string {
	return strings.TrimSuffix(fmt.Sprintf("%s://%s", u.Scheme, u.Host), fmt.Sprintf(":%s", u.Port()))
}

// Handles steps 3 through 6 of verfying the registering client data of a
// new credential and steps 7 through 10 of verifying an authentication assertion
// See https://www.w3.org/TR/webauthn-1/#registering-a-new-credential
// and https://www.w3.org/TR/webauthn-1/#verifying-assertion
func (c *CollectedClientData) Verify(storedChallenge string, ceremony CeremonyType, relyingPartyOrigins []string) error {

	// Registration Step 3. Verify that the value of C.type is webauthn.create.

	// Assertion Step 7. Verify that the value of C.type is the string webauthn.get.
	if c.Type != ceremony {
		err := ErrVerification.WithDetails("Error validating ceremony type")
		err.WithInfo(fmt.Sprintf("Expected Value: %s\n Received: %s\n", ceremony, c.Type))
		return err
	}

	challenge := c.Challenge
	// NOT-NORMATIVE
	// Verify that C.challenge is not an empty string
	if challenge == "" {
		err := ErrVerification.WithDetails("Error validating challenge")
		return err.WithInfo("Expected CollectedClientData.Challenge not be an empty string")
	}

	// NOT-NORMATIVE
	// Verify that C.challenge is base64url encoded
	_, base64Err := base64.RawURLEncoding.DecodeString(challenge)
	if base64Err != nil {
		err := ErrVerification.WithDetails("Error validating challenge")
		return err.WithInfo("Expected CollectedClientData.Challenge to be base64url encoded")
	}

	// Registration Step 4. Verify that the value of C.challenge matches the challenge
	// that was sent to the authenticator in the create() call.

	// Assertion Step 8. Verify that the value of C.challenge matches the challenge
	// that was sent to the authenticator in the PublicKeyCredentialRequestOptions
	// passed to the get() call.

	if 0 != strings.Compare(storedChallenge, challenge) {
		err := ErrVerification.WithDetails("Error validating challenge")
		return err.WithInfo(fmt.Sprintf("Expected b Value: %#v\nReceived b: %#v\n", storedChallenge, challenge))
	}

	// Registration Step 5 & Assertion Step 9. Verify that the value of C.origin matches
	// the Relying Party's origin.
	clientDataOrigin, err := url.Parse(c.Origin)
	if err != nil {
		return ErrParsingData.WithDetails("Error decoding clientData origin as URL")
	}

	foundOriginMatch := false
	fullyQualifiedClientDataOrigin := c.Origin
	if clientDataOrigin.Scheme == "https" || clientDataOrigin.Scheme == "http" {
		fullyQualifiedClientDataOrigin = FullyQualifiedOrigin(clientDataOrigin)
	}
	for _, origin := range relyingPartyOrigins {
		if strings.EqualFold(fullyQualifiedClientDataOrigin, origin) {
			foundOriginMatch = true
		}
	}

	if !foundOriginMatch {
		err := ErrVerification.WithDetails("Error validating origin")
		return err.WithInfo(fmt.Sprintf("Expected Value list: %q\n Received: %s\n", relyingPartyOrigins, FullyQualifiedOrigin(clientDataOrigin)))
	}

	// Registration Step 6 and Assertion Step 10. Verify that the value of C.tokenBinding.status
	// matches the state of Token Binding for the TLS connection over which the assertion was
	// obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id
	// matches the base64url encoding of the Token Binding ID for the connection.
	if c.TokenBinding != nil {
		if c.TokenBinding.Status == "" {
			return ErrParsingData.WithDetails("Error decoding clientData, token binding present without status")
		}
		if c.TokenBinding.Status != Present && c.TokenBinding.Status != Supported && c.TokenBinding.Status != NotSupported {
			return ErrParsingData.WithDetails("Error decoding clientData, token binding present with invalid status").WithInfo(fmt.Sprintf("Got: %s\n", c.TokenBinding.Status))
		}
	}
	// Not yet fully implemented by the spec, browsers, and me.

	return nil
}
