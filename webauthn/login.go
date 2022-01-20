package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"github.com/teamhanko/webauthn/credential"
	"net/http"

	"github.com/teamhanko/webauthn/protocol"
)

// BEGIN REGISTRATION
// These objects help us creat the CredentialCreationOptions
// that will be passed to the authenticator via the user client

// LoginOption is used to provide parameters that modify the default Credential Assertion Payload that is sent to the user.
type LoginOption func(*protocol.PublicKeyCredentialRequestOptions)

// BeginLogin creates the CredentialAssertion data payload that should be sent to the user agent for beginning the
// login/assertion process. The format of this data can be seen in §5.5 of the WebAuthn specification
// (https://www.w3.org/TR/webauthn-1/#assertion-options). These default values can be amended by providing
// additional LoginOption parameters. This function also returns sessionData, that must be stored by the
// RP in a secure manner and then provided to the FinishLogin function. This data helps us verify the
// ownership of the credential being retreived.
func (webauthn *WebAuthn) BeginLogin(user User, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, nil, err
	}

	var credentials []credential.Credential
	if user != nil {
		credentials, err = webauthn.CredentialService.GetCredentialForUser(user.WebAuthnID())
		if err != nil {
			return nil, nil, err
		}
	}

	if len(credentials) == 0 && user != nil { // If the user does not have any credentials, we cannot do login
		return nil, nil, protocol.ErrBadRequest.WithDetails("Found no credentials for user")
	}

	var allowedCredentials = make([]protocol.CredentialDescriptor, len(credentials))

	for i, cred := range credentials {
		var credentialDescriptor protocol.CredentialDescriptor
		credentialDescriptor.CredentialID = cred.ID
		credentialDescriptor.Type = protocol.PublicKeyCredentialType
		allowedCredentials[i] = credentialDescriptor
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:          challenge,
		Timeout:            webauthn.Config.Timeouts.Authentication,
		RelyingPartyID:     webauthn.Config.RPID,
		UserVerification:   webauthn.Config.AuthenticatorSelection.UserVerification,
		AllowedCredentials: allowedCredentials,
	}

	for _, setter := range opts {
		setter(&requestOptions)
	}

	newSessionData := SessionData{
		Challenge:            base64.RawURLEncoding.EncodeToString(requestOptions.Challenge),
		AllowedCredentialIDs: requestOptions.GetAllowedCredentialIDs(),
		UserVerification:     requestOptions.UserVerification,
		Timeout: requestOptions.Timeout,
	}

	response := protocol.CredentialAssertion{Response: requestOptions}

	return &response, &newSessionData, nil
}

// WithAllowedCredentials updates the allowed credential list with Credential Descripiptors, discussed in §5.10.3
// (https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialdescriptor) with user-supplied values
func WithAllowedCredentials(allowList []protocol.CredentialDescriptor) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.AllowedCredentials = allowList
	}
}

// WithUserVerification requests a user verification preference
func WithUserVerification(userVerification protocol.UserVerificationRequirement) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.UserVerification = userVerification
	}
}

// WithAssertionExtensions requests additional extensions for assertion
func WithAssertionExtensions(extensions protocol.AuthenticationExtensions) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Extensions = extensions
	}
}

// WithTransaction request with transaction context
func WithTransaction(transaction string) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		if transaction != "" {
			transactionHash := sha256.Sum256([]byte(transaction))
			cco.Challenge = append(cco.Challenge, transactionHash[:]...)
		}
	}
}

// WithLoginTimeout adds a custom timeout in milliseconds for the Login Operation
func WithLoginTimeout(timeout int) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Timeout = timeout
	}
}


// FinishLogin takes the response from the client and validates it against the user credentials and stored session data
func (webauthn *WebAuthn) FinishLogin(session SessionData, response *http.Request) (credential *credential.Credential, userId []byte, error error) {
	parsedResponse, err := protocol.ParseCredentialRequestResponse(response)
	if err != nil {
		return nil, nil, err
	}

	return webauthn.ValidateLogin(session, parsedResponse)
}

// ValidateLogin takes a parsed response and validates it against the user credentials and session data
func (webauthn *WebAuthn) ValidateLogin(session SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (credential *credential.Credential, userId []byte, error error) {
	// Step 1. If the allowCredentials option was given when this authentication ceremony was initiated,
	// verify that credential.id identifies one of the public key credentials that were listed in
	// allowCredentials.
	if len(session.AllowedCredentialIDs) > 0 {
		var credentialAllowed bool
		for _, allowedCredentialId := range session.AllowedCredentialIDs {
			if bytes.Equal(allowedCredentialId, parsedResponse.Response.AuthenticatorData.AttData.CredentialID) {
				credentialAllowed = true
				break
			}
		}
		if !credentialAllowed {
			return nil, nil, protocol.ErrBadRequest.WithDetails("Credential is not allowed by allowedCredential list")
		}
	}

	// Step 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
	// for your use case), look up the corresponding credential public key.
	cred, userId, err := webauthn.CredentialService.GetCredential(parsedResponse.RawID)
	if err != nil {
		return nil, nil, err
	}
	if cred == nil || userId == nil || len(userId) == 0 {
		return nil, nil, protocol.ErrCredentialNotFound
	}

	// Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
	// the owner of the public key credential identified by credential.id.
	userHandle := parsedResponse.Response.UserHandle
	if len(userHandle) > 0 {
		if !bytes.Equal(userId, parsedResponse.Response.UserHandle) {
			return nil, nil, protocol.ErrBadRequest.WithDetails("userHandle and User ID do not match")
		}
	}

	shouldVerifyUser := session.UserVerification == protocol.VerificationRequired

	rpID := webauthn.Config.RPID
	rpOrigins := webauthn.Config.RPOrigins

	// Handle steps 4 through 16
	validError := parsedResponse.Verify(session.Challenge, rpID, rpOrigins, shouldVerifyUser, cred.PublicKey)
	if validError != nil {
		return nil, nil, validError
	}

	// Handle step 17
	err = cred.Authenticator.CheckCounter(parsedResponse.Response.AuthenticatorData.Counter)
	if err != nil {
		return nil, nil, err
	}
	cred.Authenticator.UpdateCounter(parsedResponse.Response.AuthenticatorData.Counter)

	return cred, userId, nil
}
