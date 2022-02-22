package webauthn

import (
	"testing"

	"bytes"
	"github.com/teamhanko/webauthn-go/protocol"
)

func TestRegistration_FinishRegistrationFailure(t *testing.T) {
	session := SessionData{
		UserID: []byte("ABC"),
	}

	webauthn := &WebAuthn{}
	credential, err := webauthn.FinishRegistration(session, nil)
	if err == nil {
		t.Errorf("FinishRegistration() error = nil, want %v", protocol.ErrBadRequest.Type)
	}
	if credential != nil {
		t.Errorf("FinishRegistration() credential = %v, want nil", credential)
	}
}

func TestRegistration_BeginRegistrationDefaultOptions(t *testing.T) {
	user := &defaultUser{
		id: []byte("123"),
	}

	webauthn := WebAuthn{&Config{
		RPID:          "http://localhost",
		RPDisplayName: "Test Relying Party",
		RPIcon:        "icon",
	},
		nil,
		nil,
		nil,
	}
	options, sessionData, err := webauthn.BeginRegistration(user)

	if err != nil {
		t.Error(err)
	}

	if sessionData.UserVerification != protocol.VerificationPreferred {
		t.Errorf("BeginRegistration() sessionData.UserVerification = %s, want %s", sessionData.UserVerification, protocol.VerificationPreferred)
	}

	if !bytes.Equal(sessionData.UserID, user.id) {
		t.Errorf("BeginRegistration() sessionData.UserID = %s, want %s", string(sessionData.UserID), string(user.id))
	}

	if options == nil {
		t.Errorf("BeginRegistration() options = nil, want options != nil")
	}

	if !bytes.Equal(options.Response.User.ID, user.id) {
		t.Errorf("BeginRegistration() options.Response.User.ID = %s, want %s", string(options.Response.User.ID), string(user.id))
	}

	if options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationPreferred {
		t.Errorf("BeginRegistration() options.Response.AuthenticatorSelection.UserVerification = %s, want %s", options.Response.AuthenticatorSelection.UserVerification, protocol.VerificationPreferred)
	}

	if options.Response.RelyingParty.ID != webauthn.Config.RPID {
		t.Errorf("BeginRegistration() optons.Response.RelyingParty.ID = %s, want %s", options.Response.RelyingParty.ID, webauthn.Config.RPID)
	}

	if options.Response.RelyingParty.Name != webauthn.Config.RPDisplayName {
		t.Errorf("BeginRegistration() optons.Response.RelyingParty.Name = %s, want %s", options.Response.RelyingParty.Name, webauthn.Config.RPDisplayName)
	}

	if options.Response.RelyingParty.Icon != webauthn.Config.RPIcon {
		t.Errorf("BeginRegistration() optons.Response.RelyingParty.Icon = %s, want %s", options.Response.RelyingParty.Icon, webauthn.Config.RPIcon)
	}
}

func TestRegistration_BeginRegistrationAuthenticatorSelectionOption(t *testing.T) {
	user := &defaultUser{
		id: []byte("123"),
	}

	webauthn := WebAuthn{&Config{
		RPID:          "http://localhost",
		RPDisplayName: "Test Relying Party",
		RPIcon:        "icon",
	},
		nil,
		nil,
		nil,
	}

	authenticatorSelection := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey:      protocol.ResidentKeyUnrequired(),
		UserVerification:        protocol.VerificationRequired,
	}

	options, sessionData, err := webauthn.BeginRegistration(user, WithAuthenticatorSelection(authenticatorSelection))

	if err != nil {
		t.Error(err)
	}

	if sessionData.UserVerification != authenticatorSelection.UserVerification {
		t.Errorf("BeginRegistration() sessionData.UserVerification = %s, want %s", sessionData.UserVerification, protocol.VerificationPreferred)
	}

	if options.Response.AuthenticatorSelection.AuthenticatorAttachment != authenticatorSelection.AuthenticatorAttachment {
		t.Errorf("BeginRegistration() options.Response.AuthenticatorSelection.UserVerification = %s, want %s", options.Response.AuthenticatorSelection.AuthenticatorAttachment, authenticatorSelection.AuthenticatorAttachment)
	}

	if options.Response.AuthenticatorSelection.RequireResidentKey != authenticatorSelection.RequireResidentKey {
		t.Errorf("BeginRegistration() options.Response.AuthenticatorSelection = %v, want %v", options.Response.AuthenticatorSelection.RequireResidentKey, authenticatorSelection.RequireResidentKey)
	}

	if options.Response.AuthenticatorSelection.UserVerification != authenticatorSelection.UserVerification {
		t.Errorf("BeginRegistration() options.Response.AuthenticatorSelection.UserVerification = %s, want %s", options.Response.AuthenticatorSelection.UserVerification, authenticatorSelection.UserVerification)
	}
}

func TestRegistration_BeginRegistrationConveyancePreferenceOption(t *testing.T) {
	user := &defaultUser{
		id: []byte("123"),
	}

	webauthn := WebAuthn{&Config{
		RPID:          "http://localhost",
		RPDisplayName: "Test Relying Party",
		RPIcon:        "icon",
	},
		nil,
		nil,
		nil,
	}

	options, _, err := webauthn.BeginRegistration(user, WithConveyancePreference(protocol.PreferDirectAttestation))

	if err != nil {
		t.Error(err)
	}

	if options.Response.Attestation != protocol.PreferDirectAttestation {
		t.Errorf("BeginRegistartion() options.Response.Attestation = %s, want %s", options.Response.Attestation, protocol.PreferDirectAttestation)
	}
}

func TestRegistration_BeginRegistrationCredentialDescriptorOption(t *testing.T) {
	user := &defaultUser{
		id: []byte("123"),
	}

	webauthn := WebAuthn{&Config{
		RPID:          "http://localhost",
		RPDisplayName: "Test Relying Party",
		RPIcon:        "icon",
	},
		nil,
		nil,
		nil,
	}

	excludeList := make([]protocol.CredentialDescriptor, 2)
	excludeList[0] = protocol.CredentialDescriptor{
		Type:         protocol.PublicKeyCredentialType,
		CredentialID: []byte("987"),
	}
	excludeList[1] = protocol.CredentialDescriptor{
		Type:         protocol.PublicKeyCredentialType,
		CredentialID: []byte("456"),
		Transport:    []protocol.AuthenticatorTransport{protocol.Internal},
	}

	options, _, err := webauthn.BeginRegistration(user, WithExclusions(excludeList))

	if err != nil {
		t.Error(err)
	}

	if len(options.Response.CredentialExcludeList) != 2 {
		t.Errorf("BeginRegistration() len(options.Response.CredentialExcludeList) = %d, want %d", len(options.Response.CredentialExcludeList), len(excludeList))
	}

	if options.Response.CredentialExcludeList[0].Type != protocol.PublicKeyCredentialType {
		t.Errorf("BeginRegistration() options.Response.CredentialExcludeList[0].Type = %s, want %s", options.Response.CredentialExcludeList[0].Type, protocol.PublicKeyCredentialType)
	}

	if !bytes.Equal(options.Response.CredentialExcludeList[0].CredentialID, excludeList[0].CredentialID) {
		t.Errorf("BeginRegistration() options.Response.CredentialExcludeList[0].CredentialID = %s, want %s", string(options.Response.CredentialExcludeList[0].CredentialID), string(excludeList[0].CredentialID))
	}
}
