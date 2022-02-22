package webauthn

import (
	"testing"

	"github.com/teamhanko/webauthn-go/protocol"
)

func TestLogin_FinishLoginFailure(t *testing.T) {
	session := SessionData{
		UserID: []byte("ABC"),
	}

	webauthn := &WebAuthn{}
	credential, userId, err := webauthn.FinishLogin(session, nil)
	if err == nil {
		t.Errorf("FinishLogin() error = nil, want %v", protocol.ErrBadRequest.Type)
	}
	if credential != nil {
		t.Errorf("FinishLogin() credential = %v, want nil", credential)
	}
	if userId != nil {
		t.Errorf("FinishLogin() user_id = %v, want nil", userId)
	}
}
