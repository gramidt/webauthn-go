package webauthn

import (
	"github.com/teamhanko/webauthn-go/metadata"
	"github.com/teamhanko/webauthn-go/protocol"
	"reflect"
	"testing"
)

func TestValidateRpPolicy(t *testing.T) {
	type args struct {
		rpPolicy        protocol.RelyingPartyPolicy
		metadataService metadata.MetadataService
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No Policy given",
			args: args{
				rpPolicy:        nil,
				metadataService: nil,
			},
			wantErr: false,
		},
		{
			name: "AllowAllPolicy Without MetadataService",
			args: args{
				rpPolicy:        protocol.AllowAllPolicy{},
				metadataService: nil,
			},
			wantErr: false,
		},
		{
			name: "AllowAllPolicy With MetadataService",
			args: args{
				rpPolicy:        protocol.AllowAllPolicy{},
				metadataService: &testMetadataService{},
			},
			wantErr: false,
		},
		{
			name: "AllowlistPolicy Without MetadataService",
			args: args{
				rpPolicy:        protocol.AllowlistPolicy{},
				metadataService: nil,
			},
			wantErr: true,
		},
		{
			name: "AllowlistPolicy With MetadataService",
			args: args{
				rpPolicy:        protocol.AllowlistPolicy{},
				metadataService: &testMetadataService{},
			},
			wantErr: false,
		},
		{
			name: "AllowOnlyAuthenticatorFromMetadataServicePolicy Without MetadataService",
			args: args{
				rpPolicy:        protocol.AllowOnlyAuthenticatorFromMetadataServicePolicy{},
				metadataService: nil,
			},
			wantErr: true,
		},
		{
			name: "AllowOnlyAuthenticatorFromMetadataServicePolicy With MetadataService",
			args: args{
				rpPolicy:        protocol.AllowOnlyAuthenticatorFromMetadataServicePolicy{},
				metadataService: &testMetadataService{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRelyingPartyPolicyRequirements(tt.args.rpPolicy, tt.args.metadataService)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRelyingPartyPolicyRequirements() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

type testMetadataService struct{}

func (service *testMetadataService) GetWebAuthnAuthenticator(aaguid string) *metadata.MetadataStatement {
	return nil
}
func (service *testMetadataService) GetU2FAuthenticator(attestationCertificateKeyIdentifier string) *metadata.MetadataStatement {
	return nil
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		inputConfig *Config
		wantConfig  *Config
		wantErr     bool
	}{
		{
			name: "Success",
			inputConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "https://test.com",
				RPOrigin:               "https://test.com",
				RPIcon:                 "https://test.com/icon.png",
				RPOrigins:              []string{"https://test.com"},
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   1000,
					Authentication: 1000,
				},
				Debug: false,
			},
			wantConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "https://test.com",
				RPOrigin:               "https://test.com",
				RPOrigins:              []string{"https://test.com", "https://test.com"},
				RPIcon:                 "https://test.com/icon.png",
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   1000,
					Authentication: 1000,
				},
				Debug: false,
			},
			wantErr: false,
		},
		{
			name: "Success with missing RPOrigin",
			inputConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "test.com",
				RPOrigin:               "",
				RPOrigins:              []string{"https://test.com"},
				RPIcon:                 "https://test.com/icon.png",
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   1000,
					Authentication: 1000,
				},
				Debug: false,
			},
			wantConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "test.com",
				RPOrigin:               "",
				RPOrigins:              []string{"https://test.com"},
				RPIcon:                 "https://test.com/icon.png",
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   1000,
					Authentication: 1000,
				},
				Debug: false,
			},
			wantErr: false,
		},
		{
			name: "Success with missing timeout",
			inputConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "https://test.com",
				RPOrigin:               "https://test.com",
				RPIcon:                 "https://test.com/icon.png",
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   0,
					Authentication: 0,
				},
				Debug: false,
			},
			wantConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "https://test.com",
				RPOrigin:               "https://test.com",
				RPOrigins:              []string{"https://test.com"},
				RPIcon:                 "https://test.com/icon.png",
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   60000,
					Authentication: 60000,
				},
				Debug: false,
			},
			wantErr: false,
		},
		{
			name: "Success with Path in RPID",
			inputConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "https://test.com/hanko/test",
				RPOrigin:               "https://test.com",
				RPIcon:                 "https://test.com/icon.png",
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   1000,
					Authentication: 1000,
				},
				Debug: false,
			},
			wantConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "https://test.com/hanko/test",
				RPOrigin:               "https://test.com",
				RPOrigins:              []string{"https://test.com"},
				RPIcon:                 "https://test.com/icon.png",
				AttestationPreference:  "direct",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   1000,
					Authentication: 1000,
				},
				Debug: false,
			},
			wantErr: false,
		},
		{
			name: "Empty Config",
			inputConfig: &Config{
				RPDisplayName:          "",
				RPID:                   "",
				RPOrigin:               "",
				RPIcon:                 "",
				AttestationPreference:  "",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   0,
					Authentication: 0,
				},
				Debug: false,
			},
			wantConfig: nil,
			wantErr:    true,
		},
		{
			name: "Missing RPID",
			inputConfig: &Config{
				RPDisplayName:          "Test Relying Party",
				RPID:                   "",
				RPOrigin:               "",
				RPIcon:                 "",
				AttestationPreference:  "",
				AuthenticatorSelection: protocol.AuthenticatorSelection{},
				Timeouts: Timeouts{
					Registration:   1000,
					Authentication: 1000,
				},
				Debug: false,
			},
			wantConfig: nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inputConfig.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.wantErr {
				return
			}

			if !reflect.DeepEqual(tt.inputConfig, tt.wantConfig) {
				t.Errorf("Config.validate() expected different values in Config got = %v, want = %v", tt.inputConfig, tt.wantConfig)
			}
		})
	}
}
