package protocol

import (
	uuid "github.com/satori/go.uuid"
	"github.com/teamhanko/webauthn/metadata"
	"testing"
)

func TestAllowAllPolicy_Verify(t *testing.T) {
	policy := AllowAllPolicy{}
	type args struct {
		pcc               *ParsedCredentialCreationData
		trustError        error
		metadataStatement *metadata.MetadataStatement
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Missing ParsedCredentialData, TrustworthinessError and MetadataStatement",
			args: args{
				pcc:               nil,
				trustError:        nil,
				metadataStatement: nil,
			},
			wantErr: false,
		},
		{
			name: "Missing ParsedCredentialCreationData",
			args: args{
				pcc:               nil,
				trustError:        ErrAttestation,
				metadataStatement: testMetadataStatement,
			},
			wantErr: false,
		},
		{
			name: "Missing MetadataStatement",
			args: args{
				pcc: &ParsedCredentialCreationData{
					ParsedPublicKeyCredential: ParsedPublicKeyCredential{},
					Response:                  ParsedAttestationResponse{},
					Raw:                       CredentialCreationResponse{},
				},
				trustError:        ErrAttestation,
				metadataStatement: nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policy.Verify(tt.args.pcc, tt.args.trustError, tt.args.metadataStatement)

			if (err != nil) != tt.wantErr {
				t.Errorf("AllowAllPolicy.Verify() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAllowOnlyAuthenticatorFromMetadataServicePolicy_Verify(t *testing.T) {
	policy := AllowOnlyAuthenticatorFromMetadataServicePolicy{}
	type args struct {
		pcc               *ParsedCredentialCreationData
		trustError        error
		metadataStatement *metadata.MetadataStatement
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Success (no TrustworthinessError and found MetadataStatement)",
			args: args{
				pcc: &ParsedCredentialCreationData{
					ParsedPublicKeyCredential: ParsedPublicKeyCredential{},
					Response:                  ParsedAttestationResponse{},
					Raw:                       CredentialCreationResponse{},
				},
				trustError:        nil,
				metadataStatement: testMetadataStatement,
			},
			wantErr: false,
		},
		{
			name: "Missing ParsedCredentialData, TrustworthinessError and MetadataStatement",
			args: args{
				pcc:               nil,
				trustError:        nil,
				metadataStatement: nil,
			},
			wantErr: true,
		},
		{
			name: "Missing ParsedCredentialCreationData",
			args: args{
				pcc:               nil,
				trustError:        ErrAttestation,
				metadataStatement: testMetadataStatement,
			},
			wantErr: true,
		},
		{
			name: "Missing MetadataStatement",
			args: args{
				pcc: &ParsedCredentialCreationData{
					ParsedPublicKeyCredential: ParsedPublicKeyCredential{},
					Response:                  ParsedAttestationResponse{},
					Raw:                       CredentialCreationResponse{},
				},
				trustError:        ErrAttestation,
				metadataStatement: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policy.Verify(tt.args.pcc, tt.args.trustError, tt.args.metadataStatement)

			if (err != nil) != tt.wantErr {
				t.Errorf("AllowOnlyAuthenticatorFromMetadataServicePolicy.Verify() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAllowlistPolicy_Verify(t *testing.T) {
	policy := AllowlistPolicy{Allowlist: []string{testMetadataStatement.AaGUID}}
	type args struct {
		pcc               *ParsedCredentialCreationData
		trustError        error
		metadataStatement *metadata.MetadataStatement
	}

	allowlistAaguid, err := uuid.FromString(testMetadataStatement.AaGUID)
	if err != nil {
		t.Errorf("AAGUID is not a valid uuid: %v", err)
		return
	}

	notAllowlistAaguid, err := uuid.FromString("00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Errorf("AAGUID is not a valid uuid: %v", err)
		return
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				pcc: &ParsedCredentialCreationData{
					ParsedPublicKeyCredential: ParsedPublicKeyCredential{},
					Response: ParsedAttestationResponse{
						CollectedClientData: CollectedClientData{},
						AttestationObject: AttestationObject{
							AuthData: AuthenticatorData{
								RPIDHash: nil,
								Flags:    0,
								Counter:  0,
								AttData: AttestedCredentialData{
									AAGUID:              allowlistAaguid.Bytes(),
									CredentialID:        nil,
									CredentialPublicKey: nil,
								},
								ExtData: nil,
							},
							RawAuthData:  nil,
							Format:       "",
							AttStatement: nil,
						},
					},
					Raw: CredentialCreationResponse{},
				},
				trustError:        nil,
				metadataStatement: testMetadataStatement,
			},
			wantErr: false,
		},
		{
			name: "Authenticator AAGUID not in allowlist",
			args: args{
				pcc: &ParsedCredentialCreationData{
					ParsedPublicKeyCredential: ParsedPublicKeyCredential{},
					Response: ParsedAttestationResponse{
						CollectedClientData: CollectedClientData{},
						AttestationObject: AttestationObject{
							AuthData: AuthenticatorData{
								RPIDHash: nil,
								Flags:    0,
								Counter:  0,
								AttData: AttestedCredentialData{
									AAGUID:              notAllowlistAaguid.Bytes(),
									CredentialID:        nil,
									CredentialPublicKey: nil,
								},
								ExtData: nil,
							},
							RawAuthData:  nil,
							Format:       "",
							AttStatement: nil,
						},
					},
					Raw: CredentialCreationResponse{},
				},
				trustError:        nil,
				metadataStatement: testMetadataStatement,
			},
			wantErr: true,
		},
		{
			name: "Authenticator AAGUID in allowlist, but trustworthiness error",
			args: args{
				pcc: &ParsedCredentialCreationData{
					ParsedPublicKeyCredential: ParsedPublicKeyCredential{},
					Response: ParsedAttestationResponse{
						CollectedClientData: CollectedClientData{},
						AttestationObject: AttestationObject{
							AuthData: AuthenticatorData{
								RPIDHash: nil,
								Flags:    0,
								Counter:  0,
								AttData: AttestedCredentialData{
									AAGUID:              allowlistAaguid.Bytes(),
									CredentialID:        nil,
									CredentialPublicKey: nil,
								},
								ExtData: nil,
							},
							RawAuthData:  nil,
							Format:       "",
							AttStatement: nil,
						},
					},
					Raw: CredentialCreationResponse{},
				},
				trustError:        ErrAttestation,
				metadataStatement: testMetadataStatement,
			},
			wantErr: true,
		},
		{
			name: "Authenticator AAGUID in allowlist, but no MetadataStatement available",
			args: args{
				pcc: &ParsedCredentialCreationData{
					ParsedPublicKeyCredential: ParsedPublicKeyCredential{},
					Response: ParsedAttestationResponse{
						CollectedClientData: CollectedClientData{},
						AttestationObject: AttestationObject{
							AuthData: AuthenticatorData{
								RPIDHash: nil,
								Flags:    0,
								Counter:  0,
								AttData: AttestedCredentialData{
									AAGUID:              allowlistAaguid.Bytes(),
									CredentialID:        nil,
									CredentialPublicKey: nil,
								},
								ExtData: nil,
							},
							RawAuthData:  nil,
							Format:       "",
							AttStatement: nil,
						},
					},
					Raw: CredentialCreationResponse{},
				},
				trustError:        ErrAttestation,
				metadataStatement: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policy.Verify(tt.args.pcc, tt.args.trustError, tt.args.metadataStatement)

			if (err != nil) != tt.wantErr {
				t.Errorf("AllowlistPolicy.Verify() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

var testMetadataStatement = &metadata.MetadataStatement{
	LegalHeader:                          "Metadata Legal Header: Version 1.00.　Date: May 21, 2018.  To access, view and use any Metadata Statements or the TOC file (“METADATA”) from the MDS, You must be bound by the latest FIDO Alliance Metadata Usage Terms that can be found at http://mds2.fidoalliance.org/ . If you already have a valid token, access the above URL attaching your token such as http://mds2.fidoalliance.org?token=YOUR-VALID-TOKEN.  If You have not entered into the agreement, please visit the registration site found at http://fidoalliance.org/MDS/ and enter into the agreement and obtain a valid token.  You must not redistribute this file to any third party. Removal of this Legal Header or modifying any part of this file renders this file invalid.  The integrity of this file as originally provided from the MDS is validated by the hash value of this file that is recorded in the MDS. The use of invalid files is strictly prohibited. If the version number for the Legal Header is updated from Version 1.00, the METADATA below may also be updated or may not be available. Please use the METADATA with the Legal Header with the latest version number.  Dated: 2018-05-21 Version LH-1.00",
	Aaid:                                 "",
	AaGUID:                               "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
	AttestationCertificateKeyIdentifiers: nil,
	Description:                          "YubiKey Series 5 with NFC",
	AlternativeDescriptions:              nil,
	AuthenticatorVersion:                 50100,
	ProtocolFamily:                       "fido2",
	Upv:                                  nil,
	AuthenticationAlgorithms:             []string{"secp256r1_ecdsa_sha256_raw", "ed25519_eddsa_sha512_raw"},
	PublicKeyAlgAndEncodings:             []string{"ALG_KEY_COSE"},
	AttestationTypes:                     []string{"basic_full"},
	UserVerificationDetails:              nil,
	KeyProtection:                        []string{"software", "tee"},
	IsKeyRestricted:                      false,
	IsFreshUserVerificationRequired:      false,
	MatcherProtection:                    []string{"on_chip"},
	CryptoStrength:                       128,
	AttachmentHint:                       []string{"external", "wired", "wireless", "nfc"},
	TcDisplay:                            []string{},
	TcDisplayContentType:                 "",
	TcDisplayPNGCharacteristics:          nil,
	AttestationRootCertificates:          []string{"MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw=="}, // TODO
	EcdaaTrustAnchors:                    nil,
	Icon:                                 "",
	SupportedExtensions:                  nil,
}
