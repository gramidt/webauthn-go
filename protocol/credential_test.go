package protocol

import (
	"bytes"
	"encoding/base64"
	uuid "github.com/gofrs/uuid"
	"github.com/teamhanko/webauthn/cbor_options"
	"github.com/teamhanko/webauthn/credential"
	"github.com/teamhanko/webauthn/metadata"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

func TestParseCredentialCreationResponse(t *testing.T) {
	reqBody := ioutil.NopCloser(bytes.NewReader([]byte(testCredentialRequestBody)))
	httpReq := &http.Request{Body: reqBody}

	reqBodyNoAttestation := ioutil.NopCloser(bytes.NewReader([]byte(testCredentialNoAttestationDataRequestBody)))
	httpReqNoAttestation := &http.Request{Body: reqBodyNoAttestation}
	type args struct {
		response *http.Request
	}

	byteID, _ := base64.RawURLEncoding.DecodeString("6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteRPIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pSJYIMfCKfxl2SvnqJIiHQysHmpmITNgtCkQ5ESExSRjqrhXAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNc")
	byteAttObject, _ := base64.RawURLEncoding.DecodeString("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ")

	tests := []struct {
		name    string
		args    args
		want    *ParsedCredentialCreationData
		wantErr bool
	}{
		{
			name: "Successful Credential Request Parsing",
			args: args{
				response: httpReq,
			},
			want: &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "none",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRPIDHash,
							Counter:  0,
							Flags:    0x041,
							AttData: AttestedCredentialData{
								AAGUID:              make([]byte, 16),
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							Type: "public-key",
							ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "attestationObject.authData.flags. AT is not set and Attestation Data is not present",
			args:    args{response: httpReqNoAttestation},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialCreationResponse(tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialCreationResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				if !reflect.DeepEqual(got.Extensions, tt.want.Extensions) {
					t.Errorf("Extensions = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.ID, tt.want.ID) {
					t.Errorf("ID = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.ParsedCredential, tt.want.ParsedCredential) {
					t.Errorf("ParsedCredential = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.ParsedPublicKeyCredential, tt.want.ParsedPublicKeyCredential) {
					t.Errorf("ParsedPublicKeyCredential = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.Raw, tt.want.Raw) {
					t.Errorf("Raw = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.RawID, tt.want.RawID) {
					t.Errorf("RawID = %v \n want: %v", got, tt.want)
				}
				// Unmarshall CredentialPublicKey
				var pkWant interface{}
				keyBytesWant := tt.want.Response.AttestationObject.AuthData.AttData.CredentialPublicKey
				cbor_options.CborDecMode.Unmarshal(keyBytesWant, &pkWant)
				var pkGot interface{}
				keyBytesGot := got.Response.AttestationObject.AuthData.AttData.CredentialPublicKey
				cbor_options.CborDecMode.Unmarshal(keyBytesGot, &pkGot)
				if !reflect.DeepEqual(pkGot, pkWant) {
					t.Errorf("Response = %+v \n want: %+v", pkGot, pkWant)
				}
				if !reflect.DeepEqual(got.Type, tt.want.Type) {
					t.Errorf("Type = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.Response.CollectedClientData, tt.want.Response.CollectedClientData) {
					t.Errorf("CollectedClientData = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.Response.AttestationObject.Format, tt.want.Response.AttestationObject.Format) {
					t.Errorf("Format = %v \n want: %v", got, tt.want)
				}
				if !reflect.DeepEqual(got.Response.AttestationObject.AuthData.AttData.CredentialID, tt.want.Response.AttestationObject.AuthData.AttData.CredentialID) {
					t.Errorf("CredentialID = %v \n want: %v", got, tt.want)
				}
			}
		})
	}
}

func TestParsedCredentialCreationData_Verify(t *testing.T) {
	byteID, _ := base64.RawURLEncoding.DecodeString("6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g")
	byteChallenge, _ := base64.RawURLEncoding.DecodeString("W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteRPIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pSJYIMfCKfxl2SvnqJIiHQysHmpmITNgtCkQ5ESExSRjqrhXAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNc")
	byteAttObject, _ := base64.RawURLEncoding.DecodeString("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ")

	type fields struct {
		ParsedPublicKeyCredential ParsedPublicKeyCredential
		Response                  ParsedAttestationResponse
		Raw                       CredentialCreationResponse
	}
	type args struct {
		storedChallenge    Challenge
		verifyUser         bool
		relyingPartyID     string
		relyingPartyOrigin []string
		credentialStore    credential.CredentialService
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Successful Verification Test",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "none",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRPIDHash,
							Counter:  0,
							Flags:    0x041,
							AttData: AttestedCredentialData{
								AAGUID:              make([]byte, 16),
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							Type: "public-key",
							ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    byteChallenge,
				verifyUser:         false,
				relyingPartyID:     `webauthn.io`,
				relyingPartyOrigin: []string{`https://webauthn.io`},
				credentialStore:    nil,
			},
			wantErr: false,
		},
		{
			name: "Verification Test / CredentialID already exists",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "none",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRPIDHash,
							Counter:  0,
							Flags:    0x041,
							AttData: AttestedCredentialData{
								AAGUID:              make([]byte, 16),
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							Type: "public-key",
							ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    byteChallenge,
				verifyUser:         false,
				relyingPartyID:     `webauthn.io`,
				relyingPartyOrigin: []string{`https://webauthn.io`},
				credentialStore:    &testCredentialStore{},
			},
			wantErr: true,
		},
		{
			name: "Verification Test / CredentialID not exists",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "none",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRPIDHash,
							Counter:  0,
							Flags:    0x041,
							AttData: AttestedCredentialData{
								AAGUID:              make([]byte, 16),
								CredentialID:        make([]byte, 0),
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							Type: "public-key",
							ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    byteChallenge,
				verifyUser:         false,
				relyingPartyID:     `webauthn.io`,
				relyingPartyOrigin: []string{`https://webauthn.io`},
				credentialStore:    &testCredentialStore{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcc := &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: tt.fields.ParsedPublicKeyCredential,
				Response:                  tt.fields.Response,
				Raw:                       tt.fields.Raw,
			}
			if err := pcc.Verify(tt.args.storedChallenge.String(), tt.args.verifyUser, tt.args.relyingPartyID, tt.args.relyingPartyOrigin, nil, tt.args.credentialStore, nil); (err != nil) != tt.wantErr {
				t.Errorf("ParsedCredentialCreationData.Verify() error = %+v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsedCredentialCreationData_Verify_With_Metadata(t *testing.T) {

	byteID, _ := base64.RawURLEncoding.DecodeString("6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ")
	byteChallenge, _ := base64.RawURLEncoding.DecodeString("TGYwlX1A-MQpdohMywXLSE9zfsROEH-evNeX8CxXpy8")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAmPormdyeOUJXj5JKMNI8QRgAQOkGg__AGTG6gtLI1zu_ugRPiAqjjPveCH7mQtUNF1nn9mRvU7NIKVLPoXyNTZL_H_6ouXpRGAGayUgo6e4EbQWlAQIDJiABIVggMDErHmqshTTlzfm8TJHfH5RRwLJ9eBuepHGT37CvTmwiWCB8H31JtgyFbT3TjCb3vAVyS-PwMzm0rdHXlmgYt_6DbQ")
	byteRpIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pQECAyYgASFYIDAxKx5qrIU05c35vEyR3x-UUcCyfXgbnqRxk9-wr05sIlggfB99SbYMhW0904wm97wFckvj8DM5tK3R15ZoGLf-g20")
	byteAttObject, _ := base64.RawURLEncoding.DecodeString("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIQfRBiDtC5KAfQWhc1IAQTDfPLxTYzNX2AAoBc45GYCAiA5epypN-tO6DsEFoX_6LE4Kqf5MjKU-zwkhSLVWtYdUWN4NWOBWQLAMIICvDCCAaSgAwIBAgIEA63wEjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgNjE3MzA4MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZnoecFi233DnuSkKgRhalswn-ygkvdr4JSPltbpXK5MxlzVSgWc-9x8mzGysdbBhEecLAYfQYqpVLWWosHPoXo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBD6K5ncnjlCV4-SSjDSPEEYMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBACjrs2f-0djw4onryp_22AdXxg6a5XyxcoybHDjKu72E2SN9qDGsIZSfDy38DDFr_bF1s25joiu7WA6tylKA0HmEDloeJXJiWjv7h2Az2_siqWnJOLic4XE1lAChJS2XAqkSk9VFGelg3SLOiifrBet-ebdQwAL-2QFrcR7JrXRQG9kUy76O2VcSgbdPROsHfOYeywarhalyVSZ-6OOYK_Q_DLIaOC0jXrnkzm2ymMQFQlBAIysrYeEM1wxiFbwDt-lAcbcOEtHEf5ZlWi75nUzlWn8bSx_5FO4TbZ5hIEcUiGRpiIBEMRZlOIm4ZIbZycn_vJOFRTVps0V0S4ygtDdoYXV0aERhdGFYxHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wRQAAAJj6K5ncnjlCV4-SSjDSPEEYAEDpBoP_wBkxuoLSyNc7v7oET4gKo4z73gh-5kLVDRdZ5_Zkb1OzSClSz6F8jU2S_x_-qLl6URgBmslIKOnuBG0FpQECAyYgASFYIDAxKx5qrIU05c35vEyR3x-UUcCyfXgbnqRxk9-wr05sIlggfB99SbYMhW0904wm97wFckvj8DM5tK3R15ZoGLf-g20")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVEdZd2xYMUEtTVFwZG9oTXl3WExTRTl6ZnNST0VILWV2TmVYOEN4WHB5OCIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9")
	aaguid, _ := uuid.FromString("fa2b99dc-9e39-4257-8f92-4a30d23c4118")
	byteAAGUID := aaguid.Bytes()

	wrongAaguid, _ := uuid.FromString("dd1561ed-53de-4c74-a200-e83d35c3e861")
	byteWrongAaguid := wrongAaguid.Bytes()

	certificate := []byte{48, 130, 2, 188, 48, 130, 1, 164, 160, 3, 2, 1, 2, 2, 4, 3, 173, 240, 18, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 46, 49, 44, 48, 42, 6, 3, 85, 4, 3, 19, 35, 89, 117, 98, 105, 99, 111, 32, 85, 50, 70, 32, 82, 111, 111, 116, 32, 67, 65, 32, 83, 101, 114, 105, 97, 108, 32, 52, 53, 55, 50, 48, 48, 54, 51, 49, 48, 32, 23, 13, 49, 52, 48, 56, 48, 49, 48, 48, 48, 48, 48, 48, 90, 24, 15, 50, 48, 53, 48, 48, 57, 48, 52, 48, 48, 48, 48, 48, 48, 90, 48, 109, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 83, 69, 49, 18, 48, 16, 6, 3, 85, 4, 10, 12, 9, 89, 117, 98, 105, 99, 111, 32, 65, 66, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 49, 38, 48, 36, 6, 3, 85, 4, 3, 12, 29, 89, 117, 98, 105, 99, 111, 32, 85, 50, 70, 32, 69, 69, 32, 83, 101, 114, 105, 97, 108, 32, 54, 49, 55, 51, 48, 56, 51, 52, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 25, 158, 135, 156, 22, 45, 183, 220, 57, 238, 74, 66, 160, 70, 22, 165, 179, 9, 254, 202, 9, 47, 118, 190, 9, 72, 249, 109, 110, 149, 202, 228, 204, 101, 205, 84, 160, 89, 207, 189, 199, 201, 179, 27, 43, 29, 108, 24, 68, 121, 194, 192, 97, 244, 24, 170, 149, 75, 89, 106, 44, 28, 250, 23, 163, 108, 48, 106, 48, 34, 6, 9, 43, 6, 1, 4, 1, 130, 196, 10, 2, 4, 21, 49, 46, 51, 46, 54, 46, 49, 46, 52, 46, 49, 46, 52, 49, 52, 56, 50, 46, 49, 46, 55, 48, 19, 6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 2, 1, 1, 4, 4, 3, 2, 4, 48, 48, 33, 6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 1, 1, 4, 4, 18, 4, 16, 250, 43, 153, 220, 158, 57, 66, 87, 143, 146, 74, 48, 210, 60, 65, 24, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 40, 235, 179, 103, 254, 209, 216, 240, 226, 137, 235, 202, 159, 246, 216, 7, 87, 198, 14, 154, 229, 124, 177, 114, 140, 155, 28, 56, 202, 187, 189, 132, 217, 35, 125, 168, 49, 172, 33, 148, 159, 15, 45, 252, 12, 49, 107, 253, 177, 117, 179, 110, 99, 162, 43, 187, 88, 14, 173, 202, 82, 128, 208, 121, 132, 14, 90, 30, 37, 114, 98, 90, 59, 251, 135, 96, 51, 219, 251, 34, 169, 105, 201, 56, 184, 156, 225, 113, 53, 148, 0, 161, 37, 45, 151, 2, 169, 18, 147, 213, 69, 25, 233, 96, 221, 34, 206, 138, 39, 235, 5, 235, 126, 121, 183, 80, 192, 2, 254, 217, 1, 107, 113, 30, 201, 173, 116, 80, 27, 217, 20, 203, 190, 142, 217, 87, 18, 129, 183, 79, 68, 235, 7, 124, 230, 30, 203, 6, 171, 133, 169, 114, 85, 38, 126, 232, 227, 152, 43, 244, 63, 12, 178, 26, 56, 45, 35, 94, 185, 228, 206, 109, 178, 152, 196, 5, 66, 80, 64, 35, 43, 43, 97, 225, 12, 215, 12, 98, 21, 188, 3, 183, 233, 64, 113, 183, 14, 18, 209, 196, 127, 150, 101, 90, 46, 249, 157, 76, 229, 90, 127, 27, 75, 31, 249, 20, 238, 19, 109, 158, 97, 32, 71, 20, 136, 100, 105, 136, 128, 68, 49, 22, 101, 56, 137, 184, 100, 134, 217, 201, 201, 255, 188, 147, 133, 69, 53, 105, 179, 69, 116, 75, 140, 160, 180, 55}
	x5c := [][]byte{certificate}

	// convert [][]byte to []interface, because the cbor library returns parsed information in that manner
	x5cInterface := make([]interface{}, len(x5c))
	for i := range x5c {
		x5cInterface[i] = x5c[i]
	}

	attStatementMetadata := make(map[string]interface{})
	attStatementMetadata["alg"] = int64(-7)
	attStatementMetadata["sig"] = []byte{48, 69, 2, 33, 0, 132, 31, 68, 24, 131, 180, 46, 74, 1, 244, 22, 133, 205, 72, 1, 4, 195, 124, 242, 241, 77, 140, 205, 95, 96, 0, 160, 23, 56, 228, 102, 2, 2, 32, 57, 122, 156, 169, 55, 235, 78, 232, 59, 4, 22, 133, 255, 232, 177, 56, 42, 167, 249, 50, 50, 148, 251, 60, 36, 133, 34, 213, 90, 214, 29, 81}
	attStatementMetadata["x5c"] = x5cInterface

	type fields struct {
		ParsedPublicKeyCredential ParsedPublicKeyCredential
		Response                  ParsedAttestationResponse
		Raw                       CredentialCreationResponse
	}
	type args struct {
		storedChallenge    Challenge
		verifyUser         bool
		relyingPartyID     string
		relyingPartyOrigin []string
		metadataService    metadata.MetadataService
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Verification Test with Metadata#1/Successful",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "TGYwlX1A-MQpdohMywXLSE9zfsROEH-evNeX8CxXpy8",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "packed",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRpIDHash,
							Counter:  152,
							Flags:    0x045,
							AttData: AttestedCredentialData{
								AAGUID:              byteAAGUID,
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
						AttStatement: attStatementMetadata,
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
							Type: "public-key",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    byteChallenge,
				verifyUser:         true,
				relyingPartyID:     "webauthn.io",
				relyingPartyOrigin: []string{"https://webauthn.io"},
				metadataService:    defaultMetadataService,
			},
		},
		{
			name: "Verification Test with Metadata#2/Different Challenge",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "TGYwlX1A-MQpdohMywXLSE9zfsROEH-evNeX8CxXpy4",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "packed",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRpIDHash,
							Counter:  152,
							Flags:    0x045,
							AttData: AttestedCredentialData{
								AAGUID:              byteAAGUID,
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
						AttStatement: attStatementMetadata,
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
							Type: "public-key",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    byteChallenge,
				verifyUser:         true,
				relyingPartyID:     "webauthn.io",
				relyingPartyOrigin: []string{"https://webauthn.io"},
				metadataService:    defaultMetadataService,
			},
			wantErr: true,
		},
		{
			name: "Verification Test with Metadata#3/User not verified",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "TGYwlX1A-MQpdohMywXLSE9zfsROEH-evNeX8CxXpy8",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "packed",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRpIDHash,
							Counter:  152,
							Flags:    0x041,
							AttData: AttestedCredentialData{
								AAGUID:              byteAAGUID,
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
						AttStatement: attStatementMetadata,
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
							Type: "public-key",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    byteChallenge,
				verifyUser:         true,
				relyingPartyID:     "webauthn.io",
				relyingPartyOrigin: []string{"https://webauthn.io"},
				metadataService:    defaultMetadataService,
			},
			wantErr: true,
		},
		{
			name: "Verification Test with Metadata#4/Different AAGUID in AttestedCredentialData as in AttestationCertificate",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
						Type: "public-key",
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "TGYwlX1A-MQpdohMywXLSE9zfsROEH-evNeX8CxXpy8",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "packed",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRpIDHash,
							Counter:  152,
							Flags:    0x045,
							AttData: AttestedCredentialData{
								AAGUID:              byteWrongAaguid,
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
						AttStatement: attStatementMetadata,
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							ID:   "6QaD_8AZMbqC0sjXO7-6BE-ICqOM-94IfuZC1Q0XWef2ZG9Ts0gpUs-hfI1Nkv8f_qi5elEYAZrJSCjp7gRtBQ",
							Type: "public-key",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    byteChallenge,
				verifyUser:         true,
				relyingPartyID:     "webauthn.io",
				relyingPartyOrigin: []string{"https://webauthn.io"},
				metadataService:    defaultMetadataService,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcc := &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: tt.fields.ParsedPublicKeyCredential,
				Response:                  tt.fields.Response,
				Raw:                       tt.fields.Raw,
			}
			if err := pcc.Verify(tt.args.storedChallenge.String(), tt.args.verifyUser, tt.args.relyingPartyID, tt.args.relyingPartyOrigin, tt.args.metadataService, nil, nil); (err != nil) != tt.wantErr {
				t.Errorf("ParsedCredentialCreationData.Verify() error = %+v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

var testCredentialRequestBody = `{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		}
	}`

var testCredentialNoAttestationDataRequestBody = `{
	"id":"xYMIlXmY_0AJLjsV0ENJrP84FhNLhdMgqaNrpNko84w",
	"rawId":"xYMIlXmY_0AJLjsV0ENJrP84FhNLhdMgqaNrpNko84w",
	"response":{
		"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAKKBewWLF_QEN-3kSMIfjbmytI7CsaR8TXPZO3XAvQOqAiEAyGExoG9vQHAv9sIcs-lKfIy0wkKRG_T_iVHelLPjrm1jeDVjgVkERTCCBEEwggIpoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA1MjMxNDM5NDNaFw0yODA1MjAxNDM5NDNaMIHCMSMwIQYDVQQDDBpGSURPMiBCQVRDSCBLRVkgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQsFAAOCAgEAh92gn_ggiQXRLUHOCaTp1HpcBhsOw8ZwTKJBxwYK8ycQ5_QRXBcMRi8axVexH2HoUDTg_u-DkvH2UYGYjX_RAxgGIh4dPgrKXwVndtMwiI5QnQwXMocKtzyyeuSQv6INwk_QCuJL5LOAyPtNUWMTb_UvCcdYWjtZYFOeYQSK9T_6dtWSp6XAhIT4wf3CBaxyai-YiRn3nfi154vUrqtuDh56eODK7-Iezg9npbucln3XxW_kRhtk2FERSBmBoo7IotPd8NGTATnwUvt16vw6x3mW2a6zZGOOeYCQmeXlfNza7fSff1BdFWR5f4cJ0gFAv297Tf5dGZQvZD3DcyQ9OJeJ3RQQ9inX0Nhxk1-6cm1i2e8h9gTN7otjqYmnGjs3ezhPdax2AdrmckO43YNuchfTPECPTRzP4rQo3QbwGLeEAk_HV-oJmYiBkdhf2F2QLMm7SdeqZ1Jjg1W1vNJT288vj1EGF-_aKXg_bujAaK86_YNPBJaW9Rdw4EnfFUi5bEdkD5ZSpeAHCQzCDn2RzkBjs2rTFe4qRFUWtC-RZ4wFqRx70jXLIw-ArpeetpjtzJSNqQsqPlEvpyMxuV2ZjnruA2_ysP3RDzqNs7R8JVNKiie0RAbG7et43ULZcC7oix8JKYsJ6wDmX8Gyy7vWM-LS9XiZUH37sEvwKJbM-xxoYXV0aERhdGFYJ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAEUAAA",
		"clientDataJSON":"eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwMDAiLCJjaGFsbGVuZ2UiOiJyaWFpaHlPQnZtRFplZUhfbHRFY2pvS1ZSQzdnNnpUSUVES0pRSlk0Y0pVIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
	},
	"type":"public-key"
}
`

func TestVerifyX509CertificateChainAgainstMetadata(t *testing.T) {
	x5cBytes := []byte{48, 130, 2, 188, 48, 130, 1, 164, 160, 3, 2, 1, 2, 2, 4, 3, 173, 240, 18, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 46, 49, 44, 48, 42, 6, 3, 85, 4, 3, 19, 35, 89, 117, 98, 105, 99, 111, 32, 85, 50, 70, 32, 82, 111, 111, 116, 32, 67, 65, 32, 83, 101, 114, 105, 97, 108, 32, 52, 53, 55, 50, 48, 48, 54, 51, 49, 48, 32, 23, 13, 49, 52, 48, 56, 48, 49, 48, 48, 48, 48, 48, 48, 90, 24, 15, 50, 48, 53, 48, 48, 57, 48, 52, 48, 48, 48, 48, 48, 48, 90, 48, 109, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 83, 69, 49, 18, 48, 16, 6, 3, 85, 4, 10, 12, 9, 89, 117, 98, 105, 99, 111, 32, 65, 66, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 49, 38, 48, 36, 6, 3, 85, 4, 3, 12, 29, 89, 117, 98, 105, 99, 111, 32, 85, 50, 70, 32, 69, 69, 32, 83, 101, 114, 105, 97, 108, 32, 54, 49, 55, 51, 48, 56, 51, 52, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 25, 158, 135, 156, 22, 45, 183, 220, 57, 238, 74, 66, 160, 70, 22, 165, 179, 9, 254, 202, 9, 47, 118, 190, 9, 72, 249, 109, 110, 149, 202, 228, 204, 101, 205, 84, 160, 89, 207, 189, 199, 201, 179, 27, 43, 29, 108, 24, 68, 121, 194, 192, 97, 244, 24, 170, 149, 75, 89, 106, 44, 28, 250, 23, 163, 108, 48, 106, 48, 34, 6, 9, 43, 6, 1, 4, 1, 130, 196, 10, 2, 4, 21, 49, 46, 51, 46, 54, 46, 49, 46, 52, 46, 49, 46, 52, 49, 52, 56, 50, 46, 49, 46, 55, 48, 19, 6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 2, 1, 1, 4, 4, 3, 2, 4, 48, 48, 33, 6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 1, 1, 4, 4, 18, 4, 16, 250, 43, 153, 220, 158, 57, 66, 87, 143, 146, 74, 48, 210, 60, 65, 24, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 40, 235, 179, 103, 254, 209, 216, 240, 226, 137, 235, 202, 159, 246, 216, 7, 87, 198, 14, 154, 229, 124, 177, 114, 140, 155, 28, 56, 202, 187, 189, 132, 217, 35, 125, 168, 49, 172, 33, 148, 159, 15, 45, 252, 12, 49, 107, 253, 177, 117, 179, 110, 99, 162, 43, 187, 88, 14, 173, 202, 82, 128, 208, 121, 132, 14, 90, 30, 37, 114, 98, 90, 59, 251, 135, 96, 51, 219, 251, 34, 169, 105, 201, 56, 184, 156, 225, 113, 53, 148, 0, 161, 37, 45, 151, 2, 169, 18, 147, 213, 69, 25, 233, 96, 221, 34, 206, 138, 39, 235, 5, 235, 126, 121, 183, 80, 192, 2, 254, 217, 1, 107, 113, 30, 201, 173, 116, 80, 27, 217, 20, 203, 190, 142, 217, 87, 18, 129, 183, 79, 68, 235, 7, 124, 230, 30, 203, 6, 171, 133, 169, 114, 85, 38, 126, 232, 227, 152, 43, 244, 63, 12, 178, 26, 56, 45, 35, 94, 185, 228, 206, 109, 178, 152, 196, 5, 66, 80, 64, 35, 43, 43, 97, 225, 12, 215, 12, 98, 21, 188, 3, 183, 233, 64, 113, 183, 14, 18, 209, 196, 127, 150, 101, 90, 46, 249, 157, 76, 229, 90, 127, 27, 75, 31, 249, 20, 238, 19, 109, 158, 97, 32, 71, 20, 136, 100, 105, 136, 128, 68, 49, 22, 101, 56, 137, 184, 100, 134, 217, 201, 201, 255, 188, 147, 133, 69, 53, 105, 179, 69, 116, 75, 140, 160, 180, 55}
	x5c := [][]byte{x5cBytes}

	x5cInterface := make([]interface{}, len(x5c))
	for i := range x5c {
		x5cInterface[i] = x5c[i]
	}

	verifyError := VerifyX509CertificateChainAgainstMetadata(metadataStatement, x5cInterface)
	if verifyError != nil {
		t.Errorf("VerifyX509CertificateChainAgainstMetadata() returned error = %v, want error = nil", verifyError)
	}
}

func TestVerifyX509CertificateChainAgainstMetadata_empty_x5c(t *testing.T) {
	verifyError := VerifyX509CertificateChainAgainstMetadata(metadataStatement, nil)
	if verifyError == nil {
		t.Errorf("VerifyX509CertificateChainAgainstMetadata() returned error = nil, want error = %v", ErrAttestation)
	}
}

func TestGenerateAttestationCertificateKeyIdentifier(t *testing.T) {
	reqBody := ioutil.NopCloser(bytes.NewReader([]byte(registrationResponseString)))
	httpReq := &http.Request{Body: reqBody}

	parsedCredentialCreationResponse, err := ParseCredentialCreationResponse(httpReq)
	if err != nil {
		t.Errorf("Error while parsing response: %v", err)
		return
	}
	type args struct {
		pcc *ParsedCredentialCreationData
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				pcc: parsedCredentialCreationResponse,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identifier, err := GenerateAttestationCertificateKeyIdentifier(tt.args.pcc)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateAttestationCertificateKeyIdentifier() error = %+v, wantErr %v", err, tt.wantErr)
			}
			if identifier != "7295499531c0fb059d6c88d1b29665547757c6c6" {
				t.Errorf("GenerateAttestationCertificateKeyIdentifier() got = '%v', want = '7295499531c0fb059d6c88d1b29665547757c6c6'", identifier)
			}
		})
	}
}

var defaultMetadataService = &TestMetadataService{}

type TestMetadataService struct {
}

func (metadataService *TestMetadataService) WebAuthnAuthenticator(aaguid string) *metadata.MetadataStatement {
	if aaguid == "fa2b99dc-9e39-4257-8f92-4a30d23c4118" {
		return metadataStatement
	} else {
		return nil
	}
}

func (metadataService *TestMetadataService) U2FAuthenticator(attestationCertificateKeyIdentifier string) *metadata.MetadataStatement {
	return nil
}

var metadataStatement = &metadata.MetadataStatement{
	LegalHeader:                          "Metadata Legal Header: Version 1.00.　Date: May 21, 2018.  To access, view and use any Metadata Statements or the TOC file (“METADATA”) from the MDS, You must be bound by the latest FIDO Alliance Metadata Usage Terms that can be found at http://mds2.fidoalliance.org/ . If you already have a valid token, access the above URL attaching your token such as http://mds2.fidoalliance.org?token=YOUR-VALID-TOKEN.  If You have not entered into the agreement, please visit the registration site found at http://fidoalliance.org/MDS/ and enter into the agreement and obtain a valid token.  You must not redistribute this file to any third party. Removal of this Legal Header or modifying any part of this file renders this file invalid.  The integrity of this file as originally provided from the MDS is validated by the hash value of this file that is recorded in the MDS. The use of invalid files is strictly prohibited. If the version number for the Legal Header is updated from Version 1.00, the METADATA below may also be updated or may not be available. Please use the METADATA with the Legal Header with the latest version number.  Dated: 2018-05-21 Version LH-1.00",
	Aaid:                                 "",
	AaGUID:                               "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
	AttestationCertificateKeyIdentifiers: nil,
	Description:                          "YubiKey Series 5 with NFC",
	AlternativeDescriptions:              nil,
	AuthenticatorVersion:                 50100,
	ProtocolFamily:                       "fido2",
	Upv:                                  nil,
	AssertionScheme:                      "FIDOV2",
	AuthenticationAlgorithm:              1,
	AuthenticationAlgorithms:             []uint16{1, 18},
	PublicKeyAlgAndEncoding:              260,
	PublicKeyAlgAndEncodings:             nil,
	AttestationTypes:                     []uint16{15879},
	UserVerificationDetails:              nil,
	KeyProtection:                        10,
	IsKeyRestricted:                      false,
	IsFreshUserVerificationRequired:      false,
	MatcherProtection:                    4,
	CryptoStrength:                       128,
	OperatingEnv:                         "Secure Element (SE)",
	AttachmentHint:                       30,
	IsSecondFactorOnly:                   false,
	TcDisplay:                            0,
	TcDisplayContentType:                 "",
	TcDisplayPNGCharacteristics:          nil,
	AttestationRootCertificates:          []string{"MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw=="}, // TODO
	EcdaaTrustAnchors:                    nil,
	Icon:                                 "",
	SupportedExtensions:                  nil,
}

type testCredentialStore struct {
}

func (store *testCredentialStore) GetCredential(credentialId []byte) (*credential.Credential, []byte, error) {
	return nil, nil, nil
}

func (store *testCredentialStore) GetCredentialForUser(userId []byte) ([]credential.Credential, error) {
	return nil, nil
}

func (store *testCredentialStore) ExistsCredential(credentialId []byte) (bool, error) {
	storedId, _ := base64.RawURLEncoding.DecodeString("6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g")
	if bytes.Equal(credentialId, storedId) {
		return true, nil
	} else {
		return false, nil
	}
}

var registrationResponseString = `
	{
		"id": "bhyefcOIdulv0rYy63let_trQD8vPX0y7M_Ho8msEFFZ8gAZ2HMfn0t1nyve5w4IlUDvrqam5g727guWstT2HQ",
		"rawId": "bhyefcOIdulv0rYy63let_trQD8vPX0y7M_Ho8msEFFZ8gAZ2HMfn0t1nyve5w4IlUDvrqam5g727guWstT2HQ",
		"type":"public-key",
		"response": {
			"attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgUTpi6aL2YtXTcHFRU5jq7kzZK5Qr9uFN-NdZDpMuAJgCIQCAwyNEbo8tAeKVnTW1YVLDsZFWQ21Xi9m5p6x0H07MMmN4NWOBWQLAMIICvDCCAaSgAwIBAgIEA63wEjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgNjE3MzA4MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZnoecFi233DnuSkKgRhalswn-ygkvdr4JSPltbpXK5MxlzVSgWc-9x8mzGysdbBhEecLAYfQYqpVLWWosHPoXo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBD6K5ncnjlCV4-SSjDSPEEYMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBACjrs2f-0djw4onryp_22AdXxg6a5XyxcoybHDjKu72E2SN9qDGsIZSfDy38DDFr_bF1s25joiu7WA6tylKA0HmEDloeJXJiWjv7h2Az2_siqWnJOLic4XE1lAChJS2XAqkSk9VFGelg3SLOiifrBet-ebdQwAL-2QFrcR7JrXRQG9kUy76O2VcSgbdPROsHfOYeywarhalyVSZ-6OOYK_Q_DLIaOC0jXrnkzm2ymMQFQlBAIysrYeEM1wxiFbwDt-lAcbcOEtHEf5ZlWi75nUzlWn8bSx_5FO4TbZ5hIEcUiGRpiIBEMRZlOIm4ZIbZycn_vJOFRTVps0V0S4ygtDdoYXV0aERhdGFYxHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBuHJ59w4h26W_StjLreV63-2tAPy89fTLsz8ejyawQUVnyABnYcx-fS3WfK97nDgiVQO-upqbmDvbuC5ay1PYdpQECAyYgASFYIOTMALEN44svHfeaakgiI-DFLyg5dzylHgXyi8ebZ0csIlggZK1-s46igwq-g0_mF86gh2KEElcyJ4rqx1nLfhiHX8M",
			"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZk5hX1J2bHhvSGFEZkgxR2E3akE5LVVmWFVaRXcwaWVjZ2dDY1NGVjR6SSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
		}
	}`
