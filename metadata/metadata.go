package metadata

import (
	"errors"
	"github.com/gofrs/uuid"
)

// Metadata is a map of authenticator AAGUIDs to corresponding metadata statements
var Metadata = make(map[uuid.UUID]MetadataBLOBPayloadEntry)

// Conformance indicates if test metadata is currently being used
var Conformance = false

type MetadataBLOBPayload struct {
	//The legalHeader, which MUST be in each BLOB, is an indication of the acceptance of the relevant legal agreement for using the MDS. The FIDO Alliance’s Blob will contain this legal header: "legalHeader": "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
	LegalHeader string `json:"legalHeader"`
	//The serial number of this Metadata BLOB Payload. Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor BLOB will have a "no" value exactly incremented by one.
	Number int `json:"no"`
	// ISO-8601 formatted date when the next update will be provided at latest.
	NextUpdate string `json:"nextUpdate"`
	// List of MetadataBLOBPayloadEntry objects.
	Entries []MetadataBLOBPayloadEntry `json:"entries"`
}

func (m *MetadataBLOBPayload) Valid() error {
	err := m.VerifyEntries()
	if err != nil {
		return err
	}
	return nil
}

func (m *MetadataBLOBPayload) VerifyEntries() error {
	if m.Entries == nil || len(m.Entries) == 0 {
		return errors.New("entries must not be nil or empty")
	}
	return nil
}

type MetadataBLOBPayloadEntry struct {
	//The AAID of the authenticator this metadata BLOB payload entry relates to. See [UAFProtocol] for the definition of the AAID structure. This field MUST be set if the authenticator implements FIDO UAF.
	Aaid string `json:"aaid"`
	// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the definition of the AAGUID structure. This field MUST be set if the authenticator implements FIDO2.
	AaGUID string `json:"aaguid"`
	// A list of the attestation certificate public key identifiers encoded as hex string.
	AttestationCertificateKeyIdentifiers []string `json:"attestationCertificateKeyIdentifiers"`
	//The metadataStatement JSON object as defined in [FIDOMetadataStatement].
	MetadataStatement MetadataStatement `json:"metadataStatement"`
	// Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator
	BiometricStatusReports []BiometricStatusReport `json:"biometricStatusReports"`
	// An array of status reports applicable to this authenticator.
	StatusReports []StatusReport `json:"statusReports"`
	// ISO-8601 formatted date since when the status report array was set to the current value.
	TimeOfLastStatusChange string `json:"timeOfLastStatusChange"`
	// URL of a list of rogue (i.e. untrusted) individual authenticators.
	RogueListURL string `json:"rogueListURL"`
	// The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL (with type rogueListEntry[]).
	RogueListHash string `json:"rogueListHash"`
}

// MetadataStatement - Authenticator metadata statements are used directly by the FIDO server at a relying party, but the information contained in the authoritative statement is used in several other places.
type MetadataStatement struct {
	// The legalHeader, if present, contains a legal guide for accessing and using metadata, which itself MAY contain URL(s) pointing to further information, such as a full Terms and Conditions statement.
	LegalHeader string `json:"legalHeader"`
	// Schema Numerical identifier of the schema. Use this to check if you are dealing with old or new metadata.
	Schema uint16 `json:"schema"`
	// The Authenticator Attestation ID.
	Aaid string `json:"aaid"`
	// The Authenticator Attestation GUID.
	AaGUID string `json:"aaguid"`
	// A list of the attestation certificate public key identifiers encoded as hex string.
	AttestationCertificateKeyIdentifiers []string `json:"attestationCertificateKeyIdentifiers"`
	// A human-readable, short description of the authenticator, in English.
	Description string `json:"description"`
	// A list of human-readable short descriptions of the authenticator in different languages.
	AlternativeDescriptions map[string]string `json:"alternativeDescriptions"`
	// Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
	AuthenticatorVersion uint32 `json:"authenticatorVersion"`
	// The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
	ProtocolFamily string `json:"protocolFamily"`
	// The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
	Upv []Version `json:"upv"`
	// The list of authentication algorithms supported by the authenticator.
	AuthenticationAlgorithms []string `json:"authenticationAlgorithms"`
	// The list of public key formats supported by the authenticator during registration operations.
	PublicKeyAlgAndEncodings []string `json:"publicKeyAlgAndEncodings"`
	// The supported attestation type(s).
	AttestationTypes []string `json:"attestationTypes"`
	// A list of alternative VerificationMethodANDCombinations.
	UserVerificationDetails [][]VerificationMethodDescriptor `json:"userVerificationDetails"`
	// A 16-bit number representing the bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values
	KeyProtection []string `json:"keyProtection"`
	// This entry is set to true or it is omitted, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.
	// This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions.
	IsKeyRestricted bool `json:"isKeyRestricted"`
	// This entry is set to true or it is omitted, if Uauth key usage always requires a fresh user verification
	// This entry is set to false, if the Uauth key can be used without requiring a fresh user verification, e.g. without any additional user interaction, if the user was verified a (potentially configurable) caching time ago.
	IsFreshUserVerificationRequired bool `json:"isFreshUserVerificationRequired"`
	// A 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in the FIDO Registry of Predefined Values
	MatcherProtection []string `json:"matcherProtection"`
	// The authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level).
	CryptoStrength uint16 `json:"cryptoStrength"`
	// A string array representing the bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values
	AttachmentHint []string `json:"attachmentHint"`
	// A 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values
	TcDisplay []string `json:"tcDisplay"`
	// Supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
	TcDisplayContentType string `json:"tcDisplayContentType"`
	// A list of alternative DisplayPNGCharacteristicsDescriptor. Each of these entries is one alternative of supported image characteristics for displaying a PNG image.
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics"`
	// Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
	// Multiple certificates might be used for different batches of the same model.
	// The array does not represent a certificate chain, but only the trust anchor of that chain.
	// A trust anchor can be a root certificate, an intermediate CA certificate or even the attestation certificate itself.
	AttestationRootCertificates []string `json:"attestationRootCertificates"`
	// A list of trust anchors used for ECDAA attestation. This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA.
	EcdaaTrustAnchors []EcdaaTrustAnchor `json:"ecdaaTrustAnchors"`
	// A data: url [RFC2397] encoded PNG [PNG] icon for the Authenticator.
	Icon string `json:"icon"`
	// List of extensions supported by the authenticator.
	SupportedExtensions []ExtensionDescriptor `json:"supportedExtensions"`
	// Describes supported versions, extensions, AAGUID of the device and its capabilities.
	AuthenticatorGetInfo AuthenticatorGetInfo `json:"authenticatorGetInfo"`
}

type AuthenticatorGetInfo struct {
	Versions   []string        `json:"versions"`
	Extensions []string        `json:"extensions"`
	AaGUID     string          `json:"aaguid"`
	Options    map[string]bool `json:"options"`
	MaxMsgSize uint            `json:"maxMsgSize"`
	// Ambiguous: The Spec says PinProtocols. In the Blob stands pinUvAuthProtocols
	PinProtocols []uint `json:"pinUvAuthProtocols"`
}

// AuthenticatorStatus - This enumeration describes the status of an authenticator model as identified by its AAID and potentially some additional information (such as a specific attestation key).
type AuthenticatorStatus string

const (
	// NotFidoCertified - This authenticator is not FIDO certified.
	NotFidoCertified = "NOT_FIDO_CERTIFIED"
	// FidoCertified - This authenticator has passed FIDO functional certification. This certification scheme is phased out and will be replaced by FIDO_CERTIFIED_L1.
	FidoCertified = "FIDO_CERTIFIED"
	// UserVerificationBypass - Indicates that malware is able to bypass the user verification. This means that the authenticator could be used without the user's consent and potentially even without the user's knowledge.
	UserVerificationBypass = "USER_VERIFICATION_BYPASS"
	// AttestationKeyCompromise - Indicates that an attestation key for this authenticator is known to be compromised. Additional data should be supplied, including the key identifier and the date of compromise, if known.
	AttestationKeyCompromise = "ATTESTATION_KEY_COMPROMISE"
	// UserKeyRemoteCompromise - This authenticator has identified weaknesses that allow registered keys to be compromised and should not be trusted. This would include both, e.g. weak entropy that causes predictable keys to be generated or side channels that allow keys or signatures to be forged, guessed or extracted.
	UserKeyRemoteCompromise = "USER_KEY_REMOTE_COMPROMISE"
	// UserKeyPhysicalCompromise - This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys to be extracted by an adversary in physical possession of the device.
	UserKeyPhysicalCompromise = "USER_KEY_PHYSICAL_COMPROMISE"
	// UpdateAvailable - A software or firmware update is available for the device. Additional data should be supplied including a URL where users can obtain an update and the date the update was published.
	UpdateAvailable = "UPDATE_AVAILABLE"
	// Revoked - The FIDO Alliance has determined that this authenticator should not be trusted for any reason, for example if it is known to be a fraudulent product or contain a deliberate backdoor.
	Revoked = "REVOKED"
	// SelfAssertionSubmitted - The authenticator vendor has completed and submitted the self-certification checklist to the FIDO Alliance. If this completed checklist is publicly available, the URL will be specified in StatusReport.url.
	SelfAssertionSubmitted = "SELF_ASSERTION_SUBMITTED"
	// FidoCertifiedL1 - The authenticator has passed FIDO Authenticator certification at level 1. This level is the more strict successor of FIDO_CERTIFIED.
	FidoCertifiedL1 = "FIDO_CERTIFIED_L1"
	// FidoCertifiedL1plus - The authenticator has passed FIDO Authenticator certification at level 1+. This level is the more than level 1.
	FidoCertifiedL1plus = "FIDO_CERTIFIED_L1plus"
	// FidoCertifiedL2 - The authenticator has passed FIDO Authenticator certification at level 2. This level is more strict than level 1+.
	FidoCertifiedL2 = "FIDO_CERTIFIED_L2"
	// FidoCertifiedL2plus - The authenticator has passed FIDO Authenticator certification at level 2+. This level is more strict than level 2.
	FidoCertifiedL2plus = "FIDO_CERTIFIED_L2plus"
	// FidoCertifiedL3 - The authenticator has passed FIDO Authenticator certification at level 3. This level is more strict than level 2+.
	FidoCertifiedL3 = "FIDO_CERTIFIED_L3"
	// FidoCertifiedL3plus - The authenticator has passed FIDO Authenticator certification at level 3+. This level is more strict than level 3.
	FidoCertifiedL3plus = "FIDO_CERTIFIED_L3plus"
)

type AuthenticatorAttestationType string

//Attestation Types
const (
	// BasicFull - Indicates full basic attestation, based on an attestation private key shared among a class of authenticators (e.g. same model). Authenticators must provide its attestation signature during the registration process for the same reason. The attestation trust anchor is shared with FIDO Servers out of band (as part of the Metadata). This sharing process should be done according to [UAFMetadataService].
	BasicFull AuthenticatorAttestationType = "basic_full"
	// BasicSurrogate - Just syntactically a Basic Attestation. The attestation object self-signed, i.e. it is signed using the UAuth.priv key, i.e. the key corresponding to the UAuth.pub key included in the attestation object. As a consequence it does not provide a cryptographic proof of the security characteristics. But it is the best thing we can do if the authenticator is not able to have an attestation private key.
	BasicSurrogate AuthenticatorAttestationType = "basic_surrogate"
	// Ecdaa - Indicates use of elliptic curve based direct anonymous attestation as defined in [FIDOEcdaaAlgorithm]. Support for this attestation type is optional at this time. It might be required by FIDO Certification.
	Ecdaa AuthenticatorAttestationType = "ecdaa"
	// AttCA - Indicates PrivacyCA attestation as defined in [TCG-CMCProfile-AIKCertEnroll]. Support for this attestation type is optional at this time. It might be required by FIDO Certification.
	AttCA  AuthenticatorAttestationType = "attca"
	AnonCa AuthenticatorAttestationType = "anonca"
	None   AuthenticatorAttestationType = "none"
)

// UndesiredAuthenticatorStatus is an array of undesirable authenticator statuses
var UndesiredAuthenticatorStatus = [...]AuthenticatorStatus{
	AttestationKeyCompromise,
	UserVerificationBypass,
	UserKeyRemoteCompromise,
	UserKeyPhysicalCompromise,
	Revoked,
}

// IsUndesiredAuthenticatorStatus returns whether the supplied authenticator status is desirable or not
func IsUndesiredAuthenticatorStatus(status AuthenticatorStatus) bool {
	for _, s := range UndesiredAuthenticatorStatus {
		if s == status {
			return true
		}
	}
	return false
}

// StatusReport - Contains the current BiometricStatusReport of one of the authenticator's biometric component.
type StatusReport struct {
	// Status of the authenticator. Additional fields MAY be set depending on this value.
	Status string `json:"status"`
	// ISO-8601 formatted date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.
	EffectiveDate string `json:"effectiveDate"`
	// Base64-encoded [RFC4648] (not base64url!) DER [ITU-X690-2008] PKIX certificate value related to the current status, if applicable.
	Certificate string `json:"certificate"`
	// HTTPS URL where additional information may be found related to the current status, if applicable.
	URL string `json:"url"`
	// Describes the externally visible aspects of the Authenticator Certification evaluation.
	CertificationDescriptor string `json:"certificationDescriptor"`
	// The unique identifier for the issued Certification.
	CertificateNumber string `json:"certificateNumber"`
	// The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".
	CertificationPolicyVersion string `json:"certificationPolicyVersion"`
	// The Document Version of the Authenticator Security Requirements (DV) [FIDOAuthenticatorSecurityRequirements] the implementation is certified to, e.g. "1.2.0".
	CertificationRequirementsVersion string `json:"certificationRequirementsVersion"`
}

// BiometricStatusReport - Contains the current BiometricStatusReport of one of the authenticator's biometric component.
type BiometricStatusReport struct {
	// Achieved level of the biometric certification of this biometric component of the authenticator
	CertLevel uint16 `json:"certLevel"`
	// A single USER_VERIFY constant indicating the modality of the biometric component
	Modality uint32 `json:"modality"`
	// ISO-8601 formatted date since when the certLevel achieved, if applicable. If no date is given, the status is assumed to be effective while present.
	EffectiveDate string `json:"effectiveDate"`
	// Describes the externally visible aspects of the Biometric Certification evaluation.
	CertificationDescriptor string `json:"certificationDescriptor"`
	// The unique identifier for the issued Biometric Certification.
	CertificateNumber string `json:"certificateNumber"`
	// The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".
	CertificationPolicyVersion string `json:"certificationPolicyVersion"`
	// The version of the Biometric Requirements [FIDOBiometricsRequirements] the implementation is certified to, e.g. "1.0.0".
	CertificationRequirementsVersion string `json:"certificationRequirementsVersion"`
}

// RogueListEntry - Contains a list of individual authenticators known to be rogue
type RogueListEntry struct {
	// Base64url encoding of the rogue authenticator's secret key
	Sk string `json:"sk"`
	// ISO-8601 formatted date since when this entry is effective.
	Date string `json:"date"`
}

// Version - Represents a generic version with major and minor fields.
type Version struct {
	// Major version.
	Major uint16 `json:"major"`
	// Minor version.
	Minor uint16 `json:"minor"`
}

// CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user verification methods.
type CodeAccuracyDescriptor struct {
	// The numeric system base (radix) of the code, e.g. 10 in the case of decimal digits.
	Base uint16 `json:"base"`
	// The minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.
	MinLength uint16 `json:"minLength"`
	// Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.
	MaxRetries uint16 `json:"maxRetries"`
	// Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar).
	// 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded.
	// All alternative user verification methods MUST be specified appropriately in the Metadata in userVerificationDetails.
	BlockSlowdown uint16 `json:"blockSlowdown"`
}

// The BiometricAccuracyDescriptor describes relevant accuracy/complexity aspects in the case of a biometric user verification method.
type BiometricAccuracyDescriptor struct {
	// The false rejection rate [ISO19795-1] for a single template, i.e. the percentage of verification transactions with truthful claims of identity that are incorrectly denied.
	SelfAttestedFRR int64 `json:"selfAttestedFRR "`
	// The false acceptance rate [ISO19795-1] for a single template, i.e. the percentage of verification transactions with wrongful claims of identity that are incorrectly confirmed.
	SelfAttestedFAR int64 `json:"selfAttestedFAR "`
	// Maximum number of alternative templates from different fingers allowed.
	MaxTemplates uint16 `json:"maxTemplates"`
	// Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.
	MaxRetries uint16 `json:"maxRetries"`
	// Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar).
	// 0 means that this user verification method will be blocked either permanently or until an alternative user verification method succeeded.
	// All alternative user verification methods MUST be specified appropriately in the metadata in userVerificationDetails.
	BlockSlowdown uint16 `json:"blockSlowdown"`
}

// The PatternAccuracyDescriptor describes relevant accuracy/complexity aspects in the case that a pattern is used as the user verification method.
type PatternAccuracyDescriptor struct {
	// Number of possible patterns (having the minimum length) out of which exactly one would be the right one, i.e. 1/probability in the case of equal distribution.
	MinComplexity uint64 `json:"minComplexity"`
	// Maximum number of false attempts before the authenticator will block authentication using this method (at least temporarily). 0 means it will never block.
	MaxRetries uint16 `json:"maxRetries"`
	// Enforced minimum number of seconds wait time after blocking (due to forced reboot or similar mechanism).
	// 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded.
	// All alternative user verification methods MUST be specified appropriately in the metadata under userVerificationDetails.
	BlockSlowdown uint16 `json:"blockSlowdown"`
}

// VerificationMethodDescriptor - A descriptor for a specific base user verification method as implemented by the authenticator.
type VerificationMethodDescriptor struct {
	// a single USER_VERIFY constant (see [FIDORegistry]), not a bit flag combination. This value MUST be non-zero.
	UserVerification uint32 `json:"userVerification"`
	// May optionally be used in the case of method USER_VERIFY_PASSCODE.
	CaDesc CodeAccuracyDescriptor `json:"caDesc"`
	// May optionally be used in the case of method USER_VERIFY_FINGERPRINT, USER_VERIFY_VOICEPRINT, USER_VERIFY_FACEPRINT, USER_VERIFY_EYEPRINT, or USER_VERIFY_HANDPRINT.
	BaDesc BiometricAccuracyDescriptor `json:"baDesc"`
	// May optionally be used in case of method USER_VERIFY_PATTERN.
	PaDesc PatternAccuracyDescriptor `json:"paDesc"`
}

// VerificationMethodANDCombinations MUST be non-empty. It is a list containing the base user verification methods which must be passed as part of a successful user verification.
type VerificationMethodANDCombinations struct {
	//This list will contain only a single entry if using a single user verification method is sufficient.
	// If this list contains multiple entries, then all of the listed user verification methods MUST be passed as part of the user verification process.
	VerificationMethodAndCombinations []VerificationMethodDescriptor `json:"verificationMethodANDCombinations"`
}

// The rgbPaletteEntry is an RGB three-sample tuple palette entry
type rgbPaletteEntry struct {
	// Red channel sample value
	R uint16 `json:"r"`
	// Green channel sample value
	G uint16 `json:"g"`
	// Blue channel sample value
	B uint16 `json:"b"`
}

// The DisplayPNGCharacteristicsDescriptor describes a PNG image characteristics as defined in the PNG [PNG] spec for IHDR (image header) and PLTE (palette table)
type DisplayPNGCharacteristicsDescriptor struct {
	// image width
	Width uint32 `json:"width"`
	// image height
	Height uint32 `json:"height"`
	// Bit depth - bits per sample or per palette index.
	BitDepth byte `json:"bitDepth"`
	// Color type defines the PNG image type.
	ColorType byte `json:"colorType"`
	// Compression method used to compress the image data.
	Compression byte `json:"compression"`
	// Filter method is the preprocessing method applied to the image data before compression.
	Filter byte `json:"filter"`
	// Interlace method is the transmission order of the image data.
	Interlace byte `json:"interlace"`
	// 1 to 256 palette entries
	Plte []rgbPaletteEntry `json:"plte"`
}

// EcdaaTrustAnchor - In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor MUST be specified in this field.
type EcdaaTrustAnchor struct {
	// base64url encoding of the result of ECPoint2ToB of the ECPoint2 X
	X string `json:"x"`
	// base64url encoding of the result of ECPoint2ToB of the ECPoint2 Y
	Y string `json:"y"`
	// base64url encoding of the result of BigNumberToB(c)
	C string `json:"c"`
	// base64url encoding of the result of BigNumberToB(sx)
	SX string `json:"sx"`
	// base64url encoding of the result of BigNumberToB(sy)
	SY string `json:"sy"`
	// Name of the Barreto-Naehrig elliptic curve for G1. "BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported.
	G1Curve string `json:"G1Curve"`
}

// ExtensionDescriptor - This descriptor contains an extension supported by the authenticator.
type ExtensionDescriptor struct {
	// Identifies the extension.
	ID string `json:"id"`
	// The TAG of the extension if this was assigned. TAGs are assigned to extensions if they could appear in an assertion.
	Tag uint16 `json:"tag"`
	// Contains arbitrary data further describing the extension and/or data needed to correctly process the extension.
	Data string `json:"data"`
	// Indicates whether unknown extensions must be ignored (false) or must lead to an error (true) when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
	FailIfUnknown bool `json:"fail_if_unknown"`
}
