package credential

// TODO: Doc
type CredentialService interface {
	ExistsCredential(credentialId []byte) (bool, error)
	GetCredential(credentialId []byte) (cred *Credential, userId []byte, err error)
	GetCredentialForUser(userId []byte) ([]Credential, error)
}
