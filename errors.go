package lastpass

import "fmt"

// AccountNotFoundError indicates that no account with AccountNotFoundError.ID exists on LastPass.
type AccountNotFoundError struct {
	// account ID that does not exist
	ID string
}

func (e *AccountNotFoundError) Error() string {
	return "could not find LastPass account with ID=" + e.ID
}

// AuthenticationError indicates that the Client is not logged in.
type AuthenticationError struct {
	msg string
}

func NewAuthenticationError(msg string) *AuthenticationError {
	return &AuthenticationError{msg}
}
func (e *AuthenticationError) Error() string {
	return e.msg
}

type weakECBEncryptionError struct {
	accountID string
}

func (e *weakECBEncryptionError) Error() string {
	return fmt.Sprintf(
		"refused to decrypt account with id=%s because it is AES 256 ECB encrypted which is insecure; "+
			"update this account with any up-to-date LastPass client to re-encrypt it using AES 256 CBC",
		e.accountID)
}
