package lastpass

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
