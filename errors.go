package lastpass

// AccountNotFoundError indicates that no account with AccountNotFoundError.ID exists on LastPass
type AccountNotFoundError struct {
	// account ID that does not exist
	ID string
}

func (e *AccountNotFoundError) Error() string {
	return "could not find LastPass account with ID=" + e.ID
}

// UnauthenticatedError indicates that the Client is not logged in.
type UnauthenticatedError struct{}

func (e *UnauthenticatedError) Error() string {
	return "client is not logged in"
}
