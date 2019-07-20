package lastpass

// AccountNotFoundError indicates that no account with AccountNotFoundError.ID exists on LastPass
type AccountNotFoundError struct {
	// account ID that does not exist
	ID string
}

func (e *AccountNotFoundError) Error() string {
	return "could not find LastPass account with ID=" + e.ID
}
