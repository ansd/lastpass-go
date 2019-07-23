package lastpass_test

import "github.com/ansd/lastpass-go"

// Login with master password (without two-factor authentication).
//
// If an invalid user name or master password is supplied,
// NewClient returns an error of type *AuthenticationError.
func ExampleNewClient_passwordBasedAuthentication() {
	_, err := lastpass.NewClient("user name", "master password")
	if err != nil {
		// TODO handle error
	}
}

// Login with two-factor authentication:
// 1st factor is master passord,
// 2nd factor is out-of-band mechanism (e.g. LastPass Authenticator Push Notification or
// Duo Security Push Notification).
//
// Below code is the same as the login without two-factor authentication.
// Once the NewClient function got invoked, the user has around 90 seconds to accept
// the out-of-band mechanism (e.g. by selecting "Approve" in the LastPass Authenticator or
// Duo Security app.)
//
// If the user does not accept the out-of-band mechanism within the 90 seconds,
// NewClient returns an error of type *AuthenticationError.
func ExampleNewClient_outOfBandAuthentication() {
	_, err := lastpass.NewClient("user name", "master password")
	if err != nil {
		// TODO handle error
	}
}

// Login with two-factor authentication:
// 1st factor is master passord,
// 2nd factor is one-time password (e.g. one-time verification code of LastPass Authenticator,
// Google Authenticator, Microsoft Authenticator, YubiKey, Transakt, Duo Security, or Sesame).
//
// If an invalid user name, master password, or one-time password is supplied,
// NewClient returns an error of type *AuthenticationError.
func ExampleNewClient_oneTimePasswordAuthentication() {
	_, err := lastpass.NewClient("user name", "master password", lastpass.WithOneTimePassword("123456"))
	if err != nil {
		// TODO handle error
	}
}
