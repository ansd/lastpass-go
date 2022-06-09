package lastpass_test

import (
	"context"
	"log"
	"os"

	"github.com/veloceapps/lastpass-go"
)

// Login with master password (without two-factor authentication).
//
// If an invalid user name or master password is supplied,
// NewClient returns an error of type *AuthenticationError.
func ExampleNewClient_passwordBasedAuthentication() {
	_, _ = lastpass.NewClient(context.Background(), "user name", "master password")
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
	_, _ = lastpass.NewClient(context.Background(), "user name", "master password")
}

// Login with two-factor authentication:
// 1st factor is master passord,
// 2nd factor is one-time password (e.g. one-time verification code of LastPass Authenticator,
// Google Authenticator, Microsoft Authenticator, YubiKey, Transakt, Duo Security, or Sesame).
//
// If an invalid user name, master password, or one-time password is supplied,
// NewClient returns an error of type *AuthenticationError.
func ExampleNewClient_oneTimePasswordAuthentication() {
	_, _ = lastpass.NewClient(context.Background(), "user name", "master password",
		lastpass.WithOneTimePassword("123456"),
	)
}

// Login with two-factor authentication and trust:
//
// The WithTrust option will cause subsequent logins to not require multifactor authentication.
// It will create a trust label with the format `<hostname> <operating system name> lastpass-go`
// which will show up in the LastPass Web Browser Extension under Account Settings => Trusted Devices.
func ExampleNewClient_trust() {
	// On first login, the 2nd factor must be provided.
	_, _ = lastpass.NewClient(context.Background(), "user name", "master password",
		lastpass.WithOneTimePassword("123456"),
		lastpass.WithTrust(),
	)
	// Thereafter, within the next 30 days, the 2nd factor can be omitted.
	// (If you want to disable the default limit of 30 days, in the LastPass Web Browser Extension select the checkbox
	// Account Settings => General => Show Advanced Settings => Don't end trust period after 30 days.)
	_, _ = lastpass.NewClient(context.Background(), "user name", "master password")
}

// WithLogger enables logging for all methods on lastpass.Client.
func ExampleWithLogger() {
	logger := log.New(os.Stderr, "lastpass: ", log.LstdFlags)

	_, _ = lastpass.NewClient(context.Background(), "user name", "master password",
		lastpass.WithLogger(logger))
}

// NewContextWithLogger logs only for a specific method (request scope).
// In the following example, it emits logs for only the NewClient method.
func ExampleNewContextWithLogger() {
	logger := log.New(os.Stderr, "lastpass: ", log.LstdFlags)

	_, _ = lastpass.NewClient(
		lastpass.NewContextWithLogger(context.Background(), logger),
		"user name", "master password")
}
