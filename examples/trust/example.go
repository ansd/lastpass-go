// Example showing the trust feature which allows to skip multifactor authentication in subsequent logins.
// This example assumes multifactor authentication is set up.
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/veloceapps/lastpass-go"
)

func main() {
	// Read LastPass username and master password from file.
	b, err := ioutil.ReadFile("../credentials.txt")
	if err != nil {
		log.Fatalln(err)
	}
	lines := strings.Split(string(b), "\n")
	username := lines[0]
	masterPassword := lines[1]

	// Store file trusted_id in directory $HOME/.lastpass-go/
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalln(err)
	}
	configDir := filepath.Join(homeDir, ".lastpass-go")

	// On 1st login, provide the following:
	client, err := lastpass.NewClient(
		context.Background(),
		username,
		masterPassword,
		lastpass.WithOneTimePassword("123456"), // the 2nd factor (here in the form of a one-time password, e.g. from you Google Authenticator app)
		lastpass.WithTrust(),                   // this option will generate a random trust ID if file trusted_id doesn't exist already
		lastpass.WithConfigDir(configDir),      // optionally, provide a configuration directory where file trusted_id will be stored
	)
	if err != nil {
		log.Fatalln(err)
	}

	if err = client.Logout(context.Background()); err != nil {
		log.Fatalln(err)
	}

	// On 1st login using WithTrust(), a file `$HOME/.lastpass-go/trusted_id` is created.
	// This file contains a randomly generated trust ID which will replace the 2nd factor (one-time password) for the next 30 days.
	// (If you want to disable the default limit of 30 days, in the LastPass Web Browser Extension select the checkbox
	// Account Settings => General => Show Advanced Settings => Don't end trust period after 30 days.)
	// Additionally, a trust label with the format `<hostname> <operating system name> lastpass-go` will show up in the LastPass
	// Web Browser Extension under Account Settings => Trusted Devices.

	// From now on, you can omit the 2nd factor (one time password) when logging in from the same device.
	// If you set an optional configuration directory on 1st login (as done above), you'll need to set it every time
	// when creating a NewClient() (since the new client needs to know where the trusted_id file is located).
	client, err = lastpass.NewClient(
		context.Background(),
		username,
		masterPassword,
		lastpass.WithConfigDir(configDir),
	)
	if err != nil {
		log.Fatalln(err)
	}

	// Print all account names.
	accounts, err := client.Accounts(context.Background())
	if err != nil {
		log.Fatalln(err)
	}
	for _, a := range accounts {
		fmt.Println(a.Name)
	}

	if err = client.Logout(context.Background()); err != nil {
		log.Fatalln(err)
	}
}
