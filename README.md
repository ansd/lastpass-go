[![Documentation](https://godoc.org/github.com/ansd/lastpass-go?status.svg)](https://pkg.go.dev/github.com/ansd/lastpass-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/ansd/lastpass-go)](https://goreportcard.com/report/github.com/ansd/lastpass-go)
![Test](https://github.com/ansd/lastpass-go/workflows/Test/badge.svg)
# Go client for LastPass

## Features
- login with
	- user name and master password
	- two-factor authentication with out-of-band mechanism such as push notification to LastPass Authenticator or Duo Security
	- two-factor authentication with one-time password from LastPass Authenticator, Google Authenticator, Microsoft Authenticator, YubiKey, Duo Security, Sesame, etc.
	- trust: after first successful login with two-factor authentication, the second factor can be skipped
- create account
- read accounts (including accounts from shared folders)
- update account
- delete account
- logout

## Documentation
https://pkg.go.dev/github.com/ansd/lastpass-go

## Installation

Install:

```shell
$ go get github.com/ansd/lastpass-go
```

Import:

```go
import "github.com/ansd/lastpass-go"
```

## Usage

Below, error handling is excluded for brevity.

See [examples](https://github.com/ansd/lastpass-go/tree/master/examples) directory for more examples.

```go
// authenticate with LastPass servers
client, _ := lastpass.NewClient(context.Background(), "user name", "master password")

// two-factor authentication with one-time password as second factor:
// client, _ := lastpass.NewClient(context.Background(), "user name", "master password", lastpass.WithOneTimePassword("123456"))

account := &lastpass.Account{
	Name:     "my site",
	Username: "my user",
	Password: "my pwd",
	URL:      "https://myURL",
	Group:    "my group",
	Notes:    "my notes",
}

// Add() account
client.Add(context.Background(), account)

// read all Accounts()
accounts, _ := client.Accounts(context.Background())

// Update() account
account.Password = "updated password"
client.Update(context.Background(), account)

// Delete() account
client.Delete(context.Background(), account.ID)

// Logout()
client.Logout(context.Background())
```

## Notes

This repository is a port of [detunized/lastpass-ruby](https://github.com/detunized/lastpass-ruby)
and a clone of [mattn/lastpass-go](https://github.com/mattn/lastpass-go).

This project is licensed under the MIT License - see the [LICENSE](https://github.com/ansd/lastpass-go/blob/master/LICENSE) file for details.

This repository's `ecb` (Electronic Codebook) package contains code which is "Copyright 2013 The Go Authors. All rights reserved."
