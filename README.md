# Go client for LastPass

This repository is a clone of https://github.com/mattn/lastpass-go.

## Features
- login via
	- user name and master password
	- two-factor authentication with out-of-band mechanism such as push notification to LastPass Authenticator or Duo Security
	- two-factor authentication with one-time password from LastPass Authenticator, Google Authenticator, Microsoft Authenticator, YubiKey, Duo Security, Sesame, etc.
- create account
- read accounts
- update account
- delete account
- logout

## Documentation
[GoDoc](http://godoc.org/github.com/ansd/lastpass-go)

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
See [example](https://github.com/ansd/lastpass-go/tree/master/example) directory for a complete example.

```go
// authenticate with LastPass servers
client, _ := lastpass.NewClient("user name", "master password")

// two-factor authentication with one-time password as second factor:
// client, _ := lastpass.NewClient("user name", "master password", lastpass.WithOneTimePassword("123456"))

account := &lastpass.Account{
	Name:     "my site",
	Username: "my user",
	Password: "my pwd",
	URL:      "https://myURL",
	Group:    "my group",
	Notes:    "my notes",
}

// Add() account
client.Add(account)

// read all Accounts()
accounts, _ := client.Accounts()

// Update() account
account.Password = "updated password"
client.Update(account)

// Delete() account
client.Delete(account.ID)

// Logout()
client.Logout()
```
