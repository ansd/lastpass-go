# Go client for LastPass

This is an unofficial LastPass client.

This is work in progress. Therefore, the API is likely to change.

This client is based on and extends https://github.com/mattn/lastpass-go.

## Features
- login with username and master password (no two-factor authentication yet)
- create account
- read accounts
- update account
- delete account
- logout

## Documentation
[API Reference](http://godoc.org/github.com/ansd/lastpass-go)

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

```go
// create default Client
client := &lastpass.Client{}

// Login()
client.Login(username, masterPassword)

// Add() account
addedID, _ := client.Add("my site", "my user", "my pwd", "https://myURL", "my group", "my notes")

// read all Accounts()
accounts, _ := client.Accounts()

var addedAccount *lastpass.Account
for _, acct := range accounts {
	if acct.ID == addedID {
		addedAccount = acct
		break
	}
}

// Update() account
addedAccount.Password = "updated password"
client.Update(addedAccount)

// Delete() account
client.Delete(addedID)

// Logout()
client.Logout()
```

See [example](https://github.com/ansd/lastpass-go/tree/master/example) directory for a complete example.
