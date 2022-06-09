// Example showing how to create, read, update, delete accounts.
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
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

	// NewClient() authenticates with LastPass servers.
	// Read examples at https://pkg.go.dev/github.com/veloceapps/lastpass-go#NewClient for two-factor authentication.
	client, err := lastpass.NewClient(context.Background(), username, masterPassword)
	if err != nil {
		log.Fatalln(err)
	}

	account := &lastpass.Account{
		Name:     "my site",
		Username: "my user",
		Password: "my pwd",
		URL:      "https://myURL",
		Group:    "my group",
		Notes:    "my notes",
	}

	// Add() account
	if err = client.Add(context.Background(), account); err != nil {
		log.Fatalln(err)
	}

	// read all Accounts()
	accounts, err := client.Accounts(context.Background())
	if err != nil {
		log.Fatalln(err)
	}

	// print all Accounts
	for _, a := range accounts {
		fmt.Printf("%+v\n", a)
	}

	// Update() account
	account.Username = "updated user"
	account.Password = "updated password"
	if err = client.Update(context.Background(), account); err != nil {
		log.Fatalln(err)
	}

	// Delete() account
	if err = client.Delete(context.Background(), account); err != nil {
		log.Fatalln(err)
	}

	// Logout()
	if err = client.Logout(context.Background()); err != nil {
		log.Fatalln(err)
	}
}
