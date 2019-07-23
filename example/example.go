package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/ansd/lastpass-go"
)

func main() {

	// read LastPass username and master password from file
	b, err := ioutil.ReadFile("credentials.txt")
	if err != nil {
		log.Fatalln(err)
	}
	lines := strings.Split(string(b), "\n")
	username := lines[0]
	masterPassword := lines[1]

	// NewClient() authenticates with LastPass servers
	// check the examples at https://godoc.org/github.com/ansd/lastpass-go#NewClient
	// for two-factor authentication
	client, err := lastpass.NewClient(username, masterPassword)
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
	if err = client.Add(account); err != nil {
		log.Fatalln(err)
	}

	// read all Accounts()
	accounts, err := client.Accounts()
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
	if err = client.Update(account); err != nil {
		log.Fatalln(err)
	}

	// Delete() account
	if err = client.Delete(account.ID); err != nil {
		log.Fatalln(err)
	}

	// Logout()
	if err = client.Logout(); err != nil {
		log.Fatalln(err)
	}
}
