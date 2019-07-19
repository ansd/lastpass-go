package main

import (
	"io/ioutil"
	"log"
	"strings"

	"github.com/ansd/lastpass-go"
)

func main() {

	// Read LastPass username and master password from file
	b, err := ioutil.ReadFile("credentials.txt")
	if err != nil {
		log.Fatalln(err)
	}
	lines := strings.Split(string(b), "\n")
	username := lines[0]
	masterPassword := lines[1]

	// Create the default Client
	client := &lastpass.Client{}

	// Login()
	if err = client.Login(username, masterPassword); err != nil {
		log.Fatalln(err)
	}

	// Add() account
	addedID, err := client.Add("my site", "my user",
		"my pwd", "https://myURL", "my group", "my notes")
	if err != nil {
		log.Fatalln(err)
	}

	// read all Accounts()
	accounts, err := client.Accounts()
	if err != nil {
		log.Fatalln(err)
	}

	var addedAccount *lastpass.Account
	for _, acct := range accounts {
		if acct.ID == addedID {
			addedAccount = acct
			break
		}
	}

	// Update() account
	addedAccount.Username = "updated user"
	addedAccount.Password = "updated password"
	if err = client.Update(addedAccount); err != nil {
		log.Fatalln(err)
	}

	// Delete() account
	if err = client.Delete(addedID); err != nil {
		log.Fatalln(err)
	}

	// Logout()
	if err = client.Logout(); err != nil {
		log.Fatalln(err)
	}
}
