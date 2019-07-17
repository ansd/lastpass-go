package main

import (
	"fmt"
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
	password := lines[1]

	// Login()
	client, err := lastpass.Login(username, password)
	if err != nil {
		log.Fatalln(err)
	}

	// read all Accounts()
	accounts, err := client.Accounts()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("accounts:")
	for _, acct := range accounts {
		fmt.Printf("%+v\n", *acct)
	}

	// Add() account
	addedID, err := client.Add("coolSite", "coolUser",
		"coolPwd", "https://coolUrl", "social", "cool Notes")
	if err != nil {
		log.Fatalln(err)
	}

	// read single Account()
	account, err := client.Account(addedID)
	if err != nil {
		log.Fatalln(err)
	}

	// Update() account
	account.Username = "updated user"
	account.Password = "updated password"
	err = client.Update(account)
	if err != nil {
		log.Fatalln(err)
	}

	// Delete() account
	err = client.Delete(addedID)
	if err != nil {
		log.Fatalln(err)
	}

	// Logout()
	err = client.Logout()
	if err != nil {
		log.Fatalln(err)
	}
}
