package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/ansd/lastpass-go"
)

func main() {

	// Read LastPass username and password from file
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

	printAccounts(client)

	// Add() account
	addedID, err := client.Add("coolSite", "coolUser", "nicePwd", "https://coolUrl", "social", "cool Notes")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("\nAdded accountID=%s\n", addedID)

	accts := printAccounts(client)

	for _, acct := range accts {
		if acct.ID == addedID {
			acct.Username = "updated user"
			acct.Password = "updated password"
			fmt.Printf("\nUpdating accountID=%s\n", addedID)

			// Update() account
			err = client.Update(acct)
			if err != nil {
				log.Fatalln(err)
			}
			printAccounts(client)
		}
	}

	fmt.Printf("\nDeleting accountID=%s\n", addedID)
	// Delete() account
	err = client.Delete(addedID)
	if err != nil {
		log.Fatalln(err)
	}

	printAccounts(client)

	// Logout()
	err = client.Logout()
	if err != nil {
		log.Fatalln(err)
	}
}

func printAccounts(client *lastpass.Client) []*lastpass.Account {
	// read Accounts()
	accounts, err := client.Accounts()
	if err != nil {
		log.Fatalln(err)
	}

	if len(accounts) == 0 {
		fmt.Println("no accounts")
		return nil
	}

	fmt.Println("accounts:")
	for _, acct := range accounts {
		fmt.Printf("%+v\n", *acct)
	}
	return accounts
}
