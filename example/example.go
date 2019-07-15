package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/ansd/lastpass-go"
)

func main() {
	b, err := ioutil.ReadFile("credentials.txt")
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	username := lines[0]
	password := lines[1]

	client, err := lastpass.Login(username, password)
	if err != nil {
		log.Fatalln(err)
	}

	printAccounts(client)

	accountID, err := client.Add("coolSite", "coolUser", "nicePwd", "https://coolUrl", "social", "cool Notes")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Added accountID=%s\n", accountID)

	printAccounts(client)

	fmt.Printf("Deleting accountID=%s\n", accountID)
	err = client.Delete(accountID)
	if err != nil {
		log.Fatalln(err)
	}

	printAccounts(client)
}

func printAccounts(client *lastpass.Client) {
	accounts, err := client.Accounts()
	if err != nil {
		log.Fatalln(err)
	}
	for i, acct := range accounts {
		fmt.Printf("account-%d: %+v\n", i, *acct)
	}
}
