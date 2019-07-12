package main

import (
	"io/ioutil"
	"log"
	"strings"
	"fmt"
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

	c, err := lastpass.Login(username, password)
	if err != nil {
		log.Fatalln(err)
	}

	accounts, err := c.Accounts()
	if err != nil {
		log.Fatalln(err)
	}
	for i, acct := range accounts{
	fmt.Printf("account-%d: %+v\n", i,*acct)
	}

	err = c.Delete(accounts[0])
	if err != nil {
		log.Fatalln(err)
	}
}
