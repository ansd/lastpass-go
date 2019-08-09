// Example showing how to log HTTP requests
package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http/httptrace"
	"strings"

	"github.com/ansd/lastpass-go"
)

func main() {
	// read LastPass username and master password from file
	b, err := ioutil.ReadFile("../credentials.txt")
	if err != nil {
		log.Fatalln(err)
	}
	lines := strings.Split(string(b), "\n")
	username := lines[0]
	masterPassword := lines[1]

	// log requests' HTTP method and path
	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(key string, value []string) {
			if key == ":method" || key == ":path" {
				log.Println(key, value)
			}
		},
	}

	// NewClient() authenticates with LastPass servers
	client, err := lastpass.NewClient(httptrace.WithClientTrace(context.Background(), trace), username, masterPassword)
	if err != nil {
		log.Fatalln(err)
	}

	// read all Accounts()
	_, err = client.Accounts(httptrace.WithClientTrace(context.Background(), trace))
	if err != nil {
		log.Fatalln(err)
	}

	// Logout()
	if err = client.Logout(httptrace.WithClientTrace(context.Background(), trace)); err != nil {
		log.Fatalln(err)
	}
}
