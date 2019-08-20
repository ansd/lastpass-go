// This is a helper program used by scripts/create-unit-test-data.sh.
//
// It expects 2 arguments: username and password.
//
// It outputs in JSON format the user's encrypted private key as returned by /login.php
// and the base64 encoded blob as returned by /getaccts.php.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/ansd/lastpass-go/test/unit/login"
)

func main() {
	type result struct {
		PrivateKeyEncrypted string `xml:"privatekeyenc,attr"`
		Blob                string
	}
	output := &result{}

	client, respLogin := login.NewClient()
	output.PrivateKeyEncrypted = respLogin.PrivateKeyEncrypted

	respGetAccts, err := client.Get("https://lastpass.com/getaccts.php?b64=1&requestsrc=cli&mobile=1&hasplugin=1.3.3")
	if err != nil {
		panic(err)
	}
	if respGetAccts.StatusCode != http.StatusOK {
		panic("/getaccts.php " + respGetAccts.Status)
	}
	defer respGetAccts.Body.Close()
	blob, err := ioutil.ReadAll(respGetAccts.Body)
	if err != nil {
		panic(err)
	}
	output.Blob = string(blob)

	json, err := json.Marshal(output)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", json)
}
