// This is a helper program used by scripts/create-unit-test-data.sh.
//
// It expects 2 arguments: username and password.
//
// It outputs in JSON format the user's encrypted private key as returned by /login.php
// and the base64 encoded blob as returned by /getaccts.php.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		panic("Usage: dumpblob <user> <password>")
	}
	user := args[0]
	passwd := args[1]

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	client := &http.Client{
		Jar: cookieJar,
	}

	type response struct {
		PrivateKeyEncrypted string `xml:"privatekeyenc,attr"`
		Blob                string
	}
	result := &response{}

	encryptionKey := pbkdf2.Key([]byte(passwd), []byte(user), 100100, 32, sha256.New)
	loginHash := hex.EncodeToString(pbkdf2.Key(encryptionKey, []byte(passwd), 1, 32, sha256.New))
	form := url.Values{
		"method":               []string{"cli"},
		"xml":                  []string{"1"},
		"username":             []string{user},
		"hash":                 []string{loginHash},
		"iterations":           []string{"100100"},
		"includeprivatekeyenc": []string{"1"},
	}
	rsp, err := client.PostForm("https://lastpass.com/login.php", form)
	if err != nil {
		panic(err)
	}
	if rsp.StatusCode != http.StatusOK {
		panic("/login.php " + rsp.Status)
	}
	defer rsp.Body.Close()
	if err = xml.NewDecoder(rsp.Body).Decode(result); err != nil {
		panic(err)
	}

	rsp, err = client.Get("https://lastpass.com/getaccts.php?b64=1&requestsrc=cli&mobile=1&hasplugin=1.3.3")
	if err != nil {
		panic(err)
	}
	if rsp.StatusCode != http.StatusOK {
		panic("/getaccts.php " + rsp.Status)
	}
	defer rsp.Body.Close()
	blob, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		panic(err)
	}
	result.Blob = string(blob)

	json, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", json)
}
