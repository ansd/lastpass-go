package login

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type Response struct {
	PrivateKeyEncrypted string `xml:"privatekeyenc,attr"`
	Token               string `xml:"token,attr"`
	EncryptionKey       []byte
}

func NewClient() (*http.Client, *Response) {
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		path, err := os.Executable()
		if err != nil {
			panic(err)
		}
		panic(fmt.Sprintf("Usage: %s <user> <password>", path))
	}
	user, passwd := args[0], args[1]

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	client := &http.Client{
		Jar: cookieJar,
	}

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

	parsed := &Response{EncryptionKey: encryptionKey}
	defer rsp.Body.Close()
	if err := xml.NewDecoder(rsp.Body).Decode(parsed); err != nil {
		panic(err)
	}
	return client, parsed
}
