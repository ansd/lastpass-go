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
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// Response contains fields which got parsed from the response of the /login.php endpoint.
type Response struct {
	PrivateKeyEncrypted string `xml:"privatekeyenc,attr"`
	Token               string `xml:"token,attr"`
	EncryptionKey       []byte
}

// NewClient reads the executable's username and password arguments and authenticates with the LastPass servers.
// It returns an http.Client with the cookie set returned by LastPass and a Response containing parsed fields from the /login.php response.
func NewClient() (*http.Client, *Response) {
	var passwordIterations = flag.Int("iterations", 100100, "LastPass password iterations count")
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

	var encryptionKey []byte
	var loginHash string
	if *passwordIterations == 1 {
		key := sha256.Sum256([]byte(user + passwd))
		encryptionKey = key[:]
		b := sha256.Sum256([]byte(hex.EncodeToString(encryptionKey) + passwd))
		loginHash = hex.EncodeToString(b[:])
	} else {
		encryptionKey = pbkdf2.Key([]byte(passwd), []byte(user), *passwordIterations, 32, sha256.New)
		loginHash = hex.EncodeToString(pbkdf2.Key(encryptionKey, []byte(passwd), 1, 32, sha256.New))
	}

	form := url.Values{
		"method":               []string{"cli"},
		"xml":                  []string{"1"},
		"username":             []string{user},
		"hash":                 []string{loginHash},
		"iterations":           []string{strconv.Itoa(*passwordIterations)},
		"includeprivatekeyenc": []string{"1"},
	}
	rsp, err := client.PostForm("https://lastpass.com/login.php", form)
	if err != nil {
		panic(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		panic("/login.php " + rsp.Status)
	}

	parsed := &Response{EncryptionKey: encryptionKey}
	if err := xml.NewDecoder(rsp.Body).Decode(parsed); err != nil {
		panic(err)
	}
	return client, parsed
}
