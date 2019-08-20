// This is a helper program used by scripts/create-unit-test-data.sh.
//
// It expects 2 arguments: username and password.
//
// It adds an AES 256 ECB base 64 encrypted account to LastPass.
// It outputs the ID of the added account.

package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ansd/lastpass-go"
	"github.com/ansd/lastpass-go/ecb"
	"github.com/ansd/lastpass-go/test/unit/login"
)

func main() {
	client, resp := login.NewClient()
	key := resp.EncryptionKey

	acctECBBase64 := &lastpass.Account{
		Name:     encryptECBBase64("nameECB", key),
		Username: encryptECBBase64("user ECB", key),
		Password: encryptECBBase64("password ECB", key),
		Group:    encryptECBBase64("groupECB", key),
		Notes:    encryptECBBase64("notes ECB", key),
		URL:      hex.EncodeToString([]byte("http://urlECB")),
	}
	add(client, resp.Token, acctECBBase64)
	fmt.Print(acctECBBase64.ID)
}

func add(client *http.Client, token string, acct *lastpass.Account) {
	type result struct {
		Msg       string `xml:"msg,attr"`
		AccountID string `xml:"aid,attr"`
	}
	var response struct {
		Result result `xml:"result"`
	}
	res, err := client.PostForm("https://lastpass.com/show_website.php", url.Values{
		"extjs":     []string{"1"},
		"token":     []string{token},
		"method":    []string{"cli"},
		"pwprotect": []string{"off"},
		"aid":       []string{"0"},
		"url":       []string{acct.URL},
		"name":      []string{acct.Name},
		"grouping":  []string{acct.Group},
		"username":  []string{acct.Username},
		"password":  []string{acct.Password},
		"extra":     []string{acct.Notes},
	})
	if err != nil {
		panic(err)
	}
	if res.StatusCode != http.StatusOK {
		panic(res.Status)
	}
	if res.Header.Get("Content-Length") == "0" {
		panic("Empty response")
	}
	defer res.Body.Close()
	if err = xml.NewDecoder(res.Body).Decode(&response); err != nil {
		panic(err)
	}
	if response.Result.Msg != "accountadded" {
		panic("failed to add account")
	}
	acct.ID = response.Result.AccountID
}

func encryptECBBase64(plaintext string, encryptionKey []byte) string {
	if len(plaintext) == 0 {
		return ""
	}
	encrypted := encryptAES256ECB(plaintext, encryptionKey)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
	base64.StdEncoding.Encode(encoded, encrypted)
	return string(encoded)
}

func encryptAES256ECB(plaintext string, encryptionKey []byte) []byte {
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err)
	}
	enc := ecb.NewECBEncrypter(block)
	encrypted := make([]byte, len(padded))
	enc.CryptBlocks(encrypted, padded)
	return encrypted
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}
