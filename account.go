package lastpass

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/url"
)

type Account struct {
	ID       string
	Name     string
	Username string
	Password string
	URL      string
	Group    string
	Notes    string
}

func (c *Client) Accounts() ([]*Account, error) {
	blob, err := c.blob()
	if err != nil {
		return nil, err
	}

	chunks, err := extractChunks(bytes.NewReader(blob), []uint32{chunkIDFromString("ACCT")})
	if err != nil {
		return nil, err
	}
	accountChunks := chunks[chunkIDFromString("ACCT")]
	accounts := make([]*Account, len(accountChunks))

	for i, chunk := range accountChunks {
		account, err := parseAccount(bytes.NewReader(chunk), c.encryptionKey)
		if err != nil {
			return nil, err
		}
		accounts[i] = account
	}
	return accounts, nil
}

func (c *Client) blob() ([]byte, error) {
	u, err := url.Parse("https://lastpass.com/getaccts.php")
	if err != nil {
		return nil, err
	}
	u.RawQuery = url.Values{
		"mobile":    []string{"1"},
		"b64":       []string{"1"},
		"hash":      []string{"0.0"},
		"PHPSESSID": []string{c.session.id},
	}.Encode()

	res, err := c.httpClient.Get(u.String())
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	b, err = base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func parseAccount(r io.Reader, encryptionKey []byte) (*Account, error) {
	id, err := readItem(r)
	if err != nil {
		return nil, err
	}

	name, err := readItem(r)
	if err != nil {
		return nil, err
	}
	namePlain, err := decryptAES256(name, encryptionKey)
	if err != nil {
		return nil, err
	}

	group, err := readItem(r)
	if err != nil {
		return nil, err
	}
	groupPlain, err := decryptAES256(group, encryptionKey)
	if err != nil {
		return nil, err
	}

	url, err := readItem(r)
	if err != nil {
		return nil, err
	}

	notes, err := readItem(r)
	if err != nil {
		return nil, err
	}
	notesPlain, err := decryptAES256(notes, encryptionKey)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 2; i++ {
		err = skipItem(r)
		if err != nil {
			return nil, err
		}
	}

	username, err := readItem(r)
	if err != nil {
		return nil, err
	}
	usernamePlain, err := decryptAES256(username, encryptionKey)
	if err != nil {
		return nil, err
	}

	password, err := readItem(r)
	if err != nil {
		return nil, err
	}
	passwordPlain, err := decryptAES256(password, encryptionKey)
	if err != nil {
		return nil, err
	}

	return &Account{
		string(id),
		namePlain,
		usernamePlain,
		passwordPlain,
		string(decodeHex(url)),
		groupPlain,
		notesPlain,
	}, nil
}
