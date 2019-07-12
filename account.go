package lastpass

import (
	"bytes"
	"io"
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
	chunks, err := extractChunks(bytes.NewReader(c.blob), []uint32{chunkIDFromString("ACCT")})
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

func parseAccount(r io.Reader, encryptionKey []byte) (*Account, error) {
	id, err := readItem(r)
	if err != nil {
		return nil, err
	}
	name, err := readItem(r)
	if err != nil {
		return nil, err
	}
	group, err := readItem(r)
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
	password, err := readItem(r)
	if err != nil {
		return nil, err
	}

	return &Account{
		string(id),
		decryptAES256(name, encryptionKey),
		decryptAES256(username, encryptionKey),
		decryptAES256(password, encryptionKey),
		string(decodeHex(url)),
		decryptAES256(group, encryptionKey),
		decryptAES256(notes, encryptionKey),
	}, nil
}
