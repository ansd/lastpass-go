package lastpass

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Account represents a LastPass item.
// An item can be a password, payment card, bank account, etc., or a custom item type.
type Account struct {
	ID       string
	Name     string
	Username string
	Password string
	URL      string
	Group    string
	Notes    string
}

type encryptedAccount struct {
	id       string
	name     []byte
	username []byte
	password []byte
	url      []byte
	group    []byte
	notes    []byte
}

// the blob returned by the /getaccts.php endpoint is made up of chunks
type chunk struct {
	id      uint32
	payload []byte
}

// Accounts lists all LastPass accounts.
//
// If Client is not logged in, an *AuthenticationError is returned.
func (c *Client) Accounts(ctx context.Context) ([]*Account, error) {
	loggedIn, err := c.loggedIn(ctx)
	if err != nil {
		return nil, err
	}
	if !loggedIn {
		return nil, &AuthenticationError{"client not logged in"}
	}

	endpoint := c.baseURL + EndpointGetAccts
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	u.RawQuery = url.Values{
		"requestsrc": []string{"cli"},
		"mobile":     []string{"1"},
		"b64":        []string{"1"},
		"hasplugin":  []string{"1.3.3"},
	}.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	log(ctx, c, "%s %s\n", req.Method, req.URL)
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u.String(), res.Status)
	}

	defer res.Body.Close()
	blobBase64, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	blob, err := decodeBase64(blobBase64)
	if err != nil {
		return nil, err
	}
	return c.parseBlob(bytes.NewReader(blob))
}

func (c *Client) parseBlob(r io.Reader) ([]*Account, error) {
	chunks, err := extractChunks(r)
	if err != nil {
		return nil, err
	}

	if !areComplete(chunks) {
		return nil, errors.New("blob is truncated")
	}

	accts := make([]*Account, 0)
	key := c.encryptionKey
	shareName := ""

	for _, chunk := range chunks {
		switch chunk.id {
		case chunkIDFromString("ACCT"):
			encryptedAccount, err := parseAccount(bytes.NewReader(chunk.payload))
			if err != nil {
				return nil, err
			}
			acct, err := decryptAccount(encryptedAccount, key)
			if err != nil {
				return nil, err
			}
			if acct.URL == "http://group" {
				// ignore "group" accounts since they are made up by LastPass and have no credentials
				continue
			}
			if acct.Group == "" && shareName != "" {
				// this is an account in a shared folder
				acct.Group = shareName
			}
			accts = append(accts, acct)

		case chunkIDFromString("SHAR"):
			// after SHAR chunk all the following ACCTs are enrypted with the SHAR's sharing key
			shareName, key, err = parseShare(bytes.NewReader(chunk.payload), c.encryptionKey, c.session.privateKey)
			if err != nil {
				return nil, err
			}
		default:
			// the blob contains many other chunks we're currently not interested in
			// see https://github.com/lastpass/lastpass-cli/blob/a84aa9629957033082c5930968dda7fbed751dfa/blob.c#L585-L676
		}
	}
	return accts, nil
}

func parseAccount(r io.Reader) (*encryptedAccount, error) {
	id, err := readItem(r)
	if err != nil {
		return nil, err
	}
	nameEncrypted, err := readItem(r)
	if err != nil {
		return nil, err
	}
	groupEncrypted, err := readItem(r)
	if err != nil {
		return nil, err
	}
	urlHexEncoded, err := readItem(r)
	if err != nil {
		return nil, err
	}
	notesEncrypted, err := readItem(r)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ {
		if err = skipItem(r); err != nil {
			return nil, err
		}
	}
	usernameEncrypted, err := readItem(r)
	if err != nil {
		return nil, err
	}
	passwordEncrypted, err := readItem(r)
	if err != nil {
		return nil, err
	}
	return &encryptedAccount{
		string(id),
		nameEncrypted,
		usernameEncrypted,
		passwordEncrypted,
		urlHexEncoded,
		groupEncrypted,
		notesEncrypted,
	}, nil
}

func decryptAccount(encrypted *encryptedAccount, encryptionKey []byte) (*Account, error) {
	name, err := decryptItem(encrypted.name, encryptionKey)
	if err != nil {
		return nil, err
	}
	username, err := decryptItem(encrypted.username, encryptionKey)
	if err != nil {
		return nil, err
	}
	password, err := decryptItem(encrypted.password, encryptionKey)
	if err != nil {
		return nil, err
	}
	url, err := decodeHex(encrypted.url)
	if err != nil {
		return nil, err
	}
	group, err := decryptItem(encrypted.group, encryptionKey)
	if err != nil {
		return nil, err
	}
	notes, err := decryptItem(encrypted.notes, encryptionKey)
	if err != nil {
		return nil, err
	}
	return &Account{
		encrypted.id,
		name,
		username,
		password,
		string(url),
		group,
		notes,
	}, nil
}

func parseShare(r io.Reader, encryptionKey []byte, privateKey *rsa.PrivateKey) (
	name string, sharingKey []byte, err error) {

	// skip ID
	if err = skipItem(r); err != nil {
		return "", nil, err
	}

	sharingKeyRSAEncryptedHex, err := readItem(r)
	if err != nil {
		return "", nil, err
	}

	nameEncrypted, err := readItem(r)
	if err != nil {
		return "", nil, err
	}

	for i := 0; i < 2; i++ {
		if err = skipItem(r); err != nil {
			return "", nil, err
		}
	}

	sharingKeyAESEncrypted, err := readItem(r)
	if err != nil {
		return "", nil, err
	}

	if len(sharingKeyAESEncrypted) > 0 {
		// The sharing key is only AES encrypted with the regular encryption key.
		// The is the default case and happens after the user had already decrypted
		// the sharing key with their private key once before (possibly in some other LastPass client).
		key, err := decryptItem(sharingKeyAESEncrypted, encryptionKey)
		if err != nil {
			return "", nil, err
		}
		sharingKey, err = hex.DecodeString(key)
		if err != nil {
			return "", nil, err
		}

	} else {
		// The user who shares the folder with us, encrypted the sharing key with our public key.
		// Therefore, we decrypt the sharing key with our private key.

		sharingKeyRSAEncrypted, err := decodeHex(sharingKeyRSAEncryptedHex)
		if err != nil {
			return "", nil, err
		}

		key, err := privateKey.Decrypt(rand.Reader, sharingKeyRSAEncrypted, &rsa.OAEPOptions{
			// The CLI uses RSA_PKCS1_OAEP_PADDING
			// (see https://github.com/lastpass/lastpass-cli/blob/a84aa9629957033082c5930968dda7fbed751dfa/cipher.c#L78).
			// As described on https://linux.die.net/man/3/rsa_private_decrypt, RSA_PKCS1_OAEP_PADDING uses SHA1.
			Hash: crypto.SHA1,
		})
		if err != nil {
			return "", nil, err
		}

		sharingKey, err = decodeHex(key)
		if err != nil {
			return "", nil, err
		}
	}

	name, err = decryptItem(nameEncrypted, sharingKey)
	if err != nil {
		return "", nil, err
	}

	return name, sharingKey, nil
}

func areComplete(chunks []*chunk) bool {
	if len(chunks) == 0 {
		return false
	}
	lastChunk := chunks[len(chunks)-1]
	// ENDM = end marker
	return lastChunk.id == chunkIDFromString("ENDM") &&
		string(lastChunk.payload) == "OK"
}
