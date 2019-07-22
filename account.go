package lastpass

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
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

// Accounts lists all LastPass accounts.
// If Client is not logged in, an *UnauthenticatedError is returned.
func (c *Client) Accounts() ([]*Account, error) {
	loggedIn, err := c.loggedIn()
	if err != nil {
		return nil, err
	}
	if !loggedIn {
		return nil, &UnauthenticatedError{}
	}

	endpoint := c.baseURL() + "/getaccts.php"
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	u.RawQuery = url.Values{
		"requestsrc": []string{"cli"},
	}.Encode()

	res, err := c.httpClient.Get(u.String())
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", endpoint, res.Status)
	}

	type login struct {
		PasswordEncrypted string `xml:"p,attr"`
	}
	type account struct {
		ID                string `xml:"id,attr"`
		NameEncrypted     string `xml:"name,attr"`
		UsernameEncrypted string `xml:"username,attr"`
		URLBase64         string `xml:"url,attr"`
		GroupEncrypted    string `xml:"group,attr"`
		NotesEncrypted    string `xml:"extra,attr"`
		Login             login  `xml:"login"`
	}
	type accounts struct {
		Accounts []*account `xml:"account"`
		CBC      string     `xml:"cbc,attr"`
	}
	var response struct {
		Accounts accounts `xml:"accounts"`
	}

	defer res.Body.Close()
	if err = xml.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}

	if cbc := response.Accounts.CBC; cbc != "1" {
		return nil, fmt.Errorf("accounts do not seem to be AES CBC encrypted (CBC=%s)", cbc)
	}

	accts := make([]*Account, len(response.Accounts.Accounts))

	for i, acct := range response.Accounts.Accounts {
		name, err := decryptAES256Cbc(acct.NameEncrypted, c.encryptionKey)
		if err != nil {
			return nil, err
		}
		username, err := decryptAES256Cbc(acct.UsernameEncrypted, c.encryptionKey)
		if err != nil {
			return nil, err
		}
		password, err := decryptAES256Cbc(acct.Login.PasswordEncrypted, c.encryptionKey)
		if err != nil {
			return nil, err
		}
		url, err := hex.DecodeString(acct.URLBase64)
		if err != nil {
			return nil, err
		}
		group, err := decryptAES256Cbc(acct.GroupEncrypted, c.encryptionKey)
		if err != nil {
			return nil, err
		}
		notes, err := decryptAES256Cbc(acct.NotesEncrypted, c.encryptionKey)
		if err != nil {
			return nil, err
		}

		acctDecrypted := &Account{
			ID:       acct.ID,
			Name:     name,
			Username: username,
			Password: password,
			URL:      string(url),
			Group:    group,
			Notes:    notes,
		}
		accts[i] = acctDecrypted
	}

	return accts, nil
}
