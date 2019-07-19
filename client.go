// Package lastpass implements a LastPass client.
package lastpass

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	netURL "net/url"
)

// Client represents a LastPass client.
// A Client can be logged in to a single account at a given time.
type Client struct {
	// base URL of LastPass servers; defaults to "https://lastpass.com"
	BaseURL       string
	httpClient    *http.Client
	username      string
	password      string
	encryptionKey []byte
	session       *session
}

// Login authenticates with the LastPass servers.
// Currently, Login does not yet support two-factor authentication.
func (c *Client) Login(username, masterPassword string) error {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	c.httpClient = &http.Client{
		Jar: cookieJar,
	}
	c.username = username
	c.password = masterPassword
	return c.initSession()
}

// Logout invalidates the session token of the Client.
func (c *Client) Logout() error {
	res, err := c.httpClient.PostForm(
		c.baseURL()+"/logout.php",
		netURL.Values{
			"method":     []string{"cli"},
			"noredirect": []string{"1"},
			"token":      []string{c.session.token},
		})
	if err != nil {
		return err
	}

	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to logout (HTTP status %s)", res.Status)
	}
	return nil
}

// Add adds a new LastPass Account returning the newly created accountID.
func (c *Client) Add(accountName, userName, password, url, group, notes string) (accountID string, err error) {
	acct := &Account{"0", accountName, userName, password, url, group, notes}
	result, err := c.upsert(acct)
	if err != nil {
		return "", err
	}
	if result.Msg != "accountadded" {
		return "", errors.New("failed to add account")
	}
	return result.AccountID, nil
}

// Update updates the account with the given account.ID.
// When the account.ID does not exist in LastPass, an error is returned.
func (c *Client) Update(account *Account) error {
	result, err := c.upsert(account)
	if err != nil {
		if err.Error() == "empty response body" {
			return fmt.Errorf("could not find account with ID=%s", account.ID)
		}
		return err
	}
	if result.Msg != "accountupdated" {
		return fmt.Errorf("failed to update account (ID=%s)", account.ID)
	}
	return nil
}

// Delete deletes the LastPass Account with the given accountID.
func (c *Client) Delete(accountID string) error {
	res, err := c.httpClient.PostForm(
		c.baseURL()+"/show_website.php",
		netURL.Values{
			"extjs":  []string{"1"},
			"delete": []string{"1"},
			"aid":    []string{accountID},
			"token":  []string{c.session.token},
		})
	if err != nil {
		return err
	}

	var response struct {
		Result result `xml:"result"`
	}

	if res.Header.Get("Content-Length") == "0" {
		return fmt.Errorf("could not find account with ID=%s", accountID)
	}

	defer res.Body.Close()
	err = xml.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return err
	}
	if response.Result.Msg != "accountdeleted" {
		return errors.New("failed to delete account")
	}
	return nil
}

type result struct {
	Msg       string `xml:"msg,attr"`
	AccountID string `xml:"aid,attr"`
}

func (c *Client) upsert(acct *Account) (result, error) {
	var response struct {
		Result result `xml:"result"`
	}

	nameEncrypted, err := encryptAES256Cbc(acct.Name, c.encryptionKey)
	if err != nil {
		return response.Result, err
	}
	userNameEncrypted, err := encryptAES256Cbc(acct.Username, c.encryptionKey)
	if err != nil {
		return response.Result, err
	}
	passwordEncrypted, err := encryptAES256Cbc(acct.Password, c.encryptionKey)
	if err != nil {
		return response.Result, err
	}
	groupEncrypted, err := encryptAES256Cbc(acct.Group, c.encryptionKey)
	if err != nil {
		return response.Result, err
	}
	notesEncrypted, err := encryptAES256Cbc(acct.Notes, c.encryptionKey)
	if err != nil {
		return response.Result, err
	}

	res, err := c.httpClient.PostForm(
		c.baseURL()+"/show_website.php",
		netURL.Values{
			"extjs":     []string{"1"},
			"token":     []string{c.session.token},
			"method":    []string{"cli"},
			"pwprotect": []string{"off"},
			"aid":       []string{acct.ID},
			"url":       []string{hex.EncodeToString([]byte(acct.URL))},
			"name":      []string{nameEncrypted},
			"grouping":  []string{groupEncrypted},
			"username":  []string{userNameEncrypted},
			"password":  []string{passwordEncrypted},
			"extra":     []string{notesEncrypted},
		})
	if err != nil {
		return response.Result, err
	}

	if res.Header.Get("Content-Length") == "0" {
		return response.Result, errors.New("empty response body")
	}

	defer res.Body.Close()
	err = xml.NewDecoder(res.Body).Decode(&response)
	return response.Result, err
}

func (c *Client) baseURL() string {
	if c.BaseURL == "" {
		return "https://lastpass.com"
	}
	return c.BaseURL
}
