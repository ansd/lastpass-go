// Package lastpass implements a LastPass client.
package lastpass

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	netURL "net/url"
)

// Client represents a LastPass client.
// A Client can be logged in to a single account at a given time.
type Client struct {
	// base URL of LastPass servers; defaults to "https://lastpass.com"
	BaseURL       string
	httpClient    *http.Client
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
	return c.initSession(username, masterPassword)
}

// Logout invalidates the session cookie.
func (c *Client) Logout() error {
	loggedIn, err := c.loggedIn()
	if err != nil {
		return err
	}
	if !loggedIn {
		return nil
	}

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
	c.session = nil
	return nil
}

// Add adds a new LastPass Account returning the newly created accountID.
// If Client is not logged in, an *UnauthenticatedError is returned.
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
// If Client is not logged in, an *UnauthenticatedError is returned.
// If account.ID does not exist in LastPass, an *AccountNotFoundError is returned.
func (c *Client) Update(account *Account) error {
	result, err := c.upsert(account)
	if err != nil {
		return err
	}
	if result.Msg != "accountupdated" {
		return fmt.Errorf("failed to update account (ID=%s)", account.ID)
	}
	return nil
}

// Delete deletes the LastPass Account with the given accountID.
// If Client is not logged in, an *UnauthenticatedError is returned.
// If accountID does not exist in LastPass, an *AccountNotFoundError is returned.
func (c *Client) Delete(accountID string) error {
	loggedIn, err := c.loggedIn()
	if err != nil {
		return err
	}
	if !loggedIn {
		return &UnauthenticatedError{}
	}

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
		return &AccountNotFoundError{accountID}
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

	loggedIn, err := c.loggedIn()
	if err != nil {
		return response.Result, err
	}
	if !loggedIn {
		return response.Result, &UnauthenticatedError{}
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
		return response.Result, &AccountNotFoundError{acct.ID}
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

func (c *Client) loggedIn() (bool, error) {
	if c.session == nil || c.session.token == "" {
		return false, nil
	}

	res, err := c.httpClient.PostForm(
		c.baseURL()+"/login_check.php",
		url.Values{
			"method": []string{"cli"},
		},
	)
	if err != nil {
		return false, err
	}
	type ok struct {
		AcctsVersion string `xml:"accts_version,attr"`
	}
	var response struct {
		Ok ok `xml:"ok"`
	}
	defer res.Body.Close()
	if err = xml.NewDecoder(res.Body).Decode(&response); err != nil {
		return false, err
	}
	loggedIn := response.Ok.AcctsVersion != ""
	return loggedIn, nil
}
