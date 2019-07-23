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

const (
	EndpointLogin       = "/login.php"
	EndpointLoginCheck  = "/login_check.php"
	EndpointIterations  = "/iterations.php"
	EndointGetAccts     = "/getaccts.php"
	EndpointShowWebsite = "/show_website.php"
	EndointLogout       = "/logout.php"
)

// Client represents a LastPass client.
// A Client can be logged in to a single account at a given time.
type Client struct {
	user          string
	httpClient    *http.Client
	encryptionKey []byte
	session       *session
	baseURL       string
	otp           string
}

// ClientOption is the type of constructor options for NewClient(...).
type ClientOption func(c *Client)

// NewClient authenticates with the LastPass servers.
//
// The following authentication schemes are supported:
// single-factor authentication via master password,
// two-factor authentication via out-of-band mechanism
// (e.g. LastPass Authenticator Push Notification, Duo Security Push Notification),
// and two-factor authentication via one-time password
// (e.g. one-time verification code of LastPass Authenticator, Google Authenticator,
// Microsoft Authenticator, YubiKey, Transakt, Duo Security, or Sesame)
//
// If authentication fails, an *AuthenticationError is returned.
func NewClient(username, masterPassword string, opts ...ClientOption) (*Client, error) {
	if username == "" {
		return nil, &AuthenticationError{"username must not be empty"}
	}
	if masterPassword == "" {
		return nil, &AuthenticationError{"masterPassword must not be empty"}
	}
	c := &Client{
		user:    username,
		baseURL: "https://lastpass.com/",
	}
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c.httpClient = &http.Client{
		Jar: cookieJar,
	}
	for _, opt := range opts {
		opt(c)
	}
	if err = c.initSession(masterPassword); err != nil {
		return nil, err
	}
	return c, nil
}

func WithOneTimePassword(oneTimePassword string) ClientOption {
	return func(c *Client) {
		c.otp = oneTimePassword
	}
}

func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.baseURL = baseURL
	}
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
		c.baseURL+EndointLogout,
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

// Add adds the account to LastPass.
// Since LastPass generates a new account ID, account.ID is ignored.
// When this method returns (without an error), account.ID is set to the newly generated account ID.
// If Client is not logged in, an *AuthenticationError is returned.
func (c *Client) Add(account *Account) error {
	if account.Name == "" {
		return errors.New("account.Name must not be empty")
	}
	account.ID = "0"
	result, err := c.upsert(account)
	if err != nil {
		return err
	}
	if result.Msg != "accountadded" {
		return errors.New("failed to add account")
	}
	account.ID = result.AccountID
	return nil
}

// Update updates the account with the given account.ID.
// If account.ID does not exist in LastPass, an *AccountNotFoundError is returned.
// If Client is not logged in, an *AuthenticationError is returned.
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
// If accountID does not exist in LastPass, an *AccountNotFoundError is returned.
// If Client is not logged in, an *AuthenticationError is returned.
func (c *Client) Delete(accountID string) error {
	loggedIn, err := c.loggedIn()
	if err != nil {
		return err
	}
	if !loggedIn {
		return &AuthenticationError{"client not logged in"}
	}

	res, err := c.httpClient.PostForm(
		c.baseURL+EndpointShowWebsite,
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
		return response.Result, &AuthenticationError{"client not logged in"}
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
		c.baseURL+EndpointShowWebsite,
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

func (c *Client) loggedIn() (bool, error) {
	if c.session == nil || c.session.token == "" {
		return false, nil
	}

	res, err := c.httpClient.PostForm(
		c.baseURL+EndpointLoginCheck,
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
