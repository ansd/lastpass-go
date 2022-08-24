// Package lastpass implements a LastPass client.
package lastpass

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LastPass API endpoints used by this client.
const (
	EndpointLogin       = "/login.php"
	EndpointTrust       = "/trust.php"
	EndpointLoginCheck  = "/login_check.php"
	EndpointGetAccts    = "/getaccts.php"
	EndpointShowWebsite = "/show_website.php"
	EndpointLogout      = "/logout.php"
)

const (
	fileTrustID           = "trusted_id"
	allowedCharsInTrustID = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$"
)

const (
	defaultPasswdIterations = 100100
)

// Client represents a LastPass client.
// A Client can be logged in to a single account at a given time.
type Client struct {
	httpClient HTTPClient
	session    *Session
	baseURL    string
	otp        string
	logger     Logger
	configDir  string
	trust      bool
	trustID    string
	trustLabel string
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
func NewClient(ctx context.Context, username, masterPassword string, opts ...ClientOption) (*Client, error) {
	if username == "" {
		return nil, &AuthenticationError{"username must not be empty"}
	}
	if masterPassword == "" {
		return nil, &AuthenticationError{"masterPassword must not be empty"}
	}
	client, err := setupClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	currentSession, err := client.login(ctx, username, masterPassword, defaultPasswdIterations)
	if err != nil {
		return nil, err
	}
	client.session = currentSession
	return client, nil
}

func NewClientFromSession(ctx context.Context, currentSession *Session, opts ...ClientOption) (*Client, error) {
	client, err := setupClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	client.session = currentSession
	return client, nil
}

func setupClient(ctx context.Context, opts ...ClientOption) (*Client, error) {
	c := &Client{
		baseURL: "https://lastpass.com",
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.httpClient == nil {
		cookieJar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		c.httpClient = &http.Client{
			Jar: cookieJar,
		}
	}
	if err := c.setConfigDir(); err != nil {
		return nil, err
	}
	if err := c.calculateTrustID(ctx); err != nil {
		return nil, err
	}
	if err := c.calculateTrustLabel(); err != nil {
		return nil, err
	}
	return c, nil
}

// WithOneTimePassword enables two-factor authentication with a one-time password
// as the second factor. For an example how to use this function see
// https://godoc.org/github.com/ansd/lastpass-go#example-NewClient--OneTimePasswordAuthentication.
func WithOneTimePassword(oneTimePassword string) ClientOption {
	return func(c *Client) {
		c.otp = oneTimePassword
	}
}

// WithBaseURL overwrites the Client's default base URL https://lastpass.com/.
// This function is used for unit testing.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// WithLogger enables logging.
func WithLogger(logger Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithConfigDir sets the path of this library's cofiguration directory to persist user specific configuration.
// If this option is not specified, the configuration directory defaults to <default-config-root-directory>/lastpass-go
// where <default-config-root-directory> is the path returned by method UserConfigDir, see https://golang.org/pkg/os/#UserConfigDir.
// The only user specific configuration currently supported by this library is a file called `trusted_id`.
func WithConfigDir(path string) ClientOption {
	return func(c *Client) {
		c.configDir = path
	}
}

// WithTrust will cause subsequent logins to not require multifactor authentication.
// It behaves like the `lpass login --trust` option of the LastPass CLI.
// If not already present, it will create a file `trusted_id` with a random trust ID in the configuration directory set by WithConfigDir.
// It will create a trust label with the format `<hostname> <operating system name> lastpass-go` which will show up in the LastPass
// Web Browser Extension under Account Settings => Trusted Devices.
func WithTrust() ClientOption {
	return func(c *Client) {
		c.trust = true
	}
}

// HTTPClient abstracts a Go http.Client with the Do method.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WithHTTPClient optionally specifies a custom HTTPClient to use.
//
// A new instance of a http.Client is used if this option is
// not specified.
func WithHTTPClient(httpClient HTTPClient) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

func (c *Client) Session() (*Session, error) {
	if c.session == nil {
		return nil, errors.New("current session is nil")
	}

	return c.session, nil
}

// Logout invalidates the session cookie.
func (c *Client) Logout(ctx context.Context) error {
	loggedIn, err := c.loggedIn(ctx)
	if err != nil {
		return err
	}
	if !loggedIn {
		return nil
	}

	res, err := c.postForm(ctx, EndpointLogout, url.Values{
		"method":     []string{"cli"},
		"noredirect": []string{"1"},
		"token":      []string{c.session.Token},
	})
	if err != nil {
		return err
	}
	res.Body.Close()
	c.session = nil
	return nil
}

// Add adds the account to LastPass.
// Since LastPass generates a new account ID, account.ID is ignored.
// When this method returns (without an error), account.ID is set to the newly generated account ID.
// If Client is not logged in, an *AuthenticationError is returned.
// To add an account to a shared folder, account.Share must be prefixed with "Shared-".
func (c *Client) Add(ctx context.Context, account *Account) error {
	if account.Name == "" {
		return errors.New("account.Name must not be empty")
	}
	account.ID = "0"
	result, err := c.upsert(ctx, account)
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
//
// Updating an account within a shared folder is supported unless field account.Share itself is modified:
// To move an account to / from a shared folder, use Delete() and Add() functions instead.
func (c *Client) Update(ctx context.Context, account *Account) error {
	result, err := c.upsert(ctx, account)
	if err != nil {
		return err
	}
	if result.Msg != "accountupdated" {
		return fmt.Errorf("failed to update account (ID=%s)", account.ID)
	}
	return nil
}

// Delete deletes the LastPass Account with the given account.ID.
// If account.ID does not exist in LastPass, an *AccountNotFoundError is returned.
// If Client is not logged in, an *AuthenticationError is returned.
// If Client is not logged in, an *AuthenticationError is returned.
//
// All Account fields other than account.ID and account.Share are ignored.
func (c *Client) Delete(ctx context.Context, account *Account) error {
	loggedIn, err := c.loggedIn(ctx)
	if err != nil {
		return err
	}
	if !loggedIn {
		return &AuthenticationError{"client not logged in"}
	}

	data := url.Values{
		"extjs":  []string{"1"},
		"delete": []string{"1"},
		"aid":    []string{account.ID},
		"token":  []string{c.session.Token},
	}

	if account.isShared() {
		share, err := c.getShare(ctx, account.Share)
		if err != nil {
			return err
		}
		if share.readOnly {
			return fmt.Errorf(
				"Account with ID %s cannot be deleted from read-only shared folder %s.",
				account.ID, account.Share)
		}
		data.Set("sharedfolderid", share.id)
	}

	res, err := c.postForm(ctx, EndpointShowWebsite, data)
	if err != nil {
		return err
	}

	var response struct {
		Result result `xml:"result"`
	}

	if res.Header.Get("Content-Length") == "0" {
		return &AccountNotFoundError{account.ID}
	}

	defer res.Body.Close()
	err = xml.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return err
	}
	if response.Result.Msg != "accountdeleted" {
		return fmt.Errorf("failed to delete account (ID=%s)", account.ID)
	}
	return nil
}

type result struct {
	Msg       string `xml:"msg,attr"`
	AccountID string `xml:"aid,attr"`
}

func (c *Client) upsert(ctx context.Context, acct *Account) (result, error) {
	var response struct {
		Result result `xml:"result"`
	}

	loggedIn, err := c.loggedIn(ctx)
	if err != nil {
		return response.Result, err
	}
	if !loggedIn {
		return response.Result, &AuthenticationError{"client not logged in"}
	}

	key := c.session.EncryptionKey
	share := share{}
	if acct.isShared() {
		share, err = c.getShare(ctx, acct.Share)
		if err != nil {
			return response.Result, err
		}
		if share.readOnly {
			return response.Result, fmt.Errorf(
				"Account cannot be written to read-only shared folder %s.",
				acct.Share)
		}
		key = share.key
	}

	nameEncrypted, err := encryptAESCBC(acct.Name, key)
	if err != nil {
		return response.Result, err
	}
	userNameEncrypted, err := encryptAESCBC(acct.Username, key)
	if err != nil {
		return response.Result, err
	}
	passwordEncrypted, err := encryptAESCBC(acct.Password, key)
	if err != nil {
		return response.Result, err
	}
	groupEncrypted, err := encryptAESCBC(acct.Group, key)
	if err != nil {
		return response.Result, err
	}
	notesEncrypted, err := encryptAESCBC(acct.Notes, key)
	if err != nil {
		return response.Result, err
	}

	data := url.Values{
		"extjs":     []string{"1"},
		"token":     []string{c.session.Token},
		"method":    []string{"cli"},
		"pwprotect": []string{"off"},
		"aid":       []string{acct.ID},
		"url":       []string{hex.EncodeToString([]byte(acct.URL))},
		"name":      []string{nameEncrypted},
		"grouping":  []string{groupEncrypted},
		"username":  []string{userNameEncrypted},
		"password":  []string{passwordEncrypted},
		"extra":     []string{notesEncrypted},
	}
	if share.id != "" {
		data.Set("sharedfolderid", share.id)
	}

	res, err := c.postForm(ctx, EndpointShowWebsite, data)
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

func (c *Client) loggedIn(ctx context.Context) (bool, error) {
	if c.session == nil || c.session.Token == "" {
		return false, nil
	}

	res, err := c.postForm(ctx, EndpointLoginCheck, url.Values{"method": []string{"cli"}})
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

func (c *Client) postForm(ctx context.Context, path string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	c.log(ctx, "%s %s\n", req.Method, req.URL)
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s%s: %s", c.baseURL, path, res.Status)
	}
	return res, nil
}

func (c *Client) setConfigDir() error {
	if c.configDir != "" {
		// user provided config dir
		return nil
	}
	// set default config dir
	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	c.configDir = filepath.Join(dir, "lastpass-go")
	return nil
}

func (c *Client) calculateTrustLabel() error {
	if c.trust {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		c.trustLabel = fmt.Sprintf("%s %s %s", hostname, runtime.GOOS, "lastpass-go")
	}
	return nil
}

// calculateTrustID implements
// https://github.com/lastpass/lastpass-cli/blob/8767b5e53192ad4e72d1352db4aa9218e928cbe1/endpoints-login.c#L105-L118
func (c *Client) calculateTrustID(ctx context.Context) error {
	pathTrustID := filepath.Join(c.configDir, fileTrustID)

	_, err := os.Stat(pathTrustID)
	if err == nil {
		// file exists
		data, err := ioutil.ReadFile(pathTrustID)
		if err != nil {
			return err
		}
		c.trustID = string(data)
		return nil
	}

	if os.IsNotExist(err) {
		// file does not exist
		if c.trust {
			// create file with a new random trust ID
			trustID, err := random(32)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(c.configDir, 0700); err != nil {
				return err
			}
			if err := ioutil.WriteFile(pathTrustID, trustID, 0600); err != nil {
				return err
			}
			c.log(ctx, "wrote random trust ID to %s\n", pathTrustID)
			c.trustID = string(trustID)
		}
		return nil
	}

	// file may or may not exist
	return err
}

func random(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	for i, b := range bytes {
		bytes[i] = allowedCharsInTrustID[b%byte(len(allowedCharsInTrustID))]
	}
	return bytes, nil
}
