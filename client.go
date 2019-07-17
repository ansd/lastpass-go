package lastpass

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	netURL "net/url"
)

type Client struct {
	httpClient    *http.Client
	username      string
	password      string
	encryptionKey []byte
	session       *session
}

func Login(username, password string) (*Client, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	c := &Client{
		httpClient: &http.Client{
			Jar: cookieJar,
		},
		username: username,
		password: password,
	}

	err = c.initSession()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) Logout() error {
	res, err := c.httpClient.PostForm(
		"https://lastpass.com/logout.php",
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

// Update the account with the given account.ID
// returns an error if the account.ID does not exist in LastPass
func (c *Client) Update(account *Account) error {
	result, err := c.upsert(account)
	if err != nil {
		return err
	}
	if result.Msg != "accountupdated" {
		return errors.New("failed to update account")
	}
	return nil
}

func (c *Client) Delete(accountID string) error {
	res, err := c.httpClient.PostForm(
		"https://lastpass.com/show_website.php",
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

	res, err := c.httpClient.PostForm(
		"https://lastpass.com/show_website.php",
		netURL.Values{
			"extjs":     []string{"1"},
			"token":     []string{c.session.token},
			"method":    []string{"cli"},
			"pwprotect": []string{"off"},
			"aid":       []string{acct.ID},
			"url":       []string{string(encodeHex([]byte(acct.URL)))},
			"name":      []string{encryptAES256Cbc(acct.Name, c.encryptionKey)},
			"grouping":  []string{encryptAES256Cbc(acct.Group, c.encryptionKey)},
			"username":  []string{encryptAES256Cbc(acct.Username, c.encryptionKey)},
			"password":  []string{encryptAES256Cbc(acct.Password, c.encryptionKey)},
			"extra":     []string{encryptAES256Cbc(acct.Notes, c.encryptionKey)},
		})
	if err != nil {
		return response.Result, err
	}

	defer res.Body.Close()
	err = xml.NewDecoder(res.Body).Decode(&response)
	return response.Result, err
}
