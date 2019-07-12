package lastpass

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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

func (c *Client) Delete(account *Account) error {
	res, err := c.httpClient.PostForm(
		"https://lastpass.com/show_website.php",
		url.Values{
			"extjs":  []string{"1"},
			"delete": []string{"1"},
			"aid":    []string{account.ID},
			"token":  []string{c.session.token},
		})
	if err != nil {
		return err
	}

	type Result struct {
		Msg             string `xml:"msg,attr"`
		AccountsVersion string `xml:"accts_version,attr"`
	}
	var response struct {
		Result Result `xml:"result"`
	}

	defer res.Body.Close()
	err = xml.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return err
	}

	fmt.Printf("response:%+v\n", response)

	if response.Result.Msg != "accountdeleted" {
		return errors.New("failed to delete account")
	}

	return nil
}
