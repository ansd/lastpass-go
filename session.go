package lastpass

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
)

type session struct {
	id               string
	passwdIterations int
	token            string
}

func (c *Client) initSession() error {
	c.session = &session{}

	err := c.requestIterationCount()
	if err != nil {
		return err
	}

	err = c.login()
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) requestIterationCount() error {
	res, err := c.httpClient.PostForm(
		"https://lastpass.com/iterations.php",
		url.Values{
			"email": []string{c.username},
		})
	if err != nil {
		return err
	}

	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	count, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}

	c.session.passwdIterations = count

	fmt.Printf("iteration count = %d\n", c.session.passwdIterations)

	return nil
}

func (c *Client) login() error {
	loginHash := string(c.loginHash())
	fmt.Printf("login hash = %s\n", loginHash)

	res, err := c.httpClient.PostForm(
		"https://lastpass.com/login.php",
		url.Values{
			"method":     []string{"mobile"},
			"web":        []string{"1"},
			"xml":        []string{"1"},
			"username":   []string{c.username},
			"hash":       []string{loginHash},
			"iterations": []string{fmt.Sprint(c.session.passwdIterations)},
		})
	if err != nil {
		return err
	}

	defer res.Body.Close()
	var response struct {
		SessionID string `xml:"sessionid,attr"`
		Token     string `xml:"token,attr"`
	}
	err = xml.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return err
	}

	c.session.id = response.SessionID
	c.session.token = response.Token

	url, _ := url.Parse("https://lastpass.com/")
	fmt.Printf("cookies = %v\n", c.httpClient.Jar.Cookies(url))
	fmt.Printf("session id  = %v\n", c.session.id)
	fmt.Printf("session token  = %v\n", c.session.token)

	return nil
}
