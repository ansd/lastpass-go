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

	return nil
}

func (c *Client) login() error {
	res, err := c.httpClient.PostForm(
		"https://lastpass.com/login.php",
		url.Values{
			"method":     []string{"mobile"},
			"web":        []string{"1"},
			"xml":        []string{"1"},
			"username":   []string{c.username},
			"hash":       []string{string(c.loginHash())},
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

	return nil
}
