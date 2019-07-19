package lastpass

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
)

type session struct {
	passwdIterations int
	token            string
}

func (c *Client) initSession() error {
	c.session = &session{}
	if err := c.requestIterationCount(); err != nil {
		return err
	}
	if err := c.login(); err != nil {
		return err
	}
	return nil
}

func (c *Client) requestIterationCount() error {
	res, err := c.httpClient.PostForm(
		c.baseURL()+"/iterations.php",
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
		c.baseURL()+"/login.php",
		url.Values{
			"method":     []string{"cli"},
			"xml":        []string{"1"},
			"username":   []string{c.username},
			"hash":       []string{c.loginHash()},
			"iterations": []string{fmt.Sprint(c.session.passwdIterations)},
		})
	if err != nil {
		return err
	}

	defer res.Body.Close()
	var response struct {
		Token string `xml:"token,attr"`
	}
	if err = xml.NewDecoder(res.Body).Decode(&response); err != nil {
		return err
	}
	c.session.token = response.Token

	return nil
}
