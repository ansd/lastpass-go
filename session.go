package lastpass

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
	"time"
)

const MaxLoginRetries = 7

type session struct {
	passwdIterations int
	token            string
}

func (c *Client) initSession(password string) error {
	c.session = &session{}
	if err := c.requestIterationCount(c.user); err != nil {
		return err
	}
	if err := c.login(password); err != nil {
		return err
	}
	return nil
}

func (c *Client) requestIterationCount(username string) error {
	res, err := c.httpClient.PostForm(
		c.baseURL+EndpointIterations,
		url.Values{
			"email": []string{username},
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

func (c *Client) login(password string) error {
	form := url.Values{
		"method":     []string{"cli"},
		"xml":        []string{"1"},
		"username":   []string{c.user},
		"hash":       []string{c.loginHash(password)},
		"iterations": []string{fmt.Sprint(c.session.passwdIterations)},
	}
	if c.otp != "" {
		form.Set("otp", c.otp)
	}

	loginStartTime := time.Now()
	httpRsp, err := c.httpClient.PostForm(c.baseURL+EndpointLogin, form)
	if err != nil {
		return err
	}

	defer httpRsp.Body.Close()
	type Error struct {
		Msg     string `xml:"message,attr"`
		Cause   string `xml:"cause,attr"`
		RetryID string `xml:"retryid,attr"`
	}
	type response struct {
		Error Error  `xml:"error"`
		Token string `xml:"token,attr"`
	}
	rsp := &response{}
	if err = xml.NewDecoder(httpRsp.Body).Decode(rsp); err != nil {
		return err
	}

	const outOfBandRequired = "outofbandrequired"
	if rsp.Error.Cause == outOfBandRequired {
		form.Set("outofbandrequest", "1")
		form.Set("outofbandretry", "1")
		form.Set("outofbandretryid", rsp.Error.RetryID)
		for i := 0; i < MaxLoginRetries; i++ {
			rsp = &response{}
			httpRsp, err = c.httpClient.PostForm(c.baseURL+EndpointLogin, form)
			if err != nil {
				return err
			}
			defer httpRsp.Body.Close()
			if err = xml.NewDecoder(httpRsp.Body).Decode(&rsp); err != nil {
				return err
			}
			if rsp.Error.Cause != outOfBandRequired {
				break
			}
		}
		if rsp.Error.Cause == outOfBandRequired {
			return &AuthenticationError{fmt.Sprintf(
				"didn't receive out-of-band approval within the last %.0f seconds",
				time.Since(loginStartTime).Seconds(),
			)}
		}
	}

	if rsp.Error.Cause != "" {
		return &AuthenticationError{fmt.Sprintf("%s: %s", rsp.Error.Cause, rsp.Error.Msg)}
	}

	c.session.token = rsp.Token
	return nil
}
