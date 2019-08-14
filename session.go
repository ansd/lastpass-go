package lastpass

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// MaxLoginRetries determines the maximum number of login retries
// if the login fails with cause "outofbandrequired".
// This increases the user's time to approve the out-of-band (2nd) factor
// (e.g. approving a push notification sent to their mobile phone).
const MaxLoginRetries = 7

type session struct {
	passwdIterations int
	token            string
	// user's private key for decrypting sharing keys (encryption keys of shared folders)
	privateKey *rsa.PrivateKey
}

func (c *Client) initSession(ctx context.Context, password string) error {
	c.session = &session{}
	if err := c.requestIterationCount(ctx, c.user); err != nil {
		return err
	}
	if err := c.login(ctx, password); err != nil {
		return err
	}
	return nil
}

func (c *Client) requestIterationCount(ctx context.Context, username string) error {
	res, err := c.postForm(ctx, EndpointIterations, url.Values{"email": []string{username}})
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

func (c *Client) login(ctx context.Context, password string) error {
	form := url.Values{
		"method":               []string{"cli"},
		"xml":                  []string{"1"},
		"username":             []string{c.user},
		"hash":                 []string{c.loginHash(password)},
		"iterations":           []string{fmt.Sprint(c.session.passwdIterations)},
		"includeprivatekeyenc": []string{"1"},
	}
	if c.otp != "" {
		form.Set("otp", c.otp)
	}

	loginStartTime := time.Now()
	httpRsp, err := c.postForm(ctx, EndpointLogin, form)
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
		Error               Error  `xml:"error"`
		Token               string `xml:"token,attr"`
		PrivateKeyEncrypted string `xml:"privatekeyenc,attr"`
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
			httpRsp, err = c.postForm(ctx, EndpointLogin, form)
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
	privateKey, err := decryptPrivateKey(rsp.PrivateKeyEncrypted, c.encryptionKey)
	if err != nil {
		return err
	}
	c.session.privateKey = privateKey

	return nil
}

func (c *Client) loginHash(password string) string {
	iterations := c.session.passwdIterations
	key := encryptionKey(c.user, password, iterations)
	c.encryptionKey = key

	if iterations == 1 {
		b := sha256.Sum256([]byte(hex.EncodeToString(key) + password))
		return hex.EncodeToString(b[:])
	}
	return hex.EncodeToString(pbkdf2.Key(key, []byte(password), 1, 32, sha256.New))
}

func encryptionKey(username, password string, passwdIterations int) []byte {
	if passwdIterations == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), passwdIterations, 32, sha256.New)
}
