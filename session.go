package lastpass

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// MaxLoginRetries determines the maximum number of login retries
// if the login fails with cause "outofbandrequired".
// This increases the user's time to approve the out-of-band (2nd) factor
// (e.g. approving a push notification sent to their mobile phone).
const (
	MaxLoginRetries         = 7
	defaultPasswdIterations = 100100
)

type session struct {
	// passwdIterations controls how many times password is hashed using PBKDF2
	// before being sent to LastPass servers.
	passwdIterations int
	token            string
	// user's private key for decrypting sharing keys (encryption keys of shared folders)
	privateKey *rsa.PrivateKey
}

func (c *Client) login(ctx context.Context, password string) error {
	if c.session == nil {
		c.session = &session{
			passwdIterations: defaultPasswdIterations,
		}
	}
	form := url.Values{
		"method":               []string{"cli"},
		"xml":                  []string{"1"},
		"username":             []string{c.user},
		"hash":                 []string{c.loginHash(password)},
		"iterations":           []string{fmt.Sprint(c.session.passwdIterations)},
		"includeprivatekeyenc": []string{"1"},
	}
	if c.trustID != "" {
		form.Set("uuid", c.trustID)
	}
	if c.trustLabel != "" {
		form.Set("trustlabel", c.trustLabel)
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
		Msg        string `xml:"message,attr"`
		Cause      string `xml:"cause,attr"`
		RetryID    string `xml:"retryid,attr"`
		Iterations string `xml:"iterations,attr"`
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

	if rsp.Error.Iterations != "" {
		var iterations int
		if iterations, err = strconv.Atoi(rsp.Error.Iterations); err != nil {
			return fmt.Errorf(
				"failed to parse iterations count, expected '%s' to be integer: %w",
				rsp.Error.Iterations, err)
		}
		c.log(ctx, "failed to login with %d password iterations, re-trying with %d password iterations...",
			c.session.passwdIterations, iterations)
		c.session.passwdIterations = iterations
		return c.login(ctx, password)
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

	if c.trust {
		trustForm := url.Values{
			"token":      []string{rsp.Token},
			"uuid":       []string{c.trustID},
			"trustlabel": []string{c.trustLabel},
		}
		if _, err := c.postForm(ctx, EndpointTrust, trustForm); err != nil {
			return err
		}
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
