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
	MaxLoginRetries = 7
)

type Session struct {
	// PasswdIterations controls how many times the user's password
	// is hashed using PBKDF2 before being sent to LastPass.
	PasswdIterations int

	// Token is the session token returned by LastPass during
	// the login process.
	Token string

	// EncryptionKey is derived by hashing the user's password
	// using PBKDF2.
	EncryptionKey []byte

	// OptSharingKey is the user's private key for decrypting sharing
	// keys. This is used for encryption keys of shared folders.
	//
	// This is nil if the user has not generated a sharing key.
	OptSharingKey *rsa.PrivateKey
}

func (c *Client) login(ctx context.Context, user string, passwd string, passwdIterations int) (*Session, error) {
	loginHash, encKey := loginHashAndEncKey(user, passwd, passwdIterations)

	form := url.Values{
		"method":               []string{"cli"},
		"xml":                  []string{"1"},
		"username":             []string{user},
		"hash":                 []string{loginHash},
		"iterations":           []string{fmt.Sprint(passwdIterations)},
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
		return nil, err
	}

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
	err = xml.NewDecoder(httpRsp.Body).Decode(rsp)
	_ = httpRsp.Body.Close()
	if err != nil {
		return nil, err
	}

	if rsp.Error.Iterations != "" {
		var iterations int
		if iterations, err = strconv.Atoi(rsp.Error.Iterations); err != nil {
			return nil, fmt.Errorf(
				"failed to parse iterations count, expected '%s' to be integer: %w",
				rsp.Error.Iterations, err)
		}
		c.log(ctx, "failed to login with %d password iterations, re-trying with %d password iterations...",
			passwdIterations, iterations)
		return c.login(ctx, user, passwd, iterations)
	}

	const outOfBandRequired = "outofbandrequired"
	if rsp.Error.Cause == outOfBandRequired {
		form.Set("outofbandrequest", "1")
		form.Set("outofbandretry", "1")
		form.Set("outofbandretryid", rsp.Error.RetryID)
		for i := 0; i < MaxLoginRetries; i++ {
			rsp = &response{}
			oobResp, err := c.postForm(ctx, EndpointLogin, form)
			if err != nil {
				return nil, err
			}
			err = xml.NewDecoder(oobResp.Body).Decode(&rsp)
			_ = oobResp.Body.Close()
			if err != nil {
				return nil, err
			}
			if rsp.Error.Cause != outOfBandRequired {
				break
			}
		}
		if rsp.Error.Cause == outOfBandRequired {
			return nil, &AuthenticationError{fmt.Sprintf(
				"didn't receive out-of-band approval within the last %.0f seconds",
				time.Since(loginStartTime).Seconds(),
			)}
		}
	}

	if rsp.Error.Cause != "" {
		return nil, &AuthenticationError{fmt.Sprintf("%s: %s", rsp.Error.Cause, rsp.Error.Msg)}
	}

	if c.trust {
		trustForm := url.Values{
			"token":      []string{rsp.Token},
			"uuid":       []string{c.trustID},
			"trustlabel": []string{c.trustLabel},
		}
		if _, err := c.postForm(ctx, EndpointTrust, trustForm); err != nil {
			return nil, err
		}
	}

	optPrivateKey, err := decryptPrivateKey(rsp.PrivateKeyEncrypted, encKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		PasswdIterations: passwdIterations,
		Token:            rsp.Token,
		EncryptionKey:    encKey,
		OptSharingKey:    optPrivateKey,
	}, nil
}

func loginHashAndEncKey(username string, password string, passwdIterations int) (string, []byte) {
	encKey := encryptionKey(username, password, passwdIterations)

	if passwdIterations == 1 {
		b := sha256.Sum256([]byte(hex.EncodeToString(encKey) + password))
		return hex.EncodeToString(b[:]), encKey
	}
	return hex.EncodeToString(pbkdf2.Key(encKey, []byte(password), 1, 32, sha256.New)), encKey
}

func encryptionKey(username, password string, passwdIterations int) []byte {
	if passwdIterations == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), passwdIterations, 32, sha256.New)
}
