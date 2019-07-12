package lastpass

import (
	"encoding/base64"
	"io/ioutil"
	"net/url"
)

func (c *Client) fetchBlob() error {
	u, err := url.Parse("https://lastpass.com/getaccts.php")
	if err != nil {
		return err
	}
	u.RawQuery = url.Values{
		"mobile":    []string{"1"},
		"b64":       []string{"1"},
		"hash":      []string{"0.0"},
		"PHPSESSID": []string{c.session.id},
	}.Encode()

	res, err := c.httpClient.Get(u.String())
	if err != nil {
		return err
	}

	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	b, err = base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return err
	}

	c.blob = b

	return nil
}
