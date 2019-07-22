package lastpass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func (c *Client) loginHash(username, password string) string {
	iterations := c.session.passwdIterations
	key := encryptionKey(username, password, iterations)
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

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func pkcs7Unpad(data []byte) []byte {
	size := len(data)
	unpadding := int(data[size-1])
	return data[:(size - unpadding)]
}

func encodeBase64(b []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(encoded, b)
	return encoded
}

func decodeBase64(b []byte) []byte {
	d := make([]byte, len(b))
	n, _ := base64.StdEncoding.Decode(d, b)
	return d[:n]
}

func encryptAES256Cbc(plaintext string, encryptionKey []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(ciphertext[aes.BlockSize:], padded)

	ivBase64 := encodeBase64(iv)
	ciphertextBase64 := encodeBase64(ciphertext[aes.BlockSize:])

	// use the same format as the CLI does it in (v1.3.3)
	// https://github.com/lastpass/lastpass-cli/blob/a84aa9629957033082c5930968dda7fbed751dfa/cipher.c#L296
	return fmt.Sprintf("!%s|%s", ivBase64, ciphertextBase64), nil
}

func decryptAES256Cbc(encrypted string, encryptionKey []byte) (string, error) {
	data := []byte(encrypted)

	if len(data) == 0 {
		return "", nil
	}
	if data[0] != '!' {
		return "", errors.New("input doesn't start with '!'")
	}
	if data[25] != '|' {
		return "", errors.New("can't determine length of IV")
	}

	ivBase64 := data[1:25]
	iv := decodeBase64(ivBase64)

	inBase64 := data[26:]
	in := decodeBase64(inBase64)
	lenIn := len(in)

	if lenIn < aes.BlockSize {
		return "", fmt.Errorf("input is only %d bytes; expected at least %d bytes", lenIn, aes.BlockSize)
	}
	if lenIn%aes.BlockSize != 0 {
		return "", fmt.Errorf("input size is not a multilpe of %d bytes", aes.BlockSize)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, lenIn)
	dec.CryptBlocks(out, in)

	return string(pkcs7Unpad(out)), nil
}
