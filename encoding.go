package lastpass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"

	"github.com/ansd/lastpass-go/ecb"
	"golang.org/x/crypto/pbkdf2"
)

func (c *Client) loginHash() []byte {
	iterations := c.session.passwdIterations
	key := encryptionKey(c.username, c.password, iterations)
	c.encryptionKey = key

	if iterations == 1 {
		b := sha256.Sum256([]byte(string(encodeHex(key)) + c.password))
		return encodeHex(b[:])
	}
	return encodeHex(pbkdf2.Key(key, []byte(c.password), 1, 32, sha256.New))
}

func encryptionKey(username, password string, passwdIterations int) []byte {
	if passwdIterations == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), passwdIterations, 32, sha256.New)
}

func encodeHex(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

func decodeHex(b []byte) []byte {
	d := make([]byte, len(b))
	n, _ := hex.Decode(d, b)
	return d[:n]
}

func chunkIDFromString(s string) uint32 {
	b := []byte(s)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func chunkIDFromBytes(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func extractChunks(r io.Reader, filter []uint32) (map[uint32][][]byte, error) {
	chunks := map[uint32][][]byte{}
	for {
		chunkID, err := readID(r)
		if err != nil {
			if err == io.EOF {
				break
			}
		}

		payload, err := readItem(r)
		if err != nil {
			return nil, err
		}

		found := false
		for _, filterID := range filter {
			if filterID == chunkID {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		if _, ok := chunks[chunkID]; !ok {
			chunks[chunkID] = [][]byte{payload}
		} else {
			chunks[chunkID] = append(chunks[chunkID], payload)
		}
	}
	return chunks, nil
}

func readID(r io.Reader) (uint32, error) {
	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, err
	}
	return chunkIDFromBytes(b), nil
}

func readSize(r io.Reader) (uint32, error) {
	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func readItem(r io.Reader) ([]byte, error) {
	size, err := readSize(r)
	if err != nil {
		return nil, err
	}
	b := make([]byte, size)
	n, err := r.Read(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func skipItem(r io.Reader) error {
	readSize, err := readSize(r)
	if err != nil {
		return err
	}
	b := make([]byte, readSize)
	_, err = r.Read(b)
	if err != nil {
		return err
	}
	return nil
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

func decryptAes256CbcPlain(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	iv, in := data[:aes.BlockSize], data[aes.BlockSize:]
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return pkcs7Unpad(out)
}

func decryptAes256CbcBase64(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	iv, in := decodeBase64(data[:24]), decodeBase64(data[24:])
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return pkcs7Unpad(out)
}

func decryptAes256EcbPlain(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	dec := ecb.NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return pkcs7Unpad(out)
}

func decryptAes256EcbBase64(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	data = decodeBase64(data)
	dec := ecb.NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return pkcs7Unpad(out)
}

func decryptAES256(data []byte, encryptionKey []byte) string {
	size := len(data)
	size16 := size % 16
	size64 := size % 64

	switch {
	case size == 0:
		return ""
	case size16 == 0:
		return string(decryptAes256EcbPlain(data, encryptionKey))
	case size64 == 0 || size64 == 24 || size64 == 44:
		return string(decryptAes256EcbBase64(data, encryptionKey))
	case size16 == 1:
		return string(decryptAes256CbcPlain(data[1:], encryptionKey))
	case size64 == 6 || size64 == 26 || size64 == 50:
		return string(decryptAes256CbcBase64(data, encryptionKey))
	}
	panic("Input doesn't seem to be AES-256 encrypted")
}

func encryptAES256CbcBase64(plaintext string, encryptionKey []byte) string {
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	if len(padded)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], padded)

	ivBase64Encoded := encodeBase64(iv)
	ciphertextBase64Encoded := encodeBase64(ciphertext[aes.BlockSize:])

	// use the same format as the CLI does it in (v1.3.3)
	// https://github.com/lastpass/lastpass-cli/blob/a84aa9629957033082c5930968dda7fbed751dfa/cipher.c#L296
	return "!" + string(ivBase64Encoded) + "|" + string(ciphertextBase64Encoded)
}
