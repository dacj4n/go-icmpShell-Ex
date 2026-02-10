package common

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
)

type Auth struct {
	Token      []byte
	tokenMD5   []byte
	SessionKey []byte
}

func (a *Auth) SetSessionKey(key []byte) {
	a.SessionKey = key
}

func (a *Auth) GetKey() ([]byte, error) {
	if len(a.SessionKey) > 0 {
		return a.SessionKey, nil
	}
	return a.getTokenMD5()
}

func (a *Auth) GenerateSessionKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (a *Auth) Decrypt(text []byte) ([]byte, error) {
	key, err := a.GetKey()
	if err != nil {
		return nil, err
	}
	return xor(text, key), nil
}

func (a *Auth) Encrypt(text []byte) ([]byte, error) {
	key, err := a.GetKey()
	if err != nil {
		return nil, err
	}
	return xor(text, key), nil
}

// EncryptWithToken always uses the Token (MD5) for encryption
func (a *Auth) EncryptWithToken(text []byte) ([]byte, error) {
	key, err := a.getTokenMD5()
	if err != nil {
		return nil, err
	}
	return xor(text, key), nil
}

// DecryptWithToken always uses the Token (MD5) for decryption
func (a *Auth) DecryptWithToken(text []byte) ([]byte, error) {
	key, err := a.getTokenMD5()
	if err != nil {
		return nil, err
	}
	return xor(text, key), nil
}

func xor(text []byte, key []byte) []byte {
	if len(key) == 0 {
		return text
	}
	textNew := make([]byte, len(text))
	for i, b := range text {
		textNew[i] = b ^ key[i%len(key)]
	}
	return textNew
}

func (a *Auth) getTokenMD5() ([]byte, error) {
	if a.Token == nil {
		return nil, errors.New("auth: token is empty")
	}

	if a.tokenMD5 == nil {
		md5Handle := md5.New()
		md5Handle.Write(a.Token)
		a.tokenMD5 = md5Handle.Sum(nil)
	}

	return a.tokenMD5, nil
}
