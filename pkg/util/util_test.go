package util

import (
	"testing"
)

func TestSaltGeneration(t *testing.T) {
	salt := GenerateSalt()
	if len(salt) != SALTBYTES*2 {
		t.Errorf("Incorrect Salt length from GenerateSalt()")
	}
}

func TestEncryptionFailure(t *testing.T) {
	secret := "secretpassphrase"
	salt := GenerateSalt()
	password := Encrypt(salt, secret)
	salt2 := GenerateSalt()
	password2 := Encrypt(salt2, secret)
	if password == password2 {
		t.Errorf("Encrypted password should not match...")
	}
}

func TestEncryptionSuccess(t *testing.T) {
	secret := "secretpassphrase"
	salt := GenerateSalt()
	password := Encrypt(salt, secret)
	password2 := Encrypt(salt, secret)
	if password != password2 {
		t.Errorf("Encryption match failed...")
	}
}
