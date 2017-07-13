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
