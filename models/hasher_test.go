package models

import (
	"testing"
)

func TestGeneratePasswordHash_NoId(t *testing.T) {

	if _, err := GeneratePasswordHash("", "th3P0rd", "some salt"); err == nil {
		t.Fatal("there should be an error when no id is given")
	}

}

func TestGeneratePasswordHash_NoPw(t *testing.T) {

	if _, err := GeneratePasswordHash("1234", "", "some salt"); err != nil {
		t.Fatal("there should NOT be an error when no pw is given")
	}

}

func TestGeneratePasswordHash_NoSalt(t *testing.T) {

	if _, err := GeneratePasswordHash("1234", "th3P0rd", ""); err == nil {
		t.Fatal("there should be an error when no pw is given")
	}

}

func TestGeneratePasswordHash(t *testing.T) {

	if pwHashed, err := GeneratePasswordHash("1234", "th3P0rd", "some salt"); err != nil {
		t.Fatal("there should be an error when no pw is given")
	} else {
		reHashed, _ := GeneratePasswordHash("1234", "th3P0rd", "some salt")

		if pwHashed != reHashed {
			t.Fatal("the two hash's should match")
		}

		badHashed, _ := GeneratePasswordHash("1235", "th3P0rd", "some salt")

		if pwHashed == badHashed {
			t.Fatal("the two hash's should NOT match as they have different userid's")
		}
	}

}
