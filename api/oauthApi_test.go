package api

import (
	"net/url"
	"testing"

	tpClients "github.com/tidepool-org/go-common/clients"
)

func Test_signupScope(t *testing.T) {

	formData := make(url.Values)
	formData[string(scopeView)] = []string{string(scopeView)}
	formData[string(scopeUpload)] = []string{string(scopeUpload)}

	scope := signupScope(formData)

	expectedScope := string(scopeView) + "," + string(scopeUpload)

	if scope != expectedScope {
		t.Fatalf("got %s expected %s", scope, expectedScope)
	}
}

func Test_signupFormValid(t *testing.T) {

	formData := make(url.Values)
	formData["usr_name"] = []string{"other"}
	formData["password"] = []string{"stuff"}
	formData["uri"] = []string{"and"}
	formData["email"] = []string{"some@more.org"}

	valid := signupFormValid(formData)

	if valid == false {
		t.Fatalf("form %v should be valid", formData)
	}

}

func Test_signupFormValid_false(t *testing.T) {

	formData := make(url.Values)
	formData["usr_name"] = []string{"other"}
	formData["password"] = []string{""}
	formData["uri"] = []string{"and"}
	formData["email"] = []string{"some@more.org"}

	valid := signupFormValid(formData)

	if valid {
		t.Fatalf("form %v should NOT be valid", formData)
	}

}

func Test_applyPermissons(t *testing.T) {

	mockPerms := tpClients.NewGatekeeperMock(nil, nil)

	api := OAuthApi{permsApi: mockPerms}

	done := api.applyPermissons("123", "456", "view,upload")

	if done == false {
		t.Fatal("applyPermissons should have returned true on success")
	}

}
