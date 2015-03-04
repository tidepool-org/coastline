package clients

import (
	"testing"

	"github.com/RangelReale/osin"
)

var (
	a_client_cache = &osin.DefaultClient{
		Id:          "6789",
		Secret:      "aaxxccyy",
		RedirectUri: "http://localhost:14000",
	}
	auth_data_cache = &osin.AuthorizeData{
		Code:     "67+89_c",
		Scope:    "upload",
		UserData: *a_client_cache,
	}
	access_data_cache = &osin.AccessData{
		AccessToken: "9867",
		UserData:    *a_client_cache,
		Scope:       "upload,view",
	}
)

func Test_CacheClientStorage(t *testing.T) {

	c := NewTestStorage()
	c.SetClient(a_client_cache.GetId(), a_client_cache)

	if fndClient, err := c.GetClient(a_client_cache.GetId()); err != nil {
		t.Fatalf("Error trying to get client %s", err.Error())
	} else {
		if fndClient == nil {
			t.Fatal("Client not found ")
		} else if fndClient.GetId() != a_client_cache.GetId() {
			t.Fatalf("wrong client: found %v expected %v", fndClient, a_client_cache)
		}
	}
}

func Test_CacheAuthorizeStorage(t *testing.T) {

	c := NewTestStorage()
	c.SaveAuthorize(auth_data_cache)

	if authD, err := c.LoadAuthorize(auth_data_cache.Code); err != nil {
		t.Fatalf("Error trying to get auth data %s", err.Error())
	} else {
		if authD == nil {
			t.Fatal("Auth not found ")
		} else if authD.Code != auth_data_cache.Code {
			t.Fatalf("wrong auth data: found %v expected %v", authD, auth_data_cache)
		}
	}
}

func Test_CacheAccessStorage(t *testing.T) {

	c := NewTestStorage()
	c.SaveAccess(access_data)

	if accessD, err := c.LoadAccess(access_data.AccessToken); err != nil {
		t.Fatalf("Error trying to get access data %s", err.Error())
	} else {
		if accessD == nil {
			t.Fatal("Access not found ")
		} else if accessD.AccessToken != access_data.AccessToken {
			t.Fatalf("wrong access data: found %v expected %v", accessD, access_data)
		}
	}
}
