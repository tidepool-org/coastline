package clients

import (
	//"log"
	"testing"

	"github.com/RangelReale/osin"
	"github.com/tidepool-org/go-common/clients/mongo"
)

var (
	a_client = &osin.DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "http://localhost:14000",
	}

	auth_data = &osin.AuthorizeData{
		Code:   "12+34",
		Scope:  "view",
		Client: a_client,
	}

	access_data = &osin.AccessData{
		AccessToken: "4321",
		Client:      a_client,
		Scope:       "upload,view",
	}

	testingConfig = &mongo.Config{ConnectionString: "mongodb://localhost/oauth_test"}
)

func TestOAuth_ClientStorage(t *testing.T) {

	os := NewOAuthStorage(testingConfig)

	/*
	 * INIT THE TEST - we use a clean copy of the collection before we start
	 */
	cpy := os.session.Copy()
	defer cpy.Close()

	//just drop and don't worry about any errors
	cpy.DB("").DropDatabase()

	/*
	 * THE TESTS
	 */
	os.SetClient(a_client.GetId(), a_client)

	if fndClient, err := os.GetClient(a_client.GetId()); err != nil {
		t.Fatalf("Error trying to get client %s", err.Error())
	} else if fndClient.GetId() != a_client.GetId() || fndClient.GetRedirectUri() != a_client.GetRedirectUri() || fndClient.GetSecret() != a_client.GetSecret() {
		t.Fatalf("got %v expected %v", fndClient, a_client)
	}
}

func TestOAuth_AccessStorage(t *testing.T) {

	os := NewOAuthStorage(testingConfig)

	/*
	 * INIT THE TEST - we use a clean copy of the collection before we start
	 */
	cpy := os.session.Copy()
	defer cpy.Close()

	//just drop and don't worry about any errors
	cpy.DB("").DropDatabase()

	/*
	 * THE TESTS
	 */
	os.SaveAccess(access_data)

	if foundAccess, err := os.LoadAccess(access_data.AccessToken); err != nil {
		t.Fatalf("Error trying to get access %s", err.Error())
	} else if foundAccess.AccessToken != access_data.AccessToken || foundAccess.Client == nil || foundAccess.Scope != access_data.Scope {
		t.Fatalf("got %v expected %v", foundAccess, access_data)
	}
}

func TestOAuth_AuthorizeStorage(t *testing.T) {

	os := NewOAuthStorage(testingConfig)

	/*
	 * INIT THE TEST - we use a clean copy of the collection before we start
	 */
	cpy := os.session.Copy()
	defer cpy.Close()

	//just drop and don't worry about any errors
	cpy.DB("").DropDatabase()

	/*
	 * THE TESTS
	 */
	os.SaveAuthorize(auth_data)

	if foundAuthorize, err := os.LoadAuthorize(auth_data.Code); err != nil {
		t.Fatalf("Error trying to get auth %s", err.Error())
	} else if foundAuthorize.Code != auth_data.Code || foundAuthorize.Scope != auth_data.Scope || foundAuthorize.Client == nil {
		t.Fatalf("got %v expected %v", foundAuthorize, auth_data)
	}
}
