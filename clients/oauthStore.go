package clients

import (
	"log"

	"github.com/RangelReale/osin"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type OAuthStorage struct {
	session *mgo.Session
}

const (
	//mongo collections
	client_collection    = "oauth_client"
	authorize_collection = "oauth_authorize"
	access_collection    = "oauth_access"
	db_name              = ""

	refreshtoken = "refreshtoken"
)

//filter used to exclude the mongo _id from being returned
var selectFilter = bson.M{"_id": 0}

func NewOAuthStorage(session *mgo.Session) *OAuthStorage {

	//cpy := session.Copy()
	//defer cpy.Close()

	storage := &OAuthStorage{session: session}

	index := mgo.Index{
		Key:        []string{refreshtoken},
		Unique:     false, // refreshtoken is sometimes empty
		DropDups:   false,
		Background: true,
		Sparse:     true,
	}

	accesses := storage.session.DB(db_name).C(access_collection)

	idxErr := accesses.EnsureIndex(index)
	if idxErr != nil {
		log.Print("NewOAuthStorage EnsureIndex error")
		log.Fatal(idxErr)
	}
	return storage
}

func (s *OAuthStorage) Clone() osin.Storage {
	return s
}

func (s *OAuthStorage) Close() {
	s.session.Close()
	return
}

func (store *OAuthStorage) GetClient(id string) (osin.Client, error) {
	log.Printf("GetClient %s", id)
	log.Print("GetClient copy the session")
	cpy := store.session.Copy()
	defer cpy.Close()
	log.Print("GetClient after session copy")
	clients := cpy.DB(db_name).C(client_collection)
	log.Print("GetClient after getting the clients collections")
	client := &osin.DefaultClient{}
	log.Print("GetClient about to do the query")
	err := clients.FindId(id).Select(selectFilter).One(client)
	log.Printf("GetClient found %v", client)
	log.Printf("GetClient err %v", err)
	cpy.Refresh()
	return client, err
}

func (store *OAuthStorage) SetClient(id string, client osin.Client) error {
	session := store.session.Copy()
	defer session.Close()
	clients := session.DB(db_name).C(client_collection)
	_, err := clients.UpsertId(id, client)
	return err
}

func (store *OAuthStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	session := store.session.Copy()
	defer session.Close()
	authorizations := session.DB(db_name).C(authorize_collection)
	_, err := authorizations.UpsertId(data.Code, data)
	return err
}

func (store *OAuthStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	session := store.session.Copy()
	defer session.Close()
	authorizations := session.DB(db_name).C(authorize_collection)
	authData := new(osin.AuthorizeData)
	err := authorizations.FindId(code).Select(selectFilter).One(authData)
	return authData, err
}

func (store *OAuthStorage) RemoveAuthorize(code string) error {
	session := store.session.Copy()
	defer session.Close()
	authorizations := session.DB(db_name).C(authorize_collection)
	return authorizations.RemoveId(code)
}

func (store *OAuthStorage) SaveAccess(data *osin.AccessData) error {
	session := store.session.Copy()
	defer session.Close()
	accesses := session.DB(db_name).C(access_collection)
	_, err := accesses.UpsertId(data.AccessToken, data)
	return err
}

func (store *OAuthStorage) LoadAccess(token string) (*osin.AccessData, error) {
	session := store.session.Copy()
	defer session.Close()
	accesses := session.DB(db_name).C(access_collection)
	accData := new(osin.AccessData)
	err := accesses.FindId(token).Select(selectFilter).One(accData)
	return accData, err
}

func (store *OAuthStorage) RemoveAccess(token string) error {
	session := store.session.Copy()
	defer session.Close()
	accesses := session.DB(db_name).C(access_collection)
	return accesses.RemoveId(token)
}

func (store *OAuthStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	session := store.session.Copy()
	defer session.Close()
	accesses := session.DB(db_name).C(access_collection)
	accData := new(osin.AccessData)
	err := accesses.Find(bson.M{refreshtoken: token}).Select(selectFilter).One(accData)
	return accData, err
}

func (store *OAuthStorage) RemoveRefresh(token string) error {
	session := store.session.Copy()
	defer session.Close()
	accesses := session.DB(db_name).C(access_collection)
	return accesses.Update(bson.M{refreshtoken: token}, bson.M{
		"$unset": bson.M{
			refreshtoken: 1,
		}})
}
