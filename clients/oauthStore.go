package clients

import (
	"log"

	"github.com/RangelReale/osin"
	"github.com/tidepool-org/go-common/clients/mongo"
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

func NewOAuthStorage(config *mongo.Config) *OAuthStorage {

	mongoSession, err := mongo.Connect(config)
	if err != nil {
		log.Fatal(err)
	}

	storage := &OAuthStorage{session: mongoSession}

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
		log.Printf("NewOAuthStorage EnsureIndex error[%s] ", idxErr.Error())
		log.Fatal(idxErr)
	}
	return storage
}

func getUserData(raw interface{}) map[string]interface{} {
	if raw != nil {
		userDataM := raw.(bson.M)
		return map[string]interface{}{"AppName": userDataM["AppName"]}
	}
	log.Print("getUserData has no raw data to process")
	return nil
}

func getClient(raw interface{}) *osin.DefaultClient {

	if raw != nil {

		clientM := raw.(bson.M)

		return &osin.DefaultClient{
			Id:          clientM["id"].(string),
			RedirectUri: clientM["redirecturi"].(string),
			Secret:      clientM["secret"].(string),
			UserData:    getUserData(clientM["userdata"]),
		}
	}
	log.Print("getClient has no raw data to process")
	return &osin.DefaultClient{}
}

func (s *OAuthStorage) Clone() osin.Storage {
	return s
}

func (s *OAuthStorage) Close() {
	log.Print("OAuthStorage.Close(): closing the connection")
	//s.session.Close()
	return
}

func (store *OAuthStorage) GetClient(id string) (osin.Client, error) {
	log.Printf("GetClient id[%s]", id)
	cpy := store.session.Copy()
	defer cpy.Close()
	clients := cpy.DB(db_name).C(client_collection)
	client := &osin.DefaultClient{}
	if err := clients.Find(bson.M{"id": id}).Select(selectFilter).One(client); err != nil {
		log.Printf("GetClient error[%s]", err.Error())
		return nil, err
	}
	log.Printf("GetClient found %v", client)
	client.UserData = getUserData(client.UserData)
	return client, nil
}

func (store *OAuthStorage) SetClient(id string, client osin.Client) error {
	cpy := store.session.Copy()
	defer cpy.Close()
	clients := cpy.DB(db_name).C(client_collection)

	//see https://github.com/RangelReale/osin/issues/40
	clientToSave := osin.DefaultClient{}
	clientToSave.CopyFrom(client)

	_, err := clients.Upsert(bson.M{"id": id}, clientToSave)
	return err
}

func (store *OAuthStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	log.Printf("SaveAuthorize for code[%s]", data.Code)
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)

	//see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.Client.(*osin.DefaultClient)
	data.Client = nil

	if _, err := authorizations.Upsert(bson.M{"code": data.Code}, data); err != nil {
		log.Printf("SaveAuthorize error[%s]", err.Error())
		return err
	}
	return nil
}

func (store *OAuthStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	log.Printf("LoadAuthorize for code[%s]", code)
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)
	data := &osin.AuthorizeData{}

	if err := authorizations.Find(bson.M{"code": code}).Select(selectFilter).One(data); err != nil {
		log.Printf("LoadAuthorize error[%s]", err.Error())
		return nil, err
	}

	log.Printf("LoadAuthorize found %v", data)

	//see https://github.com/RangelReale/osin/issues/40
	data.Client = getClient(data.UserData)
	data.UserData = nil

	return data, nil
}

func (store *OAuthStorage) RemoveAuthorize(code string) error {
	log.Printf("RemoveAuthorize for code[%s]", code)
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)
	return authorizations.Remove(bson.M{"code": code})
}

func (store *OAuthStorage) SaveAccess(data *osin.AccessData) error {
	log.Printf("SaveAccess for token[%s]", data.AccessToken)
	cpy := store.session.Copy()
	defer cpy.Close()

	//see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.Client.(*osin.DefaultClient)
	data.Client = nil

	accesses := cpy.DB(db_name).C(access_collection)

	if _, err := accesses.Upsert(bson.M{"accesstoken": data.AccessToken}, data); err != nil {
		log.Printf("SaveAccess error[%s]", err.Error())
	}

	return nil
}

func (store *OAuthStorage) LoadAccess(token string) (*osin.AccessData, error) {
	log.Printf("LoadAccess for token[%s]", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	data := &osin.AccessData{}
	if err := accesses.Find(bson.M{"accesstoken": token}).Select(selectFilter).One(data); err != nil {
		log.Printf("LoadAccess error[%s]", err.Error())
		return nil, err
	}
	log.Printf("LoadAccess found %v", data)
	//see https://github.com/RangelReale/osin/issues/40
	data.Client = getClient(data.UserData)
	data.UserData = nil

	return data, nil
}

func (store *OAuthStorage) RemoveAccess(token string) error {
	log.Printf("RemoveAccess for token[%s]", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	return accesses.Remove(bson.M{"accesstoken": token})
}

func (store *OAuthStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	log.Printf("LoadRefresh for token[%s]", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	data := new(osin.AccessData)

	if err := accesses.Find(bson.M{"refreshtoken": token}).Select(selectFilter).One(data); err != nil {
		log.Printf("LoadRefresh error[%s]", err.Error())
		return nil, err
	}
	log.Printf("LoadRefresh found %v", data)
	return data, nil
}

func (store *OAuthStorage) RemoveRefresh(token string) error {
	log.Printf("RemoveRefresh for token[%s]", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	return accesses.Update(bson.M{"refreshtoken": token}, bson.M{
		"$unset": bson.M{
			refreshtoken: 1,
		}})
}
