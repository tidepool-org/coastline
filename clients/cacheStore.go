package clients

import (
	"errors"
	"fmt"
	"time"

	"github.com/RangelReale/osin"
	"github.com/muesli/cache2go"
)

const (
	clients_cache   = "clients"
	authorize_cache = "authorize"
	access_cache    = "access"
	refresh_cache   = "refresh"
)

type (
	clients   map[string]osin.Client
	authorize map[string]*osin.AuthorizeData
	access    map[string]*osin.AccessData
	refresh   map[string]string

	TestStorage struct {
		cache *cache2go.CacheTable
	}
)

func NewTestStorage() *TestStorage {
	return &TestStorage{cache: cache2go.Cache("oauth2")}
}

func (s *TestStorage) Clone() osin.Storage {
	return s
}

func (s *TestStorage) Close() {
}

func (s *TestStorage) GetClient(id string) (osin.Client, error) {
	fmt.Printf("GetClient: %s\n", id)

	res, err := s.cache.Value(clients_cache)
	if err == nil {
		currentClients := res.Data().(clients)
		fmt.Printf("GetClient: found records [%t]", currentClients != nil)
		return currentClients[id], nil
	}
	return nil, errors.New("Client not found")
}

func (s *TestStorage) SetClient(id string, client osin.Client) error {
	fmt.Printf("SetClient: %s\n", id)

	currentClients := make(clients)

	res, err := s.cache.Value(clients_cache)
	if err == nil {
		currentClients = res.Data().(clients)
		fmt.Printf("SetClient: currently [%v] records", currentClients)
	}

	currentClients[id] = client
	fmt.Printf("SetClient: %v\n", currentClients[id])

	fmt.Printf("SetClient: currently [%v] records", currentClients)

	s.cache.Add(clients_cache, 36*time.Hour, currentClients)

	return nil
}

func (s *TestStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	fmt.Printf("SaveAuthorize: %s\n", data.Code)
	currentAuth := make(authorize)

	res, err := s.cache.Value(authorize_cache)
	if err == nil {
		currentAuth = res.Data().(authorize)
		fmt.Printf("LoadAuthorize: found records [%t]", currentAuth != nil)
	}

	currentAuth[data.Code] = data
	s.cache.Add(authorize_cache, 36*time.Hour, currentAuth)

	return nil
}

func (s *TestStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	fmt.Printf("LoadAuthorize: %s\n", code)

	authClients := make(authorize)

	res, err := s.cache.Value(authorize_cache)
	if err == nil {
		authClients = res.Data().(authorize)
		fmt.Printf("LoadAuthorize: found records [%t]", authClients != nil)
	}

	if d, ok := authClients[code]; ok {
		return d, nil
	}
	return nil, errors.New("Authorize not found")
}

func (s *TestStorage) RemoveAuthorize(code string) error {
	fmt.Printf("RemoveAuthorize: %s\n", code)
	currentAuth := make(authorize)

	res, err := s.cache.Value(authorize_cache)
	if err == nil {
		currentAuth = res.Data().(authorize)
	}

	delete(currentAuth, code)

	s.cache.Add(authorize_cache, 36*time.Hour, currentAuth)
	return nil
}

func (s *TestStorage) SaveAccess(data *osin.AccessData) error {
	fmt.Printf("SaveAccess: %s\n", data.AccessToken)

	currentAccess := make(access)

	res, err := s.cache.Value(access_cache)
	if err == nil {
		currentAccess = res.Data().(access)
		fmt.Printf("SaveAccess: found records [%t]", currentAccess != nil)
	}

	currentAccess[data.AccessToken] = data
	s.cache.Add(access_cache, 36*time.Hour, currentAccess)

	return nil
}

func (s *TestStorage) LoadAccess(code string) (*osin.AccessData, error) {
	fmt.Printf("LoadAccess: %s\n", code)

	accessClients := make(access)

	res, err := s.cache.Value(access_cache)
	if err == nil {
		accessClients = res.Data().(access)
		fmt.Printf("LoadAccess: found records [%t]", accessClients != nil)
	}

	if d, ok := accessClients[code]; ok {
		return d, nil
	}
	return nil, errors.New("Access not found")
}

func (s *TestStorage) RemoveAccess(code string) error {
	fmt.Printf("RemoveAccess: %s\n", code)
	currentAccess := make(access)

	res, err := s.cache.Value(access_cache)
	if err == nil {
		currentAccess = res.Data().(access)
	}

	delete(currentAccess, code)

	s.cache.Add(access_cache, 36*time.Hour, currentAccess)
	return nil

}

func (s *TestStorage) LoadRefresh(code string) (*osin.AccessData, error) {
	return nil, errors.New("Refresh not found")
}

func (s *TestStorage) RemoveRefresh(code string) error {
	return nil
}
