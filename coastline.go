package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/hakken"
	//"github.com/tidepool-org/go-common/clients/highwater"
	//"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/go-common/clients/shoreline"
	//"labix.org/v2/mgo"

	"./api"
	sc "./clients"
)

type (
	Config struct {
		clients.Config
		Service disc.ServiceListing `json:"service"`
		//Mongo   mongo.Config        `json:"mongo"`
		Api api.OAuthConfig `json:"coastline"`
	}
)

func main() {
	var config Config

	if err := common.LoadConfig([]string{"./config/env.json", "./config/server.json"}, &config); err != nil {
		log.Panic("Problem loading config", err)
	}

	/*
	 * Hakken setup
	 */
	hakkenClient := hakken.NewHakkenBuilder().
		WithConfig(&config.HakkenConfig).
		Build()

	if err := hakkenClient.Start(); err != nil {
		log.Fatal(err)
	}
	defer hakkenClient.Close()

	/*
	 * Clients
	 */

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: tr}

	/*highwater := highwater.NewHighwaterClientBuilder().
	WithHostGetter(config.HighwaterConfig.ToHostGetter(hakkenClient)).
	WithHttpClient(httpClient).
	WithConfig(&config.HighwaterConfig.HighwaterClientConfig).
	Build()*/

	shoreline := shoreline.NewShorelineClientBuilder().
		WithHostGetter(config.ShorelineConfig.ToHostGetter(hakkenClient)).
		WithHttpClient(httpClient).
		WithConfig(&config.ShorelineConfig.ShorelineClientConfig).
		Build()

	if err := shoreline.Start(); err != nil {
		log.Fatal(err)
	}

	/*
		 *  Mongo session for use

		mongoSession, err := mongo.Connect(&config.Mongo)
		if err != nil {
			log.Fatal(err)
		}

		mongoSession.SetMode(mgo.Monotonic, true)

		sessionCpy := mongoSession.Copy()
		defer sessionCpy.Close()
	*/

	rtr := mux.NewRouter()

	/*
	 * Oauth2 setup
	 */
	oauthApi := api.InitOAuthApi(api.OAuthConfig{Salt: config.Api.Salt}, sc.NewTestStorage(), shoreline)
	oauthApi.SetHandlers("", rtr)

	/*
	 * Serve it up and publish
	 */
	done := make(chan bool)
	server := common.NewServer(&http.Server{
		Addr:    config.Service.GetPort(),
		Handler: rtr,
	})

	var start func() error
	if config.Service.Scheme == "https" {
		sslSpec := config.Service.GetSSLSpec()
		start = func() error { return server.ListenAndServeTLS(sslSpec.CertFile, sslSpec.KeyFile) }
	} else {
		start = func() error { return server.ListenAndServe() }
	}
	if err := start(); err != nil {
		log.Fatal(err)
	}

	hakkenClient.Publish(&config.Service)

	signals := make(chan os.Signal, 40)
	signal.Notify(signals)
	go func() {
		for {
			sig := <-signals
			log.Printf("Got signal [%s]", sig)

			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				server.Close()
				done <- true
			}
		}
	}()

	<-done

}
