package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RangelReale/osin"
	"github.com/gorilla/mux"
	tpClients "github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/shoreline"

	"../clients"
	"../models"
)

type (
	OAuthConfig struct {
		ExpireDays int `json:"expireDays"`
	}
	OAuthApi struct {
		oauthServer *osin.Server
		storage     *clients.OAuthStorage
		userApi     shoreline.Client
		permsApi    tpClients.Gatekeeper
		OAuthConfig
	}
	//scope that maps to a tidepool permisson
	scope struct {
		name, requestMsg, grantMsg string
	}
)

var (
	//Available scopes's
	scopeView   scope = scope{name: "view", requestMsg: "Request uploading of data", grantMsg: "Allow uploading of data on your behalf"}
	scopeUpload scope = scope{name: "upload", requestMsg: "Request viewing of data", grantMsg: "Allow viewing of data on your behalf"}
)

const (
	//errors
	error_signup_details           = "sorry but look like something was wrong with your signup details!"
	error_signup_account           = "sorry but there was an issue creating an account for your oauth2 user"
	error_signup_account_duplicate = "sorry but there is already an account with those details"

	msg_signup_complete             = "Your account has been created"
	msg_tidepool_permissons_granted = "Login to grant these permissons to your Tidepool account"

	oneDayInSecs = 86400
	//TODO: get prefix from router??
	authPostAction = "/oauth/authorize?response_type=%s&client_id=%s&state=%s&scope=%s&redirect_uri=%s"
	//TODO: stop gap for styling
	basicCss = "<style type=\"text/css\">body{margin:40px auto;max-width:650px;line-height:1.6;font-size:18px;color:#444;padding:0 10px}h1,h2,h3{line-height:1.2}</style>"
)

func InitOAuthApi(
	config OAuthConfig,
	storage *clients.OAuthStorage,
	userApi shoreline.Client,
	permsApi tpClients.Gatekeeper) *OAuthApi {

	log.Print("OAuthApi setting up ...")

	sconfig := osin.NewServerConfig()
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = true

	return &OAuthApi{
		storage:     storage,
		oauthServer: osin.NewServer(sconfig, storage),
		userApi:     userApi,
		permsApi:    permsApi,
		OAuthConfig: config,
	}
}

func (o *OAuthApi) SetHandlers(prefix string, rtr *mux.Router) {

	log.Print("OAuthApi attaching handlers ...")

	rtr.HandleFunc(prefix+"/signup", o.signup).Methods("POST")
	rtr.HandleFunc(prefix+"/signup", o.signupShow).Methods("GET")
	rtr.HandleFunc(prefix+"/authorize", o.authorize).Methods("POST", "GET")
	rtr.HandleFunc(prefix+"/token", o.token).Methods("GET")
	rtr.HandleFunc(prefix+"/info", o.info).Methods("GET")

}

/*
 * Show the signup from so an external user can signup to the tidepool platform
 */
func (o *OAuthApi) signupShow(w http.ResponseWriter, r *http.Request) {

	//TODO: as a template
	w.Write([]byte("<html>"))
	w.Write([]byte(fmt.Sprintf("<head>%s</head>", basicCss)))
	w.Write([]byte("<body>"))
	w.Write([]byte("DEVELOPER ACCOUNT SIGNUP <br/><br/>"))
	w.Write([]byte("<form action=\"\" method=\"POST\">"))
	w.Write([]byte("<fieldset>"))
	w.Write([]byte("<legend>Application</legend>"))
	w.Write([]byte("App Name: <input type=\"text\" name=\"usr_name\" /><br/>"))
	w.Write([]byte("App Redirect Uri: <input type=\"text\" name=\"uri\" /><br/>"))
	w.Write([]byte("Permissons:"))
	w.Write([]byte(makeScopeOption(scopeUpload) + "<br />"))
	w.Write([]byte(makeScopeOption(scopeView) + " <br />"))
	w.Write([]byte("<br/><br/>Email: <input type=\"email\" name=\"email\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("<br/><br/><input type=\"submit\"/>"))
	w.Write([]byte("</fieldset>"))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))
}

func makeScopeOption(theScope scope) string {
	//disabled and selected by default at this stage
	selected := "checked"
	disabled := "onclick=\"return false\""

	return fmt.Sprintf("<input type=\"checkbox\" name=\"%s\"  value=\"%s\" %s %s /> %s", theScope.name, theScope.name, theScope.requestMsg, selected, disabled)
}

//check we have all the fields we require
func signupFormValid(formData url.Values) bool {
	return formData.Get("usr_name") != "" &&
		formData.Get("password") != "" &&
		formData.Get("email") != "" &&
		formData.Get("uri") != ""
}

//return requested scope as a comma seperated list
func signupScope(formData url.Values) string {

	scopes := []string{}

	if formData.Get(scopeView.name) != "" {
		scopes = append(scopes, scopeView.name)
	}
	if formData.Get(scopeUpload.name) != "" {
		scopes = append(scopes, scopeUpload.name)
	}

	return strings.Join(scopes, ",")
}

func (o *OAuthApi) applyPermissons(authorizingUserId, appUserId, scope string) bool {

	var empty struct{}
	scopes := strings.Split(scope, ",")
	permsToApply := make(tpClients.Permissions)

	for i := range scopes {
		permsToApply[scopes[i]] = empty
	}

	log.Printf("applyPermissons: permissons to apply %v", permsToApply)

	if appliedPerms, err := o.permsApi.SetPermissions(appUserId, authorizingUserId, permsToApply); err != nil {
		log.Printf("applyPermissons: err %v setting the permissons %v", err, appliedPerms)
		return false
	} else {
		log.Printf("applyPermissons: permissons %v set", permsToApply)
		return true
	}
}

/*
 * Process signup for the app user
 */
func (o *OAuthApi) signup(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	if r.Method == "POST" && signupFormValid(r.Form) {

		var signupData = []byte(fmt.Sprintf(`{"username": "%s", "password": "%s","emails":["%s"]}`, r.Form.Get("usr_name"), r.Form.Get("password"), r.Form.Get("email")))

		log.Printf("signup: details for new user [%s]", string(signupData[:]))

		//TODO: add call to go-common
		if signupResp, err := http.Post("http://localhost:8009/auth/user", "application/json", bytes.NewBuffer(signupData)); err != nil {
			w.Write([]byte(fmt.Sprintf("err during app account signup: %s", err.Error())))
		} else {
			if signupResp.StatusCode == http.StatusCreated {

				body, _ := ioutil.ReadAll(signupResp.Body)

				var usr map[string]string
				_ = json.Unmarshal(body, &usr)

				log.Printf("tidepool account %v", usr)

				secret, _ := models.GenerateHash(usr["userid"], r.Form.Get("uri"), time.Now().String())

				theClient := &osin.DefaultClient{
					Id:          usr["userid"],
					Secret:      secret,
					RedirectUri: r.Form.Get("uri"),
				}

				authData := &osin.AuthorizeData{
					Client:      theClient,
					Scope:       signupScope(r.Form),
					RedirectUri: theClient.RedirectUri,
					ExpiresIn:   int32(o.OAuthConfig.ExpireDays * oneDayInSecs),
					CreatedAt:   time.Now(),
				}

				log.Printf("signup: AuthorizeData %v", authData)
				if saveErr := o.storage.SaveAuthorize(authData); saveErr != nil {
					log.Printf("signup error during SaveAuthorize: %s", saveErr.Error())
					w.Write([]byte(saveErr.Error()))
					return
				}
				log.Printf("signup: SetClient ID=%s", theClient.Id)
				log.Printf("signup: SetClient Client=%v", theClient)
				if setErr := o.storage.SetClient(theClient.Id, theClient); setErr != nil {
					log.Printf("signup error during SetClient: %s", setErr.Error())
					w.Write([]byte(setErr.Error()))
					return
				}
				log.Print("signup: about to announce the details")
				//Inform of the results
				signedUpIdMsg := fmt.Sprintf("client_id=%s", theClient.Id)
				signedUpSecretMsg := fmt.Sprintf("client_secret=%s", theClient.Secret)

				w.Write([]byte("<html>"))
				w.Write([]byte(fmt.Sprintf("<head>%s</head>", basicCss)))
				w.Write([]byte("<body>"))
				w.Write([]byte(msg_signup_complete + " <br/>"))
				w.Write([]byte(signedUpIdMsg + " <br/>"))
				w.Write([]byte(signedUpSecretMsg + " <br/>"))
				w.Write([]byte("</html></body>"))

				log.Printf("signup: client %v", authData.Client)
				log.Print("signup: " + signedUpIdMsg)
				log.Print("signup: " + signedUpSecretMsg)
			} else if signupResp.StatusCode == http.StatusConflict {
				w.Write([]byte(error_signup_account_duplicate))
				log.Printf("signup: [%s] ", error_signup_account_duplicate)
			} else {
				w.Write([]byte(error_signup_account))
				log.Printf("signup: [%s] status[%s]", error_signup_account, signupResp.Status)
			}
		}

	} else if r.Method == "POST" {
		log.Print(error_signup_details)
		w.Write([]byte(error_signup_details))
	}
}

/*
 * Authorize 'app' user to access the tidepool platfrom, returning a token
 */
func (o *OAuthApi) authorize(w http.ResponseWriter, r *http.Request) {

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	log.Print("authorize: off to handle auth request")
	if ar := o.oauthServer.HandleAuthorizeRequest(resp, r); ar != nil {
		log.Print("authorize: lets do the user login")
		if loggedInId := o.handleLoginPage(ar, w, r); loggedInId == "" {
			log.Print("authorize: no joy trying to login to tidepool!! ")
			return
		} else {
			log.Print("authorize: logged in so finish the auth request")
			log.Printf("authorize: the valid request %v", ar)
			if o.applyPermissons(loggedInId, ar.Client.GetId(), ar.Scope) {
				log.Printf("authorize: applyPermissons [%s] to userid [%s]", ar.Scope, loggedInId)
				ar.Authorized = true
				o.oauthServer.FinishAuthorizeRequest(resp, r, ar)
			} else {
				log.Print("ERROR: authorize failed to apply the permissons")
			}
		}
	}
	if resp.IsError && resp.InternalError != nil {
		log.Print("authorize: stink bro it's all gone pete tong")
		log.Printf("ERROR: %s\n", resp.InternalError)
	}
	osin.OutputJSON(resp, w, r)
}

func (o *OAuthApi) handleLoginPage(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) string {
	r.ParseForm()
	if r.Method == "POST" && r.Form.Get("login") != "" && r.Form.Get("password") != "" {
		log.Print("handleLoginPage: do the login")

		//TODO: handle bad credentials

		if usr, _, err := o.userApi.Login(r.Form.Get("login"), r.Form.Get("password")); err != nil {
			log.Printf("handleLoginPage: err during account login: %s", err.Error())
		} else if err == nil && usr == nil {
			log.Print("handleLoginPage: tidepool login failed as nothing was found")
		} else if usr != nil {
			log.Printf("handleLoginPage: tidepool login success [%s] ", usr.UserID)
			return usr.UserID
		}
		return ""
	}
	log.Print("handleLoginPage: show login form")
	//TODO: as a template

	w.Write([]byte("<html>"))
	w.Write([]byte(fmt.Sprintf("<head>%s</head>", basicCss)))
	w.Write([]byte("<body>"))
	w.Write([]byte(fmt.Sprintf("<form action="+authPostAction+" method=\"POST\">",
		ar.Type, ar.Client.GetId(), ar.State, ar.Scope, url.QueryEscape(ar.RedirectUri))))

	w.Write([]byte(msg_tidepool_permissons_granted + "<br/>"))

	log.Printf("Login scopes %s", ar.Scope)

	//if strings.Contains(ar.Scope, scopeView.name) {
	//TODO: defaulted at this stage for initial implementation
	w.Write([]byte("<ol>"))
	w.Write([]byte("<li>" + scopeView.grantMsg + " </li>"))
	//}
	//if strings.Contains(ar.Scope, scopeUpload.name) {
	w.Write([]byte("<li>" + scopeUpload.grantMsg + " </li>"))
	w.Write([]byte("</ol>"))
	//}
	w.Write([]byte("Email: <input type=\"text\" name=\"login\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("<input type=\"submit\"/>"))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))

	return ""
}

// Access token endpoint
func (o *OAuthApi) token(w http.ResponseWriter, r *http.Request) {

	log.Print("OAuthApi: token")

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	if ar := o.oauthServer.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		o.oauthServer.FinishAccessRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	osin.OutputJSON(resp, w, r)
}

// Information endpoint
func (o *OAuthApi) info(w http.ResponseWriter, r *http.Request) {

	log.Print("OAuthApi: info")

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	if ir := o.oauthServer.HandleInfoRequest(resp, r); ir != nil {
		o.oauthServer.FinishInfoRequest(resp, r, ir)
	}
	osin.OutputJSON(resp, w, r)
}
