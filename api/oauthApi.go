package api

import (
	"errors"
	"fmt"
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
	details map[string]interface{}
)

var (
	//Available scopes's
	scopeView   scope = scope{name: "view", requestMsg: "Requests uploading of data on behalf", grantMsg: "Allow uploading of data on your behalf"}
	scopeUpload scope = scope{name: "upload", requestMsg: "Requests viewing of data on behalf", grantMsg: "Allow viewing of data on your behalf"}
)

const (
	//errors
	error_signup_details           = "sorry but it appears that something was wrong with your signup details!"
	error_signup_pw_match          = "sorry but your passwords don't match"
	error_signup_account           = "sorry but there was an issue creating an account for your oauth2 user"
	error_signup_account_duplicate = "sorry but there is already an account with those details"
	error_generic                  = "sorry but there setting up your account, please contact support@tidepool.org"
	error_check_tidepool_creds     = "sorry but there was an issue authorizing your tidepool user, are your credentials correct?"
	error_applying_permissons      = "sorry but there was an issue apply the permissons for your tidepool user"
	error_oauth_service            = "sorry but there was an issue with our OAuth service"
	//user message
	msg_signup_complete             = "Your Tidepool developer account has been created"
	msg_signup_save_details         = "Please save these details"
	msg_tidepool_account_access     = "Login to grant access to Tidepool"
	msg_tidepool_permissons_granted = "With access to your Tidepool account %s can:"
	//form text
	btn_authorize            = "Grant access to Tidepool"
	btn_no_authorize         = "Deny access to Tidepool"
	btn_signup               = "Signup"
	placeholder_email        = "Email"
	placeholder_pw           = "Password"
	placeholder_pw_confirm   = "Confirm Password"
	placeholder_redirect_uri = "Application redirect_uri"
	placeholder_name         = "Application Name"

	oneDayInSecs = 86400
	//TODO: get prefix from router??
	authPostAction = "https://devel-api.tidepool.io/oauth/authorize?response_type=%s&client_id=%s&state=%s&scope=%s&redirect_uri=%s"
	//TODO: stop gap for styling
	btnCss   = "input[type=submit]{background:#0b9eb3;color:#fff;}"
	inputCss = "input{width:80%%;height:37px;margin:5px;font-size:18px;}"
	mfwCss   = "body{margin:40px auto;max-width:650px;line-height:1.6;font-size:18px;color:#444;padding:0 10px}h1,h2,h3{line-height:1.2}"
	basicCss = "<style type=\"text/css\"></style>"
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
	//signup user and give them secret and id required for oauth2 usage
	rtr.HandleFunc(prefix+"/signup", o.signup).Methods("GET", "POST")

	//the oauth2 specific part of the api
	rtr.HandleFunc(prefix+"/authorize", o.authorize).Methods("GET", "POST")
	rtr.HandleFunc(prefix+"/token", o.token).Methods("GET")
	rtr.HandleFunc(prefix+"/info", o.info).Methods("GET")

}

func makeScopeOption(theScope scope) string {
	//disabled and selected by default at this stage
	selected := "checked"
	disabled := "return false"
	return fmt.Sprintf("<input type=\"checkbox\" name=\"%s\"  value=\"%s\" %s onclick=\"%s\" /> %s", theScope.name, theScope.name, theScope.requestMsg, selected, disabled)
}

//check we have all the fields we require
func signupFormValid(formData url.Values) (string, bool) {

	if formData.Get("password") != formData.Get("password_confirm") {
		return error_signup_pw_match, false
	}

	if formData.Get("usr_name") != "" &&
		formData.Get("password") != "" &&
		formData.Get("email") != "" &&
		formData.Get("uri") != "" {
		return "", true
	}

	return error_signup_details, false
}

//return requested scope as a comma seperated list
func selectedScopes(formData url.Values) string {

	scopes := []string{}

	if formData.Get(scopeView.name) != "" {
		scopes = append(scopes, scopeView.name)
	}
	if formData.Get(scopeUpload.name) != "" {
		scopes = append(scopes, scopeUpload.name)
	}

	return strings.Join(scopes, ",")
}

func getAllScopes() string {
	return fmt.Sprintf("%s,%s", scopeView.name, scopeUpload.name)
}

//attach basic styles to the rendered components
func applyStyle(w http.ResponseWriter) {
	style := fmt.Sprintf("<head><style type=\"text/css\">%s%s%s</style></head>", mfwCss, inputCss, btnCss)
	w.Write([]byte(style))
}

//show the signup from so an external user can signup to the tidepool platform
func showSignupForm(w http.ResponseWriter) {

	//TODO: as a template
	w.Write([]byte("<html>"))
	applyStyle(w)
	w.Write([]byte("<body>"))
	w.Write([]byte("<h2>Tidepool developer account signup</h2>"))
	w.Write([]byte("<form action=\"\" method=\"POST\">"))
	w.Write([]byte("<fieldset>"))
	w.Write([]byte("<h4>Application Information:</h4>"))
	w.Write([]byte(fmt.Sprintf("<input type=\"text\" name=\"usr_name\" placeholder=\"%s\" /><br/>", placeholder_name)))
	w.Write([]byte(fmt.Sprintf("<input type=\"text\" name=\"uri\" placeholder=\"%s\" /><br/>", placeholder_redirect_uri)))
	w.Write([]byte("<ol>"))
	w.Write([]byte("<li>" + scopeView.requestMsg + " </li>"))
	w.Write([]byte("<li>" + scopeUpload.requestMsg + " </li>"))
	w.Write([]byte("</ol>"))
	//TODO: enable the ability to choose but hardcode for now
	//w.Write([]byte(makeScopeOption(scopeUpload) + "<br />"))
	//w.Write([]byte(makeScopeOption(scopeView) + "<br />"))
	w.Write([]byte("<h4>Account Information:</h4>"))
	w.Write([]byte(fmt.Sprintf("<input type=\"email\" name=\"email\" placeholder=\"%s\" /><br/>", placeholder_email)))
	w.Write([]byte(fmt.Sprintf("<input type=\"password\" name=\"password\" placeholder=\"%s\" /><br/>", placeholder_pw)))
	w.Write([]byte(fmt.Sprintf("<input type=\"password\" name=\"password_confirm\" placeholder=\"%s\" /><br/>", placeholder_pw_confirm)))
	w.Write([]byte(fmt.Sprintf("<input type=\"submit\" value=\"%s\"/>", btn_signup)))
	w.Write([]byte("</fieldset>"))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))
}

//show details on successful signup
func showSignupSuccess(w http.ResponseWriter, signedUp *osin.DefaultClient) {
	signedUpIdMsg := fmt.Sprintf("client_id=%s", signedUp.Id)
	signedUpSecretMsg := fmt.Sprintf("client_secret=%s", signedUp.Secret)
	log.Printf("showSignupSuccess: complete [%v] [%s] ", signedUpIdMsg, signedUpSecretMsg)

	w.Write([]byte("<html>"))
	applyStyle(w)
	w.Write([]byte("<body>"))
	w.Write([]byte("<h2>" + msg_signup_complete + "</h2>"))
	w.Write([]byte("<p>" + msg_signup_save_details + "</p>"))

	w.Write([]byte(signedUpIdMsg + " <br/>"))
	w.Write([]byte(signedUpSecretMsg + " <br/>"))
	w.Write([]byte("</html></body>"))
}

//show login form for user giving authorization
func showLoginForm(ar *osin.AuthorizeRequest, w http.ResponseWriter) {
	ud := ar.Client.GetUserData().(map[string]interface{})

	w.Write([]byte("<html>"))
	applyStyle(w)
	w.Write([]byte("<body>"))
	w.Write([]byte("<h2>" + msg_tidepool_account_access + "</h2>"))
	w.Write([]byte("<b>" + fmt.Sprintf(msg_tidepool_permissons_granted, ud["AppName"]) + "</b>"))
	w.Write([]byte(fmt.Sprintf("<form action="+authPostAction+" method=\"POST\">",
		ar.Type, ar.Client.GetId(), ar.State, ar.Scope, url.QueryEscape(ar.RedirectUri))))
	//TODO: defaulted at this stage for initial implementation e.g. strings.Contains(ar.Scope, scopeView.name)
	w.Write([]byte("<ol>"))
	w.Write([]byte("<li>" + scopeView.grantMsg + " </li>"))
	w.Write([]byte("<li>" + scopeUpload.grantMsg + " </li>"))
	w.Write([]byte("</ol>"))
	w.Write([]byte(fmt.Sprintf("<input type=\"text\" name=\"login\" placeholder=\"%s\" /><br/>", placeholder_email)))
	w.Write([]byte(fmt.Sprintf("<input type=\"password\" name=\"password\" placeholder=\"%s\" /><br/>", placeholder_pw)))
	w.Write([]byte(fmt.Sprintf("<input type=\"submit\" value=\"%s\"/>", btn_authorize)))
	//TODO allow them to deny
	//w.Write([]byte(fmt.Sprintf("<input type=\"submit\" value=\"%s\"/>", btn_no_authorize)))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))
}

//wrapper to write error and show to the user
func showError(w http.ResponseWriter, errorMessage string, statusCode int) {
	w.WriteHeader(statusCode)
	applyStyle(w)
	w.Write([]byte("<html><body>"))
	w.Write([]byte("<i>" + errorMessage + "</i>"))
	w.Write([]byte("</body></html>"))
	return
}

// Apply the requested permissons for the app on authorizing users account
func (o *OAuthApi) applyPermissons(authorizingUserId, appUserId, scope string) bool {

	log.Printf("applyPermissons: raw scope asked for %s", scope)

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
	}
	log.Printf("applyPermissons: permissons %v set", permsToApply)
	return true
}

//try login the user to the platform and apply requested permissons
func (o *OAuthApi) applyAuthorization(user, password string, ar *osin.AuthorizeRequest) error {
	log.Print("applyAuthorization")

	if usr, _, err := o.userApi.Login(user, password); err != nil {
		log.Printf("applyAuthorization: err during account login: %s", err.Error())
		return err
	} else if usr != nil {
		log.Printf("applyAuthorization: tidepool login success for userid[%s] now applying permissons", usr.UserID)
		if o.applyPermissons(usr.UserID, ar.Client.GetId(), getAllScopes()) {
			return nil
		} else {
			log.Printf("applyAuthorization: error[%s]", error_applying_permissons)
			return errors.New(error_applying_permissons)
		}
	}
	log.Printf("applyAuthorization: no user or error from login returning[%s] ", error_check_tidepool_creds)
	return errors.New(error_check_tidepool_creds)
}

//login page for user that is authroizing access to thier tidepool account
func (o *OAuthApi) handleLoginPage(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) bool {

	r.ParseForm()

	if r.Method == "POST" && r.Form.Get("login") != "" && r.Form.Get("password") != "" {

		if err := o.applyAuthorization(r.Form.Get("login"), r.Form.Get("password"), ar); err == nil {
			return true
		} else {
			showError(w, error_check_tidepool_creds, http.StatusBadRequest)
		}
	}
	showLoginForm(ar, w)
	return false
}

//Process signup for the app user
func (o *OAuthApi) signup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	validationMsg, formValid := signupFormValid(r.Form)

	if r.Method == "POST" && formValid {

		if signupResp, err := o.userApi.Signup(r.Form.Get("usr_name"), r.Form.Get("password"), r.Form.Get("email")); err != nil {
			log.Printf("processSignup: error[%s] status[%s]", error_signup_account, err.Error())
			showError(w, error_signup_account, http.StatusInternalServerError)
		} else {
			secret, _ := models.GenerateHash(signupResp.UserID, r.Form.Get("uri"), time.Now().String())

			theClient := &osin.DefaultClient{
				Id:          signupResp.UserID,
				Secret:      secret,
				RedirectUri: r.Form.Get("uri"),
				UserData:    map[string]interface{}{"AppName": signupResp.UserName},
			}

			authData := &osin.AuthorizeData{
				Client:      theClient,
				Scope:       getAllScopes(),
				RedirectUri: theClient.RedirectUri,
				ExpiresIn:   int32(o.OAuthConfig.ExpireDays * oneDayInSecs),
				CreatedAt:   time.Now(),
			}

			// generate token code
			code, err := o.oauthServer.AuthorizeTokenGen.GenerateAuthorizeToken(authData)
			if err != nil {
				log.Print("processSignup: err[%s]", err.Error())
				showError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			authData.Code = code

			log.Printf("processSignup: AuthorizeData %v", authData)
			if saveErr := o.storage.SaveAuthorize(authData); saveErr != nil {
				log.Printf("processSignup: error during SaveAuthorize: %s", saveErr.Error())
				showError(w, error_generic, http.StatusInternalServerError)
			}

			if setErr := o.storage.SetClient(theClient.Id, theClient); setErr != nil {
				log.Printf("signup error during SetClient: %s", setErr.Error())
				showError(w, error_generic, http.StatusInternalServerError)
			}
			log.Print("processSignup: about to announce the details")
			showSignupSuccess(w, theClient)
		}
		return
	} else if r.Method == "POST" && formValid == false {
		log.Printf("processSignup: error[%s]", validationMsg)
		showError(w, validationMsg, http.StatusBadRequest)
		return
	} else if r.Method == "GET" {
		showSignupForm(w)
	}
}

/***
 * Implementation of OAuth2 endpoints
 **/

//OAuth2 authorize endpoint
func (o *OAuthApi) authorize(w http.ResponseWriter, r *http.Request) {

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	log.Print("authorize: off to handle auth request via oauthServer")

	if ar := o.oauthServer.HandleAuthorizeRequest(resp, r); ar != nil {
		log.Print("authorize: show the login")

		if o.handleLoginPage(ar, w, r) == false {
			return
		}
		log.Printf("authorize: resp code[%s] state[%s] ", resp.Output["code"], resp.Output["state"])
		ar.Authorized = true
		o.oauthServer.FinishAuthorizeRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Printf("authorize: stink bro it's all gone pete tong error[%s] code[%d] ", resp.InternalError.Error(), resp.StatusCode)
	}
	osin.OutputJSON(resp, w, r)
}

// OAuth2 token endpoint
func (o *OAuthApi) token(w http.ResponseWriter, r *http.Request) {

	log.Print("token: getting token")
	applyStyle(w)

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	if ar := o.oauthServer.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		o.oauthServer.FinishAccessRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Printf("token: error[%s] status[%d]", resp.InternalError.Error(), resp.StatusCode)
	}
	osin.OutputJSON(resp, w, r)
}

// OAuth2 information endpoint
func (o *OAuthApi) info(w http.ResponseWriter, r *http.Request) {

	log.Print("OAuthApi: info")
	applyStyle(w)

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	if ir := o.oauthServer.HandleInfoRequest(resp, r); ir != nil {
		o.oauthServer.FinishInfoRequest(resp, r, ir)
	}
	osin.OutputJSON(resp, w, r)
}
