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
	"github.com/tidepool-org/go-common/clients/shoreline"

	"../clients"
	"../models"
)

type (
	OAuthConfig struct {
		Salt       string `json:"salt"`
		ExpireDays int    `json:"expireDays"`
	}
	OAuthApi struct {
		oauthServer *osin.Server
		storage     *clients.TestStorage
		userApi     shoreline.Client
		OAuthConfig
	}
	//scope Enum type's
	scope string
)

const (
	//errors
	error_signup_details = "sorry but look like something was wrong with your signup details!"

	oneDayInSecs = 86400

	//Available scopes's
	//TODO: configrable ??
	scopeView   scope = "view"
	scopeUpload scope = "upload"
	scopeNote   scope = "note"

	//TODO: get prefix from router??
	authPostAction = "/oauth/v1/authorize?response_type=%s&client_id=%s&state=%s&scope=%s&redirect_uri=%s"
	scopeItem      = "<input type=\"checkbox\" name=\"%s\" value=\"%s\" />"
)

func InitOAuthApi(cfg OAuthConfig, s *clients.TestStorage, userApi shoreline.Client) *OAuthApi {

	log.Print("OAuthApi setting up ...")

	sconfig := osin.NewServerConfig()
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = true

	return &OAuthApi{
		storage:     s,
		oauthServer: osin.NewServer(sconfig, s),
		userApi:     userApi,
		OAuthConfig: cfg,
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
 * Tidepool OAuth to allow
 */

/*
 * Show the signup from so an external user can signup to the tidepool platform
 */
func (o *OAuthApi) signupShow(w http.ResponseWriter, r *http.Request) {

	//TODO: as a template
	w.Write([]byte("<html><body>"))
	w.Write([]byte("DEVELOPER ACCOUNT SIGNUP <br/><br/>"))
	w.Write([]byte("<form action=\"\" method=\"POST\">"))
	w.Write([]byte("<fieldset>"))
	w.Write([]byte("<legend>Application</legend>"))
	w.Write([]byte("Name: <input type=\"text\" name=\"usr_name\" /><br/>"))
	w.Write([]byte("Redirect Uri: <input type=\"text\" name=\"uri\" /><br/>"))
	w.Write([]byte("</fieldset>"))
	w.Write([]byte("<fieldset>"))
	w.Write([]byte("<legend>User</legend>"))
	w.Write([]byte("Email: <input type=\"email\" name=\"email\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("</fieldset>"))
	w.Write([]byte("<fieldset>"))
	w.Write([]byte("<legend>Scope</legend>"))
	w.Write([]byte(fmt.Sprintf(scopeItem+" Allow Upload on behalf <br />", scopeUpload, scopeUpload)))
	w.Write([]byte(fmt.Sprintf(scopeItem+" Allow Viewing of data <br />", scopeView, scopeView)))
	w.Write([]byte(fmt.Sprintf(scopeItem+" Allow Commenting on data <br />", scopeNote, scopeNote)))
	w.Write([]byte("<input type=\"submit\"/>"))
	w.Write([]byte("</fieldset>"))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))
}

//check we have all the fields we require
func signupFormValid(fromData url.Values) bool {
	return fromData.Get("usr_name") != "" && fromData.Get("password") != "" && fromData.Get("email") != "" && fromData.Get("uri") != ""
}

//return requested scope as a comma seperated list
func signupScope(fromData url.Values) string {

	scopes := []string{}

	if fromData.Get(string(scopeView)) != "" {
		scopes = append(scopes, string(scopeView))
	}
	if fromData.Get(string(scopeUpload)) != "" {
		scopes = append(scopes, string(scopeUpload))
	}
	if fromData.Get(string(scopeNote)) != "" {
		scopes = append(scopes, string(scopeNote))
	}

	return strings.Join(scopes, ",")
}

/*
 * Process signup for the app user
 */
func (o *OAuthApi) signup(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	if r.Method == "POST" && signupFormValid(r.Form) {

		var signupData = []byte(fmt.Sprintf(`{"username": "%s", "password": "%s","emails":["%s"]}`, r.Form.Get("usr_name"), r.Form.Get("password"), r.Form.Get("email")))

		log.Printf("signup: details for new user [%s]", string(signupData[:]))

		if signupResp, err := http.Post("http://localhost:8009/auth/user", "application/json", bytes.NewBuffer(signupData)); err != nil {
			w.Write([]byte(fmt.Sprintf("err during app account signup: %s", err.Error())))
		} else {

			if signupResp.StatusCode == http.StatusCreated {

				body, _ := ioutil.ReadAll(signupResp.Body)

				var usr map[string]string
				_ = json.Unmarshal(body, &usr)

				log.Printf("tidepool account %v", usr)

				secret, _ := models.GeneratePasswordHash(usr["userid"], "", o.OAuthConfig.Salt)

				clientUsr := &osin.DefaultClient{
					Id:          usr["userid"],
					Secret:      secret,
					RedirectUri: r.Form.Get("uri"),
				}

				authData := &osin.AuthorizeData{
					UserData:    clientUsr,
					Scope:       signupScope(r.Form),
					RedirectUri: clientUsr.RedirectUri,
					ExpiresIn:   int32(o.OAuthConfig.ExpireDays * oneDayInSecs),
					CreatedAt:   time.Now(),
				}

				w.Write([]byte(fmt.Sprintf("signup: with auth data %v", authData)))
				log.Printf("signup: with auth data %v", authData)
				o.storage.SaveAuthorize(authData)

				w.Write([]byte(fmt.Sprintf("signup: created app account!! %v", clientUsr)))
				log.Printf("signup: created app account!! %v", clientUsr)
				o.storage.SetClient(clientUsr.GetId(), clientUsr)
			} else {
				//Not what we hoped for so lets report it!
				w.Write([]byte(fmt.Sprintf("signup: issue during signup %b %s", signupResp.StatusCode, signupResp.Status)))
				log.Printf("signup: issue during signup %b %s", signupResp.StatusCode, signupResp.Status)
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
		if !o.handleLoginPage(ar, w, r) {
			return
		}
		log.Print("authorize: logged in so finish the auth request")
		ar.Authorized = true
		o.oauthServer.FinishAuthorizeRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Print("authorize: stink bro it's all gone pete tong")
		log.Printf("ERROR: %s\n", resp.InternalError)
	}
	log.Print("authorize: so close, about to give you the JSON ...")
	osin.OutputJSON(resp, w, r)

}

func (o *OAuthApi) handleLoginPage(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) bool {
	r.ParseForm()
	if r.Method == "POST" && r.Form.Get("login") != "" && r.Form.Get("password") != "" {
		log.Print("handleLoginPage: do the login")

		if usr, _, err := o.userApi.Login(r.Form.Get("login"), r.Form.Get("password")); err != nil {
			log.Printf("handleLoginPage: err during account login: %s", err.Error())
		} else if err == nil && usr == nil {
			log.Print("handleLoginPage: tidepool login failed as nothing was found")
		} else if usr != nil {
			log.Print("handleLoginPage: tidepool login success")
			return true
		}
		return false
	}
	log.Print("handleLoginPage: show login form")
	w.Write([]byte("<html><body>"))
	w.Write([]byte("LOGIN <br/>"))
	w.Write([]byte(fmt.Sprintf("<form action="+authPostAction+" method=\"POST\">",
		ar.Type, ar.Client.GetId(), ar.State, ar.Scope, url.QueryEscape(ar.RedirectUri))))

	w.Write([]byte("Email: <input type=\"text\" name=\"login\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("<input type=\"submit\"/>"))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))

	return false
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
