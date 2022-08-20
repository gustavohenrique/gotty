package social

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleToken struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	Expiry       *time.Time `json:"expiry,omitempty"`
}

type GoogleUser struct {
	Sub           string      `json:"sub"` // ID
	Name          string      `json:"name"`
	GivenName     string      `json:"given_name"`
	FamilyName    string      `json:"family_name"`
	Profile       string      `json:"profile"`
	Picture       string      `json:"picture"`
	Email         string      `json:"email"`
	EmailVerified bool        `json:"email_verified"`
	Gender        string      `json:"gender"`
	Token         GoogleToken `json:"token"`
}

func NewGoogle(config Config) OpenConnect {
	return OpenConnect{config: config}
}

func (s *OpenConnect) GetRedirectUrl(hash string) string {
	return s.getGoogleOAuthConfig().AuthCodeURL(hash)
}

func (s *OpenConnect) GetKeyFromURL(req *http.Request) string {
	return req.URL.Query().Get("state")
}

func (s *OpenConnect) GetCodeFromURL(req *http.Request) string {
	return req.URL.Query().Get("code")
}

func (s *OpenConnect) FetchUserByCode(code string) (GoogleUser, error) {
	var googleUser GoogleUser
	conf := s.getGoogleOAuthConfig()
	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return googleUser, err
	}
	googleToken := GoogleToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       &token.Expiry,
	}
	googleUser.Token = googleToken

	client := conf.Client(oauth2.NoContext, token)
	url := "https://openidconnect.googleapis.com/v1/userinfo"
	resp, err := client.Get(url)
	if err != nil {
		return googleUser, err
	}
	defer resp.Body.Close()
	raw, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(raw, &googleUser)
	return googleUser, err
}

func (s *OpenConnect) getGoogleOAuthConfig() *oauth2.Config {
	if s.googleOauthConfig == nil {
		config := s.config
		s.googleOauthConfig = &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.CallbackURL,
			Scopes: []string{
				"email",
				"profile",
				"openid",
			},
			Endpoint: google.Endpoint,
		}
	}
	return s.googleOauthConfig
}
