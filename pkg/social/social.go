package social

import "golang.org/x/oauth2"

type Config struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

type OpenConnect struct {
	googleOauthConfig *oauth2.Config
	config            Config
}
