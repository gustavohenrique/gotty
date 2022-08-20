package server

import (
	"github.com/pkg/errors"
)

type Options struct {
	Address             string `hcl:"address" flagName:"address" flagSName:"a" flagDescribe:"IP address to listen" default:"0.0.0.0"`
	Port                string `hcl:"port" flagName:"port" flagSName:"p" flagDescribe:"Port number to liten" default:"8080"`
	Path                string `hcl:"path" flagName:"path" flagSName:"m" flagDescribe:"Base path" default:"/"`
	PermitWrite         bool   `hcl:"permit_write" flagName:"permit-write" flagSName:"w" flagDescribe:"Permit clients to write to the TTY (BE CAREFUL)" default:"false"`
	EnableBasicAuth     bool   `hcl:"enable_basic_auth" default:"false"`
	Credential          string `hcl:"credential" flagName:"credential" flagSName:"c" flagDescribe:"Credential for Basic Authentication (ex: user:pass, default disabled)" default:""`
	EnableRandomUrl     bool   `hcl:"enable_random_url" flagName:"random-url" flagSName:"r" flagDescribe:"Add a random string to the URL" default:"false"`
	RandomUrlLength     int    `hcl:"random_url_length" flagName:"random-url-length" flagDescribe:"Random URL length" default:"8"`
	EnableTLS           bool   `hcl:"enable_tls" flagName:"tls" flagSName:"t" flagDescribe:"Enable TLS/SSL" default:"false"`
	TLSCrtFile          string `hcl:"tls_crt_file" flagName:"tls-crt" flagDescribe:"TLS/SSL certificate file path" default:"~/.gotty.crt"`
	TLSKeyFile          string `hcl:"tls_key_file" flagName:"tls-key" flagDescribe:"TLS/SSL key file path" default:"~/.gotty.key"`
	EnableTLSClientAuth bool   `hcl:"enable_tls_client_auth" default:"false"`
	TLSCACrtFile        string `hcl:"tls_ca_crt_file" flagName:"tls-ca-crt" flagDescribe:"TLS/SSL CA certificate file for client certifications" default:"~/.gotty.ca.crt"`
	IndexFile           string `hcl:"index_file" flagName:"index" flagDescribe:"Custom index.html file" default:""`
	TitleFormat         string `hcl:"title_format" flagName:"title-format" flagSName:"" flagDescribe:"Title format of browser window" default:"{{ .command }}@{{ .hostname }}"`
	EnableReconnect     bool   `hcl:"enable_reconnect" flagName:"reconnect" flagDescribe:"Enable reconnection" default:"false"`
	ReconnectTime       int    `hcl:"reconnect_time" flagName:"reconnect-time" flagDescribe:"Time to reconnect" default:"10"`
	MaxConnection       int    `hcl:"max_connection" flagName:"max-connection" flagDescribe:"Maximum connection to gotty" default:"0"`
	Once                bool   `hcl:"once" flagName:"once" flagDescribe:"Accept only one client and exit on disconnection" default:"false"`
	Timeout             int    `hcl:"timeout" flagName:"timeout" flagDescribe:"Timeout seconds for waiting a client(0 to disable)" default:"0"`
	PermitArguments     bool   `hcl:"permit_arguments" flagName:"permit-arguments" flagDescribe:"Permit clients to send command line arguments in URL (e.g. http://example.com:8080/?arg=AAA&arg=BBB)" default:"false"`
	Width               int    `hcl:"width" flagName:"width" flagDescribe:"Static width of the screen, 0(default) means dynamically resize" default:"0"`
	Height              int    `hcl:"height" flagName:"height" flagDescribe:"Static height of the screen, 0(default) means dynamically resize" default:"0"`
	WSOrigin            string `hcl:"ws_origin" flagName:"ws-origin" flagDescribe:"A regular expression that matches origin URLs to be accepted by WebSocket. No cross origin requests are acceptable by default" default:""`
	EnableWebGL         bool   `hcl:"enable_webgl" flagName:"enable-webgl" flagDescribe:"Enable WebGL renderer" default:"true"`
	Quiet               bool   `hcl:"quiet" flagName:"quiet" flagDescribe:"Don't log" default:"false"`

	EnableGoogleOAuth    bool   `hcl:"enable_google_oauth" default:"true"`
	GoogleClientID       string `hcl:"google_client_id" default:""`
	GoogleClientSecret   string `hcl:"google_client_secret" default:""`
	GoogleCallbackURL    string `hcl:"google_callback_url" default:"http://localhost:8010/callback"`
	GoogleCookieName     string `hcl:"google_cookie_name" default:"gotty_google_auth"`
	GoogleCookiePath     string `hcl:"google_cookie_path" default:"/"`
	GoogleCookieMaxAge   int    `hcl:"google_cookie_max_age" default:"86400"`
	GoogleCookieHttpOnly bool   `hcl:"google_cookie_http_only" default:"true"`
	JwtAudience          string `hcl:"jwt_audience" default:""`
	JwtSecret            string `hcl:"jwt_secret" default:""`
	JwtCookieName        string `hcl:"jwt_cookie_name" default:"gotty_auth"`
	JwtCookiePath        string `hcl:"jwt_cookie_path" default:"/"`
	JwtCookieMaxAge      int    `hcl:"jwt_cookie_max_age" default:"86400"`
	JwtCookieHttpOnly    bool   `hcl:"jwt_cookie_http_only" default:"true"`
	JwtExpiration        string `hcl:"jwt_expiration" default:"100000"`
	UsersFile            string `hcl:"users_file" default:"/root/users.json"`

	TitleVariables map[string]interface{}
}

func (options *Options) Validate() error {
	if options.EnableTLSClientAuth && !options.EnableTLS {
		return errors.New("TLS client authentication is enabled, but TLS is not enabled")
	}
	return nil
}
