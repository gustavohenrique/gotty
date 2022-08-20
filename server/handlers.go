package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"

	"github.com/sorenisanerd/gotty/pkg/randomstring"
	"github.com/sorenisanerd/gotty/webtty"
)

func (server *Server) generateHandleWS(ctx context.Context, cancel context.CancelFunc, counter *counter) http.HandlerFunc {
	once := new(int64)

	go func() {
		select {
		case <-counter.timer().C:
			cancel()
		case <-ctx.Done():
		}
	}()

	return func(w http.ResponseWriter, r *http.Request) {
		if server.options.Once {
			success := atomic.CompareAndSwapInt64(once, 0, 1)
			if !success {
				http.Error(w, "Server is shutting down", http.StatusServiceUnavailable)
				return
			}
		}

		num := counter.add(1)
		closeReason := "unknown reason"

		defer func() {
			num := counter.done()
			log.Printf(
				"Connection closed by %s: %s, connections: %d/%d",
				closeReason, r.RemoteAddr, num, server.options.MaxConnection,
			)

			if server.options.Once {
				cancel()
			}
		}()

		if int64(server.options.MaxConnection) != 0 {
			if num > server.options.MaxConnection {
				closeReason = "exceeding max number of connections"
				return
			}
		}

		log.Printf("New client connected: %s, connections: %d/%d", r.RemoteAddr, num, server.options.MaxConnection)

		if r.Method != "GET" {
			http.Error(w, "Method not allowed", 405)
			return
		}

		conn, err := server.upgrader.Upgrade(w, r, nil)
		if err != nil {
			closeReason = err.Error()
			return
		}
		defer conn.Close()

		token := server.jwt.GetTokenFromCookie(server.jwtCookieStore, r)
		err = server.processWSConn(ctx, conn, token)

		switch err {
		case ctx.Err():
			closeReason = "cancelation"
		case webtty.ErrSlaveClosed:
			closeReason = server.factory.Name()
		case webtty.ErrMasterClosed:
			closeReason = "client"
		default:
			closeReason = fmt.Sprintf("an error: %s", err)
		}
	}
}

func (server *Server) processWSConn(ctx context.Context, conn *websocket.Conn, token string) error {
	typ, initLine, err := conn.ReadMessage()
	if err != nil {
		return errors.Wrapf(err, "failed to authenticate websocket connection")
	}
	if typ != websocket.TextMessage {
		return errors.New("failed to authenticate websocket connection: invalid message type")
	}

	var init InitMessage
	err = json.Unmarshal(initLine, &init)
	if err != nil {
		return errors.Wrapf(err, "failed to authenticate websocket connection")
	}
	// if init.AuthToken != server.options.Credential {
	if init.AuthToken != token {
		return errors.New("failed to authenticate websocket connection")
	}

	queryPath := "?"
	if server.options.PermitArguments && init.Arguments != "" {
		queryPath = init.Arguments
	}

	query, err := url.Parse(queryPath)
	if err != nil {
		return errors.Wrapf(err, "failed to parse arguments")
	}
	params := query.Query()
	var slave Slave
	slave, err = server.factory.New(params)
	if err != nil {
		return errors.Wrapf(err, "failed to create backend")
	}
	defer slave.Close()

	titleVars := server.titleVariables(
		[]string{"server", "master", "slave"},
		map[string]map[string]interface{}{
			"server": server.options.TitleVariables,
			"master": map[string]interface{}{
				"remote_addr": conn.RemoteAddr(),
			},
			"slave": slave.WindowTitleVariables(),
		},
	)

	titleBuf := new(bytes.Buffer)
	err = server.titleTemplate.Execute(titleBuf, titleVars)
	if err != nil {
		return errors.Wrapf(err, "failed to fill window title template")
	}

	opts := []webtty.Option{
		webtty.WithWindowTitle(titleBuf.Bytes()),
	}
	if server.options.PermitWrite {
		opts = append(opts, webtty.WithPermitWrite())
	}
	if server.options.EnableReconnect {
		opts = append(opts, webtty.WithReconnect(server.options.ReconnectTime))
	}
	if server.options.Width > 0 {
		opts = append(opts, webtty.WithFixedColumns(server.options.Width))
	}
	if server.options.Height > 0 {
		opts = append(opts, webtty.WithFixedRows(server.options.Height))
	}
	tty, err := webtty.New(&wsWrapper{conn}, slave, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create webtty")
	}

	err = tty.Run(ctx)

	return err
}

func (server *Server) handleOauth(w http.ResponseWriter, r *http.Request) {
	hash := randomstring.Generate(32)
	server.createGoogleCookieWithHash(w, r, hash)
	redirectURL := server.google.GetRedirectUrl(hash)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (server *Server) handleOauthCallback(w http.ResponseWriter, r *http.Request) {
	retrievedState := server.getHashFromGoogleCookie(r)
	queryState := server.google.GetKeyFromURL(r)
	if retrievedState != queryState {
		http.Error(w, "Invalid Google credentials", http.StatusUnauthorized)
		return
	}
	code := server.google.GetCodeFromURL(r)
	googleUser, err := server.google.FetchUserByCode(code)
	if err != nil {
		http.Error(w, "Cannot found user by code "+code, http.StatusNotFound)
		return
	}
	if err := server.checkGoogleUserPermissions(googleUser.Email); err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token, err := server.jwt.GenerateToken(googleUser.Email)
	if err != nil {
		http.Error(w, "Cannot generate the JWT Token ", http.StatusForbidden)
		return
	}
	server.createAuthCookieWithToken(w, r, token)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (server *Server) checkGoogleUserPermissions(email string) error {
	file := server.options.UsersFile
	content, err := os.ReadFile(file)
	if err != nil {
		return errors.Wrapf(err, "cannot open users file in "+file)
	}
	var emails []string
	err = json.Unmarshal(content, &emails)
	if err != nil {
		return errors.Wrapf(err, "cannot unmarhsal the emails list")
	}
	for _, e := range emails {
		if e == email {
			return nil
		}
	}
	return errors.New("the email " + email + " do not have permission to login")
}

func (server *Server) createGoogleCookieWithHash(w http.ResponseWriter, r *http.Request, content string) {
	options := server.options
	cookieName := options.GoogleCookieName
	sess, _ := server.googleCookieStore.Get(r, cookieName)
	sess.Values[cookieName] = content
	sess.Options = &sessions.Options{
		Path:     options.GoogleCookiePath,
		MaxAge:   options.GoogleCookieMaxAge,
		HttpOnly: options.GoogleCookieHttpOnly,
	}
	sess.Save(r, w)
}

func (server *Server) createAuthCookieWithToken(w http.ResponseWriter, r *http.Request, content string) {
	options := server.options
	cookieName := options.JwtCookieName
	sess, _ := server.jwtCookieStore.Get(r, cookieName)
	sess.Values[cookieName] = content
	sess.Options = &sessions.Options{
		Path:     options.JwtCookiePath,
		MaxAge:   options.JwtCookieMaxAge,
		HttpOnly: options.JwtCookieHttpOnly,
	}
	err := sess.Save(r, w)
	if err != nil {
		log.Println("Failed to save session:", err)
	}
}

func (server *Server) getHashFromGoogleCookie(req *http.Request) string {
	cookieName := server.options.GoogleCookieName
	sess, _ := server.googleCookieStore.Get(req, cookieName)
	value := sess.Values[cookieName]
	if value != nil {
		return value.(string)
	}
	return ""
}

func (server *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	indexVars, err := server.indexVariables(r)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	indexBuf := new(bytes.Buffer)
	err = server.indexTemplate.Execute(indexBuf, indexVars)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	w.Write(indexBuf.Bytes())
}

func (server *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	indexVars, err := server.indexVariables(r)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	indexBuf := new(bytes.Buffer)
	err = server.loginTemplate.Execute(indexBuf, indexVars)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	w.Write(indexBuf.Bytes())
}

func (server *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	indexVars, err := server.indexVariables(r)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	indexBuf := new(bytes.Buffer)
	err = server.manifestTemplate.Execute(indexBuf, indexVars)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	w.Write(indexBuf.Bytes())
}

func (server *Server) indexVariables(r *http.Request) (map[string]interface{}, error) {
	titleVars := server.titleVariables(
		[]string{"server", "master"},
		map[string]map[string]interface{}{
			"server": server.options.TitleVariables,
			"master": map[string]interface{}{
				"remote_addr": r.RemoteAddr,
			},
		},
	)

	titleBuf := new(bytes.Buffer)
	err := server.titleTemplate.Execute(titleBuf, titleVars)
	if err != nil {
		return nil, err
	}

	indexVars := map[string]interface{}{
		"title": titleBuf.String(),
	}
	return indexVars, err
}

func (server *Server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	// @TODO hashing?
	// w.Write([]byte("var gotty_auth_token = '" + server.options.Credential + "';"))
	token := server.jwt.GetTokenFromCookie(server.jwtCookieStore, r)
	w.Write([]byte("var gotty_auth_token = '" + token + "';"))
}

func (server *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte("var gotty_term = 'xterm';"))
}

// titleVariables merges maps in a specified order.
// varUnits are name-keyed maps, whose names will be iterated using order.
func (server *Server) titleVariables(order []string, varUnits map[string]map[string]interface{}) map[string]interface{} {
	titleVars := map[string]interface{}{}

	for _, name := range order {
		vars, ok := varUnits[name]
		if !ok {
			panic("title variable name error")
		}
		for key, val := range vars {
			titleVars[key] = val
		}
	}

	// safe net for conflicted keys
	for _, name := range order {
		titleVars[name] = varUnits[name]
	}

	return titleVars
}
