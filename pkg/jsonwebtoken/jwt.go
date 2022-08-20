package jsonwebtoken

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
)

type CustomClaims struct {
	ID string `json:"id"`
	jwt.StandardClaims
}

type Config struct {
	Secret     string
	Audience   string
	Expiration string
	CookieName string
}

type User struct {
	ID string `json:"id" form:"id"`
}

type Jwt struct {
	jwtConfig Config
}

const (
	HeaderAuthorization = "X-CSRF-Token"
	AuthScheme          = "Bearer"
)

func New(jwtConfig Config) *Jwt {
	return &Jwt{jwtConfig}
}

func (j *Jwt) GenerateToken(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("Please specify the user ID to generate token")
	}
	expiration := time.Second * time.Duration(3600)
	i, err := strconv.Atoi(j.jwtConfig.Expiration)
	if err == nil {
		expiration = time.Second * time.Duration(i)
	}
	claims := CustomClaims{
		id,
		jwt.StandardClaims{
			Audience:  j.jwtConfig.Audience,
			ExpiresAt: time.Now().Add(expiration).Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   id,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	generatedToken, err := token.SignedString([]byte(j.jwtConfig.Secret))
	if err != nil {
		return "", err
	}
	return generatedToken, nil
}

func (j *Jwt) GetTokenFromCookie(cookieStore *sessions.CookieStore, req *http.Request) string {
	cookieName := j.jwtConfig.CookieName
	sess, err := cookieStore.Get(req, cookieName)
	if err != nil {
		return ""
	}
	value := sess.Values[cookieName]
	if value == nil {
		return ""
	}
	token := value.(string)
	return token
}

func (j *Jwt) GetTokenFromRequest(req *http.Request) string {
	header := req.Header.Get(HeaderAuthorization)
	l := len(AuthScheme)
	if len(header) > l+1 && header[:l] == AuthScheme {
		token := strings.TrimSpace(header[l+1:])
		return token
	}
	return ""
}

func (j *Jwt) DecodeTokenFromRequest(req *http.Request) (string, error) {
	token := j.GetTokenFromRequest(req)
	if token == "" {
		return "", fmt.Errorf("Request nao possui %s: %s token no header.", HeaderAuthorization, AuthScheme)
	}
	id, err := j.ParseAndValidateToken(token)
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("Invalid token. %s", err.Error()))
	}
	return id, nil
}

func (j *Jwt) ParseAndValidateToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.jwtConfig.Secret), nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if ok && token.Valid {
		isCorrectContext := claims.StandardClaims.VerifyAudience(j.jwtConfig.Audience, true)
		if isCorrectContext {
			return claims.ID, nil
		}
	}
	return "", fmt.Errorf("Invalid token")
}
