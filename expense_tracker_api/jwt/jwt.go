package jwt

import (
	"errors"
	"log"
	myenv "main/env"
	"time"

	"github.com/golang-jwt/jwt"
)

var (
	ErrTokenExpired       = errors.New("token is expired")
	ErrExpNotFound        = errors.New("exp claim not found in token")
	ErrInvalidToken       = errors.New("invalid token")
	ErrValidSigningMethod = errors.New("no valid signing method")
)

type NewJwtClaims struct {
	claims jwt.MapClaims
}

func (n *NewJwtClaims) setVar(id int, username string, role string, timed time.Duration, exTime int) *jwt.Token {
	n.claims = jwt.MapClaims{
		"sub":      id,
		"username": username,
		"iss":      "server",
		"role":     role,
		"aud":      "money manager",
		"exp":      time.Now().Add(timed * time.Duration(exTime)).Unix(),
		"iat":      time.Now().Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, n.claims)
}

type JwtTokens struct {
	AccessToken   string
	AccessClaims  jwt.MapClaims
	RefreshToken  string
	RefreshClaims jwt.MapClaims
	env           myenv.FromENV
}

func (j *JwtTokens) getEnv() error {
	err := j.env.SetEnv()
	if err != nil {
		return err
	}
	return nil
}

func (j *JwtTokens) CreateTokens(id int, username string, role string) error {
	err := j.CreateJwtToken(id, username, role)
	if err != nil {
		log.Println("Error creating JWT token:", err)
		return err
	}
	err = j.CreateRefreshToken(id, username, role)
	if err != nil {
		log.Println("Error creating refresh token:", err)
		return err
	}
	return nil

}

func (j *JwtTokens) CreateJwtToken(id int, username string, role string) error {
	err := j.getEnv()
	if err != nil {
		return err
	}
	var claims NewJwtClaims
	cl := claims.setVar(id, username, role, time.Minute, j.env.ExpiredTimeForJWT)
	tokenString, err := cl.SignedString([]byte(j.env.SecretKeyForJWT))
	if err != nil {
		return err
	}
	j.AccessToken = tokenString
	return nil
}

func (j *JwtTokens) CreateRefreshToken(id int, username string, role string) error {
	err := j.getEnv()
	if err != nil {
		return err
	}
	var claims NewJwtClaims
	cl := claims.setVar(id, username, role, time.Hour, j.env.ExpiredTimeForRefresh)
	tokenString, err := cl.SignedString([]byte(j.env.SecretKeyForRefresh))
	if err != nil {
		return err
	}
	j.RefreshToken = tokenString
	return nil
}

func (j *JwtTokens) ValidateJwt() error {
	err := j.getEnv()
	if err != nil {
		return err
	}
	token, err := jwt.Parse(j.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrValidSigningMethod
		}
		return []byte(j.env.SecretKeyForJWT), nil
	})
	if err != nil {
		if err.Error() == "Token is expired" {
			return ErrTokenExpired
		}
		return err
	}
	j.AccessClaims, err = setClaims(token)
	if err != nil {
		return err
	}
	return nil
}

func (j *JwtTokens) ValidateRefresh() error {
	err := j.getEnv()
	if err != nil {
		return err
	}
	token, err := jwt.Parse(j.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrValidSigningMethod
		}
		return []byte(j.env.SecretKeyForRefresh), nil
	})
	if err != nil {
		if err.Error() == "Token is expired" {
			return ErrTokenExpired
		}
		return err
	}
	j.RefreshClaims, err = setClaims(token)
	if err != nil {
		return err
	}
	return nil
}
func setClaims(token *jwt.Token) (jwt.MapClaims, error) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, ErrTokenExpired
			}
		} else {
			return nil, ErrExpNotFound
		}
		cl, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, ErrInvalidToken
		}
		return cl, nil
	}
	return nil, ErrInvalidToken
}
