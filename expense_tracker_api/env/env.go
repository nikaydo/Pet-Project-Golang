package env

import (
	"errors"
	"os"
	"strconv"
)

var (
	ErrNoSignedKeyForJWT      = errors.New("key for jwt token not set")
	ErrNoSignedKeyForRefresh  = errors.New("key for refresh token not set")
	ErrNoExpiryTimeForJWT     = errors.New("key for expired time jwt token not set")
	ErrNoExpiryTimeForRefresh = errors.New("key for expired time refresh token not set")
	ErrNoSignedKeyForAES      = errors.New("key for aes not set")
	ErrNoKeyForCookie         = errors.New("key for cookie not set")
)

type FromENV struct {
	SecretKeyForJWT       string
	SecretKeyForRefresh   string
	SecretForAES          string
	ExpiredTimeForJWT     int
	ExpiredTimeForRefresh int
	ExpiredTimeCookie     int
}

func (f *FromENV) SetEnv() error {
	SecretKeyForJWT, exists := os.LookupEnv("SECRET_FOR_JWT")
	if !exists {
		return ErrNoSignedKeyForJWT
	}
	SecretKeyForRefresh, exists := os.LookupEnv("SECRET_FOR_REFRESH")
	if !exists {
		return ErrNoSignedKeyForRefresh
	}
	ExpiredTimeForRefresh, exists := os.LookupEnv("EXPIRED_REFRESH")
	if !exists {
		return ErrNoExpiryTimeForRefresh
	}
	SecretForAES, exists := os.LookupEnv("SECRET_FOR_AES")
	if !exists {
		return ErrNoSignedKeyForAES
	}
	numRef, err := strconv.Atoi(ExpiredTimeForRefresh)
	if err != nil {
		return err
	}
	ExpiredTimeForJWT, exists := os.LookupEnv("EXPIRED_JWT")
	if !exists {
		return ErrNoExpiryTimeForJWT
	}
	numJwt, err := strconv.Atoi(ExpiredTimeForJWT)
	if err != nil {
		return err
	}
	ExpiredTimeCookie, exists := os.LookupEnv("EXPIRED_COOKIE")
	if !exists {
		return ErrNoKeyForCookie
	}
	numCookie, err := strconv.Atoi(ExpiredTimeCookie)
	if err != nil {
		return err
	}
	f.ExpiredTimeCookie = numCookie
	f.SecretForAES = SecretForAES
	f.ExpiredTimeForRefresh = numRef
	f.SecretKeyForRefresh = SecretKeyForRefresh
	f.SecretKeyForJWT = SecretKeyForJWT
	f.ExpiredTimeForJWT = numJwt
	return nil
}
