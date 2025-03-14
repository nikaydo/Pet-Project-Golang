package handlers

import (
	"encoding/json"
	"log"
	myenv "main/env"
	myjwt "main/jwt"
	"main/models"
	"main/wallet"
	"net/http"
	"time"
)

func MakeCookie(name, value string, t int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Now().Add(time.Duration(t) * time.Minute),
		MaxAge:   86400,
	}
}

func GetSubFromClaims(c *http.Cookie, v string) (int, error) {
	j := myjwt.JwtTokens{AccessToken: v}
	err := j.ValidateJwt()
	if err != nil {
		return 0, err
	}
	sub, ok := j.AccessClaims["sub"].(float64)
	if !ok {
		log.Println("sub claim not found or is not a number")
		return 0, err
	}
	return int(sub), err
}

func MakeTransactions(w http.ResponseWriter, r *http.Request) {
	var t wallet.Transaction
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		log.Println("Error decoding request body:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, err := wallet.New("wallet.db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c, err := r.Cookie("jwt")
	if err != nil {
		http.Error(w, "Unauthorized: token not found", http.StatusUnauthorized)
		return
	}
	id, err := GetSubFromClaims(c, c.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	t.UserID = id
	err = f.NewTransactions(t)
	if err != nil {
		log.Println("Error creating new transaction:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func GetBalance(w http.ResponseWriter, r *http.Request) {
	f, err := wallet.New("wallet.db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	c, err := r.Cookie("jwt")
	if err != nil {
		http.Error(w, "Unauthorized: token not found", http.StatusUnauthorized)
		return
	}
	id, err := GetSubFromClaims(c, c.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	money, err := f.Balance(id)
	if err != nil {
		log.Println("Error getting balance:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonData, err := json.Marshal(money)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
	_, err = w.Write([]byte(jsonData))
	if err != nil {
		log.Println("Error writing response:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func GetTransactions(w http.ResponseWriter, r *http.Request) {
	f, err := wallet.New("wallet.db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	c, err := r.Cookie("jwt")
	if err != nil {
		http.Error(w, "Unauthorized: token not found", http.StatusUnauthorized)
		return
	}
	id, err := GetSubFromClaims(c, c.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tList, err := f.Transactions(id)
	if err != nil {
		log.Println("Error getting transactions:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonData, err := json.Marshal(tList)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
	_, err = w.Write([]byte(jsonData))
	if err != nil {
		log.Println("Error writing response:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func AuthUser(w http.ResponseWriter, r *http.Request) {
	var auth models.Auth
	var status int
	if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
		log.Println("Error decoding request body:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, err := wallet.New("wallet.db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	j := myjwt.JwtTokens{}
	exist, u, err := f.IsUserExists(auth)
	if err != nil {
		log.Println("Error checking user:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exist {
		err = j.CreateTokens(u.ID, u.Username, "user")
		if err != nil {
			log.Println("Error creating refresh token:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = f.UpdateRefreshToken(u)
		if err != nil {
			log.Println("Error updating user refresh token:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		status = http.StatusOK
	} else {
		err = j.CreateTokens(u.ID, u.Username, "user")
		if err != nil {
			log.Println("Error creating refresh token:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = f.AddUser(u, wallet.Balance{UserID: u.ID})
		if err != nil {
			log.Println("Error adding user:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		status = http.StatusCreated
	}
	e := myenv.FromENV{}
	err = e.SetEnv()
	if err != nil {
		log.Println("Error setting environment variables:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, MakeCookie("jwt", j.AccessToken, 30))
	w.WriteHeader(status)
	_, err = w.Write([]byte("Hello world!"))
	if err != nil {
		log.Println("Error writing response:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
