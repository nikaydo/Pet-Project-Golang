package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/golang-jwt/jwt/v5"
)

type Transaction struct {
	ID    int     `json:"id,omitempty"`
	Date  string  `json:"date,omitempty"`
	Money float32 `json:"money"`
	Note  string  `json:"note,omitempty"`
	Tag   string  `json:"tag"`
}

type Balance struct {
	Balance  float32       `json:"balance"`
	Currency string        `json:"currency"`
	Income   []Transaction `json:"income"`
	Outcome  []Transaction `json:"outcome"`
}

func (b *Balance) calcBalance() {
	var AllIncome, AllOutcome float32
	for i := range b.Income {
		AllIncome += b.Income[i].Money
	}
	for i := range b.Outcome {
		AllOutcome += b.Outcome[i].Money
	}
	b.Balance = AllIncome - AllOutcome
}

var secretKey = []byte("secres")

var Bal = Balance{
	Balance:  0,
	Currency: "RUB",
	Income:   []Transaction{},
	Outcome:  []Transaction{},
}

type SearchTag struct {
	Income  []Transaction `json:"income"`
	Outcome []Transaction `json:"outcome"`
}

func CreateJWT(username string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,
		"iss": "Money",
		"aud": getRole(username),
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	tokenString, err := claims.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil

}

func JWTCheck(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie("token")
			if err != nil {
				http.Error(w, "Unauthorized: token not found", http.StatusUnauthorized)
				return
			}

			tokenStr := c.Value
			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return secretKey, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "Unauthorized: invalid claims", http.StatusUnauthorized)
				return
			}

			userRole, ok := claims["aud"].(string)
			if !ok {
				http.Error(w, "Unauthorized: role missing", http.StatusUnauthorized)
				return
			}
			if requiredRole == "writer" && userRole != "writer" {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GetJWT(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	var tkn string = "None"
	if username == "writer" || username == "reader" {
		tokenString, err := CreateJWT(username)
		tkn = tokenString
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  "token",
			Value: tokenString,
			Path:  "/",
		})
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(tkn))
}

func getRole(username string) string {
	if username == "writer" {
		return "writer"
	}
	return "reader"
}

func AddTransaction(w http.ResponseWriter, r *http.Request) {

	var transaction Transaction
	if err := json.NewDecoder(r.Body).Decode(&transaction); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	transaction.Date = time.Now().Format("02.01.2006 15:04:05")
	if transaction.Money < 0 {
		http.Error(w, "negative amount", http.StatusBadRequest)
		return
	}

	var transactions *[]Transaction
	switch r.URL.Path {
	case "/outcome":
		transactions = &Bal.Outcome
	case "/income":
		transactions = &Bal.Income
	}

	transaction.ID = len(*transactions) + 1
	*transactions = append(*transactions, transaction)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func GetTransactionByTag(w http.ResponseWriter, r *http.Request) {
	var t SearchTag
	tag := chi.URLParam(r, "tag")
	for _, transaction := range append(Bal.Income, Bal.Outcome...) {
		if transaction.Tag == tag {
			if transaction.Money > 0 {
				t.Income = append(t.Income, transaction)
			} else {
				t.Outcome = append(t.Outcome, transaction)
			}
		}
	}
	response, err := json.Marshal(t)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(t.Income) == 0 && len(t.Outcome) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(response)

}

func GetBalance(w http.ResponseWriter, r *http.Request) {
	Bal.calcBalance()
	response, err := json.Marshal(Bal)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func main() {
	r := chi.NewRouter()
	r.Get("/balance", GetBalance)
	r.With(JWTCheck("writer")).Post("/income", AddTransaction)
	r.With(JWTCheck("writer")).Post("/outcome", AddTransaction)
	r.With(JWTCheck("reader")).Get("/transaction/{tag}", GetTransactionByTag)
	r.Get("/jwt/{username}", GetJWT)
	if err := http.ListenAndServe(":8080", r); err != nil {
		fmt.Printf("Ошибка при запуске сервера: %s", err.Error())
		return
	}
}
