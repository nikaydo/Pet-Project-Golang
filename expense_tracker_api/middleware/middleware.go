package middleware

import (
	"log"
	h "main/handlers"
	myjwt "main/jwt"
	"main/wallet"
	"net/http"
)

func CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("jwt")
		if err != nil {
			log.Println("Error getting cookie:", err)
			http.Error(w, "Unauthorized: token not found", http.StatusUnauthorized)
			return
		}
		j := myjwt.JwtTokens{AccessToken: c.Value}
		f, err := wallet.New("wallet.db")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		err = j.ValidateJwt()
		if err != nil {
			if err == myjwt.ErrTokenExpired {
				name, ok := j.AccessClaims["username"].(string)
				if !ok {
					log.Println("Error getting username:", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				u, err := f.GetUser(name)
				if err != nil {
					log.Println("Error getting refresh token:", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				j.RefreshToken = u.Refresh
				err = j.ValidateRefresh()
				if err != nil {
					log.Println("Error validating refresh token:", err)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				err = j.CreateTokens(u.ID, u.Username, "user")
				if err != nil {
					log.Println("Error creating refresh token:", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				err = f.UpdateRefreshToken(u)
				if err != nil {
					log.Println("Error updating refresh token:", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, h.MakeCookie("jwt", j.AccessToken, 30))
			}
			log.Println("Error validating token:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
