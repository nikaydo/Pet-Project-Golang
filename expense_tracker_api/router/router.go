package router

import (
	handler "main/handlers"
	m "main/middleware"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	r.Route("/user", func(r chi.Router) {
		r.Use(m.CheckJWT)
		r.Get("/balance", handler.GetBalance)
		r.Get("/transactions", handler.GetTransactions)
		r.Post("/newtransaction", handler.MakeTransactions)
	})
	r.Post("/auth", handler.AuthUser)
	return r
}
