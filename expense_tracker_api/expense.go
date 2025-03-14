package main

import (
	"fmt"
	"log"
	rt "main/router"
	"main/wallet"
	"net/http"

	"github.com/joho/godotenv"
)

func main() {

	f, err := wallet.New("wallet.db")
	if err != nil {
		return
	}
	defer f.Close()
	err = f.MakeTable()
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
	fmt.Println("Server started")
	if err := http.ListenAndServe(":8080", rt.Router()); err != nil {
		fmt.Printf("Пу пу пу: %s", err.Error())
		return
	}
}
