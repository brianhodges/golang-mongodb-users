package main

import (
	"fmt"
	"github.com/kabukky/httpscerts"
	"golang-mongodb-users/pkg/account"
	"golang-mongodb-users/pkg/util"
	"log"
	"net/http"
	"os"
)

//IndexVars used for /index template variables
type IndexVars struct {
	App  util.Application
	User account.User
}

//GET /index
func index(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		var result = account.AuthenticatedUser(r)
		if result.Username != "" {
			data := IndexVars{User: result, App: util.App}
			util.Render(w, "templates/index.html", data)
		} else {
			data := account.TemplateVars{App: util.App, Message: "Please Login.", Errors: nil}
			util.Render(w, "templates/login.html", data)
		}
	}
}

//Route for favicon - mainly just a fix for Google Chrome calling /index route twice...?
func handlerICon(w http.ResponseWriter, r *http.Request) {}

//Initialize Server with Routes
func main() {
    err := httpscerts.Check("cert.pem", "key.pem")
    if err != nil {
        err = httpscerts.Generate("cert.pem", "key.pem", "127.0.0.1:8081")
        if err != nil {
            log.Fatal("Error: Couldn't create https certs.")
        }
    }
	fmt.Println("Running local server @ http://localhost:" + os.Getenv("PORT"))
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/favicon.ico", handlerICon)
	http.HandleFunc("/", index)
	log.Fatal(http.ListenAndServeTLS(":"+os.Getenv("PORT"), "cert.pem", "key.pem", nil))
}
