package util

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/mgo.v2"
	"html/template"
	"log"
	"net/http"
	"os"
)

//Application defines application info. Used in templates
type Application struct {
	Name    string
	Version string
}

var mgoSession *mgo.Session

const (
	//SALTBYTES bytes for salt generation
	SALTBYTES = 32
)

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

//CheckError logs error
func CheckError(err error) {
	if err != nil {
		log.Println("Error:", err)
	}
}

func GetMongoDBSession() *mgo.Session {
	if mgoSession == nil {
		//Test MongoDB authentication
		//mongoDBDialInfo := &mgo.DialInfo{
		//	Addrs:    []string{MongoDBHosts},
		//	Timeout:  60 * time.Second,
		//	Database: os.Get("MONGODB_DB"),
		//	Username: os.Get("MONGODB_USERNAME),
		//	Password: os.Get("MONGODB_PASSWORD),
		//}

		// Create a session which maintains a pool of socket connections
		// mongoSession, err := mgo.DialWithInfo(mongoDBDialInfo)

		mgoSession, err := mgo.Dial(os.Getenv("MONGODB_URI"))
		CheckError(err)
		return mgoSession
	}
	return mgoSession.Copy()
}

//SetSession sets the cookie
func SetSession(userName string, response http.ResponseWriter) {
	value := map[string]string{
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

//ClearSession clears the cookie
func ClearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

//GetUsernameFromSession reads Username from Cookie
func GetUsernameFromSession(request *http.Request) (userName string) {
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	}
	return userName
}

//Encrypt encrypts password with salt to hash
func Encrypt(salt string, password string) string {
	dk, err := scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, 32)
	CheckError(err)
	encrypted := base64.URLEncoding.EncodeToString(dk)
	return encrypted
}

//GenerateSalt generates random string (salt)
func GenerateSalt() string {
	buf := make([]byte, SALTBYTES)
	_, err := rand.Read(buf)
	CheckError(err)
	return fmt.Sprintf("%x", buf)
}

//Render HTML Templates
func Render(w http.ResponseWriter, filename string, data interface{}) {
	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
