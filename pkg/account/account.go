package account

import (
	"github.com/dgrijalva/jwt-go"
	"golang-mongodb-users/pkg/util"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"os"
	"time"
)

//User defines the authenticated accounts
type User struct {
	Username             string            `bson:"username"`
	FirstName            string            `bson:"first_name"`
	LastName             string            `bson:"last_name"`
	Password             string            `bson:"-"`
	PasswordConfirmation string            `bson:"-"`
	PasswordSalt         string            `bson:"password_salt"`
	PasswordHash         string            `bson:"password_hash"`
	Errors               map[string]string `bson:"-"`
}

//TemplateVars used for template variables
type TemplateVars struct {
	App     util.Application
	Message string
	Errors  map[string]string
	Account User
}

const (
	//COLLECTION is the MongoDB Collection name
	COLLECTION = "users"
)

var tokenEncodeString string = os.Getenv("TOKEN_SECRET_PHRASE")

//Initialize Account Routes
func init() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/edit", edit)
	http.HandleFunc("/create", create)
	http.HandleFunc("/auth", auth)
	http.HandleFunc("/update", update)
}

//GET /register
func register(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := TemplateVars{App: util.App, Message: "", Errors: nil}
		util.Render(w, "templates/register.html", data)
	}
}

//GET /login
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := TemplateVars{App: util.App, Message: "", Errors: nil}
		util.Render(w, "templates/login.html", data)
	}
}

//GET /logout
func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		util.ClearSession(w)
		data := TemplateVars{App: util.App, Message: "Logged Out.", Errors: nil}
		util.Render(w, "templates/login.html", data)
	}
}

//GET /edit
func edit(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		u := AuthenticatedUser(r)
		if u.Username != "" {
			data := TemplateVars{App: util.App, Message: "", Errors: nil, Account: u}
			util.Render(w, "templates/edit.html", data)
		} else {
			data := TemplateVars{App: util.App, Message: "Please Login.", Errors: nil}
			util.Render(w, "templates/login.html", data)
		}
	}
}

//POST -> /register
func create(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		salt := util.GenerateSalt()
		username := r.PostFormValue("username")
		firstName := r.PostFormValue("first_name")
		lastName := r.PostFormValue("last_name")
		password := r.PostFormValue("password")
		passwordConfirmation := r.PostFormValue("password_confirmation")
		u := &User{
			Username:             username,
			FirstName:            firstName,
			LastName:             lastName,
			Password:             password,
			PasswordConfirmation: passwordConfirmation,
			PasswordSalt:         salt,
			PasswordHash:         util.Encrypt(salt, password),
		}

		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)

		cnt, err := c.Find(bson.M{"username": username}).Count()
		util.CheckError(err)
		if cnt == 0 {
			if u.Validate() {
				err = c.Insert(u)
				util.CheckError(err)
				data := TemplateVars{App: util.App, Message: "User Successfully Created. Login.", Errors: nil}
				util.Render(w, "templates/login.html", data)
			} else {
				data := TemplateVars{App: util.App, Message: "", Errors: u.Errors}
				util.Render(w, "templates/register.html", data)
			}
		} else {
			e := make(map[string]string)
			e["Username"] = "Username already taken."
			data := TemplateVars{App: util.App, Message: "", Errors: e}
			util.Render(w, "templates/register.html", data)
		}
	}
}

//POST -> /login
func auth(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var u User
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")

		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)

		err := c.Find(bson.M{"username": username}).One(&u)
		if correctPassword(u, password) {
			util.CheckError(err)
			token := createToken(u)
			util.SetSession(token, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			data := TemplateVars{App: util.App, Message: "Error Logging In.", Errors: nil}
			util.Render(w, "templates/login.html", data)
		}
	}
}

//POST -> /edit
func update(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		result := AuthenticatedUser(r)
		salt := util.GenerateSalt()
		username := r.PostFormValue("username")
		firstName := r.PostFormValue("first_name")
		lastName := r.PostFormValue("last_name")
		password := r.PostFormValue("password")
		passwordConfirmation := r.PostFormValue("password_confirmation")
		u := User{
			Username:             username,
			FirstName:            firstName,
			LastName:             lastName,
			Password:             password,
			PasswordConfirmation: passwordConfirmation,
			PasswordSalt:         salt,
			PasswordHash:         util.Encrypt(salt, password),
		}

		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)

		if result.Username != "" {
			if u.Validate() {
				change := bson.M{"$set": bson.M{"first_name": u.FirstName,
					"last_name": u.LastName, "password_salt": u.PasswordSalt,
					"password_hash": u.PasswordHash}}
				err := c.Update(result, change)
				util.CheckError(err)
				http.Redirect(w, r, "/", http.StatusSeeOther)
			} else {
				data := TemplateVars{App: util.App, Message: "", Errors: u.Errors, Account: result}
				util.Render(w, "templates/edit.html", data)
			}
		} else {
			e := make(map[string]string)
			e["Username"] = "Something went wrong."
			data := TemplateVars{App: util.App, Message: "", Errors: e}
			util.Render(w, "templates/login.html", data)
		}
	}
}

//Validate User struct
func (u *User) Validate() bool {
	u.Errors = make(map[string]string)
	if u.Username == "" {
		u.Errors["Username"] = "Username cannot be blank"
	}
	if len(u.Password) < 8 {
		u.Errors["Password"] = "Password must be at least 8 characters"
	}
	if u.Password != u.PasswordConfirmation {
		u.Errors["Password_Confirmation"] = "Passwords must match"
	}
	return len(u.Errors) == 0
}

//FullName concatenates User's name
func (u User) FullName() string {
	if u.LastName != "" || u.FirstName != "" {
		return u.FirstName + " " + u.LastName
	}
	return u.Username
}

//AuthenticatedUser fetches User record from DB using Cookie
func AuthenticatedUser(r *http.Request) User {
	var result User
	token := util.GetTokenFromSession(r)
	if token != "" {
		username := parseToken(token)
		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)
		err := c.Find(bson.M{"username": username}).One(&result)
		util.CheckError(err)
	}
	return result
}

//correctPassword checks input password with stored hash
func correctPassword(u User, p string) bool {
	return u.PasswordHash == util.Encrypt(u.PasswordSalt, p)
}

//createToken creates token for session
func createToken(user User) string {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := make(jwt.MapClaims)
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	token.Claims = claims
	tokenString, err := token.SignedString([]byte(tokenEncodeString))
	util.CheckError(err)
	return tokenString
}

//parseToken parses token and returns username
func parseToken(unparsedToken string) string {
	token, err := jwt.Parse(unparsedToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenEncodeString), nil
	})

	if err == nil && token.Valid {
		return token.Claims.(jwt.MapClaims)["username"].(string)
	}
	return ""
}
