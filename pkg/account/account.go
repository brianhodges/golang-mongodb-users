package account

import (
	"github.com/dgrijalva/jwt-go"
	"golang-mongodb-users/pkg/util"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"os"
	"time"
)

const (
	//COLLECTION is the MongoDB Collection name
	COLLECTION = "users"
)

var tokenEncodeString string = "secretpassphrase"
var app = util.Application{Name: "golang-mongodb-users", Version: "1.2.0"}

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
		data := TemplateVars{App: app, Message: "", Errors: nil}
		util.Render(w, "templates/register.html", data)
	}
}

//GET /login
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := TemplateVars{App: app, Message: "", Errors: nil}
		util.Render(w, "templates/login.html", data)
	}
}

//GET /logout
func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		util.ClearSession(w)
		data := TemplateVars{App: app, Message: "Logged Out.", Errors: nil}
		util.Render(w, "templates/login.html", data)
	}
}

//GET /edit
func edit(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		var result = AuthenticatedUser(r)
		if result.Username != "" {
			data := TemplateVars{App: app, Message: "", Errors: nil, Account: result}
			util.Render(w, "templates/edit.html", data)
		} else {
			data := TemplateVars{App: app, Message: "Please Login.", Errors: nil}
			util.Render(w, "templates/login.html", data)
		}
	}
}

//POST -> /register
func create(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var username string = r.PostFormValue("username")
		var firstName string = r.PostFormValue("first_name")
		var lastName string = r.PostFormValue("last_name")
		var password string = r.PostFormValue("password")
		var passwordConfirmation string = r.PostFormValue("password_confirmation")

		//connect to mongodb
		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)

		//find user and create if not exist
		cnt, err := c.Find(bson.M{"username": username}).Count()
		util.CheckError(err)
		if cnt == 0 {
			var salt string = util.GenerateSalt()
			var newuser = &User{
				Username:             username,
				FirstName:            firstName,
				LastName:             lastName,
				Password:             password,
				PasswordConfirmation: passwordConfirmation,
				PasswordSalt:         salt,
				PasswordHash:         util.Encrypt(salt, password),
			}
			if newuser.Validate() == false {
				data := TemplateVars{App: app, Message: "", Errors: newuser.Errors}
				util.Render(w, "templates/register.html", data)
			} else {
				err = c.Insert(newuser)
				util.CheckError(err)
				data := TemplateVars{App: app, Message: "User Successfully Created. Login.", Errors: nil}
				util.Render(w, "templates/login.html", data)
			}
		} else {
			var errors = make(map[string]string)
			errors["Username"] = "Username already taken."
			data := TemplateVars{App: app, Message: "", Errors: errors}
			util.Render(w, "templates/register.html", data)
		}
	}
}

//POST -> /login
func auth(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var result User
		var username string = r.PostFormValue("username")
		var password string = r.PostFormValue("password")

		//connect to mongodb
		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)

		//find user and check password
		err := c.Find(bson.M{"username": username}).One(&result)
		if result.PasswordHash == util.Encrypt(result.PasswordSalt, password) {
			util.CheckError(err)
			token := CreateToken(result)
			util.SetSession(token, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			data := TemplateVars{App: app, Message: "Error Logging In.", Errors: nil}
			util.Render(w, "templates/login.html", data)
		}
	}
}

//POST -> /edit
func update(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var result = AuthenticatedUser(r)
		var username string = r.PostFormValue("username")
		var firstName string = r.PostFormValue("first_name")
		var lastName string = r.PostFormValue("last_name")
		var password string = r.PostFormValue("password")
		var passwordConfirmation string = r.PostFormValue("password_confirmation")

		//connect to mongodb
		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)

		if result.Username != "" {
			var salt string = util.GenerateSalt()
			var updUser User
			updUser.Username = username
			updUser.FirstName = firstName
			updUser.LastName = lastName
			updUser.Password = password
			updUser.PasswordConfirmation = passwordConfirmation
			updUser.PasswordSalt = salt
			updUser.PasswordHash = util.Encrypt(salt, password)

			if updUser.Validate() == false {
				data := TemplateVars{App: app, Message: "", Errors: result.Errors, Account: result}
				util.Render(w, "templates/edit.html", data)
			} else {
				change := bson.M{"$set": bson.M{"username": updUser.Username,
					"first_name": updUser.FirstName, "last_name": updUser.LastName,
					"password_salt": updUser.PasswordSalt, "password_hash": updUser.PasswordHash}}
				err := c.Update(result, change)
				util.CheckError(err)
				token := CreateToken(result)
				util.SetSession(token, w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
		} else {
			var errors = make(map[string]string)
			errors["Username"] = "Something went wrong."
			data := TemplateVars{App: app, Message: "", Errors: errors}
			util.Render(w, "templates/login.html", data)
		}
	}
}

//Validate User struct
func (u *User) Validate() bool {
	u.Errors = make(map[string]string)
	if len(u.Password) < 8 {
		u.Errors["Password"] = "Password must be at least 8 characters"
	}
	if u.Password != u.PasswordConfirmation {
		u.Errors["Password_Confirmation"] = "Passwords must match"
	}
	return len(u.Errors) == 0
}

//AuthenticatedUser fetches User record from DB using Cookie
func AuthenticatedUser(r *http.Request) User {
	var result User
	token := util.GetTokenFromSession(r)
	if token != "" {
		username := parseToken(token)
		//connect to mongodb
		session := util.GetMongoDBSession()
		defer session.Close()
		c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)
		err := c.Find(bson.M{"username": username}).One(&result)
		util.CheckError(err)
	}
	return result
}

//CreateToken creates token for session
func CreateToken(user User) string {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := make(jwt.MapClaims)
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	token.Claims = claims
	tokenString, err := token.SignedString([]byte(tokenEncodeString))
	util.CheckError(err)
	return tokenString
}

func parseToken(unparsedToken string) string {
	token, err := jwt.Parse(unparsedToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenEncodeString), nil
	})

	if err == nil && token.Valid {
		return token.Claims.(jwt.MapClaims)["username"].(string)
	} else {
		return ""
	}
}
