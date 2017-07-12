package account

import (
	"bytes"
	"golang-mongodb-users/pkg/util"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func TestAuthStatus(t *testing.T) {
	//create db test user entry
	var salt string = util.GenerateSalt()
	var testuser = &User{
		Username:             "TestUser",
		FirstName:            "Test",
		LastName:             "User",
		Password:             "secretpassword",
		PasswordConfirmation: "secretpassword",
		PasswordSalt:         salt,
		PasswordHash:         util.Encrypt(salt, "secretpassword"),
	}

	//connect to mongodb
	session := util.GetMongoDBSession()
	defer session.Close()
	c := session.DB(os.Getenv("MONGODB_DB")).C(COLLECTION)
	cnt, err := c.Find(bson.M{"username": testuser.Username}).Count()
	util.CheckError(err)
	if cnt == 0 {
		err := c.Insert(testuser)
		util.CheckError(err)
	}

	data := url.Values{}
	data.Add("username", testuser.Username)
	data.Add("password", testuser.Password)
	b := bytes.NewBuffer([]byte(data.Encode()))
	req, err := http.NewRequest("POST", "/auth", b)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth)
	handler.ServeHTTP(rr, req)
	//redirects to root on authentication
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}
}
