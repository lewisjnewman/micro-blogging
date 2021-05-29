package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

//HTTP 201
func CreatedHelper(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": 201}`))
	w.WriteHeader(201)
}

//HTTP 400
func BadRequestHelper(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": 400}`))
	w.WriteHeader(400)
}

//HTTP 403
func ForbiddenHelper(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": 403}`))
	w.WriteHeader(403)
}

//HTTP 404
func NotFoundHelper(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": 404}`))
	w.WriteHeader(404)
}

//HTTP 500
func ServerErrorHelper(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": 500}`))
	w.WriteHeader(500)
}

func IsRequestJson(r *http.Request) bool {
	return r.Header.Get("Content-Type") == "application/json"
}

func CreateToken(id int) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{}

	// Account id as a claim
	// Make sure to convert the id to a string https://github.com/dgrijalva/jwt-go/issues/287
	claims["id"] = strconv.Itoa(id)

	// standard time claims
	claims["exp"] = now.Add(time.Minute * 15).Unix()
	claims["iat"] = now.Unix()

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tok.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", err
	}

	return token, nil
}

func (app *App) VerifyToken(token_string string) (int, error) {
	//check if token is legit

	token, err := jwt.Parse(token_string, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	if err != nil {
		return 0, err
	} else if !token.Valid {
		return 0, errors.New("Token is not valid")
	}

	claims := token.Claims.(jwt.MapClaims)

	id, err := strconv.Atoi(claims["id"].(string))

	if err != nil {
		return 0, errors.New("Error with getting id from jwt - it isnt an integer!!!")
	}

	return id, nil
}

func (a *App) HandleRoot(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	response := struct {
		Msg string `json:"msg"`
	}{
		Msg: "Hello, World!",
	}

	json.NewEncoder(w).Encode(&response)
}

// Register
func (app *App) HandleRegister(w http.ResponseWriter, r *http.Request) {

	request := struct {
		Handle   string `json:"handle"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	// Check for the correct content type
	if !IsRequestJson(r) {
		BadRequestHelper(w)
		return
	}
	//else

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		log.Printf("%s\n", err)
		BadRequestHelper(w)
		return
	}
	//else

	if request.Handle == "" || request.Email == "" || len(request.Password) < app.minimum_password || len(request.Password) > app.maximum_password {
		BadRequestHelper(w)
		return
	}

	email_valid := emailRegex.MatchString(request.Email)
	if !email_valid {
		BadRequestHelper(w)
		return
	}

	_, err = app.CreateNewAccount(request.Handle, request.Email, request.Password)
	if err != nil {
		log.Printf("%s\n", err)
		ForbiddenHelper(w)
		return
	}

	CreatedHelper(w)
}

// Authenticate
func (app *App) HandleAuthenticate(w http.ResponseWriter, r *http.Request) {
	request := struct {
		Handle   string `json:"handle"`
		Password string `json:"password"`
	}{}

	// Check for the correct content type
	if !IsRequestJson(r) {
		BadRequestHelper(w)
		return
	}
	//else

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		log.Printf("%s\n", err)
		BadRequestHelper(w)
		return
	}
	//else

	if request.Handle == "" {
		BadRequestHelper(w)
		return
	}

	account, err := app.GetAccountByHandle(request.Handle)
	if err != nil {
		log.Printf("%s\n", err)
		NotFoundHelper(w)
		return
	}
	//else

	// We check the password and return a not found error if incorrect
	// to avoid giving any information away to an attacker
	err = bcrypt.CompareHashAndPassword([]byte(account.PW_hash), []byte(request.Password))
	if err != nil {
		log.Printf("%s\n", err)
		NotFoundHelper(w)
		return
	}

	token, err := CreateToken(account.ID)
	if err != nil {
		log.Printf("%s\n", err)
		ServerErrorHelper(w)
		return
	}

	auth_cookie := http.Cookie{
		Name:     "auth",
		Value:    token,
		Expires:  time.Now().Add(15 * time.Minute),
		HttpOnly: true,
	}

	http.SetCookie(w, &auth_cookie)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": 200}`))
	w.WriteHeader(200)
}

// Get Information About an Account
func (app *App) HandleAccountInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	id_string := vars["id"]
	id, err := strconv.Atoi(id_string)
	if err != nil {
		log.Printf("%s\n", err)
		BadRequestHelper(w)
		return
	}

	account, err := app.GetAccountById(id)

	if err != nil {
		log.Printf("%s\n", err)
		NotFoundHelper(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(account)
	w.WriteHeader(200)
}

func (app *App) HandleMakePost(w http.ResponseWriter, r *http.Request) {

	authcookie, err := r.Cookie("auth")
	if err != nil {
		log.Printf("%s\n", err)
		ForbiddenHelper(w)
		return
	}

	jwt := authcookie.Value

	account_id, err := app.VerifyToken(jwt)
	if err != nil {
		log.Printf("%s\n", err)
		ForbiddenHelper(w)
		return
	}

	request := struct {
		Content string `json:"content"`
	}{}

	json.NewDecoder(r.Body).Decode(&request)

	if request.Content == "" {
		// Forbid Empty Tweets
		ForbiddenHelper(w)
		return
	}

	_, err = app.CreateNewPost(request.Content, account_id)
	if err != nil {
		log.Printf("%s\n", err)
		ForbiddenHelper(w)
		return
	} else {
		CreatedHelper(w)
	}
}

func (app *App) HandleGetPost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	post_id, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		log.Printf("%s\n", err)
		BadRequestHelper(w)
		return
	}

	post, err := app.GetPostByPostID(post_id)
	if err != nil {
		log.Printf("%s\n", err)
		NotFoundHelper(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&post)
	w.WriteHeader(200)
}

func (app *App) HandleGetAccountPosts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	account_id, err := strconv.Atoi(vars["id"])
	if err != nil {
		log.Printf("%s\n", err)
		BadRequestHelper(w)
		return
	}

	posts, err := app.GetPostsByAccountID(account_id)
	if err != nil {
		log.Printf("%s\n", err)
		NotFoundHelper(w)
		return
	}

	response := struct {
		Posts []Post `json:"posts"`
	}{
		Posts: posts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&response)
	w.WriteHeader(200)
}
