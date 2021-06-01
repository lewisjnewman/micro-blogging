package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type App struct {
	Router *mux.Router
	DB     *sqlx.DB
	rdb    *redis.Client

	// Configuration Settings
	minimum_password int
	maximum_password int
	listen_addr      string
	cors_origin      string
}

func (app *App) Initialize() {
	database_user := os.Getenv("DATABASE_USER")
	database_pass := os.Getenv("DATABASE_PASS")
	database_name := os.Getenv("DATABASE_NAME")
	database_host := os.Getenv("DATABASE_HOST")

	redis_addr := os.Getenv("REDIS_ADDR")
	redis_pass := os.Getenv("REDIS_PASS")
	redis_database, err := strconv.Atoi(os.Getenv("REDIS_DB"))

	min_password, err := strconv.Atoi(os.Getenv("MINIMUM_PASSWORD_LENGTH"))
	if err != nil {
		log.Panicf("Unable to parse MINIMUM_PASSWORD_LENGTH: %s", err)
	}

	max_password, err := strconv.Atoi(os.Getenv("MAXIMUM_PASSWORD_LENGTH"))
	if err != nil {
		log.Panicf("Unable to parse MAXIMUM_PASSWORD_LENGTH: %s", err)
	}

	app.minimum_password = min_password
	app.maximum_password = max_password

	app.listen_addr = os.Getenv("LISTEN_ADDRESS")

	app.cors_origin = os.Getenv("CORS_ORIGIN")

	log.Printf(`Connecting to database "%s" as user "%s" at host "%s"`, database_name, database_user, database_host)

	// Connect to the database and check for any errors
	for {
		db, err := sqlx.Open("postgres",
			fmt.Sprintf("user=%s password=%s dbname=%s host=%s sslmode=disable",
				database_user, database_pass, database_name, database_host))

		if err == nil {
			app.DB = db
			break
		}
		//else

		// wait for a bit before trying again
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		log.Panic(err)
	}

	// Connect to redis and check for any errors
	rdb := redis.NewClient(&redis.Options{
		Addr:     redis_addr,
		Password: redis_pass,
		DB:       redis_database,
	})

	app.rdb = rdb

	// Create Router Object
	app.Router = &mux.Router{}

	app.Router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		NotFoundHelper(w)
	})

	app.Router.Use(app.CORSMiddleware)

	// Setup Routes
	app.Router.HandleFunc("/", app.HandleRoot).Methods("GET")

	app.Router.HandleFunc("/register", app.HandleRegister).Methods("POST", "OPTIONS")
	app.Router.HandleFunc("/auth/login", app.HandleAuthenticate).Methods("POST", "OPTIONS")
	app.Router.HandleFunc("/auth/refresh", app.HandleRefresh).Methods("POST", "OPTIONS")
	app.Router.HandleFunc("/auth/expire", app.HandleExpire).Methods("POST", "OPTIONS")
	app.Router.HandleFunc("/auth/logged_in", app.HandleLoggedIn).Methods("GET")

	app.Router.HandleFunc("/account/{id:[0-9]+}/info", app.HandleAccountInfo).Methods("GET")
	app.Router.HandleFunc("/account/{id:[0-9]+}/posts", app.HandleGetAccountPosts).Methods("GET")

	app.Router.HandleFunc("/post", app.HandleMakePost).Methods("POST", "OPTIONS")
	app.Router.HandleFunc("/post/{id:[0-9]+}", app.HandleGetPost).Methods("GET")

}

func (app *App) Run() {
	log.Printf("Backend serving on %s\n", app.listen_addr)
	log.Fatal(http.ListenAndServe(app.listen_addr, app.Router))
}

func main() {
	// Enable line numbers in logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("Backend Starting")

	app := App{}

	app.Initialize()

	app.Run()
}
