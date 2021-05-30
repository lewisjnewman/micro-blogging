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
}

func (app *App) Initialize() {
	database_user := os.Getenv("DATABASE_USER")
	database_pass := os.Getenv("DATABASE_PASS")
	database_name := os.Getenv("DATABASE_NAME")
	database_host := os.Getenv("DATABASE_HOST")

	redis_addr := os.Getenv("REDIS_ADDR")
	redis_pass := os.Getenv("REDIS_PASS")
	redis_database, err := strconv.Atoi(os.Getenv("REDIS_DB"))

	log.Printf(`Connecting to database "%s" as user "%s" at host "%s"`, database_name, database_user, database_host)

	// Connect to the database and check for any errors
	db, err := sqlx.Open("postgres",
		fmt.Sprintf("user=%s password=%s dbname=%s host=%s sslmode=disable",
			database_user, database_pass, database_name, database_host))

	if err != nil {
		log.Panic(err)
	}

	app.DB = db

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

	// Setup Routes
	app.Router.HandleFunc("/", app.HandleRoot).Methods("GET")

	app.Router.HandleFunc("/register", app.HandleRegister).Methods("POST")
	app.Router.HandleFunc("/auth/login", app.HandleAuthenticate).Methods("POST")
	app.Router.HandleFunc("/auth/refresh", app.HandleRefresh).Methods("POST")
	app.Router.HandleFunc("/auth/expire", app.HandleExpire).Methods("POST")

	app.Router.HandleFunc("/account/{id:[0-9]+}/info", app.HandleAccountInfo).Methods("GET")
	app.Router.HandleFunc("/account/{id:[0-9]+}/posts", app.HandleGetAccountPosts).Methods("GET")

	app.Router.HandleFunc("/post", app.HandleMakePost).Methods("POST")
	app.Router.HandleFunc("/post/{id:[0-9]+}", app.HandleGetPost).Methods("GET")

}

func (a *App) Run(addr string) {
	log.Printf("Backend serving on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, a.Router))
}

func main() {
	// Enable line numbers in logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("Backend Starting")

	// sleep to make sure that the database is up
	time.Sleep(1 * time.Second)

	app := App{
		minimum_password: 8,
		maximum_password: 256,
	}

	app.Initialize()

	app.Run("0.0.0.0:8080")
}
