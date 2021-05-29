package main

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	ID      int    `json:"id" db:"id"`
	Handle  string `json:"handle" db:"handle"`
	Email   string `json:"email" db:"email"`
	PW_hash string `db:"pw_hash"`
}

type Post struct {
	ID       int64  `json:"id" db:"id"`
	Content  string `json:"content" db:"content"`
	Author   int    `json:"author" db:"author"`
	PostTime int64  `json:"when" db:"post_time"`
}

type Follow struct {
	Follower int `json:"follower" db:"follower"`
	Followee int `json:"followee" db:"followee"`
}

func (app *App) CreateNewAccount(handle string, email string, password string) (*Account, error) {
	insert_stmt := `INSERT INTO accounts(handle, email, pw_hash) VALUES($1, $2, $3) RETURNING id;`
	check_stmt := `SELECT COUNT(*) FROM accounts WHERE handle=$1 OR email=$2;`

	// check that both the handle and email have not been used
	var count int
	err := app.DB.QueryRow(check_stmt, handle, email).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, errors.New("Account Already Exists")
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// insert the account into the database
	var account_id int
	err = app.DB.QueryRow(insert_stmt, handle, email, string(hash)).Scan(&account_id)

	// return a copy of account
	return &Account{ID: account_id, Handle: handle, Email: email, PW_hash: string(hash)}, nil
}

func (app *App) GetAccountById(id int) (*Account, error) {
	sql_stmt := `SELECT id, handle, email, pw_hash FROM accounts WHERE id=$1;`

	var a Account
	err := app.DB.QueryRowx(sql_stmt, id).StructScan(&a)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (app *App) GetAccountByHandle(handle string) (*Account, error) {
	sql_stmt := `SELECT id, handle, email, pw_hash FROM accounts WHERE handle=$1;`

	var a Account
	err := app.DB.QueryRowx(sql_stmt, handle).StructScan(&a)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (app *App) GetAccountByEmail(email string) (*Account, error) {
	sql_stmt := `SELECT id, handle, email, pw_hash FROM accounts WHERE email=$1;`

	var a Account
	rows, err := app.DB.Queryx(sql_stmt, email)
	if err != nil {
		return nil, err
	}
	rows.StructScan(&a)

	return &a, nil
}

func (app *App) CreateNewPost(content string, author int) (*Post, error) {
	statement := `INSERT INTO posts(content, author, post_time) VALUES ($1, $2, $3) RETURNING id;`

	now := time.Now().UTC().Unix()

	var post_id int64
	err := app.DB.QueryRow(statement, content, author, now).Scan(&post_id)
	if err != nil {
		return nil, err
	}

	new_post := Post{
		ID:       post_id,
		Content:  content,
		Author:   author,
		PostTime: now,
	}

	return &new_post, nil
}

func (app *App) GetPostByPostID(id int64) (*Post, error) {
	statement := `SELECT id, content, author, post_time FROM posts WHERE id=$1;`

	var post Post

	err := app.DB.QueryRowx(statement, id).StructScan(&post)
	if err != nil {
		return nil, err
	}

	return &post, nil
}

func (app *App) GetPostsByAccountID(id int) ([]Post, error) {
	statement := `SELECT id, content, author, post_time FROM posts WHERE author=$1 ORDER BY post_time DESC;`

	posts := []Post{}

	err := app.DB.Select(&posts, statement, id)
	if err != nil {
		return nil, err
	}

	return posts, nil
}
