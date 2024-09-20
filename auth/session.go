package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"time"
)

var dbAuth *sql.DB = nil

func ConnectAuthDataBase() *sql.DB {
	connectionString := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		os.Getenv("DB_AUTH_HOST"),
		os.Getenv("DB_AUTH_PORT"),
		os.Getenv("DB_AUTH_NAME"),
		os.Getenv("DB_AUTH_USERNAME"),
		os.Getenv("DB_AUTH_PASSWORD"))

	var connectionErr error = nil
	dbAuth, connectionErr = sql.Open("postgres", connectionString)
	if connectionErr != nil {
		log.Printf(connectionErr.Error())
		return nil
	}

	return dbAuth
}

func CloseAuthDataBase() {
	if dbAuth != nil {
		return
	}
	_ = dbAuth.Close()
}

type Session struct {
	userId      string
	refreshHash string
	expireAt    time.Time
	accessId    string
	closed      bool
}

func NewSession(userId string, refreshToken string, accessId string, expireAt time.Time) (*Session, error) {
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.MinCost)
	if err != nil {
		return nil, err
	}

	return &Session{userId, string(refreshTokenHash), expireAt, accessId, false}, nil
}

func (session *Session) Register() error {
	fmt.Println("Register: access_id=" + session.accessId)
	query := `INSERT INTO sessions (user_id, refresh_hash, expire_at, access_id) VALUES ($1, $2, $3, $4)`
	_, err := dbAuth.Exec(query, session.userId, session.refreshHash, session.expireAt, session.accessId)
	return err
}

func (session *Session) Unregister() error {
	fmt.Println("Unregister: access_id=" + session.accessId)
	query := `UPDATE sessions SET closed = true WHERE user_id = $1 AND refresh_hash = $2 AND access_id = $3`
	_, err := dbAuth.Exec(query, session.userId, session.refreshHash, session.accessId)
	return err
}

func FindSession(userId string, refreshToken []byte, accessId string) (*Session, error) {
	fmt.Println("FindSession: access_id=" + accessId)
	session := Session{
		userId:   userId,
		accessId: accessId,
		closed:   false,
	}

	query := `SELECT refresh_hash, expire_at FROM sessions WHERE user_id = $1 AND (expire_at > NOW()) AND access_id = $2 AND closed = false`
	result, err := dbAuth.Query(query, userId, accessId)
	if err != nil {
		return nil, err
	}
	defer result.Close()

	for result.Next() {
		err = result.Scan(&session.refreshHash, &session.expireAt)
		if err != nil {
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(session.refreshHash), refreshToken)
		if err == nil {
			return &session, err
		}
		session.refreshHash = ""
		session.expireAt = time.Time{}
	}

	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("session not found: user=%s, accessId=%s", userId, accessId)
}
