package main

import (
	"fmt"
	"net/smtp"
)

func SendEmailWarningForUser(userId string) {
	host := "mail.example.com"
	port := "587"
	address := host + ":" + port

	auth := smtp.PlainAuth("", GetHostEmail(), GetHostEmailPassword(), host)

	to := GetUserEmail(userId)
	msg := []byte("Unauthorized access attempt.")
	err := smtp.SendMail(address, auth, "sender@.email.com", []string{to}, msg)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func GetUserEmail(userId string) string {
	// ToDo: find email of user
	return "test@email.com"
}

func GetHostEmail() string {
	// ToDo: get correct email
	return "auth@example.com"
}

func GetHostEmailPassword() string {
	// ToDo: get correct email password
	return "password"
}
