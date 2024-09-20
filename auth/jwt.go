package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

var accessSecretKey []byte

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func LoadSecretKeys() {
	accessSecretKey = []byte(os.Getenv("ACCESS_KEY"))
}

func GetNewTokenPair(context *gin.Context) {
	var userId = context.Query("userId")
	if strings.TrimSpace(userId) == "" {
		context.JSON(http.StatusBadRequest, gin.H{})
		log.Printf("No user id provided")
		return
	}
	GenerateNewTokenPair(context, userId)
}

func GenerateNewTokenPair(context *gin.Context, userId string) {
	jwtId := GenerateRandomByteArray(32)

	accessToken := CreateAccessToken(context, userId, jwtId)
	if accessToken == "" {
		context.JSON(http.StatusInternalServerError, gin.H{})
		log.Printf("Access Token creation failed")
		return
	}
	refreshToken := CreateRefreshToken(context, userId, jwtId)
	if refreshToken == "" {
		context.JSON(http.StatusInternalServerError, gin.H{})
		log.Printf("Refresh Token creation failed")
		return
	}

	context.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

type CustomClaims struct {
	UserId string `json:"user_id"`
	Ip     string `json:"ip"`
	jwt.RegisteredClaims
}

func CreateAccessToken(context *gin.Context, userId string, jwtId string) string {
	lifetime := time.Minute * 15 // 15 min

	claims := CustomClaims{
		userId,
		context.ClientIP(),
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(lifetime)),
			ID:        jwtId,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	accessToken, err := token.SignedString(accessSecretKey)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{})
		return ""
	}

	return accessToken
}

func ParseAccessToken(tokenString string) (*jwt.Token, error) {
	jwtToken, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return accessSecretKey, nil
	})
	if err != nil {
		return nil, err
	}
	return jwtToken, nil
}

func GenerateRandomByteArray(length int) string {
	bytes := make([]byte, length)

	randSource := rand.NewSource(time.Now().UnixNano())
	r := rand.New(randSource)
	_, err := r.Read(bytes)

	if err != nil {
		log.Printf("Error reading random bytes: %v", err)
		return ""
	}

	return b64.StdEncoding.EncodeToString(bytes) // Covert to readable characters.
}

func CreateRefreshToken(context *gin.Context, userId string, jwtId string) string {
	lifetime := time.Hour * 24 * 30 // 30 days
	refreshToken := GenerateRandomByteArray(32)

	session, err := NewSession(userId, refreshToken, jwtId, time.Now().Add(lifetime))
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{})
		log.Printf("New session creation failed: " + err.Error())
		return ""
	}

	err = session.Register()
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{})
		log.Printf("Refresh Token database registration failed: " + err.Error())
		return ""
	}

	return b64.StdEncoding.EncodeToString([]byte(refreshToken))
}

func ExtractAccessToken(context *gin.Context) string {
	// Authorization: <type> <credentials>
	bearToken := context.GetHeader("Authorization")
	strArr := strings.Split(bearToken, " ")

	if len(strArr) < 2 || strArr[0] != "Bearer" {
		return ""
	}

	return strArr[1]
}

func ExtractRefreshToken(context *gin.Context) ([]byte, error) {
	var body []byte
	body, err := ioutil.ReadAll(context.Request.Body)
	if err != nil {
		log.Printf(err.Error())
		return nil, err
	}
	refreshRequest := RefreshRequest{}
	err = json.Unmarshal(body, &refreshRequest)

	tokenBytes, err := b64.StdEncoding.DecodeString(refreshRequest.RefreshToken)
	if err != nil {
		log.Printf(err.Error())
		return nil, err
	}

	return tokenBytes, nil
}

func RefreshJwt(context *gin.Context) {
	accessToken, err := ParseAccessToken(ExtractAccessToken(context))
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{})
		return
	}

	claims := accessToken.Claims.(*CustomClaims)

	ip := claims.Ip
	userId := claims.UserId
	if ip != context.ClientIP() {
		context.JSON(http.StatusForbidden, gin.H{})
		SendEmailWarningForUser(userId)
		return
	}

	RefreshTokenData, err := ExtractRefreshToken(context)
	if err != nil || len(RefreshTokenData) == 0 {
		context.JSON(http.StatusBadRequest, gin.H{})
		log.Printf("Refresh Token extraction failed: " + err.Error())
		return
	}

	session, err := FindSession(userId, RefreshTokenData, claims.ID)
	if err != nil {
		context.JSON(http.StatusForbidden, gin.H{})
		log.Printf("Session is not found: " + err.Error())
		return
	}
	_ = session.Unregister()
	GenerateNewTokenPair(context, userId)
}
