package main

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"strconv"
	"testing"
)

func ParseLoginBody(response *http.Response) (LoginResponse, error) {
	var body []byte
	body, err := ioutil.ReadAll(response.Body)
	data := LoginResponse{}
	err = json.Unmarshal(body, &data)
	return data, err
}

func GetLoginResponse(t *testing.T, userId string) (*http.Response, *LoginResponse) {
	response, err := http.Get("http://localhost:8080/login?userId=" + userId)
	if err != nil {
		t.Errorf(err.Error())
		return nil, nil
	}

	body, err := ParseLoginBody(response)
	if err != nil {
		t.Errorf(err.Error())
		return nil, nil
	}

	return response, &body
}

func Refresh(t *testing.T, loginResponse *LoginResponse) (int, *LoginResponse) {
	requestBody := RefreshRequest{}
	requestBody.RefreshToken = loginResponse.RefreshToken
	requestBodyData, err := json.Marshal(requestBody)
	if err != nil {
		t.Errorf(err.Error())
		return 0, nil
	}
	request, err := http.NewRequest("POST", "http://localhost:8080/refresh", bytes.NewBuffer(requestBodyData))
	if err != nil {
		t.Errorf(err.Error())
		return 0, nil
	}
	request.Header.Add("Authorization", "Bearer "+loginResponse.AccessToken)
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		t.Errorf(err.Error())
		return 0, nil
	}
	defer response.Body.Close()

	newLogin, err := ParseLoginBody(response)
	if err != nil {
		t.Errorf(err.Error())
		return 0, nil
	}

	return response.StatusCode, &newLogin
}

func Test_Login_AccessAndRefreshToken(t *testing.T) {
	response, body := GetLoginResponse(t, "e04004db-9e2c-4d28-9fd1-b8d0f95f7eef")

	assert.NotNil(t, response)
	assert.NotNil(t, body)

	assert.Equal(t, http.StatusOK, response.StatusCode, "Status code should be "+strconv.Itoa(http.StatusOK)+" but it is "+strconv.Itoa(http.StatusOK))
	assert.NotEqual(t, "", body.AccessToken, "access token should not be empty")
	assert.NotEqual(t, "", body.RefreshToken, "refresh token should not be empty")
}

func Test_Refresh_NewAccessAndRefreshToken(t *testing.T) {
	_, login := GetLoginResponse(t, "b474d6be-ddb9-4349-8215-920e4fb9dbd2")
	statusCode, newLogin := Refresh(t, login)

	assert.Equal(t, http.StatusOK, statusCode)
	assert.NotEqual(t, "", newLogin.AccessToken, "access token should not be empty")
	assert.NotEqual(t, "", newLogin.RefreshToken, "refresh token should not be empty")
}

func Test_RefreshTwice_Error(t *testing.T) {
	_, login := GetLoginResponse(t, "eba7ed38-7196-437d-a3a6-a67b5b13f0a1")
	statusCode, _ := Refresh(t, login)

	assert.Equal(t, statusCode, http.StatusOK)

	secondStatusCode, secondLogin := Refresh(t, login)

	assert.Equal(t, http.StatusForbidden, secondStatusCode)
	assert.Equal(t, "", secondLogin.AccessToken)
	assert.Equal(t, "", secondLogin.RefreshToken)
}

func Test_RefreshWithOldRefreshToken_Error(t *testing.T) {
	_, login := GetLoginResponse(t, "eba7ed38-7196-437d-a3a6-a67b5b13f0a1")
	statusCode, newLogin := Refresh(t, login)

	assert.Equal(t, statusCode, http.StatusOK)

	fakeLogin := LoginResponse{
		AccessToken:  newLogin.AccessToken,
		RefreshToken: login.RefreshToken,
	}

	secondStatusCode, secondLogin := Refresh(t, &fakeLogin)

	assert.Equal(t, http.StatusForbidden, secondStatusCode)
	assert.Equal(t, "", secondLogin.AccessToken)
	assert.Equal(t, "", secondLogin.RefreshToken)
}

func Test_RefreshWithOldAccessToken_Error(t *testing.T) {
	_, login := GetLoginResponse(t, "51f5e459-5dea-4f2f-89a3-fcd6991691df")
	statusCode, newLogin := Refresh(t, login)

	assert.Equal(t, statusCode, http.StatusOK)

	fakeLogin := LoginResponse{
		AccessToken:  login.AccessToken,
		RefreshToken: newLogin.RefreshToken,
	}

	secondStatusCode, secondLogin := Refresh(t, &fakeLogin)

	assert.Equal(t, http.StatusForbidden, secondStatusCode)
	assert.Equal(t, "", secondLogin.AccessToken)
	assert.Equal(t, "", secondLogin.RefreshToken)
}
