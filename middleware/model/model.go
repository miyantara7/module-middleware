package model

import "github.com/golang-jwt/jwt/v4"

type UserClaims struct {
	jwt.RegisteredClaims
	Email   string `json:"email"`
	UserID  string `json:"userId"`
	Name    string `json:"name"`
	Counter int    `json:"counter"`
}

type GinMiddleware struct {
	IDToken string `header:"Authorization"`
}

type MetaData struct {
	UserID   string `json:"userid"`
	UserName string `json:"username"`
}
