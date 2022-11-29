package middleware

import (
	"errors"
	"fmt"
	"time"

	"github.com/vins7/module-middleware/middleware/model"
	"github.com/vins7/module-middleware/middleware/util"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var secretKeys string

type JWTManager struct {
	secretKey     string
	tokenDuration time.Duration
}

func NewJWTManager(secretKey string,
	tokenDuration time.Duration) *JWTManager {
	secretKeys = secretKey
	return &JWTManager{secretKey, tokenDuration}
}

func GetSecretKey() string {
	return secretKeys
}

func (manager *JWTManager) GenerateToken(email, userID, name string) (t string, e error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, model.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(manager.tokenDuration)),
		},
		Email:  email,
		UserID: userID,
		Name:   name,
	}).SignedString([]byte(manager.secretKey))

}

func HashPassword(password string) ([]byte, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func ValidateIDToken(tokenString, seceretKey string) (*model.UserClaims, error) {
	claims := &model.UserClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				err := util.NewInternal()
				return nil, fmt.Errorf("%s", err.Type)
			}
			return []byte(seceretKey), nil
		},
	)

	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(verr.Inner, errors.New("token has expired")) {
			return nil, errors.New("token has expired")
		}
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("ID token is invalid")
	}

	claims, ok := token.Claims.(*model.UserClaims)
	if !ok {
		return nil, fmt.Errorf("ID token valid but couldn't parse claims")
	}

	return claims, nil
}
