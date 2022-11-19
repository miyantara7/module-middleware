package util

import (
	"fmt"
	"net/http"
)

type Type string

const (
	Authorization Type = "AUTHORIZATION"
	BadRequest    Type = "BAD_REQUEST"
	Internal      Type = "INTERNAL"
)

type Error struct {
	Type    Type   `json:"type"`
	Message string `json:"message"`
}

func NewAuthorization(reason string) *Error {
	return &Error{
		Type:    Authorization,
		Message: reason,
	}
}

func NewBadRequest(reason string) *Error {
	return &Error{
		Type:    BadRequest,
		Message: fmt.Sprintf("Bad request. Reason: %v", reason),
	}
}

func NewInternal() *Error {
	return &Error{
		Type:    Internal,
		Message: fmt.Sprintf("Internal server error."),
	}
}

func (e *Error) Status() int {
	switch e.Type {
	case Authorization:
		return http.StatusUnauthorized
	case BadRequest:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
