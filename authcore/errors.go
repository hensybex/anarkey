package authcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Standard error types as defined in RFC 7807
var (
	ErrUnauthorized = NewProblemDetail(
		http.StatusUnauthorized,
		"unauthorized",
		"Authentication is required to access this resource",
		"https://tools.ietf.org/html/rfc7235#section-3.1",
	)

	ErrForbidden = NewProblemDetail(
		http.StatusForbidden,
		"forbidden",
		"Access to this resource is forbidden",
		"https://tools.ietf.org/html/rfc7231#section-6.5.3",
	)

	ErrTokenInvalidProblem = NewProblemDetail(
		http.StatusUnauthorized,
		"invalid_token",
		"The provided token is invalid",
		"https://tools.ietf.org/html/rfc6750#section-3.1",
	)

	ErrTokenExpiredProblem = NewProblemDetail(
		http.StatusUnauthorized,
		"token_expired",
		"The provided token has expired",
		"https://tools.ietf.org/html/rfc6750#section-3.1",
	)

	ErrMissingToken = NewProblemDetail(
		http.StatusUnauthorized,
		"missing_token",
		"No authentication token was provided",
		"https://tools.ietf.org/html/rfc6750#section-3.1",
	)

	ErrInsufficientScope = NewProblemDetail(
		http.StatusForbidden,
		"insufficient_scope",
		"The token does not have the required scope",
		"https://tools.ietf.org/html/rfc6750#section-3.1",
	)
)

// ProblemDetail represents a problem detail as defined in RFC 7807
type ProblemDetail struct {
	// Type is a URI reference that identifies the problem type
	Type string `json:"type"`
	// Title is a short, human-readable summary of the problem type
	Title string `json:"title"`
	// Status is the HTTP status code
	Status int `json:"status"`
	// Detail is a human-readable explanation specific to this occurrence of the problem
	Detail string `json:"detail,omitempty"`
	// Instance is a URI reference that identifies the specific occurrence of the problem
	Instance string `json:"instance,omitempty"`
	// Additional is a map of additional properties
	Additional map[string]interface{} `json:"-"`
}

// NewProblemDetail creates a new ProblemDetail
func NewProblemDetail(status int, title, detail, typeURI string) *ProblemDetail {
	if typeURI == "" {
		typeURI = fmt.Sprintf("https://anarkey.auth/problems/%s", title)
	}

	return &ProblemDetail{
		Type:   typeURI,
		Title:  title,
		Status: status,
		Detail: detail,
	}
}

// WithInstance adds an instance URI to the problem detail
func (p *ProblemDetail) WithInstance(instance string) *ProblemDetail {
	p.Instance = instance
	return p
}

// WithAdditional adds additional properties to the problem detail
func (p *ProblemDetail) WithAdditional(key string, value interface{}) *ProblemDetail {
	if p.Additional == nil {
		p.Additional = make(map[string]interface{})
	}
	p.Additional[key] = value
	return p
}

// Error implements the error interface
func (p *ProblemDetail) Error() string {
	return fmt.Sprintf("%s: %s", p.Title, p.Detail)
}

// MarshalJSON implements the json.Marshaler interface
func (p *ProblemDetail) MarshalJSON() ([]byte, error) {
	type Alias ProblemDetail

	data, err := json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(p),
	})

	if err != nil {
		return nil, err
	}

	// If there are no additional fields, return as is
	if p.Additional == nil || len(p.Additional) == 0 {
		return data, nil
	}

	// Otherwise, merge with additional fields
	var mapData map[string]interface{}
	if err := json.Unmarshal(data, &mapData); err != nil {
		return nil, err
	}

	for key, value := range p.Additional {
		mapData[key] = value
	}

	return json.Marshal(mapData)
}

// AsProblemDetail converts an error to a ProblemDetail
func AsProblemDetail(err error) *ProblemDetail {
	// First check if the error is already a ProblemDetail
	var pd *ProblemDetail
	if errors.As(err, &pd) {
		return pd
	}

	// Check for specific errors
	switch {
	case errors.Is(err, ErrTokenInvalid):
		return ErrTokenInvalidProblem
	case errors.Is(err, ErrTokenExpired):
		return ErrTokenExpiredProblem
	default:
		// Generic internal server error
		return NewProblemDetail(
			http.StatusInternalServerError,
			"internal_error",
			"An internal server error occurred",
			"https://tools.ietf.org/html/rfc7231#section-6.6.1",
		)
	}
}

// WriteJSON writes the problem detail as JSON to an http.ResponseWriter
func (p *ProblemDetail) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)

	json.NewEncoder(w).Encode(p)
}
