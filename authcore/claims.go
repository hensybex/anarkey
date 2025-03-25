package authcore

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Common errors related to claims
var (
	ErrMissingRequiredClaim = errors.New("missing required claim")
	ErrInvalidClaim         = errors.New("invalid claim value")
)

// Claims represents the claims in a JWT
type Claims struct {
	jwt.RegisteredClaims
	CustomClaims map[string]interface{} `json:"custom,omitempty"`
}

// NewClaims creates a standard claims structure with required fields
func NewClaims(issuer, audience string, expiry time.Duration, custom map[string]interface{}) Claims {
	now := time.Now()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   getStringFromMap(custom, "sub", ""),
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        getStringFromMap(custom, "jti", ""),
		},
		CustomClaims: filterRegisteredClaims(custom),
	}

	return claims
}

// MergeClaims merges custom claims with registered claims
func (c *Claims) MergeClaims(customClaims map[string]interface{}) {
	// If custom claims already exists, merge with new claims
	if c.CustomClaims == nil {
		c.CustomClaims = make(map[string]interface{})
	}

	for key, value := range customClaims {
		// Skip registered claims which are handled separately
		if isRegisteredClaim(key) {
			continue
		}
		c.CustomClaims[key] = value
	}
}

// Validate checks if the claims include the required fields
func (c *Claims) Validate() error {
	if c.Issuer == "" {
		return errors.New("issuer claim is required")
	}

	if len(c.Audience) == 0 {
		return errors.New("audience claim is required")
	}

	if c.ExpiresAt == nil {
		return errors.New("expires at claim is required")
	}

	if c.IssuedAt == nil {
		return errors.New("issued at claim is required")
	}

	return nil
}

// GetClaim returns a claim value by name
func (c *Claims) GetClaim(name string) interface{} {
	// First check registered claims
	switch name {
	case "iss":
		return c.Issuer
	case "sub":
		return c.Subject
	case "aud":
		return c.Audience
	case "exp":
		return c.ExpiresAt
	case "nbf":
		return c.NotBefore
	case "iat":
		return c.IssuedAt
	case "jti":
		return c.ID
	}

	// Then check custom claims
	if c.CustomClaims != nil {
		if val, ok := c.CustomClaims[name]; ok {
			return val
		}
	}

	return nil
}

// HasRole checks if the claims include a specific role
func (c *Claims) HasRole(role string) bool {
	if c.CustomClaims == nil {
		return false
	}

	// Check for roles in custom claims
	rolesInterface, ok := c.CustomClaims["roles"]
	if !ok {
		return false
	}

	// Try to convert to various role formats
	switch roles := rolesInterface.(type) {
	case []string:
		for _, r := range roles {
			if r == role {
				return true
			}
		}
	case []interface{}:
		for _, r := range roles {
			if str, ok := r.(string); ok && str == role {
				return true
			}
		}
	case string:
		return roles == role
	}

	return false
}

// Helper function to filter out registered claims from a map
func filterRegisteredClaims(claims map[string]interface{}) map[string]interface{} {
	if claims == nil {
		return nil
	}

	filtered := make(map[string]interface{})
	for key, value := range claims {
		if !isRegisteredClaim(key) {
			filtered[key] = value
		}
	}

	return filtered
}

// Helper function to check if a claim is a registered claim
func isRegisteredClaim(claim string) bool {
	registeredClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"exp": true, "nbf": true, "iat": true,
		"jti": true,
	}

	return registeredClaims[claim]
}

// Helper function to get a string from a map with a default value
func getStringFromMap(m map[string]interface{}, key, defaultValue string) string {
	if m == nil {
		return defaultValue
	}

	if val, ok := m[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	return defaultValue
}
