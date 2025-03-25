package authcore

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Common errors for token operations
var (
	ErrTokenInvalid     = errors.New("token is invalid")
	ErrTokenExpired     = errors.New("token has expired")
	ErrTokenNotYetValid = errors.New("token is not yet valid")
	ErrUnsupportedAlg   = errors.New("unsupported signing algorithm")
)

// TokenGenerator is the interface for generating tokens
type TokenGenerator interface {
	// Generate creates a new token with the given claims
	Generate(claims Claims) (string, error)
}

// TokenVerifier is the interface for verifying tokens
type TokenVerifier interface {
	// Verify checks if a token is valid and returns the claims
	Verify(tokenString string) (*Claims, error)
}

// TokenService implements both TokenGenerator and TokenVerifier
type TokenService struct {
	config      Config
	keyProvider KeyProvider
}

// NewTokenService creates a new TokenService
func NewTokenService(config Config, keyProvider KeyProvider) (*TokenService, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &TokenService{
		config:      config,
		keyProvider: keyProvider,
	}, nil
}

// Generate creates a new token with the given claims
func (s *TokenService) Generate(claims Claims) (string, error) {
	// Validate claims
	if err := claims.Validate(); err != nil {
		return "", fmt.Errorf("invalid claims: %w", err)
	}

	var token *jwt.Token

	// Create token with appropriate signing method
	switch s.config.SigningAlgorithm {
	case "HS256":
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	case "HS384":
		token = jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	case "HS512":
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	case "RS256":
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	case "RS384":
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	case "RS512":
		token = jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	case "ES256":
		token = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	case "ES384":
		token = jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	case "ES512":
		token = jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	default:
		return "", ErrUnsupportedAlg
	}

	// Get signing key
	key, err := s.keyProvider.GetSigningKey(s.config.SigningAlgorithm)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// Sign the token
	return token.SignedString(key)
}

// Verify checks if a token is valid and returns the claims
func (s *TokenService) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if token.Method.Alg() != s.config.SigningAlgorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get verification key
		return s.keyProvider.GetVerificationKey(s.config.SigningAlgorithm)
	})

	if err != nil {
		// Check for specific error types
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %s", ErrTokenInvalid, err.Error())
	}

	// Check if token is valid
	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	// Validate audience
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == s.config.Audience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, fmt.Errorf("%w: invalid audience", ErrTokenInvalid)
	}

	// Validate issuer
	if claims.Issuer != s.config.Issuer {
		return nil, fmt.Errorf("%w: invalid issuer", ErrTokenInvalid)
	}

	// Validate time-based claims
	now := time.Now()

	// Check expiration
	if claims.ExpiresAt != nil {
		if now.After(claims.ExpiresAt.Time) {
			return nil, ErrTokenExpired
		}
	}

	// Check not before
	if claims.NotBefore != nil {
		if now.Before(claims.NotBefore.Time) {
			return nil, ErrTokenNotYetValid
		}
	}

	return claims, nil
}

// GenerateTokenFromMap creates a token from a map of claims
func (s *TokenService) GenerateTokenFromMap(customClaims map[string]interface{}) (string, error) {
	claims := NewClaims(
		s.config.Issuer,
		s.config.Audience,
		s.config.TokenLifetime,
		customClaims,
	)

	return s.Generate(claims)
}
