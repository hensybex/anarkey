package authcore

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrRefreshTokenInvalid is returned when a refresh token is invalid
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid")
	// ErrRefreshTokenExpired is returned when a refresh token is expired
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	// ErrRefreshTokenRevoked is returned when a refresh token has been revoked
	ErrRefreshTokenRevoked = errors.New("refresh token has been revoked")
)

// RefreshToken represents a refresh token
type RefreshToken struct {
	// ID is the unique identifier of the refresh token
	ID string
	// UserID is the user identifier associated with the token
	UserID string
	// Token is the actual token string
	Token string
	// ExpiresAt is the expiration time of the token
	ExpiresAt time.Time
	// Claims are the custom claims associated with the token
	Claims map[string]interface{}
	// CreatedAt is the creation time of the token
	CreatedAt time.Time
	// RevokedAt is the revocation time of the token (if revoked)
	RevokedAt *time.Time
}

// IsExpired checks if the token is expired
func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsRevoked checks if the token is revoked
func (r *RefreshToken) IsRevoked() bool {
	return r.RevokedAt != nil
}

// RefreshTokenService handles refresh token operations
type RefreshTokenService struct {
	config       Config
	store        RefreshTokenStore
	hooks        HookManager
	tokenService *TokenService
}

// NewRefreshTokenService creates a new RefreshTokenService
func NewRefreshTokenService(config Config, store RefreshTokenStore, hooks HookManager, tokenService *TokenService) *RefreshTokenService {
	return &RefreshTokenService{
		config:       config,
		store:        store,
		hooks:        hooks,
		tokenService: tokenService, // Changed: Store the TokenService reference
	}
}

// Generate creates a new refresh token
func (s *RefreshTokenService) Generate(userID string, claims map[string]interface{}) (string, *RefreshToken, error) {
	// Generate random token
	tokenBytes := make([]byte, s.config.RefreshTokenLength)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate random token: %w", err)
	}

	tokenString := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create token record
	refreshToken := &RefreshToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     tokenString,
		ExpiresAt: time.Now().Add(s.config.RefreshLifetime),
		Claims:    claims,
		CreatedAt: time.Now(),
	}

	// Save token to store
	if err := s.store.Save(refreshToken); err != nil {
		return "", nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return tokenString, refreshToken, nil
}

// Verify checks if a refresh token is valid
func (s *RefreshTokenService) Verify(tokenString string) (*RefreshToken, error) {
	// Get token from store
	token, err := s.store.Get(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRefreshTokenInvalid, err.Error())
	}

	// Check if token is expired
	if token.IsExpired() {
		return nil, ErrRefreshTokenExpired
	}

	// Check if token is revoked
	if token.IsRevoked() {
		return nil, ErrRefreshTokenRevoked
	}

	return token, nil
}

// Revoke invalidates a refresh token
func (s *RefreshTokenService) Revoke(tokenString string) error {
	// Get token from store
	token, err := s.store.Get(tokenString)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrRefreshTokenInvalid, err.Error())
	}

	// Set revoked time
	now := time.Now()
	token.RevokedAt = &now

	// Save updated token
	if err := s.store.Save(token); err != nil {
		return fmt.Errorf("failed to save revoked token: %w", err)
	}

	// Trigger revoked hook
	if s.hooks != nil {
		s.hooks.OnTokenRevoked(token)
	}

	return nil
}

// RevokeAllForUser invalidates all refresh tokens for a user
func (s *RefreshTokenService) RevokeAllForUser(userID string) error {
	// Get all tokens for user
	tokens, err := s.store.GetAllForUser(userID)
	if err != nil {
		return fmt.Errorf("failed to get tokens for user: %w", err)
	}

	// Revoke each token
	now := time.Now()
	for _, token := range tokens {
		token.RevokedAt = &now
		if err := s.store.Save(token); err != nil {
			return fmt.Errorf("failed to save revoked token: %w", err)
		}

		// Trigger revoked hook
		if s.hooks != nil {
			s.hooks.OnTokenRevoked(token)
		}
	}

	return nil
}

// Refresh generates new access and refresh tokens
func (s *RefreshTokenService) Refresh(tokenString string) (string, string, error) {
	// Verify the refresh token
	token, err := s.Verify(tokenString)
	if err != nil {
		return "", "", err
	}

	// Revoke the old token
	if err := s.Revoke(tokenString); err != nil {
		return "", "", fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Get user ID from token or token claims
	userID := token.UserID
	if userID == "" {
		if userIDClaim, ok := token.Claims["user_id"]; ok {
			if userIDStr, ok := userIDClaim.(string); ok {
				userID = userIDStr
			}
		}
	}

	// Generate new tokens
	newRefreshTokenString, newRefreshToken, err := s.Generate(userID, token.Claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	// Trigger refresh hook
	if s.hooks != nil {
		s.hooks.OnTokenRefresh(token, newRefreshToken)
	}

	// Generate new access token
	accessTokenString, err := s.generateAccessToken(token.Claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return accessTokenString, newRefreshTokenString, nil
}

// Helper to generate an access token from refresh token claims
func (s *RefreshTokenService) generateAccessToken(claims map[string]interface{}) (string, error) {
	// Changed: Actually generate a token using the TokenService
	return s.tokenService.GenerateTokenFromMap(claims)
}
