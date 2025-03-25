package authcore

import (
	"errors"
	"sync"
	"time"
)

var (
	// ErrTokenNotFound is returned when a token is not found in storage
	ErrTokenNotFound = errors.New("token not found")
)

// RefreshTokenStore is the interface for storing refresh tokens
type RefreshTokenStore interface {
	// Save stores a refresh token
	Save(token *RefreshToken) error
	// Get retrieves a refresh token by token string
	Get(tokenString string) (*RefreshToken, error)
	// Delete removes a refresh token
	Delete(tokenString string) error
	// GetAllForUser retrieves all refresh tokens for a user
	GetAllForUser(userID string) ([]*RefreshToken, error)
	// Cleanup removes expired tokens
	Cleanup() error
}

// InMemoryRefreshTokenStore implements RefreshTokenStore using memory
type InMemoryRefreshTokenStore struct {
	tokens           map[string]*RefreshToken
	userTokens       map[string][]string
	denylist         map[string]time.Time
	RevokedRetention time.Duration // Changed: Made configurable
	mutex            sync.RWMutex
}

// NewInMemoryRefreshTokenStore creates a new InMemoryRefreshTokenStore
func NewInMemoryRefreshTokenStore() *InMemoryRefreshTokenStore {
	return &InMemoryRefreshTokenStore{
		tokens:           make(map[string]*RefreshToken),
		userTokens:       make(map[string][]string),
		denylist:         make(map[string]time.Time),
		RevokedRetention: 24 * time.Hour, // Changed: Default to 24 hours
		mutex:            sync.RWMutex{},
	}
}

// Save stores a refresh token
func (s *InMemoryRefreshTokenStore) Save(token *RefreshToken) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Store the token
	s.tokens[token.Token] = token

	// Check if token is revoked
	if token.RevokedAt != nil {
		s.denylist[token.Token] = *token.RevokedAt
	} else {
		// Add to user tokens map
		s.userTokens[token.UserID] = append(s.userTokens[token.UserID], token.Token)
	}

	return nil
}

// Get retrieves a refresh token by token string
func (s *InMemoryRefreshTokenStore) Get(tokenString string) (*RefreshToken, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Check if the token exists
	token, exists := s.tokens[tokenString]
	if !exists {
		return nil, ErrTokenNotFound
	}

	// Return a copy to prevent race conditions
	tokenCopy := *token
	return &tokenCopy, nil
}

// Delete removes a refresh token
func (s *InMemoryRefreshTokenStore) Delete(tokenString string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if the token exists
	token, exists := s.tokens[tokenString]
	if !exists {
		return ErrTokenNotFound
	}

	// Remove from user tokens map
	if userTokens, exists := s.userTokens[token.UserID]; exists {
		for i, t := range userTokens {
			if t == tokenString {
				// Remove the token from the slice
				s.userTokens[token.UserID] = append(userTokens[:i], userTokens[i+1:]...)
				break
			}
		}
	}

	// Remove from tokens map
	delete(s.tokens, tokenString)

	// Remove from denylist if present
	delete(s.denylist, tokenString)

	return nil
}

// GetAllForUser retrieves all refresh tokens for a user
func (s *InMemoryRefreshTokenStore) GetAllForUser(userID string) ([]*RefreshToken, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Get all token strings for the user
	tokenStrings, exists := s.userTokens[userID]
	if !exists {
		return []*RefreshToken{}, nil
	}

	// Get the actual tokens
	tokens := make([]*RefreshToken, 0, len(tokenStrings))
	for _, tokenString := range tokenStrings {
		token, exists := s.tokens[tokenString]
		if exists {
			// Make a copy to prevent race conditions
			tokenCopy := *token
			tokens = append(tokens, &tokenCopy)
		}
	}

	return tokens, nil
}

// Cleanup removes expired tokens
func (s *InMemoryRefreshTokenStore) Cleanup() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()

	// Find expired tokens
	for tokenString, token := range s.tokens {
		if now.After(token.ExpiresAt) || token.RevokedAt != nil {
			// Remove from user tokens map
			if userTokens, exists := s.userTokens[token.UserID]; exists {
				for i, t := range userTokens {
					if t == tokenString {
						// Remove the token from the slice
						s.userTokens[token.UserID] = append(userTokens[:i], userTokens[i+1:]...)
						break
					}
				}
			}

			// Remove from tokens map
			delete(s.tokens, tokenString)

			// If revoked, keep in denylist for a while
			if token.RevokedAt != nil {
				s.denylist[tokenString] = *token.RevokedAt
			} else {
				// Remove from denylist if present
				delete(s.denylist, tokenString)
			}
		}
	}

	// Cleanup old entries from denylist (keep for 24 hours)
	for tokenString, revokedAt := range s.denylist {
		// Changed: Use configurable retention period
		if now.Sub(revokedAt) > s.RevokedRetention {
			delete(s.denylist, tokenString)
		}
	}

	return nil
}

// IsRevoked checks if a token is in the denylist
func (s *InMemoryRefreshTokenStore) IsRevoked(tokenString string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	_, exists := s.denylist[tokenString]
	return exists
}
