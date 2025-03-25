package authcore

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenService(t *testing.T) {
	// Create a test config
	config := Config{
		Issuer:              "test-issuer",
		Audience:            "test-audience",
		TokenSecret:         "test-secret",
		TokenLifetime:       15 * time.Minute,
		RefreshLifetime:     24 * time.Hour,
		EnableRefreshTokens: true,
		RefreshTokenLength:  32,
	}

	// Set defaults
	config.SetDefaults()

	// Create a store
	store := NewInMemoryRefreshTokenStore()

	// Create hooks
	hooks := NewDefaultHookManager(config)

	// Create a key provider for TokenService
	keyProvider, err := NewFileOrEnvKeyProvider(config)
	require.NoError(t, err)

	// Create a token service
	tokenService, err := NewTokenService(config, keyProvider)
	require.NoError(t, err)

	// Create a refresh service with the token service
	refreshService := NewRefreshTokenService(config, store, hooks, tokenService)

	t.Run("Generate and Verify Refresh Token", func(t *testing.T) {
		// Create test claims
		customClaims := map[string]interface{}{
			"user_id": "123",
			"roles":   []string{"admin", "user"},
		}

		// Generate token
		tokenString, token, err := refreshService.Generate("123", customClaims)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)
		assert.NotNil(t, token)
		assert.Equal(t, "123", token.UserID)

		// Verify token
		verifiedToken, err := refreshService.Verify(tokenString)
		require.NoError(t, err)
		assert.Equal(t, token.ID, verifiedToken.ID)
		assert.Equal(t, token.UserID, verifiedToken.UserID)

		// Check claims
		assert.Equal(t, "123", verifiedToken.Claims["user_id"])
	})

	t.Run("Invalid Refresh Token", func(t *testing.T) {
		// Verify with invalid token
		_, err := refreshService.Verify("invalid-token")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrRefreshTokenInvalid)
	})

	t.Run("Revoke Refresh Token", func(t *testing.T) {
		// Generate token
		tokenString, _, err := refreshService.Generate("123", nil)
		require.NoError(t, err)

		// Verify token works
		_, err = refreshService.Verify(tokenString)
		require.NoError(t, err)

		// Revoke token
		err = refreshService.Revoke(tokenString)
		require.NoError(t, err)

		// Verify token is revoked
		_, err = refreshService.Verify(tokenString)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrRefreshTokenRevoked)
	})

	t.Run("Revoke All For User", func(t *testing.T) {
		// Generate multiple tokens for same user
		token1, _, err := refreshService.Generate("456", nil)
		require.NoError(t, err)

		token2, _, err := refreshService.Generate("456", nil)
		require.NoError(t, err)

		// Verify tokens work
		_, err = refreshService.Verify(token1)
		require.NoError(t, err)

		_, err = refreshService.Verify(token2)
		require.NoError(t, err)

		// Revoke all tokens for user
		err = refreshService.RevokeAllForUser("456")
		require.NoError(t, err)

		// Verify tokens are revoked
		_, err = refreshService.Verify(token1)
		assert.Error(t, err)

		_, err = refreshService.Verify(token2)
		assert.Error(t, err)
	})

	t.Run("Store Cleanup", func(t *testing.T) {
		// Create a config with short expiration
		shortConfig := config
		shortConfig.RefreshLifetime = 1 * time.Millisecond

		// Create a refresh service with short expiration
		shortStore := NewInMemoryRefreshTokenStore()

		// Changed: Pass the token service to the constructor
		shortRefreshService := NewRefreshTokenService(shortConfig, shortStore, hooks, tokenService)

		// Generate token
		tokenString, _, err := shortRefreshService.Generate("789", nil)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		// Cleanup store
		err = shortStore.Cleanup()
		require.NoError(t, err)

		// Verify token is expired
		_, err = shortRefreshService.Verify(tokenString)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrRefreshTokenInvalid) // Token should be removed from store
	})
}

func TestInMemoryRefreshTokenStore(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	t.Run("Save and Get", func(t *testing.T) {
		// Create a token
		token := &RefreshToken{
			ID:        "id1",
			UserID:    "user1",
			Token:     "token1",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Claims:    map[string]interface{}{"key": "value"},
			CreatedAt: time.Now(),
		}

		// Save token
		err := store.Save(token)
		require.NoError(t, err)

		// Get token
		retrievedToken, err := store.Get("token1")
		require.NoError(t, err)
		assert.Equal(t, token.ID, retrievedToken.ID)
		assert.Equal(t, token.UserID, retrievedToken.UserID)
	})

	t.Run("Delete", func(t *testing.T) {
		// Create a token
		token := &RefreshToken{
			ID:        "id2",
			UserID:    "user1",
			Token:     "token2",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CreatedAt: time.Now(),
		}

		// Save token
		err := store.Save(token)
		require.NoError(t, err)

		// Delete token
		err = store.Delete("token2")
		require.NoError(t, err)

		// Try to get token
		_, err = store.Get("token2")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("GetAllForUser", func(t *testing.T) {
		// Create tokens for same user
		token1 := &RefreshToken{
			ID:        "id3",
			UserID:    "user2",
			Token:     "token3",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CreatedAt: time.Now(),
		}

		token2 := &RefreshToken{
			ID:        "id4",
			UserID:    "user2",
			Token:     "token4",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CreatedAt: time.Now(),
		}

		// Save tokens
		err := store.Save(token1)
		require.NoError(t, err)

		err = store.Save(token2)
		require.NoError(t, err)

		// Get all tokens for user
		tokens, err := store.GetAllForUser("user2")
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
	})

	t.Run("Revoke", func(t *testing.T) {
		// Create a token
		token := &RefreshToken{
			ID:        "id5",
			UserID:    "user3",
			Token:     "token5",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CreatedAt: time.Now(),
		}

		// Save token
		err := store.Save(token)
		require.NoError(t, err)

		// Revoke token
		now := time.Now()
		token.RevokedAt = &now

		err = store.Save(token)
		require.NoError(t, err)

		// Check if token is revoked
		retrievedToken, err := store.Get("token5")
		require.NoError(t, err)
		assert.NotNil(t, retrievedToken.RevokedAt)
		assert.True(t, retrievedToken.IsRevoked())
	})
}
