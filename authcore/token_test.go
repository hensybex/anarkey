package authcore

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenService(t *testing.T) {
	// Create a test config
	config := Config{
		Issuer:           "test-issuer",
		Audience:         "test-audience",
		TokenSecret:      "test-secret",
		TokenLifetime:    15 * time.Minute,
		SigningAlgorithm: "HS256",
	}

	// Set defaults
	config.SetDefaults()

	// Create a key provider
	keyProvider, err := NewFileOrEnvKeyProvider(config)
	require.NoError(t, err)

	// Create a token service
	tokenService, err := NewTokenService(config, keyProvider)
	require.NoError(t, err)

	t.Run("Generate and Verify JWT", func(t *testing.T) {
		// Create test claims
		customClaims := map[string]interface{}{
			"user_id": "123",
			"roles":   []string{"admin", "user"},
		}

		claims := NewClaims(
			config.Issuer,
			config.Audience,
			config.TokenLifetime,
			customClaims,
		)

		// Generate token
		token, err := tokenService.Generate(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token
		verifiedClaims, err := tokenService.Verify(token)
		require.NoError(t, err)
		assert.Equal(t, config.Issuer, verifiedClaims.Issuer)
		assert.Contains(t, verifiedClaims.Audience, config.Audience)

		// Check custom claims
		userID := verifiedClaims.GetClaim("user_id")
		assert.Equal(t, "123", userID)

		// Check roles
		assert.True(t, verifiedClaims.HasRole("admin"))
		assert.True(t, verifiedClaims.HasRole("user"))
		assert.False(t, verifiedClaims.HasRole("guest"))
	})

	t.Run("Invalid Token", func(t *testing.T) {
		// Verify with invalid token
		_, err := tokenService.Verify("invalid.token.format")
		assert.Error(t, err)
	})

	t.Run("Expired Token", func(t *testing.T) {
		// Create test claims with expired token
		customClaims := map[string]interface{}{
			"user_id": "123",
		}

		// Create expired claims (1 hour ago)
		claims := NewClaims(
			config.Issuer,
			config.Audience,
			-1*time.Hour,
			customClaims,
		)

		// Generate token
		token, err := tokenService.Generate(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token
		_, err = tokenService.Verify(token)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("Invalid Issuer", func(t *testing.T) {
		// Create test claims with invalid issuer
		customClaims := map[string]interface{}{
			"user_id": "123",
		}

		claims := NewClaims(
			"wrong-issuer",
			config.Audience,
			config.TokenLifetime,
			customClaims,
		)

		// Generate token
		token, err := tokenService.Generate(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token
		_, err = tokenService.Verify(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer")
	})

	t.Run("Invalid Audience", func(t *testing.T) {
		// Create test claims with invalid audience
		customClaims := map[string]interface{}{
			"user_id": "123",
		}

		claims := NewClaims(
			config.Issuer,
			"wrong-audience",
			config.TokenLifetime,
			customClaims,
		)

		// Generate token
		token, err := tokenService.Generate(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token
		_, err = tokenService.Verify(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audience")
	})

	t.Run("GenerateTokenFromMap", func(t *testing.T) {
		// Create test claims
		customClaims := map[string]interface{}{
			"user_id": "123",
			"roles":   []string{"admin", "user"},
		}

		// Generate token
		token, err := tokenService.GenerateTokenFromMap(customClaims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token
		verifiedClaims, err := tokenService.Verify(token)
		require.NoError(t, err)
		assert.Equal(t, config.Issuer, verifiedClaims.Issuer)
		assert.Contains(t, verifiedClaims.Audience, config.Audience)

		// Check custom claims
		userID := verifiedClaims.GetClaim("user_id")
		assert.Equal(t, "123", userID)
	})
}
