package authcore

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// AuthCore is the main authentication and authorization service
type AuthCore struct {
	// Config holds the configuration
	Config Config
	// TokenService handles token operations
	TokenService *TokenService
	// RefreshService handles refresh token operations
	RefreshService *RefreshTokenService
	// KeyProvider provides keys for signing and verification
	KeyProvider KeyProvider
	// Hooks are called during authentication events
	Hooks HookManager
	// Store is the refresh token store
	Store RefreshTokenStore
}

// New creates a new AuthCore with config from environment variables
func New() (*AuthCore, error) {
	config := NewConfigFromEnv()
	return NewWithConfig(config)
}

// NewWithConfig creates a new AuthCore with the given config
func NewWithConfig(config Config) (*AuthCore, error) {
	// Set defaults
	config.SetDefaults()

	// Validate config
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create key provider
	keyProvider, err := NewFileOrEnvKeyProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

	// Create token service
	tokenService, err := NewTokenService(config, keyProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create token service: %w", err)
	}

	// Create hooks
	hooks := NewDefaultHookManager(config)

	// Create store
	var store RefreshTokenStore
	if config.EnableRefreshTokens {
		store = NewInMemoryRefreshTokenStore()
	}

	// Create refresh service
	var refreshService *RefreshTokenService
	if config.EnableRefreshTokens && store != nil {
		// Changed: Pass tokenService to the refresh service
		refreshService = NewRefreshTokenService(config, store, hooks, tokenService)
	}

	// Create auth core
	auth := &AuthCore{
		Config:         config,
		TokenService:   tokenService,
		RefreshService: refreshService,
		KeyProvider:    keyProvider,
		Hooks:          hooks,
		Store:          store,
	}

	return auth, nil
}

// NewFromFile creates a new AuthCore with config from a file
func NewFromFile(path string) (*AuthCore, error) {
	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return NewFromViper(v)
}

// NewFromViper creates a new AuthCore with config from Viper
func NewFromViper(v *viper.Viper) (*AuthCore, error) {
	config := NewConfigFromViper(v)
	return NewWithConfig(config)
}

// AddHook adds a hook to the auth core
func (a *AuthCore) AddHook(hook HookManager) {
	if a.Hooks == nil {
		a.Hooks = hook
		return
	}

	// If it's already a composite, add to it
	if composite, ok := a.Hooks.(*CompositeHookManager); ok {
		composite.AddHook(hook)
		return
	}

	// Otherwise, create a composite
	a.Hooks = NewCompositeHookManager(a.Hooks, hook)
}

// GenerateTokens creates an access token and optional refresh token
func (a *AuthCore) GenerateTokens(claims map[string]interface{}) (string, string, error) {
	// Generate access token
	accessToken, err := a.TokenService.GenerateTokenFromMap(claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// If refresh tokens are not enabled, return just the access token
	if !a.Config.EnableRefreshTokens || a.RefreshService == nil {
		return accessToken, "", nil
	}

	// Get user ID from claims
	userID := ""
	if subClaim, ok := claims["sub"]; ok {
		if subStr, ok := subClaim.(string); ok {
			userID = subStr
		}
	}

	if userID == "" {
		if userIDClaim, ok := claims["user_id"]; ok {
			if userIDStr, ok := userIDClaim.(string); ok {
				userID = userIDStr
			}
		}
	}

	// Generate refresh token
	refreshToken, _, err := a.RefreshService.Generate(userID, claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Trigger hook
	if a.Hooks != nil {
		a.Hooks.OnLoginSuccess(userID, claims)
	}

	return accessToken, refreshToken, nil
}

// VerifyToken verifies an access token
func (a *AuthCore) VerifyToken(tokenString string) (*Claims, error) {
	return a.TokenService.Verify(tokenString)
}

// RefreshTokens refreshes an access token and refresh token
func (a *AuthCore) RefreshTokens(refreshToken string) (string, string, error) {
	if !a.Config.EnableRefreshTokens || a.RefreshService == nil {
		return "", "", errors.New("refresh tokens are not enabled")
	}

	return a.RefreshService.Refresh(refreshToken)
}

// RevokeToken revokes a refresh token
func (a *AuthCore) RevokeToken(refreshToken string) error {
	if !a.Config.EnableRefreshTokens || a.RefreshService == nil {
		return errors.New("refresh tokens are not enabled")
	}

	return a.RefreshService.Revoke(refreshToken)
}

// RevokeAllForUser revokes all refresh tokens for a user
func (a *AuthCore) RevokeAllForUser(userID string) error {
	if !a.Config.EnableRefreshTokens || a.RefreshService == nil {
		return errors.New("refresh tokens are not enabled")
	}

	return a.RefreshService.RevokeAllForUser(userID)
}

// CleanupTokens removes expired tokens
func (a *AuthCore) CleanupTokens() error {
	if !a.Config.EnableRefreshTokens || a.Store == nil {
		return nil
	}

	return a.Store.Cleanup()
}

// GenerateTokenWithCustomLifetime creates a token with a custom lifetime
func (a *AuthCore) GenerateTokenWithCustomLifetime(claims map[string]interface{}, lifetime time.Duration) (string, error) {
	claimsCopy := NewClaims(
		a.Config.Issuer,
		a.Config.Audience,
		lifetime,
		claims,
	)

	return a.TokenService.Generate(claimsCopy)
}

// CreateUserContext creates a UserContext from claims
func (a *AuthCore) CreateUserContext(claims *Claims) UserContext {
	return NewUserContext(claims)
}
