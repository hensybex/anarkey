package authcore

import (
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Default configuration values
const (
	DefaultTokenLifetime     = 15 * time.Minute
	DefaultRefreshLifetime   = 24 * time.Hour * 7 // 7 days
	DefaultIssuer            = "anarkey"
	DefaultTokenFormat       = "jwt"
	DefaultSigningAlgorithm  = "HS256"
	DefaultTokenContextKey   = "user"
	DefaultRefreshContextKey = "refresh"
)

var (
	// ErrMissingRequiredConfig is returned when a required configuration value is missing
	ErrMissingRequiredConfig = errors.New("missing required configuration")
)

// TokenFormat represents the type of token to generate
type TokenFormat string

const (
	// FormatJWT indicates JWT token format
	FormatJWT TokenFormat = "jwt"
	// FormatPaseto indicates PASETO token format (not implemented yet)
	FormatPaseto TokenFormat = "paseto"
)

// Config holds all configuration for the auth system
type Config struct {
	// Issuer identifies the issuer of the token (required)
	Issuer string
	// Audience identifies the intended recipient of the token (required for verification)
	Audience string
	// TokenSecret is the secret key for HMAC algorithms (required for HMAC)
	TokenSecret string
	// PrivateKeyPath is the path to the private key file for RS256/ES256 algorithms
	PrivateKeyPath string
	// PublicKeyPath is the path to the public key file for RS256/ES256 algorithms
	PublicKeyPath string
	// TokenLifetime is the duration that a token is valid for
	TokenLifetime time.Duration
	// RefreshLifetime is the duration that a refresh token is valid for
	RefreshLifetime time.Duration
	// TokenFormat is the format of the token (jwt or paseto)
	TokenFormat TokenFormat
	// SigningAlgorithm is the algorithm to use for signing (HS256, RS256, ES256)
	SigningAlgorithm string
	// EnableRefreshTokens enables refresh token functionality
	EnableRefreshTokens bool
	// RefreshTokenLength is the length of the refresh token
	RefreshTokenLength int
	// TokenContextKey is the key used to store the token in the context
	TokenContextKey string
	// RefreshContextKey is the key used to store the refresh token in the context
	RefreshContextKey string
	// Logger is the logger to use
	Logger *slog.Logger
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}

	if c.Audience == "" {
		return errors.New("audience is required")
	}

	if c.SigningAlgorithm == "" {
		c.SigningAlgorithm = DefaultSigningAlgorithm
	}

	// Check algorithm-specific requirements
	switch c.SigningAlgorithm {
	case "HS256", "HS384", "HS512":
		if c.TokenSecret == "" {
			return errors.New("token secret is required for HMAC algorithms")
		}
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		if c.PrivateKeyPath == "" || c.PublicKeyPath == "" {
			return errors.New("private and public key paths are required for RSA/ECDSA algorithms")
		}
	default:
		return errors.New("unsupported signing algorithm")
	}

	return nil
}

// SetDefaults sets default values for optional configuration
func (c *Config) SetDefaults() {
	if c.TokenLifetime == 0 {
		c.TokenLifetime = DefaultTokenLifetime
	}

	if c.RefreshLifetime == 0 {
		c.RefreshLifetime = DefaultRefreshLifetime
	}

	if c.TokenFormat == "" {
		c.TokenFormat = FormatJWT
	}

	if c.SigningAlgorithm == "" {
		c.SigningAlgorithm = DefaultSigningAlgorithm
	}

	if c.TokenContextKey == "" {
		c.TokenContextKey = DefaultTokenContextKey
	}

	if c.RefreshContextKey == "" {
		c.RefreshContextKey = DefaultRefreshContextKey
	}

	if c.RefreshTokenLength == 0 {
		c.RefreshTokenLength = 32
	}

	if c.Logger == nil {
		c.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
}

// NewConfigFromViper creates a new Config from Viper
func NewConfigFromViper(v *viper.Viper) Config {
	config := Config{
		Issuer:              v.GetString("auth.issuer"),
		Audience:            v.GetString("auth.audience"),
		TokenSecret:         v.GetString("auth.token_secret"),
		PrivateKeyPath:      v.GetString("auth.private_key_path"),
		PublicKeyPath:       v.GetString("auth.public_key_path"),
		TokenLifetime:       v.GetDuration("auth.token_lifetime"),
		RefreshLifetime:     v.GetDuration("auth.refresh_lifetime"),
		TokenFormat:         TokenFormat(v.GetString("auth.token_format")),
		SigningAlgorithm:    v.GetString("auth.signing_algorithm"),
		EnableRefreshTokens: v.GetBool("auth.enable_refresh_tokens"),
		RefreshTokenLength:  v.GetInt("auth.refresh_token_length"),
		TokenContextKey:     v.GetString("auth.token_context_key"),
		RefreshContextKey:   v.GetString("auth.refresh_context_key"),
	}

	// Set defaults for values not provided
	config.SetDefaults()

	return config
}

// NewConfigFromEnv creates a new Config from environment variables
func NewConfigFromEnv() Config {
	v := viper.New()

	// Set up environment variable bindings
	v.SetEnvPrefix("AUTH")
	v.AutomaticEnv()

	// Create config directly from environment variables
	config := Config{
		Issuer:              v.GetString("ISSUER"),
		Audience:            v.GetString("AUDIENCE"),
		TokenSecret:         v.GetString("TOKEN_SECRET"),
		PrivateKeyPath:      v.GetString("PRIVATE_KEY_PATH"),
		PublicKeyPath:       v.GetString("PUBLIC_KEY_PATH"),
		TokenLifetime:       v.GetDuration("TOKEN_LIFETIME"),
		RefreshLifetime:     v.GetDuration("REFRESH_LIFETIME"),
		TokenFormat:         TokenFormat(v.GetString("TOKEN_FORMAT")),
		SigningAlgorithm:    v.GetString("SIGNING_ALGORITHM"),
		EnableRefreshTokens: v.GetBool("ENABLE_REFRESH_TOKENS"),
		RefreshTokenLength:  v.GetInt("REFRESH_TOKEN_LENGTH"),
		TokenContextKey:     v.GetString("TOKEN_CONTEXT_KEY"),
		RefreshContextKey:   v.GetString("REFRESH_CONTEXT_KEY"),
	}

	// Set defaults for values not provided
	config.SetDefaults()

	return config
}
