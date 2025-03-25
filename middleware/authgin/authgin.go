// File: middleware/authgin/authgin.go

package authgin

import (
	"errors"
	"log"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hensybex/anarkey/authcore"
)

// Middleware provides Gin middleware for authentication and authorization
type Middleware struct {
	auth        *authcore.AuthCore
	tokenLookup string
}

// Config holds middleware configuration
type Config struct {
	// TokenLookup is a string in the form of "<source>:<name>"
	// Possible values: "header:Authorization", "query:token", "cookie:auth_token"
	// You can even combine them with commas, e.g. "header:Authorization,cookie:auth_token"
	TokenLookup string
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		TokenLookup: "header:Authorization",
	}
}

// New creates a new middleware with default config
func New(auth *authcore.AuthCore) *Middleware {
	config := DefaultConfig()
	return NewWithConfig(auth, config)
}

// NewWithConfig creates a new middleware with a custom config
func NewWithConfig(auth *authcore.AuthCore, config Config) *Middleware {
	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization"
	}
	return &Middleware{
		auth:        auth,
		tokenLookup: config.TokenLookup,
	}
}

// RequireAuthentication is a Gin middleware that requires a valid token
func (m *Middleware) RequireAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := m.extractToken(c)
		if err != nil {
			problem := authcore.ErrMissingToken
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		claims, err := m.auth.VerifyToken(token)
		if err != nil {
			var problem *authcore.ProblemDetail

			if errors.Is(err, authcore.ErrTokenExpired) {
				problem = authcore.ErrTokenExpiredProblem
			} else {
				problem = authcore.ErrTokenInvalidProblem.WithAdditional("error", err.Error())
			}
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		user := m.auth.CreateUserContext(claims)
		c.Set(m.auth.Config.TokenContextKey, user)
		c.Next()
	}
}

// OptionalAuthentication is a Gin middleware that extracts token if present, but doesn't fail if absent
func (m *Middleware) OptionalAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := m.extractToken(c)
		if err != nil {
			// No token, continue
			c.Next()
			return
		}

		claims, err := m.auth.VerifyToken(token)
		if err != nil {
			// Invalid token, continue
			c.Next()
			return
		}

		user := m.auth.CreateUserContext(claims)
		c.Set(m.auth.Config.TokenContextKey, user)
		c.Next()
	}
}

// RequireRole checks if the authenticated user has a specific role
func (m *Middleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userInterface, exists := c.Get(m.auth.Config.TokenContextKey)
		if !exists {
			problem := authcore.ErrUnauthorized
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		user, ok := userInterface.(authcore.UserContext)
		if !ok {
			problem := authcore.ErrUnauthorized
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		if !user.HasRole(role) {
			problem := authcore.ErrForbidden.WithAdditional("required_role", role)
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole checks if the user has at least one of the given roles
func (m *Middleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userInterface, exists := c.Get(m.auth.Config.TokenContextKey)
		if !exists {
			problem := authcore.ErrUnauthorized
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		user, ok := userInterface.(authcore.UserContext)
		if !ok {
			problem := authcore.ErrUnauthorized
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		for _, r := range roles {
			if user.HasRole(r) {
				c.Next()
				return
			}
		}

		problem := authcore.ErrForbidden.WithAdditional("required_roles", roles)
		problem.WriteJSON(c.Writer)
		c.Abort()
	}
}

// RequireAllRoles checks if the user has all of the given roles
func (m *Middleware) RequireAllRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userInterface, exists := c.Get(m.auth.Config.TokenContextKey)
		if !exists {
			problem := authcore.ErrUnauthorized
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		user, ok := userInterface.(authcore.UserContext)
		if !ok {
			problem := authcore.ErrUnauthorized
			problem.WriteJSON(c.Writer)
			c.Abort()
			return
		}

		for _, r := range roles {
			if !user.HasRole(r) {
				problem := authcore.ErrForbidden.WithAdditional("required_roles", roles)
				problem.WriteJSON(c.Writer)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// extractToken attempts to extract the token from various sources specified in tokenLookup
func (m *Middleware) extractToken(c *gin.Context) (string, error) {
	// tokenLookup can be something like "header:Authorization,cookie:auth_token"
	lookups := strings.Split(m.tokenLookup, ",")

	for _, lookup := range lookups {
		lookup = strings.TrimSpace(lookup)
		parts := strings.Split(lookup, ":")
		if len(parts) != 2 {
			log.Printf("[DEBUG] extractToken => invalid tokenLookup format: %q", lookup)
			continue
		}

		source := parts[0]
		name := parts[1]

		switch source {
		case "header":
			token, err := extractTokenFromHeader(c, name)
			if err == nil && token != "" {
				return token, nil
			}
		case "query":
			token, err := extractTokenFromQuery(c, name)
			if err == nil && token != "" {
				return token, nil
			}
		case "cookie":
			token, err := extractTokenFromCookie(c, name)
			if err == nil && token != "" {
				return token, nil
			}
		default:
			log.Printf("[DEBUG] extractToken => unsupported source: %q", source)
		}
	}

	return "", errors.New("missing auth header or cookie")
}

// extractTokenFromHeader extracts the token from the request header
func extractTokenFromHeader(c *gin.Context, name string) (string, error) {
	log.Printf("[DEBUG] >>> extractTokenFromHeader CALLED. Looking for header: %s", name)

	auth := c.GetHeader(name)
	if auth == "" {
		log.Println("[DEBUG] extractTokenFromHeader: missing auth header")
		return "", errors.New("missing auth header")
	}

	log.Printf("[DEBUG] extractTokenFromHeader: found header value = %q", auth)

	// Check if it's a Bearer token
	if strings.HasPrefix(auth, "Bearer ") {
		tokenPart := auth[7:]
		log.Printf("[DEBUG] extractTokenFromHeader: found Bearer token: %q", tokenPart)
		return tokenPart, nil
	}

	log.Printf("[DEBUG] extractTokenFromHeader: no Bearer prefix, returning full value: %q", auth)
	return auth, nil
}

// extractTokenFromQuery extracts the token from the query string
func extractTokenFromQuery(c *gin.Context, name string) (string, error) {
	token := c.Query(name)
	if token == "" {
		return "", errors.New("missing auth query")
	}
	log.Printf("[DEBUG] extractTokenFromQuery => name: %s, token: %q", name, token)
	return token, nil
}

// extractTokenFromCookie extracts the token from a cookie
func extractTokenFromCookie(c *gin.Context, name string) (string, error) {
	cookie, err := c.Cookie(name)
	if err != nil {
		log.Printf("[DEBUG] extractTokenFromCookie => error: %v", err)
		return "", err
	}
	log.Printf("[DEBUG] extractTokenFromCookie => found cookie %q = %q", name, cookie)
	return cookie, nil
}

// UserFromGinContext is a helper to retrieve the user from gin.Context
func UserFromGinContext(c *gin.Context, contextKey string) (authcore.UserContext, error) {
	if contextKey == "" {
		contextKey = authcore.DefaultTokenContextKey
	}

	userInterface, exists := c.Get(contextKey)
	if !exists {
		return nil, authcore.ErrUserNotFound
	}

	user, ok := userInterface.(authcore.UserContext)
	if !ok {
		return nil, errors.New("invalid user type in context")
	}

	return user, nil
}
