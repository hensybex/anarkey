package authcore

import (
	"context"
	"errors"
)

var (
	// ErrUserNotFound is returned when a user is not found in the context
	ErrUserNotFound = errors.New("user not found in context")
)

// UserContext represents a user in the context
type UserContext interface {
	// GetUserID returns the user ID
	GetUserID() string
	// GetClaim returns a claim value
	GetClaim(name string) interface{}
	// HasRole checks if the user has a specific role
	HasRole(role string) bool
	// GetClaims returns all claims
	GetClaims() map[string]interface{}
}

// userContextKey is the key for the user context
type userContextKey struct{}

// defaultUserContext is the default implementation of UserContext
type defaultUserContext struct {
	claims *Claims
	userID string
}

// NewUserContext creates a new UserContext
func NewUserContext(claims *Claims) UserContext {
	userID := claims.Subject

	// If subject is not set, try to get user ID from custom claims
	if userID == "" {
		if userIDClaim := claims.GetClaim("user_id"); userIDClaim != nil {
			if userIDStr, ok := userIDClaim.(string); ok {
				userID = userIDStr
			}
		}
	}

	return &defaultUserContext{
		claims: claims,
		userID: userID,
	}
}

// GetUserID returns the user ID
func (u *defaultUserContext) GetUserID() string {
	return u.userID
}

// GetClaim returns a claim value
func (u *defaultUserContext) GetClaim(name string) interface{} {
	return u.claims.GetClaim(name)
}

// HasRole checks if the user has a specific role
func (u *defaultUserContext) HasRole(role string) bool {
	return u.claims.HasRole(role)
}

// GetClaims returns all claims
func (u *defaultUserContext) GetClaims() map[string]interface{} {
	// Get registered claims
	claims := map[string]interface{}{
		"iss": u.claims.Issuer,
		"sub": u.claims.Subject,
		"aud": u.claims.Audience,
	}

	if u.claims.ExpiresAt != nil {
		claims["exp"] = u.claims.ExpiresAt.Unix()
	}
	if u.claims.NotBefore != nil {
		claims["nbf"] = u.claims.NotBefore.Unix()
	}
	if u.claims.IssuedAt != nil {
		claims["iat"] = u.claims.IssuedAt.Unix()
	}
	if u.claims.ID != "" {
		claims["jti"] = u.claims.ID
	}

	// Add custom claims
	for key, value := range u.claims.CustomClaims {
		claims[key] = value
	}

	return claims
}

// WithUser adds a user to the context
func WithUser(ctx context.Context, user UserContext) context.Context {
	return context.WithValue(ctx, userContextKey{}, user)
}

// UserFromContext gets a user from the context
func UserFromContext(ctx context.Context) (UserContext, error) {
	user, ok := ctx.Value(userContextKey{}).(UserContext)
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// MustUserFromContext gets a user from the context or panics
func MustUserFromContext(ctx context.Context) UserContext {
	user, err := UserFromContext(ctx)
	if err != nil {
		panic(err)
	}
	return user
}

// HasRole checks if the user in the context has a specific role
func HasRole(ctx context.Context, role string) bool {
	user, err := UserFromContext(ctx)
	if err != nil {
		return false
	}
	return user.HasRole(role)
}
