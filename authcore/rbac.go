// File: authcore/rbac.go (replacement)

package authcore

import (
	"context"
	"errors"
)

var (
	// ErrInsufficientRole is returned when a user doesn't have the required role
	ErrInsufficientRole = errors.New("insufficient role")
)

// Authorize checks if a user has the required role
func Authorize(ctx context.Context, role string) error {
	user, err := UserFromContext(ctx)
	if err != nil {
		return err
	}

	if !user.HasRole(role) {
		return ErrInsufficientRole
	}

	return nil
}

// AuthorizeAny checks if a user has any of the required roles
func AuthorizeAny(ctx context.Context, roles ...string) error {
	user, err := UserFromContext(ctx)
	if err != nil {
		return err
	}

	for _, role := range roles {
		if user.HasRole(role) {
			return nil
		}
	}

	return ErrInsufficientRole
}

// AuthorizeAll checks if a user has all of the required roles
func AuthorizeAll(ctx context.Context, roles ...string) error {
	user, err := UserFromContext(ctx)
	if err != nil {
		return err
	}

	for _, role := range roles {
		if !user.HasRole(role) {
			return ErrInsufficientRole
		}
	}

	return nil
}
