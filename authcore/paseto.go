// File: authcore/paseto.go

package authcore

// PasetoService defines the interface for PASETO token operations
type PasetoService interface {
	// Generate creates a new PASETO token
	Generate(claims Claims) (string, error)
	// Verify checks if a PASETO token is valid
	Verify(tokenString string) (*Claims, error)
}

// TODO: implement actual Paseto usage
// The implementation would use the v4.Local or v4.Public options from the paseto library
// For example github.com/o1egl/paseto
