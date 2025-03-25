package authcore

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	// ErrKeyNotFound is returned when a key is not found
	ErrKeyNotFound = errors.New("key not found")
	// ErrInvalidKeyType is returned when a key is of the wrong type
	ErrInvalidKeyType = errors.New("invalid key type")
	// ErrInvalidKeyFormat is returned when a key is not in the expected format
	ErrInvalidKeyFormat = errors.New("invalid key format")
)

// KeyProvider is the interface for providing keys for signing and verification
type KeyProvider interface {
	// GetSigningKey returns the key for signing tokens
	GetSigningKey(algorithm string) (interface{}, error)
	// GetVerificationKey returns the key for verifying tokens
	GetVerificationKey(algorithm string) (interface{}, error)
}

// FileOrEnvKeyProvider implements KeyProvider using files or environment variables
type FileOrEnvKeyProvider struct {
	config          Config
	rsaPrivateKey   *rsa.PrivateKey
	rsaPublicKey    *rsa.PublicKey
	ecdsaPrivateKey *ecdsa.PrivateKey
	ecdsaPublicKey  *ecdsa.PublicKey
}

// NewFileOrEnvKeyProvider creates a new FileOrEnvKeyProvider
func NewFileOrEnvKeyProvider(config Config) (*FileOrEnvKeyProvider, error) {
	provider := &FileOrEnvKeyProvider{
		config: config,
	}

	// For asymmetric algorithms, load the keys
	if strings.HasPrefix(config.SigningAlgorithm, "RS") {
		// RSA keys
		if config.PrivateKeyPath != "" {
			privKey, err := loadRSAPrivateKey(config.PrivateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load RSA private key: %w", err)
			}
			provider.rsaPrivateKey = privKey
			provider.rsaPublicKey = &privKey.PublicKey
		}

		if config.PublicKeyPath != "" && provider.rsaPublicKey == nil {
			pubKey, err := loadRSAPublicKey(config.PublicKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load RSA public key: %w", err)
			}
			provider.rsaPublicKey = pubKey
		}
	} else if strings.HasPrefix(config.SigningAlgorithm, "ES") {
		// ECDSA keys
		if config.PrivateKeyPath != "" {
			privKey, err := loadECDSAPrivateKey(config.PrivateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load ECDSA private key: %w", err)
			}
			provider.ecdsaPrivateKey = privKey
			provider.ecdsaPublicKey = &privKey.PublicKey
		}

		if config.PublicKeyPath != "" && provider.ecdsaPublicKey == nil {
			pubKey, err := loadECDSAPublicKey(config.PublicKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load ECDSA public key: %w", err)
			}
			provider.ecdsaPublicKey = pubKey
		}
	}

	return provider, nil
}

// GetSigningKey returns the key for signing tokens
func (p *FileOrEnvKeyProvider) GetSigningKey(algorithm string) (interface{}, error) {
	// For HMAC algorithms, return the secret
	if strings.HasPrefix(algorithm, "HS") {
		if p.config.TokenSecret == "" {
			return nil, errors.New("token secret is required for HMAC algorithms")
		}
		return []byte(p.config.TokenSecret), nil
	}

	// For RSA algorithms
	if strings.HasPrefix(algorithm, "RS") {
		if p.rsaPrivateKey == nil {
			return nil, errors.New("RSA private key is required for RSA algorithms")
		}
		return p.rsaPrivateKey, nil
	}

	// For ECDSA algorithms
	if strings.HasPrefix(algorithm, "ES") {
		if p.ecdsaPrivateKey == nil {
			return nil, errors.New("ECDSA private key is required for ECDSA algorithms")
		}
		return p.ecdsaPrivateKey, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, algorithm)
}

// GetVerificationKey returns the key for verifying tokens
func (p *FileOrEnvKeyProvider) GetVerificationKey(algorithm string) (interface{}, error) {
	// For HMAC algorithms, return the secret
	if strings.HasPrefix(algorithm, "HS") {
		if p.config.TokenSecret == "" {
			return nil, errors.New("token secret is required for HMAC algorithms")
		}
		return []byte(p.config.TokenSecret), nil
	}

	// For RSA algorithms
	if strings.HasPrefix(algorithm, "RS") {
		if p.rsaPublicKey == nil {
			return nil, errors.New("RSA public key is required for RSA algorithms")
		}
		return p.rsaPublicKey, nil
	}

	// For ECDSA algorithms
	if strings.HasPrefix(algorithm, "ES") {
		if p.ecdsaPublicKey == nil {
			return nil, errors.New("ECDSA public key is required for ECDSA algorithms")
		}
		return p.ecdsaPublicKey, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, algorithm)
}

// Helper functions for loading keys

// loadRSAPrivateKey loads an RSA private key from a file
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidKeyFormat
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS8
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidKeyType
		}

		return rsaKey, nil
	}

	return key, nil
}

// loadRSAPublicKey loads an RSA public key from a file
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidKeyFormat
	}

	// Try parsing as PKIX
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as certificate
		cert, err2 := x509.ParseCertificate(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, ErrInvalidKeyType
		}

		return rsaKey, nil
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	return rsaKey, nil
}

// loadECDSAPrivateKey loads an ECDSA private key from a file
func loadECDSAPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidKeyFormat
	}

	// Try parsing as PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as EC
		ecKey, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		return ecKey, nil
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	return ecKey, nil
}

// loadECDSAPublicKey loads an ECDSA public key from a file
func loadECDSAPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidKeyFormat
	}

	// Try parsing as PKIX
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as certificate
		cert, err2 := x509.ParseCertificate(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, ErrInvalidKeyType
		}

		return ecKey, nil
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	return ecKey, nil
}
