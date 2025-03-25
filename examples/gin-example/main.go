// File: examples/gin-example/main.go

package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/hensybex/anarkey/authcore"
	"github.com/hensybex/anarkey/middleware/authgin"
)

// User represents a user in the system
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Password string   `json:"-"` // Never return this
	Roles    []string `json:"roles"`
}

// SimulateDB is a map of users for demonstration purposes
var SimulateDB = map[string]User{
	"1": {
		ID:       "1",
		Username: "admin",
		Password: "password",
		Roles:    []string{"admin", "user"},
	},
	"2": {
		ID:       "2",
		Username: "user",
		Password: "password",
		Roles:    []string{"user"},
	},
}

func main() {
	// Initialize auth core with config from env variables
	auth, err := authcore.New()
	if err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}

	// Initialize Gin
	r := gin.Default()

	// Configure CORS
	configureCORS(r)

	// Create auth middleware (header + cookie)
	authMw := authgin.NewWithConfig(auth, authgin.Config{
		TokenLookup: "header:Authorization,cookie:auth_token",
	})

	// Set up routes
	setupRoutes(r, auth, authMw)

	// Start server
	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// configureCORS sets up the default CORS middleware
func configureCORS(r *gin.Engine) {
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "https://example.com"}
	config.AllowCredentials = true
	config.AllowHeaders = append(config.AllowHeaders, "Authorization")
	r.Use(cors.New(config))
}

// setupRoutes defines all HTTP routes in the Gin router
func setupRoutes(r *gin.Engine, auth *authcore.AuthCore, authMw *authgin.Middleware) {
	// Public routes
	r.POST("/login", handleLogin(auth))
	r.POST("/refresh", handleRefresh(auth))
	r.GET("/public", authMw.OptionalAuthentication(), handlePublic(auth))
	r.GET("/health", handleHealth())

	// Protected routes
	protected := r.Group("/api")
	protected.Use(authMw.RequireAuthentication())
	protected.GET("/profile", handleProfile(auth))

	// Admin-only routes
	admin := r.Group("/api/admin")
	admin.Use(authMw.RequireAuthentication(), authMw.RequireRole("admin"))
	admin.GET("/users", handleListUsers())
}

// handleLogin processes the login request
func handleLogin(auth *authcore.AuthCore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get credentials
		username := c.PostForm("username")
		password := c.PostForm("password")

		log.Printf("[DEBUG] handleLogin => username=%q password=%q", username, password)

		// Validate credentials (simulated)
		var user User
		var found bool

		for _, u := range SimulateDB {
			if u.Username == username && u.Password == password {
				user = u
				found = true
				break
			}
		}

		if !found {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Create claims
		claims := map[string]interface{}{
			"sub":      user.ID,
			"user_id":  user.ID,
			"username": user.Username,
			"roles":    user.Roles,
		}

		// Generate tokens
		accessToken, refreshToken, err := auth.GenerateTokens(claims)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
			return
		}

		// Log the tokens
		log.Println("[DEBUG] Login successful => accessToken =", accessToken)
		log.Println("[DEBUG] Login successful => refreshToken =", refreshToken)

		// Return them
		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"token_type":    "Bearer",
			"expires_in":    int(auth.Config.TokenLifetime.Seconds()),
		})
	}
}

// handleRefresh processes token refreshing
func handleRefresh(auth *authcore.AuthCore) gin.HandlerFunc {
	return func(c *gin.Context) {
		refreshToken := c.PostForm("refresh_token")
		if refreshToken == "" {
			refreshToken = c.GetHeader("X-Refresh-Token")
		}

		log.Println("[DEBUG] handleRefresh => refresh_token =", refreshToken)

		if refreshToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing refresh token"})
			return
		}

		accessToken, newRefreshToken, err := auth.RefreshTokens(refreshToken)
		if err != nil {
			log.Println("[DEBUG] handleRefresh => refresh error:", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			return
		}

		log.Println("[DEBUG] Refresh success => new accessToken =", accessToken)
		log.Println("[DEBUG] Refresh success => new refreshToken =", newRefreshToken)

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
			"token_type":    "Bearer",
			"expires_in":    int(auth.Config.TokenLifetime.Seconds()),
		})
	}
}

// handleProfile is a protected route requiring authentication
func handleProfile(auth *authcore.AuthCore) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("[DEBUG] handleProfile => entering handler")

		// Get user from context
		user, err := authgin.UserFromGinContext(c, auth.Config.TokenContextKey)
		if err != nil {
			log.Printf("[DEBUG] handleProfile => failed to get user from context: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
			return
		}

		userID := user.GetUserID()
		log.Printf("[DEBUG] handleProfile => userID = %q\n", userID)

		// Find user in DB
		dbUser, exists := SimulateDB[userID]
		if !exists {
			log.Printf("[DEBUG] handleProfile => user not found in DB, userID=%q\n", userID)
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":       dbUser.ID,
			"username": dbUser.Username,
			"roles":    dbUser.Roles,
		})
	}
}

// handleListUsers is an admin-only endpoint
func handleListUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Convert map to slice
		users := make([]User, 0, len(SimulateDB))
		for _, user := range SimulateDB {
			users = append(users, user)
		}
		c.JSON(http.StatusOK, gin.H{"users": users})
	}
}

// handlePublic is an endpoint with optional auth
func handlePublic(auth *authcore.AuthCore) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := authgin.UserFromGinContext(c, auth.Config.TokenContextKey)

		if err == nil {
			// Authenticated
			log.Println("[DEBUG] handlePublic => user is authenticated, userID =", user.GetUserID())
			c.JSON(http.StatusOK, gin.H{
				"message":      "This is a public endpoint with optional authentication",
				"user_id":      user.GetUserID(),
				"username":     user.GetClaim("username"),
				"is_admin":     user.HasRole("admin"),
				"is_logged_in": true,
			})
		} else {
			// Not authenticated
			log.Println("[DEBUG] handlePublic => user not authenticated")
			c.JSON(http.StatusOK, gin.H{
				"message":      "This is a public endpoint with optional authentication",
				"is_logged_in": false,
			})
		}
	}
}

// handleHealth returns a simple health check response
func handleHealth() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Unix(),
		})
	}
}
