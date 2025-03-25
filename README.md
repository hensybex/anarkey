# 🔑 AnarKey

> **Freedom from authoritarian authentication!**

AnarKey is a minimalist Go authentication and authorization library designed with one goal in mind: giving developers total control over tokens, roles, and permissions without unnecessary dependencies and bloated solutions.

## 🏴 AnarKey Philosophy

- **Minimalism**: No unnecessary complexity.
- **Flexibility**: Extend and integrate painlessly.
- **Security**: Safe defaults, proven methods.
- **Transparency**: No magic, just straightforward code.

## ⚙️ Features

- Secure JWT implementation by default.
- Refresh token rotation and revocation.
- Simple and intuitive RBAC.
- Ready-to-use middleware for Gin (easy to adapt for other frameworks).
- Easy integration into your existing app.
- Robust error handling.
- Authentication event hooks (for monitoring or extension).

## 💻 Installation

```bash
go get github.com/hensybex/anarkey
```

🚀 Quick Start
```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/hensybex/anarkey/authcore"
    "github.com/hensybex/anarkey/middleware/authgin"
)

func main() {
    auth, err := authcore.NewWithConfig(authcore.Config{
        Issuer:        "my-app",
        Audience:      "my-api",
        TokenSecret:   "change-me-in-production", // Use env vars in prod!
        TokenLifetime: 15 * time.Minute,
    })
    if err != nil {
        panic("AnarKey init error: " + err.Error())
    }

    r := gin.Default()
    authMw := authgin.New(auth)

    r.POST("/login", func(c *gin.Context) {
        username, password := c.PostForm("username"), c.PostForm("password")

        if username == "admin" && password == "password" {
            claims := map[string]interface{}{
                "user_id": "123",
                "roles":   []string{"admin", "user"},
            }

            at, rt, err := auth.GenerateTokens(claims)
            if err != nil {
                c.JSON(500, gin.H{"error": "Token generation failed"})
                return
            }

            c.JSON(200, gin.H{"access_token": at, "refresh_token": rt, "token_type": "Bearer"})
        } else {
            c.JSON(401, gin.H{"error": "Invalid credentials"})
        }
    })

    r.POST("/refresh", func(c *gin.Context) {
        rt := c.PostForm("refresh_token")
        at, rtNew, err := auth.RefreshTokens(rt)
        if err != nil {
            c.JSON(401, gin.H{"error": "Invalid refresh token"})
            return
        }

        c.JSON(200, gin.H{"access_token": at, "refresh_token": rtNew, "token_type": "Bearer"})
    })

    protected := r.Group("/")
    protected.Use(authMw.RequireAuthentication())
    protected.GET("/profile", func(c *gin.Context) {
        user, _ := authgin.UserFromGinContext(c, auth.Config.TokenContextKey)
        c.JSON(200, gin.H{"user_id": user.GetClaim("user_id"), "roles": user.GetClaim("roles")})
    })

    admin := r.Group("/")
    admin.Use(authMw.RequireAuthentication(), authMw.RequireRole("admin"))
    admin.GET("/admin", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Welcome, admin!"})
    })

    r.Run(":8080")
}
```

🔧 Configuration Options
```go
// Environment variables (recommended)
auth, err := authcore.New()

// YAML file configuration
auth, err := authcore.NewFromFile("./config.yaml")

// Viper configuration
v := viper.New()
v.SetConfigFile("./config.yaml")
v.ReadInConfig()
auth, err := authcore.NewFromViper(v)
```

🔐 Security Recommendations

    Strong secrets, secure storage.

    RS256/ES256 for production.

    User authentication responsibility stays within your app.

📜 License

MIT