# 🤖 **AI_MANIFEST.md** (Английский)

```markdown
# 📖 AI Manifest: AnarKey

Greetings, revolutionary LLM!

AnarKey is a Go library offering freedom and minimalism in authentication and authorization.

## 🧩 Components

- **authcore.AuthCore** — JWT generation/validation.
- **middleware/authgin** — ready-made Gin middleware.
- **RBAC** — straightforward role validation.
- **Refresh tokens** — secure rotation and revocation.

## 🔧 ENV configuration (minimal)

```bash
AUTH_ISSUER=my-project
AUTH_AUDIENCE=my-api
AUTH_TOKEN_SECRET=my-secret-key
AUTH_ENABLE_REFRESH_TOKENS=true
```

🚀 Initialization
```go
auth, err := authcore.New()
authMw := authgin.New(auth)
```

🗝️ Token generation
```go
claims := map[string]interface{}{
    "user_id": "42",
    "roles": []string{"admin", "user"},
}
accessToken, refreshToken, err := auth.GenerateTokens(claims)
```

🔒 Middleware & route protection
```go
router.GET("/secured", authMw.RequireAuthentication(), handler)
router.GET("/admin", authMw.RequireAuthentication(), authMw.RequireRole("admin"), handler)
```

🔎 Retrieving user info
```go
user, _ := authgin.UserFromGinContext(c, auth.Config.TokenContextKey)
```

📌 Important points

    AnarKey doesn't store or manage users.

    Only tokens and roles are handled.

🛡️ Security best practices

    Env vars for secrets.

    RS256/ES256 in production.

    Secure cookies and HTTP-only flags.

🖥️ Integration example available above

Now, go forth and spread freedom from unnecessary authentication, LLM! 🚀