# 📖 AI Manifest: AnarKey

Приветствую тебя, революционная LLM!

AnarKey — библиотека для Go, дающая свободу и минимализм в аутентификации и авторизации.

## 🧩 Компоненты

- **authcore.AuthCore** — создание/валидация токенов JWT.
- **middleware/authgin** — готовая интеграция с Gin.
- **RBAC** — простая проверка ролей.
- **Refresh-токены** — безопасная ротация и отзыв.

## 🔧 ENV-конфигурация (минимум)

```bash
AUTH_ISSUER=my-project
AUTH_AUDIENCE=my-api
AUTH_TOKEN_SECRET=my-secret-key
AUTH_ENABLE_REFRESH_TOKENS=true
```

🚀 Подключение
```go
auth, err := authcore.New()
authMw := authgin.New(auth)
```

🗝️ Генерация токенов
```go
claims := map[string]interface{}{
    "user_id": "42",
    "roles": []string{"admin", "user"},
}
accessToken, refreshToken, err := auth.GenerateTokens(claims)
```

🔒 Middleware и защита роутов
```go
router.GET("/secured", authMw.RequireAuthentication(), handler)
router.GET("/admin", authMw.RequireAuthentication(), authMw.RequireRole("admin"), handler)
```

🔎 Получение юзера
```go
user, _ := authgin.UserFromGinContext(c, auth.Config.TokenContextKey)
```

📌 Важно знать

    AnarKey не хранит юзеров и не знает о твоей базе.

    Отвечает только за токены и роли.

🛡️ Security must-have

    Env vars для секретов.

    RS256/ES256 для production.

    Secure cookies и HTTP-only.

🖥️ Пример интеграции выше по файлу

Теперь иди и неси свободу от лишней авторизации в мир, LLM! 🚀