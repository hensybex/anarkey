# 🔑 AnarKey

> **Свобода от авторитарной авторизации!**

AnarKey — минималистичная библиотека авторизации и аутентификации для Go-приложений, созданная с одной целью: дать разработчикам полную власть над токенами, ролями и доступами — без лишних зависимостей и громоздких решений.

## 🏴 Философия AnarKey

- **Минимализм**: ничего лишнего.
- **Гибкость**: расширяй и интегрируй без боли.
- **Безопасность**: надёжные дефолты, проверенные подходы.
- **Прозрачность**: никакой магии — просто код.

## ⚙️ Возможности

- JWT с безопасными настройками по умолчанию.
- Refresh-токены (ротация и отзыв).
- Простая и понятная система RBAC.
- Готовые middleware для Gin (легко адаптируются под другие фреймворки).
- Легкая интеграция с твоим существующим приложением.
- Продуманная обработка ошибок.
- Хуки событий авторизации (для мониторинга или расширений).

## 💻 Установка

```bash
go get github.com/hensybex/anarkey
```

🚀 Быстрый старт
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
        TokenSecret:   "меняй-в-проде", // Env vars в продакшне!
        TokenLifetime: 15 * time.Minute,
    })
    if err != nil {
        panic("Ошибка AnarKey: " + err.Error())
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
                c.JSON(500, gin.H{"error": "Не смог создать токены"})
                return
            }

            c.JSON(200, gin.H{"access_token": at, "refresh_token": rt, "token_type": "Bearer"})
        } else {
            c.JSON(401, gin.H{"error": "Неверные креды"})
        }
    })

    r.POST("/refresh", func(c *gin.Context) {
        rt := c.PostForm("refresh_token")
        at, rtNew, err := auth.RefreshTokens(rt)
        if err != nil {
            c.JSON(401, gin.H{"error": "Невалидный refresh-токен"})
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
        c.JSON(200, gin.H{"message": "Добро пожаловать, admin!"})
    })

    r.Run(":8080")
}
```

🔧 Варианты конфигурации
```go
// Переменные окружения (рекомендуется)
auth, err := authcore.New()

// Через конфигурационный файл YAML
auth, err := authcore.NewFromFile("./config.yaml")

// Через Viper
v := viper.New()
v.SetConfigFile("./config.yaml")
v.ReadInConfig()
auth, err := authcore.NewFromViper(v)
```

🔐 Рекомендации по безопасности

    Используй сильные секреты и secure storage.

    RS256/ES256 — в продакшн.

    Авторизация юзеров — ответственность твоего приложения.

📜 Лицензия
MIT