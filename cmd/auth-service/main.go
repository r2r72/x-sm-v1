// Package main запускает Auth Service — микросервис аутентификации и управления пользователями.
//
// Основные возможности:
//   - Регистрация новых пользователей (локальная и federated)
//   - Аутентификация по логину/паролю + MFA (TOTP)
//   - Выдача JWT-токенов (Access + Refresh)
//   - Синхронизация данных с Core Service через события
//
// Безопасность:
//   - Пароли хешируются bcrypt (cost=12)
//   - MFA-секреты шифруются AES-GCM (ключ из Vault)
//   - Все операции аудируются в auth.login_attempts
//
// Запуск:
//
//	go run . -addr :8081 -db-url "postgres://esm:esm@localhost:5432/esm"
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/r2r72/x-sm-v1/cmd/auth-service/handlers"
	"github.com/r2r72/x-sm-v1/internal/repository/pg"
	"github.com/r2r72/x-sm-v1/internal/service/auth"
)

// Config — параметры запуска сервиса.
type Config struct {
	Addr   string
	DBURL  string
	Secret string // для JWT (в prod — из Vault)
}

// 🔑 Compile-time check: гарантирует, что pg.AuthRepository реализует auth.AuthRepository
var _ auth.AuthRepository = (*pg.AuthRepository)(nil)

func main() {
	// === Парсинг флагов ===
	cfg := Config{}
	flag.StringVar(&cfg.Addr, "addr", ":8081", "HTTP listen address")
	flag.StringVar(&cfg.DBURL, "db-url", "postgres://esm:esm@localhost:5432/esm?sslmode=disable", "PostgreSQL DSN")
	flag.StringVar(&cfg.Secret, "jwt-secret", "dev-secret-32-bytes-length", "JWT signing secret (32+ bytes)")
	flag.Parse()

	// === Инициализация зависимостей ===
	db, err := pg.NewDB(cfg.DBURL)
	if err != nil {
		log.Fatalf("❌ Failed to connect to DB: %v", err)
	}
	defer db.Close()

	authRepo := pg.NewAuthRepository(db)
	authSvc := auth.NewAuthService(authRepo, []byte(cfg.Secret))

	// === Настройка HTTP-сервера ===
	mux := http.NewServeMux()
	handlers.RegisterAuthRoutes(mux, authSvc)

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// === Graceful shutdown ===
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("🚀 Auth Service started on %s", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server failed: %v", err)
		}
	}()

	<-done
	log.Println("⏳ Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("❌ Server shutdown failed: %v", err)
	}

	log.Println("✅ Auth Service stopped")
}
