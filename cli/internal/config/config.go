package config

import (
	"os"
	"strings"
)

const DefaultAPIURL = "http://localhost:5000"

type Config struct {
	APIURL        string
	Token         string
	SessionCookie string
}

func Load() Config {
	cfg := Config{
		APIURL:        getenv("LUMINICENT_API_URL", DefaultAPIURL),
		Token:         getenv("LUMINICENT_API_TOKEN", ""),
		SessionCookie: getenv("LUMINICENT_SESSION_COOKIE", ""),
	}
	return cfg
}

func getenv(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
