package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:embed templates/index.html static
var webAssets embed.FS

func main() {
	backendAddress := envOr("BACKEND_URL", "http://localhost:5000")
	handler, err := newHandler(backendAddress)
	if err != nil {
		log.Fatal(err)
	}

	address := net.JoinHostPort(envOr("HOST", "0.0.0.0"), envOr("PORT", "5173"))
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       75 * time.Second,
	}

	log.Printf("Luminicent Go frontend listening on http://%s (backend: %s)", address, backendAddress)
	log.Fatal(server.ListenAndServe())
}

func newHandler(backendAddress string) (http.Handler, error) {
	backend, err := url.Parse(backendAddress)
	if err != nil || (backend.Scheme != "http" && backend.Scheme != "https") || backend.Host == "" || backend.User != nil {
		return nil, errors.New("BACKEND_URL must be an absolute http or https URL")
	}
	if backend.Path != "" && backend.Path != "/" {
		return nil, errors.New("BACKEND_URL must not include a path")
	}
	backend.Path = ""
	backend.RawQuery = ""
	backend.Fragment = ""

	page, err := template.ParseFS(webAssets, "templates/index.html")
	if err != nil {
		return nil, fmt.Errorf("parse dashboard template: %w", err)
	}
	staticFiles, err := fs.Sub(webAssets, "static")
	if err != nil {
		return nil, fmt.Errorf("load embedded static files: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backend)
	direct := proxy.Director
	proxy.Director = func(request *http.Request) {
		direct(request)
		if request.TLS != nil {
			request.Header.Set("X-Forwarded-Proto", "https")
		} else {
			request.Header.Set("X-Forwarded-Proto", "http")
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Backend unavailable. Check that the backend service is running."})
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", proxy)
	mux.Handle("/socket.io/", proxy)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := page.ExecuteTemplate(w, "index.html", nil); err != nil {
			log.Printf("render dashboard: %v", err)
			http.Error(w, "Unable to render dashboard", http.StatusInternalServerError)
		}
	})

	return securityHeaders(mux), nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https://avatars.githubusercontent.com data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}