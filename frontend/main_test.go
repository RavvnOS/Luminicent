package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardAndStaticAssets(t *testing.T) {
	handler, err := newHandler("http://127.0.0.1:5000")
	if err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "DevOps Deployment Simulator") {
		t.Fatalf("dashboard response = %d, body %q", page.Code, page.Body.String())
	}

	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "joinSession") {
		t.Fatalf("app asset response = %d", asset.Code)
	}
}

func TestAPIAndSocketIOProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path+"?"+r.URL.RawQuery)
	}))
	defer backend.Close()

	handler, err := newHandler(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/github/repos?page=1&per_page=100", "/socket.io/?EIO=4&transport=polling"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), strings.SplitN(path, "?", 2)[0]) {
			t.Errorf("proxy %s response = %d, body %q", path, response.Code, response.Body.String())
		}
	}
}

func TestRejectsBackendURLWithPath(t *testing.T) {
	if _, err := newHandler("http://localhost:5000/api"); err == nil {
		t.Fatal("expected backend URL path to be rejected")
	}
}