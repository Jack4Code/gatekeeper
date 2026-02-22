package main

import (
	"context"
	_ "embed"
	"html/template"
	"net/http"
	"time"

	"github.com/Jack4Code/bedrock"
)

//go:embed templates/health.gohtml
var healthTemplate string

var healthTmpl = template.Must(template.New("health").Parse(healthTemplate))

type htmlResponse struct {
	statusCode int
	tmpl       *template.Template
	data       any
}

func (r htmlResponse) Write(_ context.Context, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(r.statusCode)
	return r.tmpl.Execute(w, r.data)
}

type healthData struct {
	Healthy     bool
	ServiceName string
	Timestamp   string
	Error       string
}

func (s *AuthService) Health(ctx context.Context, r *http.Request) bedrock.Response {
	data := healthData{
		ServiceName: "gatekeeper",
		Timestamp:   time.Now().UTC().Format(time.RFC1123),
	}

	if err := s.db.PingContext(ctx); err != nil {
		data.Healthy = false
		data.Error = "database unreachable"
		return htmlResponse{statusCode: http.StatusServiceUnavailable, tmpl: healthTmpl, data: data}
	}

	data.Healthy = true
	return htmlResponse{statusCode: http.StatusOK, tmpl: healthTmpl, data: data}
}
