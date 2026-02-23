package main

import (
	"context"
	_ "embed"
	"html/template"
	"net/http"

	"github.com/Jack4Code/bedrock"
)

//go:embed templates/login.gohtml
var loginTemplate string

var loginTmpl = template.Must(template.New("login").Parse(loginTemplate))

func (s *AuthService) LoginPage(_ context.Context, _ *http.Request) bedrock.Response {
	return htmlResponse{statusCode: http.StatusOK, tmpl: loginTmpl, data: nil}
}
