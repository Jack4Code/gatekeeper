package main

import (
	"context"
	_ "embed"
	"html/template"
	"net/http"

	"github.com/Jack4Code/bedrock"
)

//go:embed templates/register.gohtml
var registerTemplate string

var registerTmpl = template.Must(template.New("register").Parse(registerTemplate))

func (s *AuthService) RegisterPage(_ context.Context, _ *http.Request) bedrock.Response {
	return htmlResponse{statusCode: http.StatusOK, tmpl: registerTmpl, data: nil}
}
