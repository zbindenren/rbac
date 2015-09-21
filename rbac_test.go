package rbac

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "hello world")
}

func TestAuthorize(t *testing.T) {
	SetRoleGetter(TestRoleGetter{[]string{"role1", "role2"}})
	req, _ := http.NewRequest("GET", "", nil)
	var tests = []struct {
		allowedRoles []string
		statusCode   int
	}{
		{[]string{"role1"}, http.StatusOK},
		{[]string{"role1", "admin"}, http.StatusOK},
		{[]string{"role2"}, http.StatusOK},
		{[]string{"admin"}, http.StatusUnauthorized},
		{[]string{""}, http.StatusUnauthorized},
	}

	for _, test := range tests {
		w := httptest.NewRecorder()
		sec := Authorize(helloHandler, test.allowedRoles...)
		sec(w, req)
		if w.Code != test.statusCode {
			t.Errorf("for roles '%s' got status code %d, wanted %d", strings.Join(test.allowedRoles, ", "), w.Code, test.statusCode)
		}
	}
}

func TestErrorAuthorize(t *testing.T) {
	SetRoleGetter(TestRoleGetter{}) // this role getter returns error
	req, _ := http.NewRequest("GET", "", nil)
	w := httptest.NewRecorder()
	sec := Authorize(helloHandler, "admin")
	sec(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status code %d, wanted %d", w.Code, http.StatusInternalServerError)
	}
}

func TestBasicAuthRoleGetter(t *testing.T) {
	var tests = []struct {
		authHeader string
		err        error
		role       string
	}{
		{"Basic cno6MTIzNDU2", nil, "rz"},                  // Basic rz:123456
		{"Basic cno=", ErrMalformedBasicAuth, ""},          // Basic rz
		{"Basiccno6MTIzNDU2", ErrMalformedBasicAuth, "rz"}, // Basic rz:123456
	}

	rg := BasicAuthRoleGetter{}
	req, _ := http.NewRequest("GET", "", nil)
	roles, err := rg.GetRoles(req)
	if err != nil {
		t.Errorf("got error %s but should not", err)
	}
	if len(roles) > 0 {
		t.Errorf("got roles %s, but should not", strings.Join(roles, ", "))
	}
	for _, test := range tests {
		req.Header.Set("Authorization", test.authHeader)
		roles, err = rg.GetRoles(req)
		if err != test.err {
			t.Errorf("got error %s but should not", err)
		}
		if len(roles) > 0 && roles[0] != test.role {
			t.Errorf("got role %s, but want %s", roles[0], "rz")
		}
	}
	req.Header.Set("Authorization", "Basic cno6öTIzNDU2") // ö is not valid
	roles, err = rg.GetRoles(req)
	if err == nil {
		t.Error("got no error error but should not")
	}
}
