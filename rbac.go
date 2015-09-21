package rbac

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
)

var roleGetter RoleGetter

var (
	//ErrMalformedBasicAuth is returned if the if BasicAuthRoleGetter encounters a malformed basic auth header
	ErrMalformedBasicAuth = errors.New("malformed basic auth format")
)

// Authorize is a http.HandlerFunc wrapper that checks if one of the
// current roles matches with a role in allowedRoles.
// The current roles are extracted from the http.Request by RoleGetter.
func Authorize(h http.Handler, allowedRoles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed := false
		roles, err := roleGetter.GetRoles(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	Loop:
		for _, currentRole := range roles {
			for _, allowedRole := range allowedRoles {
				if currentRole == allowedRole {
					allowed = true
					break Loop
				}
			}
		}
		if !allowed {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// RoleGetter is implemented by any type that has a GetRoles method, which
// extracts the current roles from the http.Request.
type RoleGetter interface {
	GetRoles(r *http.Request) ([]string, error)
}

// SetRoleGetter sets the RoleGetter for the package. This method has always
// be invoked before package usage.
func SetRoleGetter(rg RoleGetter) {
	m := new(sync.Mutex)
	m.Lock()
	roleGetter = rg
	m.Unlock()
}

// BasicAuthRoleGetter can be used in combination with basic auth
type BasicAuthRoleGetter struct {
}

// GetRoles returns the basic auth user name as role
func (rg BasicAuthRoleGetter) GetRoles(r *http.Request) ([]string, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) == 0 {
		return []string{}, nil
	}
	if !strings.Contains(auth, "Basic") {
		return []string{}, nil
	}
	splittedAuth := strings.Split(auth, " ")
	if len(splittedAuth) != 2 {
		return []string{}, ErrMalformedBasicAuth
	}
	decoded, err := base64.StdEncoding.DecodeString(splittedAuth[1])
	if err != nil {
		return []string{}, err
	}
	splitted := strings.Split(string(decoded), ":")
	if len(splitted) != 2 {
		return []string{}, ErrMalformedBasicAuth
	}
	return []string{splitted[0]}, nil
}

// TestRoleGetter is a RoleGetter which should only used for testing
// purposes.
type TestRoleGetter struct {
	Roles []string
}

// GetRoles returns the roles from TestRoleGetter. If list is empty
// an error is returned.
func (rg TestRoleGetter) GetRoles(r *http.Request) ([]string, error) {
	if len(rg.Roles) == 0 {
		return []string{}, errors.New("role getter failed to get roles")
	}
	return rg.Roles, nil
}
