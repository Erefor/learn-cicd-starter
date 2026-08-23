package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantAPIKey    string
		wantErrString string
		wantErrExact  error
	}{
		{
			name:         "Success - Valid ApiKey Header",
			headers:      http.Header{"Authorization": []string{"ApiKey secret123"}},
			wantAPIKey:   "secret123",
			wantErrExact: nil,
		},
		{
			name:         "Err - Missing Authorization Header",
			headers:      http.Header{},
			wantAPIKey:   "",
			wantErrExact: ErrNoAuthHeaderIncluded,
		},
		{
			name:         "Err - Empty Authorization Header",
			headers:      http.Header{"Authorization": []string{""}},
			wantAPIKey:   "",
			wantErrExact: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Err - Malformed Header (Missing ApiKey Prefix)",
			headers:       http.Header{"Authorization": []string{"Bearer secret123"}},
			wantAPIKey:    "",
			wantErrString: "malformed authorization header",
		},
		{
			name:          "Err - Malformed Header (Only Prefix)",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			wantAPIKey:    "",
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAPIKey, err := GetAPIKey(tt.headers)

			// Validar error exacto (ErrNoAuthHeaderIncluded)
			if tt.wantErrExact != nil {
				if err != tt.wantErrExact {
					t.Errorf("GetAPIKey() error = %v, wantExact %v", err, tt.wantErrExact)
				}
				return
			}

			// Validar mensaje de error dinámico
			if tt.wantErrString != "" {
				if err == nil || err.Error() != tt.wantErrString {
					t.Errorf("GetAPIKey() error = %v, wantErrString %v", err, tt.wantErrString)
				}
				return
			}

			// Validar caso sin errores
			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}

			if gotAPIKey != tt.wantAPIKey {
				t.Errorf("GetAPIKey() gotAPIKey = %v, want %v", gotAPIKey, tt.wantAPIKey)
			}
		})
	}
}
